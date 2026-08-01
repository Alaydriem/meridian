use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::ephemeral_socket::{CidKey, ClientTarget, EphemeralSocket, Liveness, SocketId};

/// Ceiling on live ephemeral sockets.
///
/// A short-header packet allocates a socket with no handshake and no SNI, so an
/// unauthenticated sender can drive allocation from arbitrary source addresses.
pub const DEFAULT_MAX_EPHEMERAL_SOCKETS: usize = 65_536;

/// Owns one backend-facing socket per client connection.
///
/// Keyed by an opaque [`SocketId`] and reached through two indexes: the client's
/// current address, and every Connection ID seen for the connection. Both change over
/// a connection's life, and each distinct source address the backend observes costs
/// one of its five never-reclaimed QUIC paths — so two indexes onto one stable entry
/// is what lets the keys change without rebinding the socket.
pub struct EphemeralSocketManager {
    sockets: DashMap<SocketId, EphemeralSocket>,
    by_client_addr: DashMap<SocketAddr, SocketId>,
    by_dcid: DashMap<CidKey, SocketId>,
    next_id: AtomicU64,
    main_socket: Arc<UdpSocket>,
    ttl: Duration,
    max_sockets: usize,
    /// Shared reference point for every socket's liveness clock.
    epoch: Instant,
}

impl EphemeralSocketManager {
    pub fn new(main_socket: Arc<UdpSocket>, ttl: Duration, max_sockets: usize) -> Arc<Self> {
        Arc::new(Self {
            sockets: DashMap::new(),
            by_client_addr: DashMap::new(),
            by_dcid: DashMap::new(),
            next_id: AtomicU64::new(1),
            main_socket,
            ttl,
            max_sockets,
            epoch: Instant::now(),
        })
    }

    /// The local wildcard a backend-facing socket must bind to reach `backend_addr`.
    ///
    /// The family has to match: a socket bound to `0.0.0.0` cannot `connect` to an
    /// IPv6 address, so hardcoding the IPv4 wildcard made an IPv6 backend unreachable.
    ///
    /// Unlike the ingress listener, this socket is connected to exactly one backend, so
    /// it never has to serve both families at once — matching is enough, and no
    /// IPV6_V6ONLY handling is needed.
    fn wildcard_for(backend_addr: SocketAddr) -> SocketAddr {
        match backend_addr {
            SocketAddr::V4(_) => {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }
            SocketAddr::V6(_) => {
                SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            }
        }
    }

    /// Get or create the backend-facing socket for a client connection.
    ///
    /// Supplying `dcid` is what makes a NAT rebind free: the address changed but the
    /// CID did not, so the existing socket is found instead of a new one bound.
    pub async fn get_or_create(
        self: &Arc<Self>,
        client_addr: SocketAddr,
        dcid: Option<&[u8]>,
        backend_addr: SocketAddr,
        shutdown: CancellationToken,
    ) -> Result<Arc<UdpSocket>> {
        // DCID first because it survives an address change; client address because
        // the Initial's DCID is client-chosen and replaced by the server's after the
        // handshake, so neither key alone spans a connection.
        let existing = dcid
            .and_then(|d| self.by_dcid.get(d).map(|r| *r.value()))
            .or_else(|| self.by_client_addr.get(&client_addr).map(|r| *r.value()));

        if let Some(id) = existing
            && let Some(socket) = self.attach(id, client_addr, dcid)
        {
            return Ok(socket);
        }

        // Checked before binding so a refusal costs no fd. Deliberately the only cap
        // check: re-checking inside the `Entry` match below would deadlock, since the
        // entry guard write-locks one shard and `DashMap::len` read-locks all of them.
        // Concurrent creators can overshoot by the number of callers in flight.
        if self.sockets.len() >= self.max_sockets {
            anyhow::bail!(
                "ephemeral socket cap reached ({}), refusing new socket for {client_addr}",
                self.max_sockets
            );
        }

        // Bind and connect are await points, so several callers for one client can
        // reach here at once.
        let candidate = UdpSocket::bind(Self::wildcard_for(backend_addr)).await?;
        candidate.connect(backend_addr).await?;
        let candidate = Arc::new(candidate);

        // Child of the global token: cancelled by shutdown OR by eviction.
        let cancel = shutdown.child_token();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // Publish the entry *before* claiming the address index, so that "id present
        // in by_client_addr" implies "entry present in sockets". The other order lets
        // a loser find the winner's id with no entry behind it.
        let entry = EphemeralSocket::new(candidate.clone(), client_addr, cancel.clone(), self.epoch);
        let liveness = entry.liveness.clone();
        let target = entry.target.clone();
        self.sockets.insert(id, entry);

        // Losers discard a candidate that never sent a byte, so the backend never
        // sees it and no QUIC path is spent.
        let claimed = match self.by_client_addr.entry(client_addr) {
            Entry::Occupied(occupied) => Err(*occupied.get()),
            Entry::Vacant(vacant) => {
                vacant.insert(id);
                Ok(())
            }
        };

        if let Err(winner) = claimed {
            // Withdraw our unpublished entry, then join the winner.
            self.sockets.remove(&id);
            cancel.cancel();
            return self
                .attach(winner, client_addr, dcid)
                .ok_or_else(|| anyhow::anyhow!("lost socket race and winner vanished"));
        }

        if let Some(d) = dcid {
            self.register_dcid(id, d);
        }

        self.spawn_return_path(candidate.clone(), target, cancel, liveness);
        Ok(candidate)
    }

    /// Bind `client_addr` and `dcid` to an existing socket and return it.
    ///
    /// `None` means the index pointed at a socket that no longer exists.
    fn attach(
        &self,
        id: SocketId,
        client_addr: SocketAddr,
        dcid: Option<&[u8]>,
    ) -> Option<Arc<UdpSocket>> {
        // Scope the guard: the calls below write-lock the same map.
        let socket = {
            let entry = self.sockets.get(&id)?;
            entry.touch();
            // Redirect the return path, so a client that moved keeps receiving.
            entry.target.set(client_addr);
            entry.socket.clone()
        };

        self.remember_client(id, client_addr);
        if let Some(d) = dcid {
            self.register_dcid(id, d);
        }

        Some(socket)
    }

    /// Index `dcid` to `id`, recording it on the entry so eviction can clear it.
    fn register_dcid(&self, id: SocketId, dcid: &[u8]) {
        if self.by_dcid.contains_key(dcid) {
            return;
        }
        self.by_dcid.insert(dcid.to_vec(), id);
        if let Some(mut entry) = self.sockets.get_mut(&id) {
            entry.dcids.push(dcid.to_vec());
        }
    }

    /// Index `client_addr` to `id`, recording it on the entry so eviction can clear
    /// it. A rebound connection accumulates addresses as it does Connection IDs.
    fn remember_client(&self, id: SocketId, client_addr: SocketAddr) {
        if self.by_client_addr.get(&client_addr).map(|r| *r.value()) == Some(id) {
            if let Some(mut entry) = self.sockets.get_mut(&id)
                && !entry.client_addrs.contains(&client_addr)
            {
                entry.client_addrs.push(client_addr);
            }
            return;
        }
        self.by_client_addr.insert(client_addr, id);
        if let Some(mut entry) = self.sockets.get_mut(&id)
            && !entry.client_addrs.contains(&client_addr)
        {
            entry.client_addrs.push(client_addr);
        }
    }

    /// Relay datagrams from the backend back to the client's *current* address.
    fn spawn_return_path(
        &self,
        recv_socket: Arc<UdpSocket>,
        target: ClientTarget,
        cancel: CancellationToken,
        liveness: Liveness,
    ) {
        let main_socket = self.main_socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = recv_socket.recv(&mut buf) => {
                        match result {
                            Ok(n) => {
                                // Downstream traffic is activity: without this a
                                // connection idle upstream is reaped, spending a path.
                                liveness.touch();
                                // Read per datagram, not captured, so a client that
                                // changed address keeps receiving.
                                let dst = target.get();
                                if let Err(e) = main_socket.send_to(&buf[..n], dst).await {
                                    tracing::debug!(
                                        %dst,
                                        error = %e,
                                        "return path send error (continuing)"
                                    );
                                    // Don't break — transient errors are expected
                                }
                            }
                            Err(e) => {
                                // On Windows, 10054 errors are common and not fatal
                                tracing::debug!(
                                    error = %e,
                                    "ephemeral socket recv error (continuing)"
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    /// Drop sockets idle beyond the TTL, cancelling their return-path tasks so the
    /// fds are closed, and clearing every index entry that referenced them.
    pub fn reap_expired(&self) {
        let now = Instant::now();

        // Collect first: mutating while holding iteration references deadlocks.
        let expired: Vec<(SocketId, Vec<SocketAddr>, Vec<CidKey>)> = self
            .sockets
            .iter()
            .filter(|r| r.value().idle_for(now) >= self.ttl)
            .map(|r| {
                (
                    *r.key(),
                    r.value().client_addrs.clone(),
                    r.value().dcids.clone(),
                )
            })
            .collect();

        for (id, client_addrs, dcids) in expired {
            if let Some((_, socket)) = self.sockets.remove(&id) {
                socket.cancel.cancel();
            }
            for addr in client_addrs {
                // Another connection may have claimed the address since.
                if self.by_client_addr.get(&addr).map(|r| *r.value()) == Some(id) {
                    self.by_client_addr.remove(&addr);
                }
            }
            for dcid in dcids {
                if self.by_dcid.get(dcid.as_slice()).map(|r| *r.value()) == Some(id) {
                    self.by_dcid.remove(&dcid);
                }
            }
        }
    }

    /// Number of live ephemeral sockets.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Size of the DCID index. Guards against an index leak across CID rotations.
    #[allow(dead_code)]
    pub fn dcid_index_len(&self) -> usize {
        self.by_dcid.len()
    }

    /// Spawn a background task that periodically removes idle sockets.
    pub fn spawn_cleanup(self: &Arc<Self>, shutdown: CancellationToken) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(manager.ttl / 2);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => manager.reap_expired(),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A socket bound to an unused local port, standing in for a backend.
    async fn backend() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    fn cid(tail: u8) -> [u8; 16] {
        let mut c = [0u8; 16];
        c[15] = tail;
        c
    }

    #[tokio::test]
    async fn eviction_closes_the_socket_and_stops_its_task() {
        let main = backend().await;
        let be = backend().await;
        let be_addr = be.local_addr().unwrap();

        let mgr = EphemeralSocketManager::new(main, Duration::from_millis(50), 1024);
        let shutdown = CancellationToken::new();

        let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let sock = mgr
            .get_or_create(client, None, be_addr, shutdown.clone())
            .await
            .unwrap();
        assert_eq!(mgr.len(), 1);

        // Three live references: this test, the map entry, the return-path task.
        assert_eq!(Arc::strong_count(&sock), 3);

        tokio::time::sleep(Duration::from_millis(120)).await;
        mgr.reap_expired();
        assert_eq!(mgr.len(), 0);

        // The task must observe cancellation and release its Arc.
        let released = tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&sock) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            released.is_ok(),
            "return-path task still holds the socket after eviction: strong_count = {}",
            Arc::strong_count(&sock)
        );

        shutdown.cancel();
    }

    // Multi-threaded on purpose: the production worker runs on a multi-thread
    // runtime, and UDP bind/connect complete without yielding, so a current-thread
    // runtime would never interleave these tasks and the race would not be
    // reachable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_datagrams_create_exactly_one_socket() {
        let main = backend().await;
        let be = backend().await;
        let be_addr = be.local_addr().unwrap();

        let mgr = EphemeralSocketManager::new(main, Duration::from_secs(60), 1024);
        let shutdown = CancellationToken::new();
        let client: SocketAddr = "127.0.0.1:40001".parse().unwrap();

        let mut handles = Vec::new();
        for _ in 0..32 {
            let mgr = mgr.clone();
            let shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                mgr.get_or_create(client, None, be_addr, shutdown)
                    .await
                    .unwrap()
            }));
        }

        let mut sockets = Vec::new();
        for h in handles {
            sockets.push(h.await.unwrap());
        }

        assert_eq!(mgr.len(), 1, "one client must yield one map entry");

        let first_port = sockets[0].local_addr().unwrap().port();
        for s in &sockets {
            assert_eq!(
                s.local_addr().unwrap().port(),
                first_port,
                "all callers must share one source port toward the backend"
            );
        }

        shutdown.cancel();
    }

    #[tokio::test]
    async fn downstream_only_traffic_keeps_the_socket_alive() {
        let main = backend().await;
        let be = backend().await;
        let be_addr = be.local_addr().unwrap();

        let mgr = EphemeralSocketManager::new(main, Duration::from_millis(80), 1024);
        let shutdown = CancellationToken::new();
        let client: SocketAddr = "127.0.0.1:42000".parse().unwrap();

        let sock = mgr
            .get_or_create(client, None, be_addr, shutdown.clone())
            .await
            .unwrap();
        let eph_addr = sock.local_addr().unwrap();

        // Backend -> proxy only, as with a muted or push-to-talk voice client.
        for _ in 0..8 {
            be.send_to(b"downstream", eph_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            mgr.reap_expired();
        }

        assert_eq!(
            mgr.len(),
            1,
            "return-path traffic must refresh liveness; reaping here rebinds the \
             source port and spends a backend QUIC path"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn socket_cap_is_enforced_and_existing_clients_still_served() {
        let main = backend().await;
        let be = backend().await;
        let be_addr = be.local_addr().unwrap();

        let mgr = EphemeralSocketManager::new(main, Duration::from_secs(60), 2);
        let shutdown = CancellationToken::new();

        let a: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let b_: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let c: SocketAddr = "127.0.0.1:41002".parse().unwrap();

        let sock_a = mgr
            .get_or_create(a, None, be_addr, shutdown.clone())
            .await
            .unwrap();
        mgr.get_or_create(b_, None, be_addr, shutdown.clone())
            .await
            .unwrap();
        assert_eq!(mgr.len(), 2);

        assert!(
            mgr.get_or_create(c, None, be_addr, shutdown.clone())
                .await
                .is_err(),
            "allocation past the cap must be refused"
        );
        assert_eq!(mgr.len(), 2, "a refused allocation must not grow the map");

        let again = mgr
            .get_or_create(a, None, be_addr, shutdown.clone())
            .await
            .unwrap();
        assert_eq!(
            again.local_addr().unwrap().port(),
            sock_a.local_addr().unwrap().port(),
            "an existing client must keep its socket even at the cap"
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn same_cid_new_address_reuses_the_socket() {
        let main = backend().await;
        let be = backend().await;
        let be_addr = be.local_addr().unwrap();
        let mgr = EphemeralSocketManager::new(main, Duration::from_secs(60), 1024);
        let shutdown = CancellationToken::new();
        let dcid = cid(1);

        let a: SocketAddr = "127.0.0.1:43000".parse().unwrap();
        let first = mgr
            .get_or_create(a, Some(&dcid), be_addr, shutdown.clone())
            .await
            .unwrap();

        // NAT rebind: new address, unchanged CID.
        let b_: SocketAddr = "127.0.0.1:43001".parse().unwrap();
        let second = mgr
            .get_or_create(b_, Some(&dcid), be_addr, shutdown.clone())
            .await
            .unwrap();

        assert_eq!(
            first.local_addr().unwrap().port(),
            second.local_addr().unwrap().port(),
            "a rebind must reuse the socket, or the backend allocates a QUIC path"
        );
        assert_eq!(mgr.len(), 1);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn handshake_dcid_switch_does_not_allocate_a_second_socket() {
        let main = backend().await;
        let be = backend().await;
        let be_addr = be.local_addr().unwrap();
        let mgr = EphemeralSocketManager::new(main, Duration::from_secs(60), 1024);
        let shutdown = CancellationToken::new();
        let client: SocketAddr = "127.0.0.1:43002".parse().unwrap();

        // Initial: client-chosen DCID.
        let d0 = cid(0xAA);
        let first = mgr
            .get_or_create(client, Some(&d0), be_addr, shutdown.clone())
            .await
            .unwrap();
        // Post-handshake: server-issued DCID, same client address.
        let s1 = cid(0xBB);
        let second = mgr
            .get_or_create(client, Some(&s1), be_addr, shutdown.clone())
            .await
            .unwrap();

        assert_eq!(
            first.local_addr().unwrap().port(),
            second.local_addr().unwrap().port()
        );
        assert_eq!(
            mgr.len(),
            1,
            "the DCID switch at the end of a handshake must not create a socket"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn eviction_clears_every_dcid_index_entry() {
        let main = backend().await;
        let be = backend().await;
        let be_addr = be.local_addr().unwrap();
        let mgr = EphemeralSocketManager::new(main, Duration::from_millis(40), 1024);
        let shutdown = CancellationToken::new();
        let client: SocketAddr = "127.0.0.1:43003".parse().unwrap();

        // Several Connection ID rotations against one socket.
        for i in 0u8..5 {
            mgr.get_or_create(client, Some(&cid(i)), be_addr, shutdown.clone())
                .await
                .unwrap();
        }
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.dcid_index_len(), 5);

        tokio::time::sleep(Duration::from_millis(100)).await;
        mgr.reap_expired();

        assert_eq!(mgr.len(), 0);
        assert_eq!(
            mgr.dcid_index_len(),
            0,
            "every registered DCID must be cleared, or rotation leaks index entries"
        );
        shutdown.cancel();
    }
}
