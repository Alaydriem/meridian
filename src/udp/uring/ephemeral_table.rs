use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Stable handle for one ephemeral socket.
///
/// Both lookup keys — client address and Connection ID — change over a connection's
/// life, so neither can identify the entry.
pub type SocketId = u64;

/// A QUIC Destination Connection ID used as a lookup key.
pub type CidKey = Vec<u8>;

/// Entry for an ephemeral socket managed by the io_uring workers.
pub struct EphEntry {
    /// Raw file descriptor for the ephemeral socket.
    pub raw_fd: i32,
    /// Index in the owning ring's fixed file table. Meaningful only to
    /// `owner_worker` — fixed indexes are ring-local.
    pub fixed_index: u32,
    /// Worker that created this socket, submitted its recv, and is the only one
    /// permitted to close it.
    pub owner_worker: usize,
    /// Client address the return path should currently send to.
    pub client_addr: SocketAddr,
    /// Milliseconds since the table's epoch at the last activity, either direction.
    last_activity_ms: AtomicU64,
    /// Recv buffer currently submitted for this socket, if any. Owner-only.
    pub pending_recv_buf: Option<u16>,
    /// Sends in progress by *non-owning* workers.
    ///
    /// The owner must not close the fd while this is non-zero: a closed fd number is
    /// recyclable, so closing underneath an in-flight send risks writing one tenant's
    /// data to another tenant's socket.
    pending_sends: AtomicU32,
    /// Unindexed and awaiting close. Checked by senders after they take a reference,
    /// so no new send starts on a dying fd.
    dead: AtomicBool,
    /// One-to-many: backends rotate Connection IDs, so a long-lived connection
    /// accumulates several. Eviction must clear all of them.
    pub dcids: Vec<CidKey>,
    pub client_addrs: Vec<SocketAddr>,
}

impl EphEntry {
    /// Claim the right to send on this fd, if it is still alive.
    ///
    /// Increments *then* re-checks `dead`, so it cannot interleave with a reaper that
    /// sets `dead` and then observes the count.
    pub fn try_acquire_send(&self) -> bool {
        self.pending_sends.fetch_add(1, Ordering::AcqRel);
        if self.dead.load(Ordering::Acquire) {
            self.pending_sends.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    pub fn release_send(&self) {
        self.pending_sends.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn sends_in_flight(&self) -> u32 {
        self.pending_sends.load(Ordering::Acquire)
    }
}

/// Ephemeral socket table shared by every io_uring worker.
///
/// Shared because `SO_REUSEPORT` rehashes a client to a different worker when its
/// source address changes, which is exactly when socket reuse must apply.
///
/// Ownership stays per-worker for the parts that must be ring-local: the recv is
/// submitted against the owner's fixed index, and only the owner closes the fd.
/// Non-owners send on the raw fd, guarded by [`EphEntry::try_acquire_send`].
pub struct EphemeralTable {
    sockets: DashMap<SocketId, EphEntry>,
    by_client: DashMap<SocketAddr, SocketId>,
    by_dcid: DashMap<CidKey, SocketId>,
    /// Unindexed entries awaiting close by their owner.
    closing: DashMap<SocketId, EphEntry>,
    next_id: AtomicU64,
    ttl: Duration,
    epoch: Instant,
}

impl EphemeralTable {
    pub fn new(ttl: Duration) -> Self {
        Self {
            sockets: DashMap::new(),
            by_client: DashMap::new(),
            by_dcid: DashMap::new(),
            closing: DashMap::new(),
            next_id: AtomicU64::new(1),
            ttl,
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Resolve a datagram to an existing socket.
    ///
    /// DCID first because it survives an address change; client address second because
    /// the Initial's DCID is client-chosen and replaced after the handshake.
    pub fn resolve(&self, dcid: Option<&[u8]>, client_addr: SocketAddr) -> Option<SocketId> {
        dcid.and_then(|d| self.by_dcid.get(d).map(|r| *r.value()))
            .or_else(|| self.by_client.get(&client_addr).map(|r| *r.value()))
    }

    /// Read from an entry under a shared reference.
    ///
    /// `f` must not touch another map: holding a reference while accessing the same
    /// map deadlocks.
    pub fn with_entry<R>(&self, id: SocketId, f: impl FnOnce(&EphEntry) -> R) -> Option<R> {
        self.sockets.get(&id).map(|r| f(r.value()))
    }

    pub fn client_addr_for_id(&self, id: SocketId) -> Option<SocketAddr> {
        self.with_entry(id, |e| e.client_addr)
    }

    pub fn next_id(&self) -> SocketId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Insert a fully-formed entry under `id`, indexing it by client address.
    pub fn insert(&self, id: SocketId, entry: EphEntry) {
        self.by_client.insert(entry.client_addr, id);
        self.sockets.insert(id, entry);
    }

    /// Build an entry. `last_activity` starts at now.
    #[allow(clippy::too_many_arguments)]
    pub fn new_entry(
        &self,
        raw_fd: i32,
        fixed_index: u32,
        owner_worker: usize,
        client_addr: SocketAddr,
        pending_recv_buf: Option<u16>,
    ) -> EphEntry {
        EphEntry {
            raw_fd,
            fixed_index,
            owner_worker,
            client_addr,
            last_activity_ms: AtomicU64::new(self.now_ms()),
            pending_recv_buf,
            pending_sends: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            dcids: Vec::new(),
            client_addrs: vec![client_addr],
        }
    }

    /// Index `dcid` to `id`, recording it on the entry so eviction can clear it.
    pub fn register_dcid(&self, id: SocketId, dcid: &[u8]) {
        if self.by_dcid.contains_key(dcid) {
            return;
        }
        self.by_dcid.insert(dcid.to_vec(), id);
        if let Some(mut entry) = self.sockets.get_mut(&id) {
            entry.dcids.push(dcid.to_vec());
        }
    }

    /// Point `client_addr` at `id` and make it the return-path target. This is how a
    /// NAT rebind keeps its socket instead of spending a backend QUIC path.
    pub fn rebind_client(&self, id: SocketId, client_addr: SocketAddr) {
        self.by_client.insert(client_addr, id);
        if let Some(mut entry) = self.sockets.get_mut(&id) {
            entry.client_addr = client_addr;
            if !entry.client_addrs.contains(&client_addr) {
                entry.client_addrs.push(client_addr);
            }
        }
    }

    /// Refresh liveness. Must be called in *both* directions: refreshing only
    /// upstream reaps connections busy downstream but idle upstream.
    pub fn touch(&self, id: SocketId) {
        let now = self.now_ms();
        if let Some(entry) = self.sockets.get(&id) {
            entry.last_activity_ms.store(now, Ordering::Relaxed);
        }
    }

    pub fn set_pending_recv(&self, id: SocketId, buf: Option<u16>) {
        if let Some(mut entry) = self.sockets.get_mut(&id) {
            entry.pending_recv_buf = buf;
        }
    }

    /// Unindex every entry past its TTL and move it to the closing set.
    ///
    /// Any worker may call this. Unindexing makes an entry unresolvable; `dead` closes
    /// the window for senders that already hold a reference.
    pub fn retire_expired(&self) {
        let now = self.now_ms();
        let ttl_ms = self.ttl.as_millis() as u64;

        let expired: Vec<SocketId> = self
            .sockets
            .iter()
            .filter(|r| {
                now.saturating_sub(r.value().last_activity_ms.load(Ordering::Relaxed)) >= ttl_ms
            })
            .map(|r| *r.key())
            .collect();

        for id in expired {
            // Before unindexing, so a sender that just resolved still observes it.
            if let Some(entry) = self.sockets.get(&id) {
                entry.dead.store(true, Ordering::Release);
            }
            if let Some((_, entry)) = self.sockets.remove(&id) {
                for addr in &entry.client_addrs {
                    if self.by_client.get(addr).map(|r| *r.value()) == Some(id) {
                        self.by_client.remove(addr);
                    }
                }
                if self.by_client.get(&entry.client_addr).map(|r| *r.value()) == Some(id) {
                    self.by_client.remove(&entry.client_addr);
                }
                for dcid in &entry.dcids {
                    if self.by_dcid.get(dcid.as_slice()).map(|r| *r.value()) == Some(id) {
                        self.by_dcid.remove(dcid);
                    }
                }
                self.closing.insert(id, entry);
            }
        }
    }

    /// Take entries this worker owns with no non-owner send in flight.
    ///
    /// Entries still in use stay in the closing set and are retried next sweep, which
    /// is what makes the fd impossible to close under a concurrent sender.
    pub fn take_closable(&self, worker_id: usize) -> Vec<(i32, u32, Option<u16>)> {
        let ready: Vec<SocketId> = self
            .closing
            .iter()
            .filter(|r| r.value().owner_worker == worker_id && r.value().sends_in_flight() == 0)
            .map(|r| *r.key())
            .collect();

        ready
            .into_iter()
            .filter_map(|id| self.closing.remove(&id))
            .map(|(_, e)| (e.raw_fd, e.fixed_index, e.pending_recv_buf))
            .collect()
    }

    /// Release a reference taken via [`EphEntry::try_acquire_send`].
    ///
    /// Checks the closing set too: the entry may have been retired mid-send, and
    /// failing to release there would pin the fd forever.
    pub fn release_send(&self, id: SocketId) {
        if let Some(entry) = self.sockets.get(&id) {
            entry.release_send();
            return;
        }
        if let Some(entry) = self.closing.get(&id) {
            entry.release_send();
        }
    }

    /// Number of live (indexed) entries.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Entries unindexed but not yet closed.
    #[allow(dead_code)]
    pub fn closing_len(&self) -> usize {
        self.closing.len()
    }

    /// Size of the DCID index. Guards against an index leak across CID rotations.
    #[allow(dead_code)]
    pub fn dcid_index_len(&self) -> usize {
        self.by_dcid.len()
    }

    /// Drain everything this worker owns, for shutdown.
    pub fn drain_owned(&self, worker_id: usize) -> Vec<(i32, u32, Option<u16>)> {
        let ids: Vec<SocketId> = self
            .sockets
            .iter()
            .filter(|r| r.value().owner_worker == worker_id)
            .map(|r| *r.key())
            .collect();

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some((_, entry)) = self.sockets.remove(&id) {
                for addr in &entry.client_addrs {
                    self.by_client.remove(addr);
                }
                self.by_client.remove(&entry.client_addr);
                for dcid in &entry.dcids {
                    self.by_dcid.remove(dcid);
                }
                out.push((entry.raw_fd, entry.fixed_index, entry.pending_recv_buf));
            }
        }

        out.extend(self.take_closable(worker_id));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Insert an entry owned by `worker`.
    ///
    /// Staleness is expressed by giving the *table* a zero TTL rather than backdating
    /// the entry: the liveness clock is relative to the table's own epoch, so a zero
    /// timestamp is not stale when the epoch is itself only microseconds old.
    fn insert(
        table: &EphemeralTable,
        worker: usize,
        fixed_index: u32,
        client: SocketAddr,
    ) -> SocketId {
        let id = table.next_id();
        let entry = table.new_entry(42, fixed_index, worker, client, Some(5));
        table.insert(id, entry);
        id
    }

    /// A table whose entries are expired the moment they are inserted.
    fn expiring_table() -> EphemeralTable {
        EphemeralTable::new(Duration::ZERO)
    }

    #[test]
    fn insert_and_lookup() {
        let table = EphemeralTable::new(Duration::from_secs(60));
        let client = make_addr(1000);
        let id = insert(&table, 0, 1, client);

        assert_eq!(table.len(), 1);
        assert_eq!(table.resolve(None, client), Some(id));
        assert_eq!(table.client_addr_for_id(id), Some(client));
    }

    #[test]
    fn expiry() {
        let table = expiring_table();
        insert(&table, 0, 1, make_addr(1000));

        table.retire_expired();
        assert_eq!(table.len(), 0);

        let closable = table.take_closable(0);
        assert_eq!(closable.len(), 1);
        assert_eq!(closable[0], (42, 1, Some(5)));
    }

    #[test]
    fn same_dcid_new_client_address_reuses_the_entry() {
        let table = EphemeralTable::new(Duration::from_secs(60));
        let id = insert(&table, 0, 1, make_addr(1000));
        table.register_dcid(id, b"dcid-1");

        // NAT rebind: unchanged DCID, new client address.
        assert_eq!(
            table.resolve(Some(b"dcid-1"), make_addr(1001)),
            Some(id),
            "a rebind must find the entry by DCID"
        );

        table.rebind_client(id, make_addr(1001));
        assert_eq!(table.len(), 1, "a rebind must not create a second entry");
        assert_eq!(table.client_addr_for_id(id), Some(make_addr(1001)));
    }

    /// A socket created on one worker must be reachable from another. Without this,
    /// `SO_REUSEPORT` rehashing on a client address change costs a backend QUIC path.
    #[test]
    fn a_socket_owned_by_one_worker_resolves_from_another() {
        let table = EphemeralTable::new(Duration::from_secs(60));
        let id = insert(&table, 0, 1, make_addr(1000));
        table.register_dcid(id, b"cid");

        // Worker 1 resolving worker 0's socket.
        let found = table.resolve(Some(b"cid"), make_addr(2222)).unwrap();
        assert_eq!(found, id);
        assert_eq!(
            table.with_entry(found, |e| e.owner_worker),
            Some(0),
            "ownership stays with the creating worker even when others resolve it"
        );
    }

    #[test]
    fn handshake_dcid_switch_reuses_the_entry() {
        let table = EphemeralTable::new(Duration::from_secs(60));
        let client = make_addr(1000);
        let id = insert(&table, 0, 1, client);

        table.register_dcid(id, b"d0");
        // Post-handshake: server-issued DCID, same client address.
        assert_eq!(table.resolve(Some(b"s1"), client), Some(id));
        table.register_dcid(id, b"s1");

        assert_eq!(table.len(), 1);
        assert_eq!(table.resolve(Some(b"s1"), make_addr(9999)), Some(id));
    }

    #[test]
    fn expiry_clears_all_indexes_including_every_dcid() {
        let table = expiring_table();
        let id = insert(&table, 0, 1, make_addr(1000));
        for i in 0u8..4 {
            table.register_dcid(id, &[i]);
        }
        table.rebind_client(id, make_addr(1001));
        assert_eq!(table.dcid_index_len(), 4);

        table.retire_expired();

        assert_eq!(table.len(), 0);
        assert_eq!(
            table.dcid_index_len(),
            0,
            "every registered DCID must be cleared, or rotation leaks index entries"
        );
        assert!(table.resolve(None, make_addr(1000)).is_none());
        assert!(
            table.resolve(None, make_addr(1001)).is_none(),
            "an address bound by a rebind must also be cleared"
        );
        assert_eq!(table.take_closable(0).len(), 1);
    }

    /// The fd-lifetime guarantee: a socket with a send in flight from another worker
    /// must not be handed back for closing. Closing it would free an fd number that
    /// can be recycled, so the in-flight send could land on an unrelated socket.
    #[test]
    fn a_socket_with_an_in_flight_send_is_not_closable() {
        let table = expiring_table();
        let id = insert(&table, 0, 1, make_addr(1000));

        // Worker 1 claims a send.
        let acquired = table.with_entry(id, |e| e.try_acquire_send()).unwrap();
        assert!(acquired);

        table.retire_expired();
        assert_eq!(table.len(), 0, "the entry is unindexed immediately");
        assert_eq!(
            table.take_closable(0).len(),
            0,
            "must not close while a send is in flight"
        );
        assert_eq!(table.closing_len(), 1, "it stays pending, to be retried");

        // Sender finishes.
        table
            .closing
            .get(&id)
            .expect("still pending")
            .release_send();

        assert_eq!(
            table.take_closable(0).len(),
            1,
            "closable once the send completes"
        );
    }

    #[test]
    fn a_retired_socket_refuses_new_sends() {
        let table = expiring_table();
        let id = insert(&table, 0, 1, make_addr(1000));
        table.retire_expired();

        let refused = table.closing.get(&id).expect("pending").try_acquire_send();
        assert!(
            !refused,
            "a dying socket must refuse new senders, or the count could never drain"
        );
    }

    #[test]
    fn only_the_owner_may_close() {
        let table = expiring_table();
        insert(&table, 3, 1, make_addr(1000));
        table.retire_expired();

        assert_eq!(
            table.take_closable(0).len(),
            0,
            "a non-owner cannot close: the fixed-file slot and recv belong to the owner"
        );
        assert_eq!(table.take_closable(3).len(), 1);
    }

    #[test]
    fn drain_owned_only_takes_this_workers_sockets() {
        let table = EphemeralTable::new(Duration::from_secs(60));
        insert(&table, 0, 1, make_addr(1000));
        insert(&table, 1, 1, make_addr(1001));

        assert_eq!(table.drain_owned(0).len(), 1);
        assert_eq!(table.len(), 1, "the other worker's socket is untouched");
        assert_eq!(table.drain_owned(1).len(), 1);
        assert_eq!(table.len(), 0);
    }
}
