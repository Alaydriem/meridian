use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::health::DatapathHealth;
use crate::routing::RoutingTable;

use super::connection_state_table::ConnectionStateTable;
use super::crypto_reassembly::CryptoReassemblyBuffer;
use super::ephemeral_socket_manager::EphemeralSocketManager;
use super::packet_router::PacketRouter;

/// Decrements the live-worker count on drop, including when the worker panics.
///
/// The panic path is the one that matters: before supervision was fixed a
/// panicking worker vanished silently, and a health signal that only decremented
/// on a clean return would have reported the same lie.
struct WorkerLiveGuard(Arc<DatapathHealth>);

impl Drop for WorkerLiveGuard {
    fn drop(&mut self) {
        self.0.worker_exited();
    }
}

pub struct UdpWorker {
    id: usize,
    routing_table: Arc<RoutingTable>,
    cid_prefix_length: u8,
    health: Arc<DatapathHealth>,
    /// Shared with every other worker.
    ///
    /// `SO_REUSEPORT` distributes by 4-tuple hash, so a client whose source address
    /// changes is rehashed to a different worker — which is precisely when the
    /// ephemeral-socket reuse in `EphemeralSocketManager` needs to apply. Per-worker
    /// state would make that reuse work only when the rehash happened to land on the
    /// same worker, spending a backend QUIC path the rest of the time.
    conn_table: Arc<ConnectionStateTable>,
    eph_manager: Arc<EphemeralSocketManager>,
    crypto_buf: Arc<CryptoReassemblyBuffer>,
}

impl UdpWorker {
    pub fn new(
        id: usize,
        routing_table: Arc<RoutingTable>,
        cid_prefix_length: u8,
        health: Arc<DatapathHealth>,
        conn_table: Arc<ConnectionStateTable>,
        eph_manager: Arc<EphemeralSocketManager>,
        crypto_buf: Arc<CryptoReassemblyBuffer>,
    ) -> Self {
        Self {
            id,
            routing_table,
            cid_prefix_length,
            health,
            conn_table,
            eph_manager,
            crypto_buf,
        }
    }

    pub async fn run(self, socket: Arc<UdpSocket>, shutdown: CancellationToken) -> Result<()> {
        tracing::info!(worker = self.id, "udp worker started");

        // Paired with `worker_exited` on every exit path below, so readiness and
        // liveness reflect reality rather than the configured count.
        self.health.worker_started();
        let _guard = WorkerLiveGuard(self.health.clone());

        // Shared state is constructed once in `WorkerPool::run` and cloned in.
        let conn_table_arc = self.conn_table.clone();
        let eph_manager = self.eph_manager.clone();
        let crypto_buf = self.crypto_buf.clone();

        let mut buf = [0u8; 65535];
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!(worker = self.id, "udp worker shutting down");
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    let (n, client_addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(worker = self.id, error = %e, "recv error (ignored)");
                            continue;
                        }
                    };
                    self.health.datagram_processed();

                    let backend_addr = match PacketRouter::resolve_backend(
                        &buf[..n],
                        client_addr,
                        &self.routing_table,
                        &crypto_buf,
                        self.cid_prefix_length,
                        |addr| conn_table_arc.get(addr),
                        |addr, state| conn_table_arc.insert(addr, state),
                    ) {
                        Ok(addr) => addr,
                        Err(e) => {
                            tracing::debug!(
                                worker = self.id, %client_addr,
                                error = %e, "route failed"
                            );
                            continue;
                        }
                    };

                    let datagram = buf[..n].to_vec();
                    let eph_manager = eph_manager.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::forward(
                            &datagram, client_addr, backend_addr,
                            &eph_manager, shutdown,
                        ).await {
                            tracing::debug!(%client_addr, error = %e, "forward failed");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// The datagram's Destination Connection ID, for ephemeral-socket indexing.
    ///
    /// Long headers state their DCID length explicitly; short headers carry the fixed
    /// 16-byte CID that backends issue. Returning `None` simply means the socket is
    /// indexed by client address alone, which is correct but loses rebind reuse.
    fn datagram_dcid(datagram: &[u8]) -> Option<&[u8]> {
        const EXPECTED_CID_LEN: usize = 16;
        let first = *datagram.first()?;
        if first & 0x80 != 0 {
            let len = *datagram.get(5)? as usize;
            datagram.get(6..6 + len)
        } else {
            datagram.get(1..1 + EXPECTED_CID_LEN)
        }
    }

    async fn forward(
        datagram: &[u8],
        client_addr: std::net::SocketAddr,
        backend_addr: std::net::SocketAddr,
        eph_manager: &Arc<EphemeralSocketManager>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let eph = eph_manager
            .get_or_create(client_addr, Self::datagram_dcid(datagram), backend_addr, shutdown)
            .await?;
        eph.send(datagram).await?;
        Ok(())
    }
}
