use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;

use super::connection_state_table::ConnectionStateTable;
use super::crypto_reassembly::CryptoReassemblyBuffer;
use super::ephemeral_socket_manager::EphemeralSocketManager;
use super::packet_router;

pub struct UdpWorker {
    id: usize,
    routing_table: Arc<RoutingTable>,
    cid_prefix_length: u8,
    connection_ttl: Duration,
}

impl UdpWorker {
    pub fn new(
        id: usize,
        routing_table: Arc<RoutingTable>,
        cid_prefix_length: u8,
        connection_ttl: Duration,
    ) -> Self {
        Self {
            id,
            routing_table,
            cid_prefix_length,
            connection_ttl,
        }
    }

    pub async fn run(self, socket: Arc<UdpSocket>, shutdown: CancellationToken) -> Result<()> {
        tracing::info!(worker = self.id, "udp worker started");

        let conn_table = ConnectionStateTable::new(self.connection_ttl);
        let conn_table_arc = Arc::new(conn_table);
        conn_table_arc.spawn_cleanup(shutdown.clone());

        let eph_manager = EphemeralSocketManager::new(socket.clone(), self.connection_ttl);
        eph_manager.spawn_cleanup(shutdown.clone());

        let crypto_buf = CryptoReassemblyBuffer::new(Duration::from_secs(10));

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

                    let backend_addr = match packet_router::resolve_backend(
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
                        if let Err(e) = forward(
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
}

async fn forward(
    datagram: &[u8],
    client_addr: std::net::SocketAddr,
    backend_addr: std::net::SocketAddr,
    eph_manager: &Arc<EphemeralSocketManager>,
    shutdown: CancellationToken,
) -> Result<()> {
    let eph = eph_manager
        .get_or_create(client_addr, backend_addr, shutdown)
        .await?;
    eph.send(datagram).await?;
    Ok(())
}
