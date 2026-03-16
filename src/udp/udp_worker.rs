use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;

use super::connection_state::ConnectionState;
use super::connection_state_table::ConnectionStateTable;
use super::crypto_reassembly::CryptoReassemblyBuffer;
use super::ephemeral_socket_manager::EphemeralSocketManager;
use super::initial_decryptor::QuicInitialDecryptor;

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

                    let backend_addr = match self.resolve_backend(
                        &buf[..n], client_addr, &conn_table_arc, &crypto_buf,
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

    fn resolve_backend(
        &self,
        datagram: &[u8],
        client_addr: SocketAddr,
        conn_table: &ConnectionStateTable,
        crypto_buf: &CryptoReassemblyBuffer,
    ) -> Result<SocketAddr> {
        if datagram.is_empty() {
            anyhow::bail!("empty datagram");
        }

        // Fast path: known client
        if let Some(state) = conn_table.get(&client_addr) {
            return Ok(state.backend_addr);
        }

        let is_long_header = datagram[0] & 0x80 != 0;

        if is_long_header {
            let packet_type = (datagram[0] & 0x30) >> 4;

            if packet_type == 0x00 {
                // Initial — try direct SNI extraction first
                if let Ok(sni) = QuicInitialDecryptor::extract_sni(datagram) {
                    return self.register_backend(client_addr, &sni, conn_table, crypto_buf);
                }

                // Direct extraction failed — try fragment reassembly
                let (dcid, fragments) = QuicInitialDecryptor::decrypt_crypto_frames(datagram)?;
                for frag in &fragments {
                    if let Some(reassembled) = crypto_buf.insert(&dcid, frag.offset, &frag.data) {
                        if let Some(sni) = crate::tls::SniParser::extract_sni(&reassembled) {
                            return self.register_backend(
                                client_addr, &sni, conn_table, crypto_buf,
                            );
                        }
                    }
                }

                anyhow::bail!("awaiting CRYPTO reassembly for {client_addr}")
            } else {
                anyhow::bail!(
                    "no state for long header type {packet_type:02x} from {client_addr}"
                )
            }
        } else {
            // Short header — CID prefix routing
            let prefix_len = self.cid_prefix_length as usize;
            if datagram.len() >= 1 + prefix_len && prefix_len >= 2 {
                let instance_id = u16::from_be_bytes([datagram[1], datagram[2]]);
                if let Some(addr) = self.routing_table.lookup_by_instance_id(instance_id) {
                    Ok(addr)
                } else {
                    anyhow::bail!("unknown instance_id {instance_id} from {client_addr}")
                }
            } else {
                anyhow::bail!("short header too small from {client_addr}")
            }
        }
    }

    fn register_backend(
        &self,
        client_addr: SocketAddr,
        sni: &str,
        conn_table: &ConnectionStateTable,
        crypto_buf: &CryptoReassemblyBuffer,
    ) -> Result<SocketAddr> {
        let backend = self
            .routing_table
            .lookup_by_hostname(sni)
            .ok_or_else(|| anyhow::anyhow!("no backend for SNI '{sni}'"))?;

        tracing::info!(
            worker = self.id,
            %client_addr,
            sni = %sni,
            backend = %backend.udp_addr,
            "routing quic initial"
        );

        conn_table.insert(
            client_addr,
            ConnectionState::new(backend.udp_addr, backend.instance_id),
        );

        crypto_buf.cleanup();
        Ok(backend.udp_addr)
    }
}

async fn forward(
    datagram: &[u8],
    client_addr: SocketAddr,
    backend_addr: SocketAddr,
    eph_manager: &Arc<EphemeralSocketManager>,
    shutdown: CancellationToken,
) -> Result<()> {
    let eph = eph_manager
        .get_or_create(client_addr, backend_addr, shutdown)
        .await?;
    eph.send(datagram).await?;
    Ok(())
}
