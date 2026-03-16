use std::net::SocketAddr;

use anyhow::Result;

use crate::routing::RoutingTable;

use super::connection_state::ConnectionState;
use super::crypto_reassembly::CryptoReassemblyBuffer;
use super::initial_decryptor::QuicInitialDecryptor;

/// Resolve which backend a datagram should be forwarded to.
///
/// This is the shared packet-routing logic used by both the tokio and io_uring
/// UDP backends. It is a pure function over the datagram contents and the
/// provided lookup/insert closures, so it works with any backing store
/// (DashMap, HashMap, etc.).
pub fn resolve_backend(
    datagram: &[u8],
    client_addr: SocketAddr,
    routing_table: &RoutingTable,
    crypto_buf: &CryptoReassemblyBuffer,
    cid_prefix_length: u8,
    get_connection: impl Fn(&SocketAddr) -> Option<ConnectionState>,
    mut insert_connection: impl FnMut(SocketAddr, ConnectionState),
) -> Result<SocketAddr> {
    if datagram.is_empty() {
        anyhow::bail!("empty datagram");
    }

    // Fast path: known client
    if let Some(state) = get_connection(&client_addr) {
        return Ok(state.backend_addr);
    }

    let is_long_header = datagram[0] & 0x80 != 0;

    if is_long_header {
        let packet_type = (datagram[0] & 0x30) >> 4;

        if packet_type == 0x00 {
            // Initial — try direct SNI extraction first
            if let Ok(sni) = QuicInitialDecryptor::extract_sni(datagram) {
                return register_backend(
                    client_addr,
                    &sni,
                    routing_table,
                    crypto_buf,
                    &mut insert_connection,
                );
            }

            // Direct extraction failed — try fragment reassembly
            let (dcid, fragments) = QuicInitialDecryptor::decrypt_crypto_frames(datagram)?;
            for frag in &fragments {
                if let Some(reassembled) = crypto_buf.insert(&dcid, frag.offset, &frag.data)
                    && let Some(sni) = crate::tls::SniParser::extract_sni(&reassembled)
                {
                    return register_backend(
                        client_addr,
                        &sni,
                        routing_table,
                        crypto_buf,
                        &mut insert_connection,
                    );
                }
            }

            anyhow::bail!("awaiting CRYPTO reassembly for {client_addr}")
        } else {
            anyhow::bail!("no state for long header type {packet_type:02x} from {client_addr}")
        }
    } else {
        // Short header — CID prefix routing
        let prefix_len = cid_prefix_length as usize;
        if datagram.len() > prefix_len && prefix_len >= 2 {
            let instance_id = u16::from_be_bytes([datagram[1], datagram[2]]);
            if let Some(addr) = routing_table.lookup_by_instance_id(instance_id) {
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
    client_addr: SocketAddr,
    sni: &str,
    routing_table: &RoutingTable,
    crypto_buf: &CryptoReassemblyBuffer,
    insert_connection: &mut impl FnMut(SocketAddr, ConnectionState),
) -> Result<SocketAddr> {
    let backend = routing_table
        .lookup_by_hostname(sni)
        .ok_or_else(|| anyhow::anyhow!("no backend for SNI '{sni}'"))?;

    insert_connection(
        client_addr,
        ConnectionState::new(backend.udp_addr, backend.instance_id),
    );

    crypto_buf.cleanup();
    Ok(backend.udp_addr)
}
