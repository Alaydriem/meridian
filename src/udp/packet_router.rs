use std::net::SocketAddr;

use anyhow::Result;

use crate::routing::RoutingTable;

use super::connection_state::ConnectionState;
use super::crypto_reassembly::CryptoReassemblyBuffer;
use super::initial_decryptor::QuicInitialDecryptor;

/// Connection ID length issued by backends (`PrefixedConnectionIdFormat`).
///
/// A short header must carry at least this much CID after the flags byte before
/// its leading bytes can be trusted as an `instance_id`.
const EXPECTED_CID_LEN: usize = 16;

pub struct PacketRouter;

impl PacketRouter {
    /// DCID of a long-header packet.
    ///
    /// Layout: flags(1) version(4) dcid_len(1) dcid. Returns `None` if the packet is
    /// truncated before the length it declares.
    fn long_header_dcid(datagram: &[u8]) -> Option<&[u8]> {
        let dcid_len = *datagram.get(5)? as usize;
        datagram.get(6..6 + dcid_len)
    }

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

        // Fast path: known client — but only while the registry still agrees the
        // cached address belongs to a live backend. `ConnectionStateTable::get`
        // refreshes the TTL on every packet, so an actively-sending client would
        // otherwise pin a stale address for the life of its connection.
        if let Some(state) = get_connection(&client_addr)
            && routing_table.is_current_backend_addr(&state.backend_addr)
        {
            return Ok(state.backend_addr);
        }

        let is_long_header = datagram[0] & 0x80 != 0;

        if is_long_header {
            let packet_type = (datagram[0] & 0x30) >> 4;

            if packet_type == 0x00 {
                // Initial — try direct SNI extraction first
                if let Ok(sni) = QuicInitialDecryptor::extract_sni(datagram) {
                    return Self::register_backend(
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
                        return Self::register_backend(
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
                // Handshake (0x02) / 0-RTT (0x01) / Retry (0x03).
                //
                // A client's Handshake packet carries a DCID the *server* issued, so
                // it holds the instance_id prefix and routes statelessly. Bailing here
                // instead meant these were routable only while the client-address
                // cache held an entry — so a client whose address changed mid-handshake,
                // or an ingress failover mid-handshake, killed the connection rather
                // than recovering, because a client that has seen a server Handshake
                // does not revert to sending Initials.
                //
                // 0-RTT still depends on the cache: its DCID is the client's own
                // random value, unprefixed. That is acceptable because a 0-RTT packet
                // is always preceded by an Initial from the same address.
                let dcid = Self::long_header_dcid(datagram).ok_or_else(|| {
                    anyhow::anyhow!("long header type {packet_type:02x} truncated from {client_addr}")
                })?;
                if dcid.len() < 2 {
                    anyhow::bail!(
                        "long header type {packet_type:02x} DCID too short from {client_addr}"
                    );
                }
                let instance_id = u16::from_be_bytes([dcid[0], dcid[1]]);
                match routing_table.lookup_by_instance_id(instance_id) {
                    Some(addr) => Ok(addr),
                    None => anyhow::bail!(
                        "no backend for instance_id {instance_id} on long header type \
                         {packet_type:02x} from {client_addr}"
                    ),
                }
            }
        } else {
            // Short header — CID prefix routing
            let prefix_len = cid_prefix_length as usize;
            if prefix_len < 2 {
                anyhow::bail!("cid_prefix_length {prefix_len} too small to carry an instance_id");
            }
            // The flags byte plus a full CID must be present. Checking only that the
            // datagram is longer than the prefix would let a truncated or hostile
            // packet have its packet-number bytes read as an instance_id and be
            // misrouted into a tenant's backend.
            if datagram.len() < 1 + EXPECTED_CID_LEN {
                anyhow::bail!(
                    "short header too small for a {EXPECTED_CID_LEN}-byte CID from {client_addr}"
                );
            }
            let instance_id = u16::from_be_bytes([datagram[1], datagram[2]]);
            match routing_table.lookup_by_instance_id(instance_id) {
                Some(addr) => Ok(addr),
                None => anyhow::bail!("unknown instance_id {instance_id} from {client_addr}"),
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::routing::Backend;

    fn table_with_instance(instance_id: u16) -> Arc<RoutingTable> {
        let t = RoutingTable::new();
        t.add_backend(
            "b".to_string(),
            Backend::new(
                "b.example.com".to_string(),
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
                instance_id,
            ),
        );
        t
    }

    fn resolve(datagram: &[u8], table: &Arc<RoutingTable>) -> Result<SocketAddr> {
        let buf = CryptoReassemblyBuffer::new(Duration::from_secs(10));
        PacketRouter::resolve_backend(
            datagram,
            "127.0.0.1:9999".parse().unwrap(),
            table,
            &buf,
            2,
            |_| None,
            |_, _| {},
        )
    }

    /// A short header with a full 16-byte CID, instance_id in the first two bytes.
    fn short_header(instance_id: u16) -> Vec<u8> {
        let mut d = vec![0x40];
        d.extend_from_slice(&instance_id.to_be_bytes());
        d.extend_from_slice(&[0xAA; 14]);
        d.extend_from_slice(&[0x01, 0x02, 0x03]);
        d
    }

    #[test]
    fn short_header_with_truncated_cid_is_rejected() {
        let table = table_with_instance(1);
        // Instance_id bytes present, but far too few bytes to hold a 16-byte CID —
        // so what follows would be packet-number or payload read as routing data.
        let datagram = [0x40, 0x00, 0x01, 0xAA];
        assert!(
            resolve(&datagram, &table).is_err(),
            "a packet too short to hold a full CID must not be routed"
        );
    }

    #[test]
    fn short_header_with_full_cid_routes_by_prefix() {
        let table = table_with_instance(1);
        let addr = resolve(&short_header(1), &table).expect("should route");
        assert_eq!(addr, "127.0.0.1:2".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn short_header_with_unknown_instance_id_is_rejected() {
        let table = table_with_instance(1);
        assert!(resolve(&short_header(999), &table).is_err());
    }

    /// Long header, given type bits, carrying a server-issued DCID whose first
    /// two bytes are `instance_id`.
    fn long_header(packet_type: u8, instance_id: u16) -> Vec<u8> {
        let mut d = vec![0x80 | ((packet_type & 0x03) << 4)];
        d.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version
        d.push(16); // DCID length
        d.extend_from_slice(&instance_id.to_be_bytes());
        d.extend_from_slice(&[0xBB; 14]);
        d.push(0); // SCID length
        d.extend_from_slice(&[0x01, 0x02, 0x03]);
        d
    }

    #[test]
    fn handshake_packet_routes_with_an_empty_cache() {
        let table = table_with_instance(1);
        // Type 0x02 = Handshake. Its DCID was issued by the server, so it carries
        // the instance_id prefix and needs no cached state.
        let addr = resolve(&long_header(0x02, 1), &table)
            .expect("a Handshake packet must route by CID prefix without cached state");
        assert_eq!(addr, "127.0.0.1:2".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn handshake_packet_with_unknown_instance_is_rejected() {
        let table = table_with_instance(1);
        assert!(resolve(&long_header(0x02, 999), &table).is_err());
    }

    #[test]
    fn truncated_long_header_is_rejected_not_panicking() {
        let table = table_with_instance(1);
        // Claims a 16-byte DCID but supplies none of it.
        let datagram = [0xE0, 0x00, 0x00, 0x00, 0x01, 16];
        assert!(resolve(&datagram, &table).is_err());
    }

    #[test]
    fn stale_cached_backend_is_not_trusted() {
        let table = table_with_instance(1);
        let stale: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let buf = CryptoReassemblyBuffer::new(Duration::from_secs(10));
        let addr = PacketRouter::resolve_backend(
            &short_header(1),
            "127.0.0.1:9999".parse().unwrap(),
            &table,
            &buf,
            2,
            // Cache claims a backend address the registry no longer knows. If a
            // dead backend's IP has been reassigned to another tenant's pod, and
            // the client keeps sending (refreshing its own cache entry), this
            // would relay one customer's traffic into another's backend forever.
            |_| Some(ConnectionState::new(stale, 1)),
            |_, _| {},
        )
        .expect("should fall through to CID routing");

        assert_eq!(
            addr,
            "127.0.0.1:2".parse::<SocketAddr>().unwrap(),
            "a cached address absent from the registry must be discarded, not used"
        );
    }

    #[test]
    fn current_cached_backend_is_still_a_fast_path() {
        let table = table_with_instance(1);
        let current: SocketAddr = "127.0.0.1:2".parse().unwrap();

        let buf = CryptoReassemblyBuffer::new(Duration::from_secs(10));
        let addr = PacketRouter::resolve_backend(
            // Deliberately unroutable by CID so only the cache can answer.
            &[0x40, 0xFF, 0xFF],
            "127.0.0.1:9999".parse().unwrap(),
            &table,
            &buf,
            2,
            |_| Some(ConnectionState::new(current, 1)),
            |_, _| {},
        )
        .expect("a cached address the registry still knows must be used");

        assert_eq!(addr, current);
    }
}
