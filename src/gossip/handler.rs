use std::net::SocketAddr;
use std::sync::Arc;

use crate::routing::{Backend, RecordKey, RegistryRecord, RoutingTable};

/// Errors surfaced to Foca from broadcast handling.
///
/// Must be `'static + Send + Sync` rather than `anyhow::Error`.
#[derive(Debug)]
pub enum GossipError {
    Decode(String),
    UnresolvableAddress(String),
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "malformed gossip record: {e}"),
            Self::UnresolvableAddress(e) => write!(f, "unresolvable address in record: {e}"),
        }
    }
}

impl std::error::Error for GossipError {}

/// Applies incoming registry records to the routing table.
///
/// `receive_item`'s return value controls dissemination: `Some` means "new, keep
/// spreading", `None` means "stale, stop". Returning `Some` unconditionally would make
/// Foca forward the record forever.
pub struct RegistryBroadcast {
    table: Arc<RoutingTable>,
}

impl RegistryBroadcast {
    pub fn new(table: Arc<RoutingTable>) -> Self {
        Self { table }
    }

    /// Apply a record if it supersedes what we hold. Returns the key when applied.
    fn apply(&self, record: RegistryRecord) -> Result<Option<RecordKey>, GossipError> {
        // Stale or duplicate: nothing to do, and nothing to disseminate.
        if let Some(existing) = self.table.lookup_by_hostname(&record.hostname)
            && !record.version.supersedes(&existing.version)
        {
            return Ok(None);
        }

        let tcp_addr = record
            .tcp_addr
            .parse::<SocketAddr>()
            .map_err(|e| GossipError::UnresolvableAddress(format!("{}: {e}", record.tcp_addr)))?;
        let udp_addr = record
            .udp_addr
            .parse::<SocketAddr>()
            .map_err(|e| GossipError::UnresolvableAddress(format!("{}: {e}", record.udp_addr)))?;

        let key = record.key();
        let backend = Backend::new(record.hostname, tcp_addr, udp_addr, record.instance_id)
            .with_version(record.version);

        // Upsert, matching the control plane path.
        if self.table.update_backend(&record.name, backend.clone()).is_none() {
            // Refused for the same reason as on the API: silently overwriting would
            // route one tenant's traffic into another's backend.
            if let Err(e) = self.table.try_add_backend(record.name.clone(), backend) {
                tracing::error!(name = %record.name, error = %e, "gossip record refused");
                return Ok(None);
            }
        }

        Ok(Some(key))
    }
}

impl foca::BroadcastHandler<SocketAddr> for RegistryBroadcast {
    type Key = RecordKey;
    type Error = GossipError;

    fn receive_item(
        &mut self,
        data: &[u8],
        sender: Option<&SocketAddr>,
    ) -> Result<Option<Self::Key>, Self::Error> {
        let record =
            RegistryRecord::decode(data).map_err(|e| GossipError::Decode(e.to_string()))?;

        // `None` means we added this ourselves via `add_broadcast`. Such a record is
        // already in our table, so the staleness check below would judge it stale and
        // Foca would never disseminate it — killing the publish path entirely.
        if sender.is_none() {
            return Ok(Some(record.key()));
        }

        self.apply(record)
    }
}

#[cfg(test)]
mod tests {
    use foca::BroadcastHandler;

    use super::*;
    use crate::routing::RecordVersion;

    /// Stands in for the peer that sent a record. `None` means "we published this
    /// ourselves", which is a different code path entirely.
    fn peer() -> SocketAddr {
        "127.0.0.1:7946".parse().unwrap()
    }

    fn record(name: &str, sequence: u64, udp_port: u16) -> RegistryRecord {
        RegistryRecord {
            name: name.to_string(),
            hostname: format!("{name}.example.com"),
            tcp_addr: "127.0.0.1:443".to_string(),
            udp_addr: format!("127.0.0.1:{udp_port}"),
            instance_id: 1,
            version: RecordVersion::new(1, sequence),
        }
    }

    #[test]
    fn a_new_record_is_applied_and_redisseminated() {
        let table = RoutingTable::new();
        let mut h = RegistryBroadcast::new(table.clone());

        let key = h
            .receive_item(&record("x", 1, 8443).encode().unwrap(), Some(&peer()))
            .unwrap();

        assert!(key.is_some(), "new information must be redisseminated");
        let stored = table.lookup_by_hostname("x.example.com").unwrap();
        assert_eq!(stored.udp_addr.port(), 8443);
    }

    #[test]
    fn a_stale_record_is_dropped_and_not_redisseminated() {
        let table = RoutingTable::new();
        let mut h = RegistryBroadcast::new(table.clone());

        h.receive_item(&record("x", 5, 8443).encode().unwrap(), Some(&peer()))
            .unwrap();
        let key = h
            .receive_item(&record("x", 2, 9999).encode().unwrap(), Some(&peer()))
            .unwrap();

        assert!(
            key.is_none(),
            "returning Some for stale data would make Foca disseminate it forever"
        );
        assert_eq!(
            table.lookup_by_hostname("x.example.com").unwrap().udp_addr.port(),
            8443,
            "a stale record must not overwrite a newer one"
        );
    }

    #[test]
    fn a_repeated_record_is_not_redisseminated() {
        let table = RoutingTable::new();
        let mut h = RegistryBroadcast::new(table);

        h.receive_item(&record("x", 5, 8443).encode().unwrap(), Some(&peer()))
            .unwrap();
        let again = h
            .receive_item(&record("x", 5, 8443).encode().unwrap(), Some(&peer()))
            .unwrap();

        assert!(
            again.is_none(),
            "an identical version is not new information"
        );
    }

    #[test]
    fn a_newer_record_replaces_the_address() {
        let table = RoutingTable::new();
        let mut h = RegistryBroadcast::new(table.clone());

        h.receive_item(&record("x", 1, 8443).encode().unwrap(), Some(&peer()))
            .unwrap();
        let key = h
            .receive_item(&record("x", 2, 9443).encode().unwrap(), Some(&peer()))
            .unwrap();

        assert!(key.is_some());
        assert_eq!(
            table.lookup_by_hostname("x.example.com").unwrap().udp_addr.port(),
            9443,
            "a backend that moved must be followed"
        );
    }

    #[test]
    fn a_locally_published_record_is_always_disseminated() {
        let table = RoutingTable::new();
        let mut h = RegistryBroadcast::new(table.clone());

        let r = record("x", 1, 8443);
        // Simulate our own registration, then publishing it.
        h.receive_item(&r.encode().unwrap(), Some(&peer())).unwrap();

        // sender = None is Foca's signal for `add_broadcast`. The record is by
        // definition already in our table, so a staleness check would suppress it
        // and nothing would ever leave this instance.
        let key = h.receive_item(&r.encode().unwrap(), None).unwrap();
        assert!(
            key.is_some(),
            "a locally published record must always be disseminated, or the publish              path is silently dead"
        );
    }

    #[test]
    fn malformed_data_is_an_error_not_a_panic() {
        let table = RoutingTable::new();
        let mut h = RegistryBroadcast::new(table);
        assert!(h.receive_item(&[0xFF, 0xFF, 0xFF], Some(&peer())).is_err());
    }

    #[test]
    fn an_unparseable_address_is_an_error_not_a_panic() {
        let table = RoutingTable::new();
        let mut h = RegistryBroadcast::new(table);

        let mut r = record("x", 1, 8443);
        r.udp_addr = "not-an-address".to_string();

        assert!(h.receive_item(&r.encode().unwrap(), Some(&peer())).is_err());
    }
}
