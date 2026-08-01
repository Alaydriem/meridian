use serde::{Deserialize, Serialize};

/// Version of a registry record, supplied by the backend that owns it.
///
/// Meridian never assigns these. Each record has exactly one writer, so that backend
/// orders its own updates — and Meridian holding no counter means a restart cannot
/// reset one and make fresh writes look stale to its peers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Serialize, Deserialize)]
pub struct RecordVersion {
    /// Random per backend process start. Ordered before `sequence` so a restarted
    /// backend's first record beats its own pre-restart records.
    pub boot_id: u64,
    /// Monotonic within one boot.
    pub sequence: u64,
}

impl RecordVersion {
    pub fn new(boot_id: u64, sequence: u64) -> Self {
        Self { boot_id, sequence }
    }

    /// Does this version replace `other`?
    ///
    /// Compares `boot_id` first, so a restart always wins regardless of how far the
    /// previous boot's sequence had advanced.
    pub fn supersedes(&self, other: &Self) -> bool {
        (self.boot_id, self.sequence) > (other.boot_id, other.sequence)
    }
}

/// A registry record as it travels between instances.
///
/// Addresses are strings so a record can carry an unresolved name, matching the
/// control plane. No lease field: it is derived locally on receipt, which keeps clock
/// skew out of expiry.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RegistryRecord {
    pub name: String,
    pub hostname: String,
    pub tcp_addr: String,
    pub udp_addr: String,
    pub instance_id: u16,
    pub version: RecordVersion,
}

impl RegistryRecord {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| anyhow::anyhow!("encode registry record: {e}"))
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("decode registry record: {e}"))
    }

    /// Key identifying this record for dissemination purposes.
    pub fn key(&self) -> RecordKey {
        RecordKey {
            name: self.name.clone(),
            version: self.version,
        }
    }
}

/// Dissemination key for a registry record.
///
/// Records for different backends are independent and never invalidate each other.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecordKey {
    pub name: String,
    pub version: RecordVersion,
}

impl foca::Invalidates for RecordKey {
    /// Does `self` replace `other` in the dissemination buffer?
    ///
    /// Buffer management, not the "is this new information" decision — that is
    /// `receive_item`'s return value. An *equal* version replaces, because records are
    /// republished periodically and non-replacement would accumulate duplicates.
    fn invalidates(&self, other: &Self) -> bool {
        self.name == other.name && !other.version.supersedes(&self.version)
    }
}

#[cfg(test)]
mod tests {
    use foca::Invalidates;

    use super::*;

    fn record(name: &str, sequence: u64) -> RegistryRecord {
        RegistryRecord {
            name: name.to_string(),
            hostname: format!("{name}.example.com"),
            tcp_addr: "10.0.0.1:443".to_string(),
            udp_addr: "10.0.0.1:8443".to_string(),
            instance_id: 42,
            version: RecordVersion::new(1, sequence),
        }
    }

    #[test]
    fn record_round_trips_through_postcard() {
        let r = record("customer-x", 5);
        let bytes = r.encode().unwrap();
        assert_eq!(RegistryRecord::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn malformed_bytes_decode_to_an_error_not_a_panic() {
        assert!(RegistryRecord::decode(&[0xFF, 0xFF, 0xFF]).is_err());
        assert!(RegistryRecord::decode(&[]).is_err());
    }

    #[test]
    fn key_invalidation_follows_version_for_the_same_name() {
        let older = record("x", 1).key();
        let newer = record("x", 2).key();
        assert!(newer.invalidates(&older));
        assert!(!older.invalidates(&newer));
    }

    #[test]
    fn different_names_never_invalidate_each_other() {
        let a = record("a", 9).key();
        let b = record("b", 1).key();
        assert!(
            !a.invalidates(&b),
            "records for different backends are independent"
        );
        assert!(!b.invalidates(&a));
    }

    #[test]
    fn an_identical_key_replaces_itself_in_the_buffer() {
        let k = record("x", 5).key();
        assert!(
            k.invalidates(&k),
            "records are republished periodically so late joiners converge; if an \
             identical key did not replace, every republish would add a duplicate \
             buffer entry. Whether a record is *new information* is decided by \
             receive_item's return value, not here."
        );
    }

    #[test]
    fn a_record_fits_one_gossip_datagram() {
        // Foca piggybacks broadcasts onto SWIM messages, so per-datagram capacity is
        // bounded. A record must fit well inside a conservative MTU.
        let r = RegistryRecord {
            name: "customer-with-a-fairly-long-identifier".to_string(),
            hostname: "customer-with-a-fairly-long-identifier.voice.example.com".to_string(),
            tcp_addr: "10.123.45.67:443".to_string(),
            udp_addr: "10.123.45.67:8443".to_string(),
            instance_id: 65_535,
            version: RecordVersion::new(u64::MAX, u64::MAX),
        };
        let len = r.encode().unwrap().len();
        assert!(
            len < 512,
            "record must fit a gossip datagram, got {len} bytes"
        );
    }

    #[test]
    fn higher_sequence_within_a_boot_supersedes() {
        let a = RecordVersion::new(7, 2);
        let b = RecordVersion::new(7, 3);
        assert!(b.supersedes(&a));
        assert!(!a.supersedes(&b));
    }

    #[test]
    fn a_restart_supersedes_regardless_of_sequence() {
        // The whole point of boot_id: a restarted backend's sequence-1 record must
        // beat its own pre-restart sequence-900 record.
        let before = RecordVersion::new(7, 900);
        let after = RecordVersion::new(8, 1);
        assert!(after.supersedes(&before));
        assert!(!before.supersedes(&after));
    }

    #[test]
    fn identical_versions_do_not_supersede() {
        let a = RecordVersion::new(7, 2);
        assert!(
            !a.supersedes(&a),
            "a repeated heartbeat is not new information; treating it as new would \
             make gossip disseminate it forever"
        );
    }

    #[test]
    fn default_is_ordered_below_any_real_version() {
        let real = RecordVersion::new(1, 1);
        assert!(real.supersedes(&RecordVersion::default()));
        assert!(!RecordVersion::default().supersedes(&real));
    }
}
