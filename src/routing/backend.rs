use std::net::SocketAddr;
use std::time::Instant;

use super::record::RecordVersion;

#[derive(Debug, Clone)]
pub struct Backend {
    pub hostname: String,
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub instance_id: u16,
    /// Version supplied by the backend itself, used to order competing writes.
    /// See [`RecordVersion`] for why Meridian must not assign this.
    pub version: RecordVersion,
    /// When this record was last written locally.
    ///
    /// Deliberately **not** serialised and never transmitted: the lease is derived
    /// as `registered_at + ttl` on whichever instance holds the record, so clock
    /// skew between machines cannot expire a healthy backend or keep a dead one
    /// alive. Ordering across instances is `version`'s job, not this field's.
    pub registered_at: Instant,
    /// Whether a heartbeat keeps this record alive, and so whether it may be reaped
    /// once `registered_at + ttl` passes.
    ///
    /// Records from static config are **not** leased: nothing re-registers them, so
    /// reaping them would delete a correctly configured backend one TTL after startup.
    pub leased: bool,
}

impl Backend {
    /// A record with no version, for callers that predate versioning (static config,
    /// tests). Ordered below any real version, so a real write always wins.
    pub fn new(
        hostname: String,
        tcp_addr: SocketAddr,
        udp_addr: SocketAddr,
        instance_id: u16,
    ) -> Self {
        Self {
            hostname,
            tcp_addr,
            udp_addr,
            instance_id,
            version: RecordVersion::default(),
            registered_at: Instant::now(),
            leased: false,
        }
    }

    /// Mark this record as heartbeat-maintained, making it subject to lease expiry.
    pub fn with_lease(mut self) -> Self {
        self.leased = true;
        self
    }

    /// The same record with a backend-supplied version attached.
    pub fn with_version(mut self, version: RecordVersion) -> Self {
        self.version = version;
        self
    }
}
