use serde::{Deserialize, Serialize};

/// Datapath health, as served by `GET /health/datapath`.
///
/// `can_serve` is deliberately not "all workers present": a pool running below
/// its configured count still serves every connection correctly, so a readiness
/// probe keyed on the stricter condition would relocate the ingress and cost
/// every live connection a QUIC path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatapathHealthResponse {
    pub live_workers: usize,
    pub configured_workers: usize,
    /// Milliseconds since the last processed datagram, or `None` if none yet.
    pub last_datagram_age_ms: Option<u64>,
    pub can_serve: bool,
}
