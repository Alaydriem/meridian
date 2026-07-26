use serde::Deserialize;
use std::collections::HashMap;

use super::api_config::ApiConfig;
use super::gossip_config::GossipConfig;
use super::backend_config::BackendConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct MeridianConfig {
    pub listen: String,
    #[serde(default = "default_cid_prefix_length")]
    pub cid_prefix_length: u8,
    #[serde(default = "default_workers")]
    pub workers: usize,
    pub api: Option<ApiConfig>,
    /// Optional: enables fleet mode. Absent means the control plane is the only
    /// source of registry records.
    pub gossip: Option<GossipConfig>,
    #[serde(default)]
    pub backend: HashMap<String, BackendConfig>,
    /// Seconds a heartbeat-maintained record survives without a refresh.
    ///
    /// Absent disables reaping. Opt-in because enabling it against backends that
    /// register once at startup rather than on a heartbeat makes every one of them
    /// unroutable one TTL after it appears. Set this only once every backend
    /// heartbeats; it must exceed the heartbeat interval by a few multiples (BVC
    /// heartbeats every 15s, so 45-60 tolerates two or three missed beats).
    pub lease_ttl_secs: Option<u64>,
}

fn default_cid_prefix_length() -> u8 {
    2
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(2).max(1))
        .unwrap_or(1)
}
