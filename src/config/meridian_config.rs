use serde::Deserialize;
use std::collections::HashMap;

use super::api_config::ApiConfig;
use super::backend_config::BackendConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct MeridianConfig {
    pub listen: String,
    #[serde(default = "default_cid_prefix_length")]
    pub cid_prefix_length: u8,
    #[serde(default = "default_workers")]
    pub workers: usize,
    pub api: Option<ApiConfig>,
    #[serde(default)]
    pub backend: HashMap<String, BackendConfig>,
}

fn default_cid_prefix_length() -> u8 {
    2
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(2).max(1))
        .unwrap_or(1)
}
