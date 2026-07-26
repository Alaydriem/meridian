use serde::Deserialize;

/// Gossip cluster settings.
///
/// `peers` holds *names*, not addresses: every A record behind each name becomes a
/// peer, so discovery works under any orchestrator with no API access and no static
/// IPs to maintain.
#[derive(Debug, Clone, Deserialize)]
pub struct GossipConfig {
    #[serde(default = "default_gossip_bind")]
    pub bind: String,
    #[serde(default)]
    pub peers: Vec<String>,
}

fn default_gossip_bind() -> String {
    "0.0.0.0:7946".to_string()
}
