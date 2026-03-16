use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub hostname: String,
    pub tcp_addr: String,
    pub udp_addr: String,
    pub instance_id: u16,
}
