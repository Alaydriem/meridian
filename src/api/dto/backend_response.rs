use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendResponse {
    pub name: String,
    pub hostname: String,
    pub tcp_addr: String,
    pub udp_addr: String,
    pub instance_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendListResponse {
    pub backends: Vec<BackendResponse>,
}
