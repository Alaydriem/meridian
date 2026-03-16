use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Backend {
    pub hostname: String,
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub instance_id: u16,
}
