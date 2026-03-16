use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub backend_addr: SocketAddr,
    #[allow(dead_code)]
    pub instance_id: u16,
    pub last_activity: Instant,
}

impl ConnectionState {
    pub fn new(backend_addr: SocketAddr, instance_id: u16) -> Self {
        Self {
            backend_addr,
            instance_id,
            last_activity: Instant::now(),
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}
