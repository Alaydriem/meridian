use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;

pub struct EphemeralSocket {
    pub socket: Arc<UdpSocket>,
    #[allow(dead_code)]
    pub client_addr: SocketAddr,
    pub last_activity: Instant,
}

impl EphemeralSocket {
    pub fn new(socket: Arc<UdpSocket>, client_addr: SocketAddr) -> Self {
        Self {
            socket,
            client_addr,
            last_activity: Instant::now(),
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}
