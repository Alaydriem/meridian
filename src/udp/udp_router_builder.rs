use std::sync::Arc;
use std::time::Duration;

use crate::routing::RoutingTable;

use super::udp_router::{UdpBackend, UdpRouter};

pub struct UdpRouterBuilder {
    routing_table: Arc<RoutingTable>,
    listen_addr: String,
    cid_prefix_length: u8,
    connection_ttl: Duration,
    workers: usize,
    backend: UdpBackend,
}

impl UdpRouterBuilder {
    pub fn new(routing_table: Arc<RoutingTable>, listen_addr: String) -> Self {
        Self {
            routing_table,
            listen_addr,
            cid_prefix_length: 2,
            connection_ttl: Duration::from_secs(60),
            workers: 1,
            backend: UdpBackend::default(),
        }
    }

    pub fn cid_prefix_length(mut self, length: u8) -> Self {
        self.cid_prefix_length = length;
        self
    }

    pub fn connection_ttl(mut self, ttl: Duration) -> Self {
        self.connection_ttl = ttl;
        self
    }

    pub fn workers(mut self, count: usize) -> Self {
        self.workers = count.max(1);
        self
    }

    pub fn backend(mut self, backend: UdpBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn build(self) -> UdpRouter {
        UdpRouter::new(
            self.routing_table,
            self.listen_addr,
            self.cid_prefix_length,
            self.connection_ttl,
            self.workers,
            self.backend,
        )
    }
}
