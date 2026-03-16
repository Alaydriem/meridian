use std::sync::Arc;

use crate::routing::RoutingTable;

use super::tcp_router::TcpRouter;

pub struct TcpRouterBuilder {
    routing_table: Arc<RoutingTable>,
    listen_addr: String,
}

impl TcpRouterBuilder {
    pub fn new(routing_table: Arc<RoutingTable>, listen_addr: String) -> Self {
        Self {
            routing_table,
            listen_addr,
        }
    }

    pub fn build(self) -> TcpRouter {
        TcpRouter::new(self.routing_table, self.listen_addr)
    }
}
