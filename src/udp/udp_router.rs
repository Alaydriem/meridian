use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;

use super::worker_pool::WorkerPool;

pub struct UdpRouter {
    pool: WorkerPool,
}

impl UdpRouter {
    pub(crate) fn new(
        routing_table: Arc<RoutingTable>,
        listen_addr: String,
        cid_prefix_length: u8,
        connection_ttl: Duration,
        workers: usize,
    ) -> Self {
        Self {
            pool: WorkerPool::new(
                routing_table,
                listen_addr,
                workers,
                cid_prefix_length,
                connection_ttl,
            ),
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        self.pool.run(shutdown).await
    }
}
