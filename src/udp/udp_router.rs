use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;

use super::worker_pool::WorkerPool;

/// Which UDP backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpBackend {
    /// Standard tokio-based async UDP (default, works everywhere).
    #[default]
    Tokio,
    /// io_uring-based backend (Linux 6.0+ only, requires `io-uring` feature).
    #[cfg(feature = "io-uring")]
    IoUring,
}

pub struct UdpRouter {
    pool: WorkerPool,
    #[cfg(feature = "io-uring")]
    uring_pool: Option<super::uring::UringWorkerPool>,
    backend: UdpBackend,
}

impl UdpRouter {
    pub(crate) fn new(
        routing_table: Arc<RoutingTable>,
        listen_addr: String,
        cid_prefix_length: u8,
        connection_ttl: Duration,
        workers: usize,
        backend: UdpBackend,
    ) -> Self {
        let pool = WorkerPool::new(
            routing_table.clone(),
            listen_addr.clone(),
            workers,
            cid_prefix_length,
            connection_ttl,
        );

        #[cfg(feature = "io-uring")]
        let uring_pool = if backend == UdpBackend::IoUring {
            Some(super::uring::UringWorkerPool::new(
                routing_table,
                listen_addr,
                workers,
                cid_prefix_length,
                connection_ttl,
            ))
        } else {
            None
        };

        Self {
            pool,
            #[cfg(feature = "io-uring")]
            uring_pool,
            backend,
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        #[cfg(feature = "io-uring")]
        if let Some(ref uring_pool) = self.uring_pool {
            return uring_pool.run(shutdown).await;
        }

        let _ = self.backend; // suppress unused warning when io-uring not enabled
        self.pool.run(shutdown).await
    }
}
