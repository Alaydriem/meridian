use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;
use crate::udp::socket_factory;

use super::probe;
use super::ring_worker;

/// A worker pool that runs io_uring ring workers on dedicated OS threads.
///
/// Each worker owns its own io_uring ring, SO_REUSEPORT socket, and local state.
/// This is the io_uring replacement for `WorkerPool` which uses tokio tasks.
pub struct UringWorkerPool {
    routing_table: Arc<RoutingTable>,
    listen_addr: String,
    worker_count: usize,
    cid_prefix_length: u8,
    connection_ttl: Duration,
}

impl UringWorkerPool {
    pub fn new(
        routing_table: Arc<RoutingTable>,
        listen_addr: String,
        worker_count: usize,
        cid_prefix_length: u8,
        connection_ttl: Duration,
    ) -> Self {
        Self {
            routing_table,
            listen_addr,
            worker_count: worker_count.max(1),
            cid_prefix_length,
            connection_ttl,
        }
    }

    /// Run the io_uring worker pool. Blocks until shutdown.
    ///
    /// This spawns N OS threads, each with its own io_uring ring and socket.
    /// The calling thread (a tokio task) awaits shutdown or worker failure.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        // Verify kernel support before creating sockets.
        probe::check_io_uring_support()
            .context("io_uring backend is not available on this system")?;

        // Create SO_REUSEPORT sockets (one per worker).
        let std_sockets =
            socket_factory::bind_worker_sockets(&self.listen_addr, self.worker_count)?;
        let actual_count = std_sockets.len();

        tracing::info!(
            addr = %self.listen_addr,
            workers = actual_count,
            backend = "io_uring",
            "uring worker pool starting"
        );

        let mut handles = Vec::with_capacity(actual_count);

        for (id, std_socket) in std_sockets.into_iter().enumerate() {
            use std::os::fd::AsRawFd;

            let raw_fd = std_socket.as_raw_fd();
            // Leak the std socket to prevent it from being closed when dropped.
            // The io_uring ring now owns this fd.
            std::mem::forget(std_socket);

            let routing_table = self.routing_table.clone();
            let cid_prefix_length = self.cid_prefix_length;
            let connection_ttl = self.connection_ttl;
            let worker_shutdown = shutdown.clone();

            let handle = std::thread::Builder::new()
                .name(format!("uring-worker-{id}"))
                .spawn(move || {
                    ring_worker::run(
                        id,
                        raw_fd,
                        routing_table,
                        cid_prefix_length,
                        connection_ttl,
                        worker_shutdown,
                    )
                })
                .with_context(|| format!("failed to spawn uring worker thread {id}"))?;

            handles.push(handle);
        }

        // Wait for shutdown.
        shutdown.cancelled().await;

        tracing::info!("uring worker pool shutting down, joining worker threads");

        // Join all worker threads.
        for (id, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!(worker = id, error = %e, "uring worker failed");
                }
                Err(_) => {
                    tracing::error!(worker = id, "uring worker thread panicked");
                }
            }
        }

        Ok(())
    }
}
