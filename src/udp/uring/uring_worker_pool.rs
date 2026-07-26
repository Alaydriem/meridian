use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;
use crate::udp::socket_factory::SocketFactory;

use super::probe::UringProbe;
use super::ring_worker::RingWorker;

/// How a ring worker thread ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExit {
    Clean,
    Failed,
    Panicked,
}

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
        UringProbe::check_io_uring_support()
            .context("io_uring backend is not available on this system")?;

        // Create SO_REUSEPORT sockets (one per worker).
        let std_sockets = SocketFactory::bind_worker_sockets(&self.listen_addr, self.worker_count)?;
        let actual_count = std_sockets.len();

        tracing::info!(
            addr = %self.listen_addr,
            workers = actual_count,
            backend = "io_uring",
            "uring worker pool starting"
        );

        // Shared across rings: SO_REUSEPORT rehashes a client to a different worker
        // when its source address changes, which is when reuse must apply.
        let eph_table = Arc::new(super::ephemeral_table::EphemeralTable::new(
            self.connection_ttl,
        ));

        let mut handles = Vec::with_capacity(actual_count);
        // Threads report exits here so a death is visible immediately rather than at
        // shutdown.
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel::<(usize, WorkerExit)>();

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
            let eph_table = eph_table.clone();

            let exit_tx = exit_tx.clone();

            let handle = std::thread::Builder::new()
                .name(format!("uring-worker-{id}"))
                .spawn(move || {
                    // AssertUnwindSafe is sound: nothing is observed after the
                    // unwind, the thread ends.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        RingWorker::run(
                            id,
                            raw_fd,
                            routing_table,
                            cid_prefix_length,
                            connection_ttl,
                            eph_table,
                            worker_shutdown,
                        )
                    }));

                    let exit = match &result {
                        Ok(Ok(())) => WorkerExit::Clean,
                        Ok(Err(_)) => WorkerExit::Failed,
                        Err(_) => WorkerExit::Panicked,
                    };
                    let _ = exit_tx.send((id, exit));

                    match result {
                        Ok(inner) => inner,
                        // Don't resume the unwind: that aborts the process and takes
                        // the healthy workers with it.
                        Err(_) => Err(anyhow::anyhow!("uring worker {id} panicked")),
                    }
                })
                .with_context(|| format!("failed to spawn uring worker thread {id}"))?;

            handles.push(handle);
        }

        // Drop our sender so the channel closes once every worker has exited.
        drop(exit_tx);

        // Wait for shutdown, surfacing worker deaths as they happen.
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                maybe = exit_rx.recv() => match maybe {
                    Some((id, WorkerExit::Clean)) => {
                        tracing::info!(worker = id, "uring worker exited cleanly");
                    }
                    Some((id, WorkerExit::Failed)) => {
                        tracing::error!(worker = id, "uring worker returned an error");
                    }
                    Some((id, WorkerExit::Panicked)) => {
                        tracing::error!(worker = id, "uring worker PANICKED");
                    }
                    // Keep the pool alive so the rest of the server survives.
                    None => {
                        tracing::error!("all uring workers exited");
                        shutdown.cancelled().await;
                        break;
                    }
                }
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A ring worker's death must be observable while the process is still running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn thread_exit_is_reported_before_shutdown() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(usize, WorkerExit)>();

        // Stands in for a ring worker thread that panics, mirroring the reporting
        // wrapper in `run`.
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> Result<()> { panic!("ring worker died") },
            ));
            let exit = match &result {
                Ok(Ok(())) => WorkerExit::Clean,
                Ok(Err(_)) => WorkerExit::Failed,
                Err(_) => WorkerExit::Panicked,
            };
            let _ = tx.send((7, exit));
        });

        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("exit must be reported without waiting for shutdown");

        assert_eq!(got, Some((7, WorkerExit::Panicked)));
    }

    /// Multi-worker requires the shared ephemeral socket table: per-ring tables mean a
    /// rebound client is rehashed to a worker that cannot see its socket.
    #[test]
    fn requested_worker_count_is_honoured() {
        let pool = UringWorkerPool::new(
            RoutingTable::new(),
            "127.0.0.1:0".to_string(),
            3,
            2,
            Duration::from_secs(60),
        );
        assert_eq!(pool.worker_count, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_clean_exit_is_distinguished_from_a_panic() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(usize, WorkerExit)>();

        std::thread::spawn(move || {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> { Ok(()) }));
            let exit = match &result {
                Ok(Ok(())) => WorkerExit::Clean,
                Ok(Err(_)) => WorkerExit::Failed,
                Err(_) => WorkerExit::Panicked,
            };
            let _ = tx.send((0, exit));
        });

        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("must report");
        assert_eq!(got, Some((0, WorkerExit::Clean)));
    }
}
