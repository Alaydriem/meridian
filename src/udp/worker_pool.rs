use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::health::DatapathHealth;
use crate::routing::RoutingTable;

use super::connection_state_table::ConnectionStateTable;
use super::crypto_reassembly::CryptoReassemblyBuffer;
use super::ephemeral_socket_manager::{DEFAULT_MAX_EPHEMERAL_SOCKETS, EphemeralSocketManager};
use super::socket_factory::SocketFactory;
use super::udp_worker::UdpWorker;

pub struct WorkerPool {
    routing_table: Arc<RoutingTable>,
    listen_addr: String,
    worker_count: usize,
    cid_prefix_length: u8,
    connection_ttl: Duration,
    health: Arc<DatapathHealth>,
}

impl WorkerPool {
    pub fn new(
        routing_table: Arc<RoutingTable>,
        listen_addr: String,
        worker_count: usize,
        cid_prefix_length: u8,
        connection_ttl: Duration,
        health: Arc<DatapathHealth>,
    ) -> Self {
        Self {
            routing_table,
            listen_addr,
            worker_count: worker_count.max(1),
            cid_prefix_length,
            connection_ttl,
            health,
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        let std_sockets = SocketFactory::bind_worker_sockets(&self.listen_addr, self.worker_count)?;
        let actual_count = std_sockets.len();

        tracing::info!(
            addr = %self.listen_addr,
            workers = actual_count,
            "udp worker pool starting"
        );

        let mut sockets = Vec::with_capacity(actual_count);
        for (id, std_socket) in std_sockets.into_iter().enumerate() {
            let tokio_socket = UdpSocket::from_std(std_socket)
                .with_context(|| format!("failed to convert socket for worker {id}"))?;
            sockets.push(Arc::new(tokio_socket));
        }

        // Shared, not per-worker: SO_REUSEPORT rehashes a client to a different
        // worker when its source address changes, which is exactly when
        // ephemeral-socket reuse must apply.
        let conn_table = ConnectionStateTable::new(self.connection_ttl);
        let conn_table = Arc::new(conn_table);
        conn_table.spawn_cleanup(shutdown.clone());

        // Any listen socket works for the return path: all are bound to the same
        // address and port, so the client cannot tell them apart.
        let eph_manager = EphemeralSocketManager::new(
            sockets[0].clone(),
            self.connection_ttl,
            DEFAULT_MAX_EPHEMERAL_SOCKETS,
        );
        eph_manager.spawn_cleanup(shutdown.clone());

        let crypto_buf = Arc::new(CryptoReassemblyBuffer::new(Duration::from_secs(10)));
        crypto_buf.spawn_cleanup(shutdown.clone());

        let mut handles = Vec::with_capacity(actual_count);

        for (id, socket) in sockets.into_iter().enumerate() {
            let worker = UdpWorker::new(
                id,
                self.routing_table.clone(),
                self.cid_prefix_length,
                self.health.clone(),
                conn_table.clone(),
                eph_manager.clone(),
                crypto_buf.clone(),
            );

            let worker_shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                worker.run(socket, worker_shutdown).await
            }));
        }

        let deaths = Arc::new(AtomicUsize::new(0));

        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("udp worker pool shutting down");
            }
            _ = Self::supervise(handles, deaths.clone()) => {
                tracing::error!(
                    deaths = deaths.load(Ordering::Relaxed),
                    "all udp workers exited"
                );
            }
        }

        Ok(())
    }

    /// Await every worker, logging each exit and counting abnormal ones.
    ///
    /// Must not return early on a single failure: `WorkerPool::run` returning propagates
    /// into `Meridian::run`'s `select!`, taking down the TCP router and control plane.
    async fn supervise(handles: Vec<JoinHandle<Result<()>>>, deaths: Arc<AtomicUsize>) {
        for (id, handle) in handles.into_iter().enumerate() {
            match handle.await {
                Ok(Ok(())) => {
                    tracing::info!(worker = id, "udp worker exited cleanly");
                }
                Ok(Err(e)) => {
                    tracing::error!(worker = id, error = %e, "udp worker returned an error");
                    deaths.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if e.is_panic() => {
                    tracing::error!(worker = id, "udp worker PANICKED");
                    deaths.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(worker = id, error = %e, "udp worker join failed");
                    deaths.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A panicking worker must be observed, and must not cause the supervisor to
    /// return — `WorkerPool::run` returning propagates into `Meridian::run`'s
    /// `select!`, which would shut down the TCP router and control plane too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn panicking_worker_is_observed_and_siblings_survive() {
        let deaths = Arc::new(AtomicUsize::new(0));
        let survivor_ticks = Arc::new(AtomicUsize::new(0));
        let shutdown = CancellationToken::new();

        let mut handles = Vec::new();

        // Worker 0 panics immediately.
        handles.push(tokio::spawn(async move {
            panic!("worker 0 died");
        }));

        // Worker 1 keeps running until shutdown.
        let ticks = survivor_ticks.clone();
        let sd = shutdown.clone();
        handles.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sd.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        ticks.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Ok(())
        }));

        let deaths_seen = deaths.clone();
        let supervisor = tokio::spawn(async move {
            WorkerPool::supervise(handles, deaths_seen).await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(
            deaths.load(Ordering::Relaxed),
            1,
            "the panicking worker must be observed, not silently dropped"
        );
        assert!(
            survivor_ticks.load(Ordering::Relaxed) > 0,
            "the surviving worker must keep running"
        );
        assert!(
            !supervisor.is_finished(),
            "one worker's death must not end supervision — that would shut down the server"
        );

        shutdown.cancel();
    }
}
