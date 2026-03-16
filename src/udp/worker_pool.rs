use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;

use super::socket_factory;
use super::udp_worker::UdpWorker;

pub struct WorkerPool {
    routing_table: Arc<RoutingTable>,
    listen_addr: String,
    worker_count: usize,
    cid_prefix_length: u8,
    connection_ttl: Duration,
}

impl WorkerPool {
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

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        let std_sockets = socket_factory::bind_worker_sockets(&self.listen_addr, self.worker_count)?;
        let actual_count = std_sockets.len();

        tracing::info!(
            addr = %self.listen_addr,
            workers = actual_count,
            "udp worker pool starting"
        );

        let mut handles = Vec::with_capacity(actual_count);

        for (id, std_socket) in std_sockets.into_iter().enumerate() {
            let tokio_socket = UdpSocket::from_std(std_socket)
                .with_context(|| format!("failed to convert socket for worker {id}"))?;
            let socket = Arc::new(tokio_socket);

            let worker = UdpWorker::new(
                id,
                self.routing_table.clone(),
                self.cid_prefix_length,
                self.connection_ttl,
            );

            let worker_shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                worker.run(socket, worker_shutdown).await
            }));
        }

        // Wait for shutdown or any worker failure
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("udp worker pool shutting down");
            }
            result = async {
                for handle in &mut handles {
                    if let Ok(Err(e)) = handle.await {
                        return Err(e);
                    }
                }
                Ok(())
            } => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "udp worker failed");
                }
            }
        }

        Ok(())
    }
}
