use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::ephemeral_socket::EphemeralSocket;

pub struct EphemeralSocketManager {
    sockets: DashMap<SocketAddr, EphemeralSocket>,
    main_socket: Arc<UdpSocket>,
    ttl: Duration,
}

impl EphemeralSocketManager {
    pub fn new(main_socket: Arc<UdpSocket>, ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            sockets: DashMap::new(),
            main_socket,
            ttl,
        })
    }

    /// Get or create an ephemeral socket for a client connection.
    /// Returns the socket to use for sending to the backend.
    pub async fn get_or_create(
        self: &Arc<Self>,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
        shutdown: CancellationToken,
    ) -> Result<Arc<UdpSocket>> {
        // Check for existing socket
        if let Some(mut entry) = self.sockets.get_mut(&client_addr) {
            entry.touch();
            return Ok(entry.socket.clone());
        }

        // Create new ephemeral socket bound to 0.0.0.0:0
        let ephemeral = UdpSocket::bind("0.0.0.0:0").await?;
        ephemeral.connect(backend_addr).await?;
        let ephemeral = Arc::new(ephemeral);

        let eph_socket = EphemeralSocket::new(ephemeral.clone(), client_addr);
        self.sockets.insert(client_addr, eph_socket);

        // Spawn return-path task: recv from backend, send to client via main socket
        let main_socket = self.main_socket.clone();
        let recv_socket = ephemeral.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = recv_socket.recv(&mut buf) => {
                        match result {
                            Ok(n) => {
                                if let Err(e) = main_socket.send_to(&buf[..n], client_addr).await {
                                    tracing::debug!(
                                        %client_addr,
                                        error = %e,
                                        "return path send error (continuing)"
                                    );
                                    // Don't break — transient errors are expected
                                }
                            }
                            Err(e) => {
                                // On Windows, 10054 errors are common and not fatal
                                tracing::debug!(
                                    %client_addr,
                                    error = %e,
                                    "ephemeral socket recv error (continuing)"
                                );
                            }
                        }
                    }
                }
            }
        });

        Ok(ephemeral)
    }

    /// Spawn a background task that periodically removes idle sockets.
    pub fn spawn_cleanup(self: &Arc<Self>, shutdown: CancellationToken) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(manager.ttl / 2);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let now = Instant::now();
                        manager.sockets.retain(|_addr, socket| {
                            now.duration_since(socket.last_activity) < manager.ttl
                        });
                    }
                }
            }
        });
    }
}
