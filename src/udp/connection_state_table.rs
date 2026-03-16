use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;

use super::connection_state::ConnectionState;

pub struct ConnectionStateTable {
    states: DashMap<SocketAddr, ConnectionState>,
    ttl: Duration,
}

impl ConnectionStateTable {
    pub fn new(ttl: Duration) -> Self {
        Self {
            states: DashMap::new(),
            ttl,
        }
    }

    pub fn insert(&self, client_addr: SocketAddr, state: ConnectionState) {
        self.states.insert(client_addr, state);
    }

    pub fn get(&self, client_addr: &SocketAddr) -> Option<ConnectionState> {
        let mut entry = self.states.get_mut(client_addr)?;
        entry.touch();
        Some(entry.clone())
    }

    pub fn remove(&self, client_addr: &SocketAddr) {
        self.states.remove(client_addr);
    }

    /// Spawn a background task that periodically removes expired entries.
    pub fn spawn_cleanup(self: &Arc<Self>, shutdown: CancellationToken) {
        let table = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(table.ttl / 2);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let now = Instant::now();
                        table.states.retain(|_addr, state| {
                            now.duration_since(state.last_activity) < table.ttl
                        });
                    }
                }
            }
        });
    }
}
