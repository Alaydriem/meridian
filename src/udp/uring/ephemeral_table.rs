use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Entry for an ephemeral socket managed by the io_uring ring.
pub struct EphEntry {
    /// Raw file descriptor for the ephemeral socket.
    pub raw_fd: i32,
    /// Index in the io_uring fixed file table.
    pub fixed_index: u32,
    /// The client address this socket is associated with.
    pub client_addr: SocketAddr,
    /// The backend address this socket is connected to.
    pub backend_addr: SocketAddr,
    /// Last time this socket was active.
    pub last_activity: Instant,
    /// Index of the recv buffer currently submitted for this socket.
    /// `None` if no recv is pending.
    pub pending_recv_buf: Option<u16>,
}

/// Per-thread ephemeral socket table. Uses plain `HashMap` since each
/// io_uring worker runs on a dedicated OS thread with no sharing.
pub struct EphemeralTable {
    by_client: HashMap<SocketAddr, EphEntry>,
    by_fixed_index: HashMap<u32, SocketAddr>,
    next_fixed_index: u32,
    ttl: Duration,
}

impl EphemeralTable {
    pub fn new(ttl: Duration) -> Self {
        // Fixed index 0 is reserved for the main listening socket.
        Self {
            by_client: HashMap::new(),
            by_fixed_index: HashMap::new(),
            next_fixed_index: 1,
            ttl,
        }
    }

    /// Get an existing entry by client address.
    pub fn get(&self, client_addr: &SocketAddr) -> Option<&EphEntry> {
        self.by_client.get(client_addr)
    }

    /// Get a mutable reference to an existing entry.
    pub fn get_mut(&mut self, client_addr: &SocketAddr) -> Option<&mut EphEntry> {
        self.by_client.get_mut(client_addr)
    }

    /// Look up client address by fixed file index.
    pub fn client_addr_for_index(&self, fixed_index: u32) -> Option<SocketAddr> {
        self.by_fixed_index.get(&fixed_index).copied()
    }

    /// Allocate the next fixed file index for a new ephemeral socket.
    pub fn alloc_fixed_index(&mut self) -> u32 {
        let idx = self.next_fixed_index;
        self.next_fixed_index += 1;
        idx
    }

    /// Insert a new ephemeral socket entry.
    pub fn insert(&mut self, entry: EphEntry) {
        let client_addr = entry.client_addr;
        let fixed_index = entry.fixed_index;
        self.by_fixed_index.insert(fixed_index, client_addr);
        self.by_client.insert(client_addr, entry);
    }

    /// Touch an entry to reset its TTL.
    pub fn touch(&mut self, client_addr: &SocketAddr) {
        if let Some(entry) = self.by_client.get_mut(client_addr) {
            entry.last_activity = Instant::now();
        }
    }

    /// Collect expired entries. Returns the list of (raw_fd, fixed_index, pending_recv_buf)
    /// for sockets that need to be cancelled and closed.
    pub fn collect_expired(&mut self) -> Vec<(i32, u32, Option<u16>)> {
        let now = Instant::now();
        let ttl = self.ttl;
        let mut expired = Vec::new();

        self.by_client.retain(|_addr, entry| {
            if now.duration_since(entry.last_activity) >= ttl {
                expired.push((entry.raw_fd, entry.fixed_index, entry.pending_recv_buf));
                false
            } else {
                true
            }
        });

        for &(_, fixed_index, _) in &expired {
            self.by_fixed_index.remove(&fixed_index);
        }

        expired
    }

    /// Number of active entries.
    pub fn len(&self) -> usize {
        self.by_client.len()
    }

    /// Drain all entries for shutdown. Returns all (raw_fd, fixed_index, pending_recv_buf).
    pub fn drain_all(&mut self) -> Vec<(i32, u32, Option<u16>)> {
        let entries: Vec<_> = self
            .by_client
            .drain()
            .map(|(_, e)| (e.raw_fd, e.fixed_index, e.pending_recv_buf))
            .collect();
        self.by_fixed_index.clear();
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn insert_and_lookup() {
        let mut table = EphemeralTable::new(Duration::from_secs(60));
        let client = make_addr(1000);
        let backend = make_addr(2000);
        let idx = table.alloc_fixed_index();

        table.insert(EphEntry {
            raw_fd: 42,
            fixed_index: idx,
            client_addr: client,
            backend_addr: backend,
            last_activity: Instant::now(),
            pending_recv_buf: None,
        });

        assert_eq!(table.len(), 1);
        assert!(table.get(&client).is_some());
        assert_eq!(table.client_addr_for_index(idx), Some(client));
    }

    #[test]
    fn expiry() {
        let mut table = EphemeralTable::new(Duration::from_millis(10));
        let client = make_addr(1000);
        let idx = table.alloc_fixed_index();

        table.insert(EphEntry {
            raw_fd: 42,
            fixed_index: idx,
            client_addr: client,
            backend_addr: make_addr(2000),
            last_activity: Instant::now() - Duration::from_secs(1),
            pending_recv_buf: Some(5),
        });

        let expired = table.collect_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], (42, idx, Some(5)));
        assert_eq!(table.len(), 0);
    }
}
