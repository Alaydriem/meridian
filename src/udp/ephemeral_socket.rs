use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Stable handle for one ephemeral socket.
///
/// Both keys a socket is reached by -- client address and Connection ID -- change
/// over a connection's life, so neither can identify it.
pub type SocketId = u64;

/// A QUIC Destination Connection ID, used as a socket index key.
pub type CidKey = Vec<u8>;

/// Liveness clock shared between a socket's map entry and its return-path task.
///
/// Milliseconds since a manager-wide epoch, so the return path can refresh it with a
/// relaxed store instead of taking a shard lock per datagram.
#[derive(Clone)]
pub struct Liveness {
    last_activity_ms: Arc<AtomicU64>,
    epoch: Instant,
}

impl Liveness {
    pub fn new(epoch: Instant) -> Self {
        Self {
            last_activity_ms: Arc::new(AtomicU64::new(epoch.elapsed().as_millis() as u64)),
            epoch,
        }
    }

    pub fn touch(&self) {
        self.last_activity_ms
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    pub fn idle_for(&self, now: Instant) -> Duration {
        let last = Duration::from_millis(self.last_activity_ms.load(Ordering::Relaxed));
        now.duration_since(self.epoch).saturating_sub(last)
    }
}

/// Where the return path should currently send.
///
/// Shared with the return-path task so a client that changes address keeps
/// receiving.
#[derive(Clone)]
pub struct ClientTarget(Arc<RwLock<SocketAddr>>);

impl ClientTarget {
    pub fn new(addr: SocketAddr) -> Self {
        Self(Arc::new(RwLock::new(addr)))
    }

    pub fn get(&self) -> SocketAddr {
        *self.0.read().expect("client target lock poisoned")
    }

    pub fn set(&self, addr: SocketAddr) {
        *self.0.write().expect("client target lock poisoned") = addr;
    }
}

pub struct EphemeralSocket {
    pub socket: Arc<UdpSocket>,
    /// Current client address. Read per datagram by the return-path task.
    pub target: ClientTarget,
    pub liveness: Liveness,
    /// Cancels the return-path task. That task holds an `Arc` clone of the socket, so
    /// dropping the map entry alone leaves the fd open for the process lifetime.
    pub cancel: CancellationToken,
    /// One-to-many: backends rotate Connection IDs, so a long-lived connection
    /// accumulates several. Eviction must clear all of them.
    pub dcids: Vec<CidKey>,
    pub client_addrs: Vec<SocketAddr>,
}

impl EphemeralSocket {
    pub fn new(
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        cancel: CancellationToken,
        epoch: Instant,
    ) -> Self {
        Self {
            socket,
            target: ClientTarget::new(client_addr),
            liveness: Liveness::new(epoch),
            cancel,
            dcids: Vec::new(),
            client_addrs: vec![client_addr],
        }
    }

    pub fn touch(&self) {
        self.liveness.touch();
    }

    pub fn idle_for(&self, now: Instant) -> Duration {
        self.liveness.idle_for(now)
    }
}
