use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Live view of the UDP datapath, shared between workers and the health check.
///
/// Readiness comes from [`DatapathHealth::can_serve`], which ignores partial worker
/// loss: with shared socket state a degraded pool still serves every connection, and
/// failing readiness would relocate the ingress and cost every connection a QUIC
/// path. Total loss is what liveness keys on.
pub struct DatapathHealth {
    live_workers: AtomicUsize,
    configured_workers: usize,
    /// Milliseconds since `started`; zero means no datagram seen yet.
    last_datagram_ms: AtomicU64,
    started: Instant,
}

impl DatapathHealth {
    pub fn new(configured_workers: usize) -> Arc<Self> {
        Arc::new(Self {
            live_workers: AtomicUsize::new(0),
            configured_workers,
            last_datagram_ms: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    pub fn worker_started(&self) {
        self.live_workers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_exited(&self) {
        self.live_workers.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn datagram_processed(&self) {
        let ms = self.started.elapsed().as_millis() as u64;
        // Saturate at 1 so "seen" is distinguishable from the zero sentinel.
        self.last_datagram_ms.store(ms.max(1), Ordering::Relaxed);
    }

    pub fn live_workers(&self) -> usize {
        self.live_workers.load(Ordering::Relaxed)
    }

    pub fn configured_workers(&self) -> usize {
        self.configured_workers
    }

    /// How long since the last datagram, or `None` if none has been processed.
    pub fn last_datagram_age(&self) -> Option<Duration> {
        let ms = self.last_datagram_ms.load(Ordering::Relaxed);
        if ms == 0 {
            return None;
        }
        Some(
            self.started
                .elapsed()
                .saturating_sub(Duration::from_millis(ms)),
        )
    }

    /// Can this instance serve traffic at all? Not "are all workers present".
    pub fn can_serve(&self) -> bool {
        self.live_workers() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_worker_loss_can_still_serve() {
        let h = DatapathHealth::new(3);
        h.worker_started();
        h.worker_started();
        h.worker_started();
        assert_eq!(h.live_workers(), 3);
        assert!(h.can_serve());

        h.worker_exited();
        assert_eq!(h.live_workers(), 2);
        assert!(
            h.can_serve(),
            "a degraded pool must still be servable — failing here would relocate \
             the ingress and cost every connection a QUIC path"
        );
    }

    #[test]
    fn total_worker_loss_cannot_serve() {
        let h = DatapathHealth::new(1);
        h.worker_started();
        h.worker_exited();
        assert_eq!(h.live_workers(), 0);
        assert!(!h.can_serve());
    }

    #[test]
    fn datagram_age_starts_empty_and_advances() {
        let h = DatapathHealth::new(1);
        assert!(h.last_datagram_age().is_none(), "no datagram seen yet");
        h.datagram_processed();
        assert!(h.last_datagram_age().is_some());
    }
}
