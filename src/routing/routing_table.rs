use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;

use super::backend::Backend;

pub struct RoutingTable {
    /// name → Backend
    by_name: DashMap<String, Backend>,
    /// hostname → name (reverse index for SNI lookups)
    hostname_to_name: DashMap<String, String>,
    /// instance_id → udp_addr (index for CID-prefix routing)
    by_instance_id: DashMap<u16, SocketAddr>,
}

impl RoutingTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_name: DashMap::new(),
            hostname_to_name: DashMap::new(),
            by_instance_id: DashMap::new(),
        })
    }

    /// Index key for a hostname.
    ///
    /// SNI hostnames are case-insensitive (RFC 6066 §3, RFC 4343) and may arrive with
    /// a trailing root dot, so the index is keyed on a normalized form. The registered
    /// `Backend::hostname` keeps whatever was submitted, for display.
    fn index_key(hostname: &str) -> String {
        hostname.trim_end_matches('.').to_ascii_lowercase()
    }

    pub fn lookup_by_hostname(&self, hostname: &str) -> Option<Backend> {
        let name = self.hostname_to_name.get(&Self::index_key(hostname))?;
        self.by_name
            .get(name.value().as_str())
            .map(|r| r.value().clone())
    }

    pub fn lookup_by_instance_id(&self, id: u16) -> Option<SocketAddr> {
        self.by_instance_id.get(&id).map(|r| *r.value())
    }

    /// Is `addr` the current UDP address of some registered backend?
    ///
    /// Used to validate cached routing decisions. The CID and the registry are
    /// authoritative; the connection cache is only a hint. Without this check a
    /// client that keeps sending refreshes its own cache entry indefinitely and
    /// can be relayed to an address since reassigned to another tenant's pod.
    pub fn is_current_backend_addr(&self, addr: &SocketAddr) -> bool {
        self.by_instance_id.iter().any(|r| r.value() == addr)
    }

    pub fn add_backend(&self, name: String, backend: Backend) {
        self.by_instance_id
            .insert(backend.instance_id, backend.udp_addr);
        self.hostname_to_name
            .insert(Self::index_key(&backend.hostname), name.clone());
        self.by_name.insert(name, backend);
    }

    /// Add a backend, refusing a conflicting `instance_id`.
    ///
    /// Provisioning is the sole allocator of `instance_id`, so a conflict means
    /// the allocator is broken. Refusing loudly is the only way it becomes
    /// visible: `add_backend` resolves a conflict by last-write-wins with no
    /// signal at all, and a collision routes one tenant's traffic into another
    /// tenant's backend.
    pub fn try_add_backend(&self, name: String, backend: Backend) -> anyhow::Result<()> {
        // Extract owned strings inside this scope so every DashMap reference is
        // released before `add_backend` writes. Holding an iteration reference
        // across a write on the same map deadlocks.
        let conflict = self
            .by_name
            .iter()
            .find(|r| {
                r.value().instance_id == backend.instance_id
                    && Self::index_key(&r.value().hostname) != Self::index_key(&backend.hostname)
            })
            .map(|r| (r.key().clone(), r.value().hostname.clone()));

        if let Some((other_name, other_hostname)) = conflict {
            anyhow::bail!(
                "instance_id {} already held by '{other_name}' ({other_hostname}); \
                 refusing to register '{name}' ({})",
                backend.instance_id,
                backend.hostname
            );
        }

        self.add_backend(name, backend);
        Ok(())
    }

    /// Re-point the hostname index after `name` stops owning `key`, or clear it if
    /// nothing else claims that hostname.
    ///
    /// Several names can carry the same hostname — a backend that generates a fresh
    /// record name per restart accumulates them — with the index naming whichever
    /// registered last. Clearing it unconditionally orphans every survivor: still
    /// present in `by_name`, unreachable by hostname.
    fn release_hostname(&self, key: String, name: &str) {
        // Resolve to owned values before writing. Holding a DashMap reference across
        // a write to the same map deadlocks, and a `let` binding drops the guard at
        // the end of its own statement rather than the end of the block.
        let points_here = self
            .hostname_to_name
            .get(&key)
            .is_some_and(|r| r.value() == name);

        if !points_here {
            return;
        }

        let successor = self
            .by_name
            .iter()
            .filter(|r| Self::index_key(&r.value().hostname) == key)
            .max_by_key(|r| (r.value().version, r.value().registered_at))
            .map(|r| r.key().clone());

        match successor {
            Some(successor) => {
                self.hostname_to_name.insert(key, successor);
            }
            None => {
                self.hostname_to_name.remove(&key);
            }
        }
    }

    /// Re-point the instance index after a record holding `instance_id` goes away, or
    /// clear it if no survivor claims that id.
    fn release_instance(&self, instance_id: u16) {
        let successor = self
            .by_name
            .iter()
            .filter(|r| r.value().instance_id == instance_id)
            .max_by_key(|r| (r.value().version, r.value().registered_at))
            .map(|r| r.value().udp_addr);

        match successor {
            Some(addr) => {
                self.by_instance_id.insert(instance_id, addr);
            }
            None => {
                self.by_instance_id.remove(&instance_id);
            }
        }
    }

    pub fn remove_backend(&self, name: &str) -> Option<Backend> {
        let (_, backend) = self.by_name.remove(name)?;
        self.release_hostname(Self::index_key(&backend.hostname), name);
        self.release_instance(backend.instance_id);
        Some(backend)
    }

    pub fn update_backend(&self, name: &str, backend: Backend) -> Option<Backend> {
        // Overwrite in place rather than remove-then-add. The latter leaves a
        // window where the hostname resolves to nothing, and 15s heartbeats across
        // many backends make that window effectively continuous.
        let old = self.by_name.insert(name.to_string(), backend.clone())?;

        // Point the hostname and instance at the new record *before* clearing any
        // stale index entries, so no lookup ever observes an absence.
        self.hostname_to_name
            .insert(Self::index_key(&backend.hostname), name.to_string());
        self.by_instance_id
            .insert(backend.instance_id, backend.udp_addr);

        // Same shadowing hazard as removal: another record may still claim the
        // hostname or instance this one just stopped using.
        if Self::index_key(&old.hostname) != Self::index_key(&backend.hostname) {
            self.release_hostname(Self::index_key(&old.hostname), name);
        }
        if old.instance_id != backend.instance_id {
            self.release_instance(old.instance_id);
        }

        Some(old)
    }

    pub fn list_backends(&self) -> Vec<(String, Backend)> {
        self.by_name
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect()
    }

    /// Remove records whose lease has lapsed. Returns how many were removed.
    ///
    /// This is what lets a departed backend disappear with no explicit delete, and
    /// so with no tombstones — which removes delete-resurrection from the design
    /// entirely. Backends keep their record alive by re-registering; one that stops
    /// ages out independently on every instance.
    ///
    /// Only leased records are considered. Static config records have no writer to
    /// refresh them, so they are immortal by construction rather than by TTL choice.
    pub fn reap_expired_with_ttl(&self, ttl: Duration) -> usize {
        let now = Instant::now();

        // Collect keys first. Mutating while holding iteration references on a
        // DashMap deadlocks.
        let expired: Vec<String> = self
            .by_name
            .iter()
            .filter(|r| r.value().leased && now.duration_since(r.value().registered_at) >= ttl)
            .map(|r| r.key().clone())
            .collect();

        for name in &expired {
            self.remove_backend(name);
        }

        if !expired.is_empty() {
            tracing::info!(count = expired.len(), "reaped backends whose lease lapsed");
        }

        expired.len()
    }

    /// Spawn a background task that reaps lapsed leases.
    pub fn spawn_lease_reaper(self: &Arc<Self>, ttl: Duration, shutdown: CancellationToken) {
        let table = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(ttl / 3);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        table.reap_expired_with_ttl(ttl);
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_backend(hostname: &str, instance_id: u16) -> Backend {
        Backend::new(
            hostname.to_string(),
            format!("127.0.0.1:{}", 10000 + instance_id)
                .parse()
                .unwrap(),
            format!("127.0.0.1:{}", 20000 + instance_id)
                .parse()
                .unwrap(),
            instance_id,
        )
    }

    #[test]
    fn test_add_and_lookup_by_hostname() {
        let table = RoutingTable::new();
        let backend = test_backend("server1.example.com", 1);
        table.add_backend("server1".to_string(), backend);

        let found = table.lookup_by_hostname("server1.example.com").unwrap();
        assert_eq!(found.hostname, "server1.example.com");
        assert_eq!(found.instance_id, 1);
    }

    #[test]
    fn test_add_and_lookup_by_instance_id() {
        let table = RoutingTable::new();
        let backend = test_backend("server1.example.com", 1);
        table.add_backend("server1".to_string(), backend.clone());

        let addr = table.lookup_by_instance_id(1).unwrap();
        assert_eq!(addr, backend.udp_addr);
    }

    #[test]
    fn test_lookup_missing() {
        let table = RoutingTable::new();
        assert!(table.lookup_by_hostname("nonexistent.com").is_none());
        assert!(table.lookup_by_instance_id(99).is_none());
    }

    #[test]
    fn test_remove_backend() {
        let table = RoutingTable::new();
        table.add_backend(
            "server1".to_string(),
            test_backend("server1.example.com", 1),
        );

        let removed = table.remove_backend("server1").unwrap();
        assert_eq!(removed.hostname, "server1.example.com");
        assert!(table.lookup_by_hostname("server1.example.com").is_none());
        assert!(table.lookup_by_instance_id(1).is_none());
    }

    #[test]
    fn test_remove_nonexistent() {
        let table = RoutingTable::new();
        assert!(table.remove_backend("nonexistent").is_none());
    }

    #[test]
    fn test_update_backend() {
        let table = RoutingTable::new();
        table.add_backend(
            "server1".to_string(),
            test_backend("server1.example.com", 1),
        );

        let updated = test_backend("server1-new.example.com", 10);
        let old = table.update_backend("server1", updated).unwrap();
        assert_eq!(old.hostname, "server1.example.com");

        assert!(table.lookup_by_hostname("server1.example.com").is_none());
        let found = table.lookup_by_hostname("server1-new.example.com").unwrap();
        assert_eq!(found.instance_id, 10);
    }

    #[test]
    fn test_list_backends() {
        let table = RoutingTable::new();
        table.add_backend(
            "server1".to_string(),
            test_backend("server1.example.com", 1),
        );
        table.add_backend(
            "server2".to_string(),
            test_backend("server2.example.com", 2),
        );

        let list = table.list_backends();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn unrefreshed_records_expire_and_refreshed_ones_do_not() {
        let table = RoutingTable::new();
        let ttl = Duration::from_millis(100);

        table.add_backend(
            "stale".to_string(),
            test_backend("stale.example.com", 1).with_lease(),
        );
        table.add_backend(
            "fresh".to_string(),
            test_backend("fresh.example.com", 2).with_lease(),
        );

        tokio::time::sleep(Duration::from_millis(60)).await;
        // Only "fresh" heartbeats.
        table.add_backend(
            "fresh".to_string(),
            test_backend("fresh.example.com", 2).with_lease(),
        );

        tokio::time::sleep(Duration::from_millis(60)).await;
        let removed = table.reap_expired_with_ttl(ttl);

        assert_eq!(removed, 1);
        assert!(table.lookup_by_hostname("stale.example.com").is_none());
        assert!(
            table.lookup_by_hostname("fresh.example.com").is_some(),
            "a refreshed lease must survive"
        );
    }

    #[tokio::test]
    async fn unleased_records_are_never_reaped() {
        let table = RoutingTable::new();

        // Static config: nothing heartbeats it, so a lease would delete a correctly
        // configured backend one TTL after startup.
        table.add_backend("static".to_string(), test_backend("static.example.com", 7));

        tokio::time::sleep(Duration::from_millis(30)).await;
        let removed = table.reap_expired_with_ttl(Duration::from_millis(1));

        assert_eq!(removed, 0);
        assert!(
            table.lookup_by_hostname("static.example.com").is_some(),
            "a record with no heartbeat behind it must not be reaped"
        );
    }

    #[test]
    fn hostname_lookup_ignores_case_and_a_trailing_dot() {
        let table = RoutingTable::new();
        table.add_backend(
            "a".to_string(),
            test_backend("Bedrock-Legends.Example.COM", 9),
        );

        for probe in [
            "bedrock-legends.example.com",
            "Bedrock-Legends.Example.COM",
            "BEDROCK-LEGENDS.EXAMPLE.COM",
            "bedrock-legends.example.com.",
        ] {
            assert!(
                table.lookup_by_hostname(probe).is_some(),
                "SNI is case-insensitive and may carry a root dot; '{probe}' must resolve"
            );
        }
    }

    /// A backend that mints a new record name per restart leaves the older records
    /// behind, all claiming one hostname. Deleting one must not strand the rest.
    #[test]
    fn removing_a_shadowing_record_hands_the_hostname_back() {
        let table = RoutingTable::new();
        let host = "one.example.com";

        table.add_backend("from-config".to_string(), test_backend(host, 5));
        // Registered later, so it owns the index.
        table.add_backend(
            "generated-name".to_string(),
            test_backend(host, 5).with_lease(),
        );
        table.remove_backend("generated-name");

        assert!(
            table.lookup_by_hostname(host).is_some(),
            "a surviving record for this hostname must still be reachable"
        );
        assert!(
            table.lookup_by_instance_id(5).is_some(),
            "the instance index must fall back to the survivor too"
        );
    }

    /// Removing the record that is *already* shadowed must leave the live one alone.
    #[test]
    fn removing_a_shadowed_record_does_not_disturb_the_live_one() {
        let table = RoutingTable::new();
        let host = "one.example.com";

        table.add_backend("shadowed".to_string(), test_backend(host, 6));
        table.add_backend("live".to_string(), test_backend(host, 6));

        let live_addr = table.lookup_by_hostname(host).unwrap().udp_addr;
        table.remove_backend("shadowed");

        assert_eq!(
            table.lookup_by_hostname(host).map(|b| b.udp_addr),
            Some(live_addr),
            "removing a shadowed record must not repoint or clear the index"
        );
    }

    #[test]
    fn removing_the_only_record_still_clears_the_indexes() {
        let table = RoutingTable::new();
        table.add_backend("only".to_string(), test_backend("one.example.com", 8));

        table.remove_backend("only");

        assert!(table.lookup_by_hostname("one.example.com").is_none());
        assert!(table.lookup_by_instance_id(8).is_none());
    }

    #[test]
    fn conflicting_instance_id_is_rejected_not_silently_overwritten() {
        let table = RoutingTable::new();
        table.add_backend("a".to_string(), test_backend("a.example.com", 5));

        // A different hostname claiming the same instance_id.
        let rejected = table.try_add_backend("b".to_string(), test_backend("b.example.com", 5));
        assert!(
            rejected.is_err(),
            "a conflicting instance_id must be refused"
        );

        // The incumbent is untouched.
        assert_eq!(
            table.lookup_by_instance_id(5),
            Some(test_backend("a.example.com", 5).udp_addr)
        );
        assert!(table.lookup_by_hostname("b.example.com").is_none());
    }

    #[test]
    fn same_hostname_reclaiming_its_own_instance_id_is_allowed() {
        let table = RoutingTable::new();
        table.add_backend("a".to_string(), test_backend("a.example.com", 5));
        // A heartbeat for the same record must not look like a conflict.
        assert!(
            table
                .try_add_backend("a".to_string(), test_backend("a.example.com", 5))
                .is_ok()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn update_never_exposes_a_missing_hostname() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let table = RoutingTable::new();
        table.add_backend("s".to_string(), test_backend("s.example.com", 1));

        let stop = Arc::new(AtomicBool::new(false));
        let misses = Arc::new(AtomicUsize::new(0));

        // Reader: the hostname must resolve at every instant.
        let reader = {
            let t = table.clone();
            let stop = stop.clone();
            let misses = misses.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    if t.lookup_by_hostname("s.example.com").is_none() {
                        misses.fetch_add(1, Ordering::Relaxed);
                    }
                    tokio::task::yield_now().await;
                }
            })
        };

        // Writer: same hostname, changing address, as a heartbeat would.
        for i in 0..2000u16 {
            let mut b = test_backend("s.example.com", 1);
            b.udp_addr = format!("127.0.0.1:{}", 30000 + (i % 100)).parse().unwrap();
            table.update_backend("s", b);
        }

        stop.store(true, Ordering::Relaxed);
        reader.await.unwrap();

        assert_eq!(
            misses.load(Ordering::Relaxed),
            0,
            "hostname must resolve throughout an update; heartbeats make any gap continuous"
        );
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let table = RoutingTable::new();
        let mut handles = vec![];

        for i in 0..10u16 {
            let t = table.clone();
            handles.push(tokio::spawn(async move {
                let hostname = format!("server{i}.example.com");
                let backend = Backend::new(
                    hostname.clone(),
                    format!("127.0.0.1:{}", 10000 + i).parse().unwrap(),
                    format!("127.0.0.1:{}", 20000 + i).parse().unwrap(),
                    i,
                );
                t.add_backend(format!("server{i}"), backend);
                assert!(t.lookup_by_hostname(&hostname).is_some());
                assert!(t.lookup_by_instance_id(i).is_some());
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(table.list_backends().len(), 10);
    }
}
