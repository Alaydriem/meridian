use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;

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

    pub fn lookup_by_hostname(&self, hostname: &str) -> Option<Backend> {
        let name = self.hostname_to_name.get(hostname)?;
        self.by_name.get(name.value().as_str()).map(|r| r.value().clone())
    }

    pub fn lookup_by_instance_id(&self, id: u16) -> Option<SocketAddr> {
        self.by_instance_id.get(&id).map(|r| *r.value())
    }

    pub fn add_backend(&self, name: String, backend: Backend) {
        self.by_instance_id
            .insert(backend.instance_id, backend.udp_addr);
        self.hostname_to_name
            .insert(backend.hostname.clone(), name.clone());
        self.by_name.insert(name, backend);
    }

    pub fn remove_backend(&self, name: &str) -> Option<Backend> {
        let (_, backend) = self.by_name.remove(name)?;
        self.hostname_to_name.remove(&backend.hostname);
        self.by_instance_id.remove(&backend.instance_id);
        Some(backend)
    }

    pub fn update_backend(&self, name: &str, backend: Backend) -> Option<Backend> {
        let old = self.remove_backend(name)?;
        self.add_backend(name.to_string(), backend);
        Some(old)
    }

    pub fn list_backends(&self) -> Vec<(String, Backend)> {
        self.by_name
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_backend(hostname: &str, instance_id: u16) -> Backend {
        Backend {
            hostname: hostname.to_string(),
            tcp_addr: format!("127.0.0.1:{}", 10000 + instance_id)
                .parse()
                .unwrap(),
            udp_addr: format!("127.0.0.1:{}", 20000 + instance_id)
                .parse()
                .unwrap(),
            instance_id,
        }
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
    async fn test_concurrent_access() {
        let table = RoutingTable::new();
        let mut handles = vec![];

        for i in 0..10u16 {
            let t = table.clone();
            handles.push(tokio::spawn(async move {
                let hostname = format!("server{i}.example.com");
                let backend = Backend {
                    hostname: hostname.clone(),
                    tcp_addr: format!("127.0.0.1:{}", 10000 + i).parse().unwrap(),
                    udp_addr: format!("127.0.0.1:{}", 20000 + i).parse().unwrap(),
                    instance_id: i,
                };
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
