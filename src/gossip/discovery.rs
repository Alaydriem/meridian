use std::collections::HashSet;
use std::net::SocketAddr;

pub struct PeerDiscovery;

impl PeerDiscovery {
    /// Resolve every address behind the configured peer names.
    ///
    /// Resolves all A records of one hostname rather than taking a list of addresses,
    /// so discovery works under any orchestrator — a headless Kubernetes Service,
    /// Consul DNS, or plain DNS records — with no API access and no static IPs to
    /// maintain.
    ///
    /// Failures are skipped rather than fatal. Proxying must keep working when DNS is
    /// unavailable: an instance that cannot find peers still routes correctly from the
    /// records it already holds and from backends registering directly with it.
    pub async fn resolve_peers(names: &[String], self_addr: SocketAddr) -> Vec<SocketAddr> {
        let mut peers = HashSet::new();

        for name in names {
            match tokio::net::lookup_host(name.as_str()).await {
                Ok(addrs) => {
                    for addr in addrs {
                        // Never gossip with ourselves.
                        if addr != self_addr {
                            peers.insert(addr);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %name,
                        error = %e,
                        "gossip peer discovery failed for this name; continuing without it"
                    );
                }
            }
        }

        let mut peers: Vec<_> = peers.into_iter().collect();
        // Stable order so logs and tests are deterministic.
        peers.sort();
        peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn excludes_self_from_the_peer_set() {
        // Resolve localhost, then claim one of its own addresses as ours.
        let all = PeerDiscovery::resolve_peers(
            &["localhost:7946".to_string()],
            "127.0.0.255:7946".parse().unwrap(),
        )
        .await;

        if let Some(&first) = all.first() {
            let filtered = PeerDiscovery::resolve_peers(&["localhost:7946".to_string()], first).await;
            assert!(
                !filtered.contains(&first),
                "an instance must not gossip with itself"
            );
        }
    }

    #[tokio::test]
    async fn unresolvable_names_are_skipped_not_fatal() {
        let peers = PeerDiscovery::resolve_peers(
            &["this-host-does-not-exist.invalid:7946".to_string()],
            "127.0.0.1:7946".parse().unwrap(),
        )
        .await;

        assert!(
            peers.is_empty(),
            "DNS failure must degrade to an empty peer set, not abort startup — \
             proxying has to keep working without gossip"
        );
    }

    #[tokio::test]
    async fn a_mix_of_good_and_bad_names_yields_the_good_ones() {
        let peers = PeerDiscovery::resolve_peers(
            &[
                "this-host-does-not-exist.invalid:7946".to_string(),
                "localhost:7946".to_string(),
            ],
            "127.0.0.255:7946".parse().unwrap(),
        )
        .await;

        assert!(
            !peers.is_empty(),
            "one bad name must not discard the peers found from the others"
        );
    }

    #[tokio::test]
    async fn results_are_deduplicated() {
        let peers = PeerDiscovery::resolve_peers(
            &["localhost:7946".to_string(), "localhost:7946".to_string()],
            "127.0.0.255:7946".parse().unwrap(),
        )
        .await;

        let unique: HashSet<_> = peers.iter().collect();
        assert_eq!(unique.len(), peers.len(), "peer set must be deduplicated");
    }
}
