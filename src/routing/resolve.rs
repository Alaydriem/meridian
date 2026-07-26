use std::net::SocketAddr;

use anyhow::{anyhow, Result};

pub struct AddressResolver;

impl AddressResolver {
    /// Resolve an address string to a SocketAddr.
    /// Accepts either `IP:port` (fast path) or `hostname:port` (DNS lookup).
    pub async fn resolve_addr(addr: &str) -> Result<SocketAddr> {
        // Fast path: direct IP:port
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            return Ok(socket_addr);
        }

        // DNS resolution
        tokio::net::lookup_host(addr)
            .await
            .map_err(|e| anyhow!("failed to resolve '{addr}': {e}"))?
            .next()
            .ok_or_else(|| anyhow!("DNS lookup for '{addr}' returned no addresses"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_ip_addr() {
        let addr = AddressResolver::resolve_addr("127.0.0.1:8080").await.unwrap();
        assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_ipv6_addr() {
        let addr = AddressResolver::resolve_addr("[::1]:8080").await.unwrap();
        assert_eq!(addr, "[::1]:8080".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        let addr = AddressResolver::resolve_addr("localhost:9999").await.unwrap();
        assert_eq!(addr.port(), 9999);
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn test_resolve_missing_port() {
        let result = AddressResolver::resolve_addr("not-a-valid-address").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_unresolvable_host() {
        let result = AddressResolver::resolve_addr("this-host-does-not-exist.invalid:443").await;
        assert!(result.is_err());
    }
}
