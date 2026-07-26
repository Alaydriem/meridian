use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use super::routing_table::RoutingTable;

/// Source of registry records.
///
/// Exists so the routing table does not need to know how it is populated. The HTTP
/// control plane writes to the table directly and needs no provider; gossip needs a
/// long-running task. Keeping both behind one trait is what lets fleet mode be
/// additive rather than a fork of the standalone path.
#[async_trait::async_trait]
pub trait RegistryProvider: Send + Sync {
    /// Run until `shutdown` is cancelled.
    async fn run(&self, table: Arc<RoutingTable>, shutdown: CancellationToken) -> Result<()>;

    /// Name for logging.
    fn name(&self) -> &'static str;
}

/// Registry populated solely by the HTTP control plane.
///
/// Has nothing to run: `create_backend` and the `PUT` upsert already write to the
/// table. This exists so a standalone deployment takes the same code path as a
/// gossiping one, rather than the provider being an `Option` threaded through
/// everything.
pub struct LocalProvider;

#[async_trait::async_trait]
impl RegistryProvider for LocalProvider {
    async fn run(&self, _table: Arc<RoutingTable>, shutdown: CancellationToken) -> Result<()> {
        tracing::info!("registry provider: local (control plane only)");
        shutdown.cancelled().await;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::routing::Backend;

    #[tokio::test]
    async fn local_provider_exits_on_shutdown_without_touching_the_table() {
        let table = RoutingTable::new();
        table.add_backend(
            "a".to_string(),
            Backend::new(
                "a.example.com".to_string(),
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
                1,
            ),
        );
        let before = table.list_backends().len();

        let shutdown = CancellationToken::new();
        let handle = {
            let t = table.clone();
            let sd = shutdown.clone();
            tokio::spawn(async move { LocalProvider.run(t, sd).await })
        };

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("must exit promptly on shutdown")
            .unwrap()
            .unwrap();

        assert_eq!(
            table.list_backends().len(),
            before,
            "the local provider must not mutate the table; the control plane owns writes"
        );
    }

    #[tokio::test]
    async fn local_provider_does_not_exit_before_shutdown() {
        let table = RoutingTable::new();
        let shutdown = CancellationToken::new();
        let handle = {
            let sd = shutdown.clone();
            tokio::spawn(async move { LocalProvider.run(table, sd).await })
        };

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "a provider that returns early would be selected on in Meridian::run and \
             would shut the whole server down"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }
}
