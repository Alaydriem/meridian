use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::api::ControlPlane;
use crate::config::MeridianConfig;
use crate::routing::RoutingTable;
use crate::tcp::TcpRouterBuilder;
use crate::udp::UdpRouterBuilder;

pub struct Meridian {
    pub(crate) config: MeridianConfig,
    pub(crate) routing_table: Arc<RoutingTable>,
}

impl Meridian {
    pub fn routing_table(&self) -> &Arc<RoutingTable> {
        &self.routing_table
    }

    pub fn config(&self) -> &MeridianConfig {
        &self.config
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        tracing::info!(listen = %self.config.listen, "meridian starting");

        let tcp_router =
            TcpRouterBuilder::new(self.routing_table.clone(), self.config.listen.clone()).build();

        #[allow(unused_mut)]
        let mut udp_builder =
            UdpRouterBuilder::new(self.routing_table.clone(), self.config.listen.clone())
                .cid_prefix_length(self.config.cid_prefix_length)
                .workers(self.config.workers);

        #[cfg(feature = "io-uring")]
        {
            udp_builder = udp_builder.backend(crate::udp::UdpBackend::IoUring);
            tracing::info!("io_uring UDP backend enabled");
        }

        let udp_router = udp_builder.build();

        let tcp_shutdown = shutdown.clone();
        let udp_shutdown = shutdown.clone();

        // Optionally start control plane if API config is present
        let api_handle = if let Some(api_config) = &self.config.api {
            let control_plane = ControlPlane::new(api_config.clone(), self.routing_table.clone())
                // Same handle the workers report into, so readiness reflects the
                // live datapath rather than just the API being up.
                .with_health(udp_router.health());
            let api_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = control_plane.run(api_shutdown).await {
                    tracing::error!(error = %e, "control plane failed");
                }
            }))
        } else {
            None
        };

        // Registry provider. Gossip when configured, otherwise the control plane is
        // the only writer. Spawned rather than selected on: a provider returning is
        // not a reason to shut down the proxy, since routing continues from records
        // already held.
        let registry_handle = {
            let provider: Box<dyn crate::routing::RegistryProvider> = match &self.config.gossip {
                Some(gossip) => Box::new(crate::gossip::GossipProvider::new(gossip.clone())),
                None => Box::new(crate::routing::LocalProvider),
            };
            tracing::info!(provider = provider.name(), "registry provider starting");
            let table = self.routing_table.clone();
            let provider_shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) = provider.run(table, provider_shutdown).await {
                    tracing::error!(error = %e, "registry provider failed");
                }
            })
        };

        // Lease reaping is opt-in: enabling it against a backend that registers once
        // at startup would make that backend unroutable one TTL later. Only records
        // marked leased are eligible, so static config is unaffected either way.
        if let Some(secs) = self.config.lease_ttl_secs {
            let ttl = std::time::Duration::from_secs(secs.max(1));
            tracing::info!(ttl_secs = secs, "lease reaping enabled");
            self.routing_table.spawn_lease_reaper(ttl, shutdown.clone());
        }

        tokio::select! {
            result = tcp_router.run(tcp_shutdown) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "tcp router failed");
                }
            }
            result = udp_router.run(udp_shutdown) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "udp router failed");
                }
            }
            _ = shutdown.cancelled() => {}
        }

        if let Some(handle) = api_handle {
            handle.abort();
        }
        registry_handle.abort();

        tracing::info!("meridian shutting down");
        Ok(())
    }
}
