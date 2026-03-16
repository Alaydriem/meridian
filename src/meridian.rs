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

        let tcp_router = TcpRouterBuilder::new(
            self.routing_table.clone(),
            self.config.listen.clone(),
        )
        .build();

        #[allow(unused_mut)]
        let mut udp_builder = UdpRouterBuilder::new(
            self.routing_table.clone(),
            self.config.listen.clone(),
        )
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
            let control_plane = ControlPlane::new(api_config.clone(), self.routing_table.clone());
            let api_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = control_plane.run(api_shutdown).await {
                    tracing::error!(error = %e, "control plane failed");
                }
            }))
        } else {
            None
        };

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

        tracing::info!("meridian shutting down");
        Ok(())
    }
}
