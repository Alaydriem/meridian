use anyhow::Result;

use crate::config::MeridianConfig;
use crate::meridian::Meridian;
use crate::routing::{Backend, RoutingTable};

pub struct MeridianBuilder {
    config: MeridianConfig,
}

impl MeridianBuilder {
    pub fn new(config: MeridianConfig) -> Self {
        Self { config }
    }

    pub fn build(self) -> Result<Meridian> {
        let routing_table = RoutingTable::new();

        for (name, backend_config) in &self.config.backend {
            let tcp_addr = backend_config.tcp_addr.parse().map_err(|e| {
                anyhow::anyhow!(
                    "invalid tcp_addr '{}' for backend '{name}': {e}",
                    backend_config.tcp_addr
                )
            })?;
            let udp_addr = backend_config.udp_addr.parse().map_err(|e| {
                anyhow::anyhow!(
                    "invalid udp_addr '{}' for backend '{name}': {e}",
                    backend_config.udp_addr
                )
            })?;

            let backend = Backend {
                hostname: backend_config.hostname.clone(),
                tcp_addr,
                udp_addr,
                instance_id: backend_config.instance_id,
            };

            routing_table.add_backend(name.clone(), backend);
        }

        Ok(Meridian {
            config: self.config,
            routing_table,
        })
    }
}
