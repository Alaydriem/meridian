use std::sync::Arc;

use crate::routing::resolve::AddressResolver;
use crate::routing::{Backend, RoutingTable};

use super::api_error::ApiError;
use super::dto::{
    BackendListResponse, BackendResponse, CreateBackendRequest, UpdateBackendRequest,
};

pub struct BackendService {
    table: Arc<RoutingTable>,
}

impl BackendService {
    pub fn new(table: Arc<RoutingTable>) -> Self {
        Self { table }
    }

    pub fn new_shared(table: Arc<RoutingTable>) -> Arc<Self> {
        Arc::new(Self::new(table))
    }

    pub fn list(&self) -> BackendListResponse {
        let backends = self
            .table
            .list_backends()
            .into_iter()
            .map(|(name, b)| BackendResponse {
                name,
                hostname: b.hostname,
                tcp_addr: b.tcp_addr.to_string(),
                udp_addr: b.udp_addr.to_string(),
                instance_id: b.instance_id,
            })
            .collect();

        BackendListResponse { backends }
    }

    pub async fn create(&self, req: CreateBackendRequest) -> Result<BackendResponse, ApiError> {
        let backend = self
            .resolve_backend(&req.hostname, &req.tcp_addr, &req.udp_addr, req.instance_id)
            .await?;

        // Refuse an instance_id already held by a different hostname. Provisioning is
        // the sole allocator, so this should never fire — but nothing else in the
        // system would detect it, and a collision routes one tenant's voice traffic
        // into another tenant's backend.
        if let Err(e) = self.table.try_add_backend(req.name.clone(), backend) {
            tracing::error!(name = %req.name, error = %e, "instance_id conflict refused");
            return Err(ApiError::Conflict(e.to_string()));
        }
        tracing::info!(name = %req.name, hostname = %req.hostname, "backend added");

        Ok(BackendResponse {
            name: req.name,
            hostname: req.hostname,
            tcp_addr: req.tcp_addr,
            udp_addr: req.udp_addr,
            instance_id: req.instance_id,
        })
    }

    /// Register or refresh a record, reporting whether it was created.
    ///
    /// A backend's heartbeat uses this to both register and refresh, so absence is
    /// not an error — otherwise a backend whose record was lost to a Meridian
    /// restart or a lapsed lease could never re-establish it.
    pub async fn upsert(
        &self,
        name: String,
        req: UpdateBackendRequest,
    ) -> Result<(bool, BackendResponse), ApiError> {
        let backend = self
            .resolve_backend(&req.hostname, &req.tcp_addr, &req.udp_addr, req.instance_id)
            .await?;

        let created = match self.table.update_backend(&name, backend.clone()) {
            Some(_old) => false,
            None => {
                // Same conflict check as create: an instance_id held by a different
                // hostname must be refused rather than silently overwriting.
                if let Err(e) = self.table.try_add_backend(name.clone(), backend) {
                    tracing::error!(%name, error = %e, "instance_id conflict refused");
                    return Err(ApiError::Conflict(e.to_string()));
                }
                true
            }
        };

        if created {
            tracing::info!(%name, hostname = %req.hostname, "backend created via upsert");
        } else {
            tracing::info!(%name, hostname = %req.hostname, "backend updated");
        }

        Ok((
            created,
            BackendResponse {
                name,
                hostname: req.hostname,
                tcp_addr: req.tcp_addr,
                udp_addr: req.udp_addr,
                instance_id: req.instance_id,
            },
        ))
    }

    pub fn delete(&self, name: &str) -> Result<(), ApiError> {
        match self.table.remove_backend(name) {
            Some(_) => {
                tracing::info!(%name, "backend removed");
                Ok(())
            }
            None => {
                tracing::warn!(%name, "backend delete failed: not found");
                Err(ApiError::NotFound(format!("backend '{name}' not found")))
            }
        }
    }

    async fn resolve_backend(
        &self,
        hostname: &str,
        tcp_addr: &str,
        udp_addr: &str,
        instance_id: u16,
    ) -> Result<Backend, ApiError> {
        let tcp = AddressResolver::resolve_addr(tcp_addr).await.map_err(|e| {
            ApiError::InvalidAddress {
                field: "tcp_addr",
                detail: e.to_string(),
            }
        })?;

        let udp = AddressResolver::resolve_addr(udp_addr).await.map_err(|e| {
            ApiError::InvalidAddress {
                field: "udp_addr",
                detail: e.to_string(),
            }
        })?;

        Ok(Backend::new(hostname.to_string(), tcp, udp, instance_id).with_lease())
    }
}
