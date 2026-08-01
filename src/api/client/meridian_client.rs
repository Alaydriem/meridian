use anyhow::{Context, Result};

use crate::api::dto::{
    BackendListResponse, BackendResponse, CreateBackendRequest, DatapathHealthResponse,
    ErrorResponse, UpdateBackendRequest,
};

pub struct MeridianClient {
    pub(super) http_client: reqwest::Client,
    pub(super) base_url: String,
    pub(super) api_key: String,
}

impl MeridianClient {
    pub fn builder(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> super::meridian_client_builder::MeridianClientBuilder {
        super::meridian_client_builder::MeridianClientBuilder::new(base_url, api_key)
    }

    /// Register a backend with the Meridian control plane.
    pub async fn register(
        &self,
        name: impl Into<String>,
        hostname: impl Into<String>,
        tcp_addr: impl Into<String>,
        udp_addr: impl Into<String>,
        instance_id: u16,
    ) -> Result<BackendResponse> {
        let req = CreateBackendRequest {
            name: name.into(),
            hostname: hostname.into(),
            tcp_addr: tcp_addr.into(),
            udp_addr: udp_addr.into(),
            instance_id,
        };

        let resp = self
            .http_client
            .post(format!("{}/backends", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&req)
            .send()
            .await
            .context("failed to send register request")?;

        let status = resp.status();
        if status.is_success() {
            resp.json::<BackendResponse>()
                .await
                .context("failed to parse register response")
        } else {
            let error = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| format!("HTTP {status}"));
            anyhow::bail!("register failed: {error}")
        }
    }

    /// List all backends registered with the Meridian control plane.
    pub async fn list_backends(&self) -> Result<Vec<BackendResponse>> {
        let resp = self
            .http_client
            .get(format!("{}/backends", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .context("failed to send list request")?;

        let status = resp.status();
        if status.is_success() {
            let list = resp
                .json::<BackendListResponse>()
                .await
                .context("failed to parse list response")?;
            Ok(list.backends)
        } else {
            let error = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| format!("HTTP {status}"));
            anyhow::bail!("list backends failed: {error}")
        }
    }

    /// Fetch datapath health. Returns `Err` if the instance cannot serve, so a
    /// caller can treat any error as "not healthy" without inspecting the body.
    pub async fn datapath_health(&self) -> Result<DatapathHealthResponse> {
        let resp = self
            .http_client
            .get(format!("{}/health/datapath", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .context("failed to send datapath health request")?;

        let status = resp.status();
        // 503 still carries a valid body describing why, so parse either way.
        if status.is_success() || status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
            resp.json::<DatapathHealthResponse>()
                .await
                .context("failed to parse datapath health response")
        } else {
            anyhow::bail!("datapath health failed: HTTP {status}")
        }
    }

    /// Update a backend by name.
    pub async fn update_backend(
        &self,
        name: &str,
        hostname: impl Into<String>,
        tcp_addr: impl Into<String>,
        udp_addr: impl Into<String>,
        instance_id: u16,
    ) -> Result<BackendResponse> {
        let req = UpdateBackendRequest {
            hostname: hostname.into(),
            tcp_addr: tcp_addr.into(),
            udp_addr: udp_addr.into(),
            instance_id,
        };

        let resp = self
            .http_client
            .put(format!("{}/backends/{name}", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&req)
            .send()
            .await
            .context("failed to send update request")?;

        let status = resp.status();
        if status.is_success() {
            resp.json::<BackendResponse>()
                .await
                .context("failed to parse update response")
        } else {
            let error = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| format!("HTTP {status}"));
            anyhow::bail!("update backend failed: {error}")
        }
    }

    /// Remove a backend by name.
    pub async fn remove_backend(&self, name: &str) -> Result<()> {
        let resp = self
            .http_client
            .delete(format!("{}/backends/{name}", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .context("failed to send delete request")?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let error = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| format!("HTTP {status}"));
            anyhow::bail!("remove backend failed: {error}")
        }
    }
}
