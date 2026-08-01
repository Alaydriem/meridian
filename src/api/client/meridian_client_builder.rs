use std::path::Path;

use anyhow::{Context, Result};

use super::meridian_client::MeridianClient;

pub struct MeridianClientBuilder {
    base_url: String,
    api_key: String,
    ca_cert_pem: Option<Vec<u8>>,
    danger_accept_invalid_certs: bool,
}

impl MeridianClientBuilder {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            ca_cert_pem: None,
            danger_accept_invalid_certs: false,
        }
    }

    /// Add a CA certificate PEM to trust (for self-signed API server certs).
    pub fn with_ca_cert_pem(mut self, pem: Vec<u8>) -> Self {
        self.ca_cert_pem = Some(pem);
        self
    }

    /// Load a CA certificate from a file path.
    pub fn with_ca_cert_file(self, path: impl AsRef<Path>) -> Result<Self> {
        let pem = std::fs::read(path.as_ref())
            .with_context(|| format!("failed to read CA cert: {}", path.as_ref().display()))?;
        Ok(self.with_ca_cert_pem(pem))
    }

    /// Accept invalid (self-signed) TLS certificates.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    pub fn build(self) -> Result<MeridianClient> {
        let mut builder = reqwest::Client::builder();

        if let Some(pem) = &self.ca_cert_pem {
            let cert =
                reqwest::tls::Certificate::from_pem(pem).context("invalid CA certificate PEM")?;
            builder = builder.add_root_certificate(cert);
        }

        if self.danger_accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let http_client = builder.build().context("failed to build HTTP client")?;

        let base_url = self.base_url.trim_end_matches('/').to_string();

        Ok(MeridianClient {
            http_client,
            base_url,
            api_key: self.api_key,
        })
    }
}
