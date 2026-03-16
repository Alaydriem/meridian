use serde::Deserialize;

use super::tls_config::TlsConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    pub listen: String,
    pub api_key: String,
    pub tls: TlsConfig,
}
