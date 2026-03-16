use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub certificate: String,
    pub key: String,
}
