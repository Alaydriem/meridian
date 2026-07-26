use anyhow::{Context, Result};

use super::meridian_config::MeridianConfig;

/// The only `cid_prefix_length` the router implements.
///
/// `packet_router` reads exactly two bytes as a `u16`, and backends embed a
/// 2-byte prefix (`PrefixedConnectionIdFormat`). Any other configured value
/// would silently behave as 2, so it is rejected rather than ignored.
const SUPPORTED_CID_PREFIX_LENGTH: u8 = 2;

pub struct ConfigParser;

impl ConfigParser {
    pub fn parse_config(hcl_content: &str) -> Result<MeridianConfig> {
        let config: MeridianConfig =
            hcl::from_str(hcl_content).context("failed to parse HCL config")?;

        if config.cid_prefix_length != SUPPORTED_CID_PREFIX_LENGTH {
            anyhow::bail!(
                "cid_prefix_length must be {SUPPORTED_CID_PREFIX_LENGTH} (got {}); \
                 only a 2-byte instance_id prefix is implemented",
                config.cid_prefix_length
            );
        }

        Ok(config)
    }

    pub fn parse_config_file(path: &str) -> Result<MeridianConfig> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {path}"))?;
        Self::parse_config(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_cid_prefix_length() {
        let hcl = r#"
            listen = "0.0.0.0:443"
            cid_prefix_length = 4
        "#;
        let err = ConfigParser::parse_config(hcl).expect_err("only a 2-byte prefix is implemented");
        assert!(
            err.to_string().contains("cid_prefix_length"),
            "error must name the offending field, got: {err}"
        );
    }

    #[test]
    fn accepts_the_supported_cid_prefix_length() {
        let hcl = r#"
            listen = "0.0.0.0:443"
            cid_prefix_length = 2
        "#;
        assert!(ConfigParser::parse_config(hcl).is_ok());
    }

    #[test]
    fn test_parse_valid_config() {
        let hcl = r#"
            listen = "0.0.0.0:443"
            cid_prefix_length = 2

            api {
                listen  = "0.0.0.0:9443"
                api_key = "test-secret"

                tls {
                    certificate = "/etc/meridian/api-cert.pem"
                    key         = "/etc/meridian/api-key.pem"
                }
            }

            backend "server1" {
                hostname    = "server1.example.com"
                tcp_addr    = "bvc-server-1:443"
                udp_addr    = "bvc-server-1:8443"
                instance_id = 1
            }

            backend "server2" {
                hostname    = "server2.example.com"
                tcp_addr    = "bvc-server-2:443"
                udp_addr    = "bvc-server-2:8443"
                instance_id = 2
            }
        "#;

        let config = ConfigParser::parse_config(hcl).unwrap();
        assert_eq!(config.listen, "0.0.0.0:443");
        assert_eq!(config.cid_prefix_length, 2);

        let api = config.api.unwrap();
        assert_eq!(api.listen, "0.0.0.0:9443");
        assert_eq!(api.api_key, "test-secret");
        assert_eq!(api.tls.certificate, "/etc/meridian/api-cert.pem");
        assert_eq!(api.tls.key, "/etc/meridian/api-key.pem");

        assert_eq!(config.backend.len(), 2);

        let s1 = &config.backend["server1"];
        assert_eq!(s1.hostname, "server1.example.com");
        assert_eq!(s1.tcp_addr, "bvc-server-1:443");
        assert_eq!(s1.udp_addr, "bvc-server-1:8443");
        assert_eq!(s1.instance_id, 1);

        let s2 = &config.backend["server2"];
        assert_eq!(s2.hostname, "server2.example.com");
        assert_eq!(s2.instance_id, 2);
    }

    #[test]
    fn test_parse_minimal_config() {
        let hcl = r#"
            listen = "0.0.0.0:443"
        "#;

        let config = ConfigParser::parse_config(hcl).unwrap();
        assert_eq!(config.listen, "0.0.0.0:443");
        assert_eq!(config.cid_prefix_length, 2); // default
        assert!(config.api.is_none());
        assert!(config.backend.is_empty());
    }

    #[test]
    fn test_parse_missing_listen() {
        let hcl = r#"
            cid_prefix_length = 2
        "#;

        let result = ConfigParser::parse_config(hcl);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_hcl() {
        let result = ConfigParser::parse_config("this is not valid { hcl }}}");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_config_default_cid_prefix() {
        let hcl = r#"
            listen = "0.0.0.0:443"

            backend "server1" {
                hostname    = "server1.example.com"
                tcp_addr    = "bvc-server-1:443"
                udp_addr    = "bvc-server-1:8443"
                instance_id = 1
            }
        "#;

        let config = ConfigParser::parse_config(hcl).unwrap();
        assert_eq!(config.cid_prefix_length, 2);
        assert_eq!(config.backend.len(), 1);
    }
}
