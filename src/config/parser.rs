use anyhow::{Context, Result};

use super::meridian_config::MeridianConfig;

pub fn parse_config(hcl_content: &str) -> Result<MeridianConfig> {
    let config: MeridianConfig =
        hcl::from_str(hcl_content).context("failed to parse HCL config")?;
    Ok(config)
}

pub fn parse_config_file(path: &str) -> Result<MeridianConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {path}"))?;
    parse_config(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let config = parse_config(hcl).unwrap();
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

        let config = parse_config(hcl).unwrap();
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

        let result = parse_config(hcl);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_hcl() {
        let result = parse_config("this is not valid { hcl }}}");
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

        let config = parse_config(hcl).unwrap();
        assert_eq!(config.cid_prefix_length, 2);
        assert_eq!(config.backend.len(), 1);
    }
}
