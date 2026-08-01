use std::net::SocketAddr;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use meridian::api::MeridianClient;
use meridian::config::{ConfigParser, MeridianConfig};

#[derive(Parser)]
#[command(name = "meridian", about = "QUIC-aware SNI proxy")]
pub struct Cli {
    /// Path to HCL config file
    #[arg(short, long, default_value = "config.hcl", global = true)]
    pub config: String,

    /// Skip TLS certificate verification when connecting to the API
    #[arg(long, global = true)]
    pub insecure: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the proxy server (default when no subcommand is given)
    Serve,
    /// Manage backends on a running meridian instance
    Backend(BackendArgs),
    /// Check health of a running meridian instance
    Health {
        /// Also require that the UDP datapath can serve.
        ///
        /// Without this, only the control plane is exercised — which is what a
        /// readiness probe wants, since a partially degraded worker pool still
        /// serves every connection. Use this for liveness, where the question is
        /// whether the datapath is wedged.
        #[arg(long)]
        datapath: bool,
    },
}

#[derive(Args)]
pub struct BackendArgs {
    #[command(subcommand)]
    pub action: BackendAction,
}

#[derive(Subcommand)]
pub enum BackendAction {
    /// List all registered backends
    List,
    /// Add a new backend
    Add(AddBackendArgs),
    /// Update an existing backend
    Update(UpdateBackendArgs),
    /// Remove a backend
    Remove(RemoveBackendArgs),
}

#[derive(Args)]
pub struct AddBackendArgs {
    /// Backend name (unique identifier)
    pub name: String,
    /// SNI hostname to match
    #[arg(long)]
    pub hostname: String,
    /// Backend address for TCP/HTTPS traffic (e.g., 10.0.0.1:443)
    #[arg(long)]
    pub tcp_addr: String,
    /// Backend address for UDP/QUIC traffic (e.g., 10.0.0.1:8443)
    #[arg(long)]
    pub udp_addr: String,
    /// CID prefix value for QUIC routing
    #[arg(long)]
    pub instance_id: u16,
}

#[derive(Args)]
pub struct UpdateBackendArgs {
    /// Backend name to update
    pub name: String,
    /// SNI hostname to match
    #[arg(long)]
    pub hostname: String,
    /// Backend address for TCP/HTTPS traffic (e.g., 10.0.0.1:443)
    #[arg(long)]
    pub tcp_addr: String,
    /// Backend address for UDP/QUIC traffic (e.g., 10.0.0.1:8443)
    #[arg(long)]
    pub udp_addr: String,
    /// CID prefix value for QUIC routing
    #[arg(long)]
    pub instance_id: u16,
}

#[derive(Args)]
pub struct RemoveBackendArgs {
    /// Backend name to remove
    pub name: String,
}

pub struct CliRunner;

impl CliRunner {
    /// Where to reach a control plane that is *listening* on `listen`.
    ///
    /// A wildcard bind address is not a usable destination. Windows rejects a connect
    /// to `0.0.0.0` outright (`WSAEADDRNOTAVAIL`), and Linux only accepts it by
    /// treating it as loopback — so taking `listen` verbatim breaks against the most
    /// ordinary production config, and breaks it on one platform but not the other.
    /// Anything that is not a wildcard (a concrete IP, or a hostname) is passed
    /// through unchanged.
    fn api_base_url(listen: &str) -> String {
        match listen.parse::<SocketAddr>() {
            Ok(SocketAddr::V4(addr)) if addr.ip().is_unspecified() => {
                format!("https://127.0.0.1:{}", addr.port())
            }
            Ok(SocketAddr::V6(addr)) if addr.ip().is_unspecified() => {
                format!("https://[::1]:{}", addr.port())
            }
            _ => format!("https://{listen}"),
        }
    }

    fn build_client_from_config(config: &MeridianConfig, insecure: bool) -> Result<MeridianClient> {
        let api = config.api.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "no 'api' block in config -- CLI commands require the API to be configured"
            )
        })?;

        let base_url = Self::api_base_url(&api.listen);

        let mut builder = MeridianClient::builder(&base_url, &api.api_key);

        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        } else {
            builder = builder.with_ca_cert_file(&api.tls.certificate)?;
        }

        builder.build()
    }

    pub async fn run_backend_command(
        config: &MeridianConfig,
        insecure: bool,
        args: &BackendArgs,
    ) -> Result<()> {
        let client = Self::build_client_from_config(config, insecure)?;

        match &args.action {
            BackendAction::List => {
                let backends = client.list_backends().await?;
                if backends.is_empty() {
                    println!("No backends registered.");
                } else {
                    let header = format!(
                        "{:<20} {:<30} {:<22} {:<22} {}",
                        "NAME", "HOSTNAME", "TCP_ADDR", "UDP_ADDR", "INSTANCE_ID"
                    );
                    println!("{header}");
                    for b in &backends {
                        println!(
                            "{:<20} {:<30} {:<22} {:<22} {}",
                            b.name, b.hostname, b.tcp_addr, b.udp_addr, b.instance_id,
                        );
                    }
                }
            }
            BackendAction::Add(add) => {
                let backend = client
                    .register(
                        &add.name,
                        &add.hostname,
                        &add.tcp_addr,
                        &add.udp_addr,
                        add.instance_id,
                    )
                    .await?;
                println!("Backend '{}' added.", backend.name);
            }
            BackendAction::Update(upd) => {
                let backend = client
                    .update_backend(
                        &upd.name,
                        &upd.hostname,
                        &upd.tcp_addr,
                        &upd.udp_addr,
                        upd.instance_id,
                    )
                    .await?;
                println!("Backend '{}' updated.", backend.name);
            }
            BackendAction::Remove(rem) => {
                client.remove_backend(&rem.name).await?;
                println!("Backend '{}' removed.", rem.name);
            }
        }

        Ok(())
    }

    pub async fn run_health(config: &MeridianConfig, insecure: bool, datapath: bool) -> Result<()> {
        let client = Self::build_client_from_config(config, insecure)?;

        let backends = match client.list_backends().await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Health check failed: {e}");
                std::process::exit(1);
            }
        };

        if datapath {
            match client.datapath_health().await {
                Ok(d) if d.can_serve => {
                    println!(
                        "Meridian is healthy. {} backend(s) registered. Datapath: {}/{} workers live.",
                        backends.len(),
                        d.live_workers,
                        d.configured_workers
                    );
                    return Ok(());
                }
                Ok(d) => {
                    eprintln!(
                        "Datapath cannot serve: {}/{} workers live",
                        d.live_workers, d.configured_workers
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Datapath health check failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        println!(
            "Meridian is healthy. {} backend(s) registered.",
            backends.len()
        );
        Ok(())
    }

    pub async fn run(cli: Cli) -> Result<()> {
        match &cli.command {
            None | Some(Command::Serve) => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                    )
                    .init();
                let config = ConfigParser::parse_config_file(&cli.config)?;
                let meridian = meridian::MeridianBuilder::new(config).build().await?;

                let shutdown = tokio_util::sync::CancellationToken::new();
                let token = shutdown.clone();

                tokio::spawn(async move {
                    tokio::signal::ctrl_c().await.ok();
                    tracing::info!("received ctrl-c, shutting down");
                    token.cancel();
                });

                meridian.run(shutdown).await
            }
            Some(Command::Backend(args)) => {
                let config = ConfigParser::parse_config_file(&cli.config)?;
                Self::run_backend_command(&config, cli.insecure, args).await
            }
            Some(Command::Health { datapath }) => {
                let config = ConfigParser::parse_config_file(&cli.config)?;
                Self::run_health(&config, cli.insecure, *datapath).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_no_subcommand() {
        let cli = Cli::try_parse_from(["meridian"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.config, "config.hcl");
        assert!(!cli.insecure);
    }

    #[test]
    fn test_serve_subcommand() {
        let cli = Cli::try_parse_from(["meridian", "serve"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Serve)));
    }

    #[test]
    fn test_health_subcommand() {
        let cli = Cli::try_parse_from(["meridian", "health"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Health { datapath: false })
        ));
    }

    #[test]
    fn test_backend_list() {
        let cli = Cli::try_parse_from(["meridian", "backend", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Backend(BackendArgs {
                action: BackendAction::List
            }))
        ));
    }

    #[test]
    fn test_backend_add() {
        let cli = Cli::try_parse_from([
            "meridian",
            "backend",
            "add",
            "server1",
            "--hostname",
            "s1.example.com",
            "--tcp-addr",
            "10.0.0.1:443",
            "--udp-addr",
            "10.0.0.1:8443",
            "--instance-id",
            "1",
        ])
        .unwrap();

        if let Some(Command::Backend(BackendArgs {
            action: BackendAction::Add(args),
        })) = cli.command
        {
            assert_eq!(args.name, "server1");
            assert_eq!(args.hostname, "s1.example.com");
            assert_eq!(args.tcp_addr, "10.0.0.1:443");
            assert_eq!(args.udp_addr, "10.0.0.1:8443");
            assert_eq!(args.instance_id, 1);
        } else {
            panic!("expected backend add");
        }
    }

    #[test]
    fn test_backend_update() {
        let cli = Cli::try_parse_from([
            "meridian",
            "backend",
            "update",
            "server1",
            "--hostname",
            "s1.example.com",
            "--tcp-addr",
            "10.0.0.1:443",
            "--udp-addr",
            "10.0.0.1:8443",
            "--instance-id",
            "2",
        ])
        .unwrap();

        if let Some(Command::Backend(BackendArgs {
            action: BackendAction::Update(args),
        })) = cli.command
        {
            assert_eq!(args.name, "server1");
            assert_eq!(args.instance_id, 2);
        } else {
            panic!("expected backend update");
        }
    }

    #[test]
    fn test_backend_remove() {
        let cli = Cli::try_parse_from(["meridian", "backend", "remove", "server1"]).unwrap();

        if let Some(Command::Backend(BackendArgs {
            action: BackendAction::Remove(args),
        })) = cli.command
        {
            assert_eq!(args.name, "server1");
        } else {
            panic!("expected backend remove");
        }
    }

    #[test]
    fn test_global_config_flag() {
        let cli = Cli::try_parse_from([
            "meridian",
            "--config",
            "/etc/meridian/custom.hcl",
            "backend",
            "list",
        ])
        .unwrap();
        assert_eq!(cli.config, "/etc/meridian/custom.hcl");
    }

    #[test]
    fn test_insecure_flag() {
        let cli = Cli::try_parse_from(["meridian", "--insecure", "health"]).unwrap();
        assert!(cli.insecure);
    }

    #[test]
    fn test_backend_add_missing_required_args() {
        let result = Cli::try_parse_from(["meridian", "backend", "add", "server1"]);
        assert!(result.is_err());
    }

    #[test]
    fn wildcard_listen_addresses_resolve_to_loopback() {
        // A control plane bound to a wildcard is the ordinary production config, and
        // the wildcard is not a destination anyone can connect to.
        assert_eq!(
            CliRunner::api_base_url("0.0.0.0:9443"),
            "https://127.0.0.1:9443"
        );
        assert_eq!(CliRunner::api_base_url("[::]:9443"), "https://[::1]:9443");
    }

    #[test]
    fn concrete_listen_addresses_are_left_alone() {
        for listen in [
            "127.0.0.1:9443",
            "10.57.2.4:9443",
            "[::1]:9443",
            "meridian.example.com:9443",
        ] {
            assert_eq!(
                CliRunner::api_base_url(listen),
                format!("https://{listen}"),
                "a reachable address must be used as configured"
            );
        }
    }

    #[test]
    fn test_build_client_missing_api_block() {
        use std::collections::HashMap;
        let config = MeridianConfig {
            listen: "0.0.0.0:443".to_string(),
            cid_prefix_length: 2,
            workers: 1,
            api: None,
            gossip: None,
            backend: HashMap::new(),
            lease_ttl_secs: None,
        };
        let result = CliRunner::build_client_from_config(&config, false);
        let err = result.err().expect("should have failed");
        assert!(err.to_string().contains("no 'api' block"));
    }
}
