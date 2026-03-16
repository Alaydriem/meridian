use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;

use meridian::config::parse_config_file;
use meridian::MeridianBuilder;

#[derive(Parser)]
#[command(name = "meridian", about = "QUIC-aware SNI proxy")]
struct Cli {
    /// Path to HCL config file
    #[arg(short, long, default_value = "config.hcl")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let config = parse_config_file(&cli.config)?;
    let meridian = MeridianBuilder::new(config).build()?;

    let shutdown = CancellationToken::new();
    let token = shutdown.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("received ctrl-c, shutting down");
        token.cancel();
    });

    meridian.run(shutdown).await
}
