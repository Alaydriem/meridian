use anyhow::Result;
use clap::Parser;

mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Cli::parse();
    cli::CliRunner::run(args).await
}
