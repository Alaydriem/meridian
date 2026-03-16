use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "client", about = "Test client for Meridian proxy")]
struct Cli {
    /// Proxy address (host:port)
    #[arg(long, default_value = "127.0.0.1:4433")]
    proxy: String,

    /// SNI hostname to connect with (must match a registered backend)
    #[arg(long)]
    sni: String,

    /// Path to certs directory (needs ca.pem)
    #[arg(long, default_value = "certs")]
    certs_dir: PathBuf,

    /// Test HTTPS only (skip QUIC)
    #[arg(long)]
    https_only: bool,

    /// Test QUIC only (skip HTTPS)
    #[arg(long)]
    quic_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let ca_path = cli.certs_dir.join("ca.pem");

    if !ca_path.exists() {
        anyhow::bail!(
            "CA cert not found: {}. Run `cargo run --example gen_certs` first.",
            ca_path.display()
        );
    }

    let mut success = true;

    if !cli.quic_only {
        println!("=== HTTPS test (SNI: {}) ===", cli.sni);
        match test_https(&cli.proxy, &cli.sni, &ca_path).await {
            Ok(body) => println!("  OK: {body}"),
            Err(e) => {
                println!("  FAIL: {e}");
                success = false;
            }
        }
    }

    if !cli.https_only {
        println!("=== QUIC test (SNI: {}) ===", cli.sni);
        match test_quic(&cli.proxy, &cli.sni, &ca_path).await {
            Ok(response) => println!("  OK: {response}"),
            Err(e) => {
                println!("  FAIL: {e}");
                success = false;
            }
        }
    }

    if success {
        println!("\nAll tests passed!");
    } else {
        println!("\nSome tests failed!");
        std::process::exit(1);
    }

    Ok(())
}

async fn test_https(
    proxy_addr: &str,
    sni: &str,
    ca_path: &std::path::Path,
) -> Result<String> {
    let ca_pem = std::fs::read(ca_path)?;

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for cert in &ca_certs {
        root_store.add(cert.clone())?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;

    let tcp_stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    let request = format!("GET /health HTTP/1.1\r\nHost: {sni}\r\n\r\n");
    tls_stream.write_all(request.as_bytes()).await?;

    let mut response = vec![0u8; 4096];
    let n = tls_stream.read(&mut response).await?;
    let body = String::from_utf8_lossy(&response[..n]).to_string();

    if body.contains("backend_id") {
        Ok(body)
    } else {
        anyhow::bail!("unexpected response: {body}")
    }
}

async fn test_quic(
    proxy_addr: &str,
    sni: &str,
    ca_path: &std::path::Path,
) -> Result<String> {
    let tls = s2n_quic::provider::tls::rustls::Client::builder()
        .with_certificate(ca_path)
        .map_err(|e| anyhow::anyhow!("tls cert error: {e}"))?
        .build()
        .map_err(|e| anyhow::anyhow!("tls build error: {e}"))?;

    let client = s2n_quic::Client::builder()
        .with_tls(tls)
        .map_err(|e| anyhow::anyhow!("with_tls: {e}"))?
        .with_io("0.0.0.0:0")
        .map_err(|e| anyhow::anyhow!("with_io: {e}"))?
        .start()
        .map_err(|e| anyhow::anyhow!("client start: {e}"))?;

    let addr: std::net::SocketAddr = tokio::net::lookup_host(proxy_addr)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve {proxy_addr}"))?;
    let connect = s2n_quic::client::Connect::new(addr).with_server_name(sni);

    let mut conn = client
        .connect(connect)
        .await
        .map_err(|e| anyhow::anyhow!("QUIC connect failed: {e}"))?;

    let stream = conn.open_bidirectional_stream().await?;
    let (mut recv, mut send) = stream.split();

    // Send test message
    tokio::io::AsyncWriteExt::write_all(&mut send, b"hello from client").await?;
    send.close().await?;

    // Read response
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf).await?;

    let response = String::from_utf8_lossy(&buf).to_string();

    if response.is_empty() {
        anyhow::bail!("no response received from QUIC backend")
    } else {
        Ok(response)
    }
}
