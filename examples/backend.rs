use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use dashmap::DashMap;
use s2n_quic::connection::Handle;
use s2n_quic::provider::connection_id;
use s2n_quic::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
#[command(name = "backend", about = "Test backend for Meridian proxy")]
struct Cli {
    /// Backend instance ID (1-65535). Used as CID prefix for QUIC routing.
    #[arg(long)]
    id: u16,

    /// TCP port to listen on for HTTPS
    #[arg(long, default_value = "0")]
    tcp_port: u16,

    /// UDP port to listen on for QUIC
    #[arg(long, default_value = "0")]
    udp_port: u16,

    /// Meridian control plane API address (e.g. https://127.0.0.1:9443)
    #[arg(long)]
    api: Option<String>,

    /// API key for Meridian control plane
    #[arg(long, default_value = "test-api-key")]
    api_key: String,

    /// Path to certs directory
    #[arg(long, default_value = "certs")]
    certs_dir: PathBuf,

    /// Advertised address for registration (default: 127.0.0.1).
    /// In Docker, set to the container's hostname or IP so Meridian can route to it.
    #[arg(long, default_value = "127.0.0.1")]
    advertise_addr: String,

    /// Bind address for listeners (default: 127.0.0.1).
    /// In Docker, set to 0.0.0.0 to accept connections from the container network.
    #[arg(long, default_value = "127.0.0.1")]
    bind_addr: String,
}

// Custom ConnectionId format with 2-byte instance_id prefix
struct PrefixedConnectionIdFormat {
    instance_id: u16,
    counter: u64,
}

impl PrefixedConnectionIdFormat {
    fn new(instance_id: u16) -> Self {
        Self {
            instance_id,
            counter: 0,
        }
    }
}

impl connection_id::Generator for PrefixedConnectionIdFormat {
    fn generate(&mut self, _conn_info: &connection_id::ConnectionInfo) -> connection_id::LocalId {
        let prefix = self.instance_id.to_be_bytes();
        let mut id = [0u8; 16];
        id[0] = prefix[0];
        id[1] = prefix[1];
        // Fill remaining bytes with counter-based pseudo-random
        self.counter += 1;
        let counter_bytes = self.counter.to_be_bytes();
        id[2..10].copy_from_slice(&counter_bytes);
        let time_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let time_bytes = time_nanos.to_be_bytes();
        id[8..16].copy_from_slice(&time_bytes);
        connection_id::LocalId::try_from_bytes(&id[..]).unwrap()
    }
}

impl connection_id::Validator for PrefixedConnectionIdFormat {
    fn validate(
        &self,
        _conn_info: &connection_id::ConnectionInfo,
        _packet: &[u8],
    ) -> Option<usize> {
        Some(16)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let hostname = format!("server-{}.localhost", cli.id);
    let cert_path = cli.certs_dir.join(format!("server-{}-cert.pem", cli.id));
    let key_path = cli.certs_dir.join(format!("server-{}-key.pem", cli.id));
    let ca_path = cli.certs_dir.join("ca.pem");

    if !cert_path.exists() {
        anyhow::bail!(
            "cert not found: {}. Run `cargo run --example gen_certs` first.",
            cert_path.display()
        );
    }

    // Start HTTPS server
    let tcp_listener = TcpListener::bind(format!("{}:{}", cli.bind_addr, cli.tcp_port)).await?;
    let tcp_port = tcp_listener.local_addr()?.port();

    // Start QUIC server
    let quic_bind = format!("{}:{}", cli.bind_addr, cli.udp_port);
    let tls = s2n_quic::provider::tls::rustls::Server::builder()
        .with_certificate(cert_path.as_path(), key_path.as_path())
        .map_err(|e| anyhow::anyhow!("tls cert error: {e}"))?
        .with_application_protocols(["h3"].iter())
        .map_err(|e| anyhow::anyhow!("alpn error: {e}"))?
        .build()
        .map_err(|e| anyhow::anyhow!("tls build error: {e}"))?;

    let cid_format = PrefixedConnectionIdFormat::new(cli.id);

    let datagram_endpoint = s2n_quic::provider::datagram::default::Endpoint::builder()
        .with_recv_capacity(200)
        .unwrap()
        .with_send_capacity(200)
        .unwrap()
        .build()
        .unwrap();

    let mut quic_server = Server::builder()
        .with_tls(tls)
        .map_err(|e| anyhow::anyhow!("with_tls error: {e}"))?
        .with_io(quic_bind.as_str())
        .map_err(|e| anyhow::anyhow!("with_io error: {e}"))?
        .with_connection_id(cid_format)
        .map_err(|e| anyhow::anyhow!("with_connection_id error: {e}"))?
        .with_datagram(datagram_endpoint)
        .map_err(|e| anyhow::anyhow!("with_datagram error: {e}"))?
        .start()
        .map_err(|e| anyhow::anyhow!("quic server start error: {e}"))?;

    let udp_port = quic_server
        .local_addr()
        .map_err(|e| anyhow::anyhow!("local_addr error: {e}"))?
        .port();

    println!("backend {hostname} (id={}) listening:", cli.id);
    println!("  HTTPS: {}:{tcp_port}", cli.bind_addr);
    println!("  QUIC:  {}:{udp_port}", cli.bind_addr);

    // Self-register with Meridian control plane
    if let Some(api_addr) = &cli.api {
        register_with_api(
            api_addr,
            &cli.api_key,
            &ca_path,
            &hostname,
            cli.id,
            &cli.advertise_addr,
            tcp_port,
            udp_port,
        )
        .await?;
    }

    let instance_id = cli.id;

    // Spawn HTTPS handler
    let https_handle = {
        let acceptor = build_tls_acceptor(&cert_path, &key_path, &ca_path)?;

        tokio::spawn(async move {
            loop {
                let (stream, peer) = tcp_listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(mut tls_stream) => {
                            let mut buf = vec![0u8; 4096];
                            let _ = tls_stream.read(&mut buf).await;
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"backend_id\":{instance_id}}}"
                            );
                            let _ = tls_stream.write_all(response.as_bytes()).await;
                            let _ = tls_stream.shutdown().await;
                            tracing::info!(%peer, "https request served");
                        }
                        Err(e) => {
                            tracing::warn!(%peer, error = %e, "tls accept failed");
                        }
                    }
                });
            }
        })
    };

    // Shared registry of all connected QUIC clients for datagram fan-out
    let connections: Arc<DashMap<u64, Handle>> = Arc::new(DashMap::new());
    let next_conn_id = Arc::new(AtomicU64::new(0));

    // QUIC handler
    let quic_handle = tokio::spawn(async move {
        while let Some(mut conn) = quic_server.accept().await {
            let peer_addr = conn
                .remote_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
            tracing::info!(peer = %peer_addr, conn_id, "quic connection accepted");

            let (conn_handle, acceptor) = conn.split();

            // Register this connection for fan-out
            connections.insert(conn_id, conn_handle.clone());

            // Spawn datagram fan-out task: recv from this client, send to all others
            let dg_handle = {
                let handle = conn_handle.clone();
                let conns = connections.clone();
                tokio::spawn(async move {
                    use s2n_quic::provider::datagram::default::{Sender, Receiver};
                    let id_bytes = instance_id.to_be_bytes();
                    loop {
                        let datagram = handle.datagram_mut(|recv: &mut Receiver| {
                            recv.recv_datagram()
                        });

                        match datagram {
                            Ok(Some(data)) => {
                                // Build the fan-out payload: [2-byte id][original data]
                                let mut payload = Vec::with_capacity(2 + data.len());
                                payload.extend_from_slice(&id_bytes);
                                payload.extend_from_slice(&data);
                                let payload = bytes::Bytes::from(payload);

                                // Fan out to all OTHER connected clients
                                for entry in conns.iter() {
                                    if *entry.key() != conn_id {
                                        let _ = entry.value().datagram_mut(|sender: &mut Sender| {
                                            sender.send_datagram_forced(payload.clone())
                                        });
                                    }
                                }
                            }
                            Ok(None) => {
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            }
                            Err(_) => break,
                        }
                    }
                    // Unregister on disconnect
                    conns.remove(&conn_id);
                })
            };

            // Spawn stream handler task
            let (mut bidi, _recv_only) = acceptor.split();
            tokio::spawn(async move {
                loop {
                    match bidi.accept_bidirectional_stream().await {
                        Ok(Some(stream)) => {
                            let peer = peer_addr.clone();
                            tokio::spawn(async move {
                                let (mut recv, mut send) = stream.split();
                                let mut header = [0u8; 4];

                                match tokio::io::AsyncReadExt::read_exact(&mut recv, &mut header).await {
                                    Ok(_) => {
                                        let len = u32::from_be_bytes(header) as usize;
                                        if len > 0 && len <= 65535 {
                                            if let Err(e) = handle_framed_stream(
                                                &mut recv, &mut send, instance_id, len, &header,
                                            ).await {
                                                tracing::debug!(%peer, error = %e, "framed stream ended");
                                            }
                                        } else {
                                            let mut buf = vec![0u8; 4096];
                                            buf[..4].copy_from_slice(&header);
                                            let n = match tokio::io::AsyncReadExt::read(&mut recv, &mut buf[4..]).await {
                                                Ok(n) => 4 + n,
                                                Err(_) => 4,
                                            };
                                            let received = String::from_utf8_lossy(&buf[..n]);
                                            let response = format!("{instance_id}:{received}");
                                            let _ = tokio::io::AsyncWriteExt::write_all(&mut send, response.as_bytes()).await;
                                            let _ = send.close().await;
                                        }
                                    }
                                    Err(_) => {}
                                }
                            });
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::warn!(error = %e, "accept stream error");
                            break;
                        }
                    }
                }
                dg_handle.abort();
            });
        }
    });

    #[allow(clippy::manual_async_fn)]
    async fn handle_framed_stream(
        recv: &mut (impl tokio::io::AsyncRead + Unpin),
        send: &mut (impl tokio::io::AsyncWrite + Unpin),
        instance_id: u16,
        first_len: usize,
        first_header: &[u8; 4],
    ) -> anyhow::Result<()> {
        let id_bytes = instance_id.to_be_bytes();
        let mut len = first_len;
        let mut is_first = true;

        loop {
            // Read payload
            let mut payload = vec![0u8; len];
            tokio::io::AsyncReadExt::read_exact(recv, &mut payload).await?;

            // Echo back: [4-byte len (payload + 2 id bytes)][id][payload]
            let resp_len = (2 + payload.len()) as u32;
            tokio::io::AsyncWriteExt::write_all(send, &resp_len.to_be_bytes()).await?;
            tokio::io::AsyncWriteExt::write_all(send, &id_bytes).await?;
            tokio::io::AsyncWriteExt::write_all(send, &payload).await?;

            // Read next frame header
            let mut header = [0u8; 4];
            match tokio::io::AsyncReadExt::read_exact(recv, &mut header).await {
                Ok(_) => {
                    len = u32::from_be_bytes(header) as usize;
                    if len == 0 || len > 65535 {
                        break;
                    }
                }
                Err(_) => break, // Stream closed
            }

            let _ = is_first;
            is_first = false;
        }

        Ok(())
    }

    tokio::select! {
        _ = https_handle => {},
        _ = quic_handle => {},
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down backend {hostname}");
        }
    }

    Ok(())
}

fn build_tls_acceptor(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<TlsAcceptor> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    let ca_pem = std::fs::read(ca_path)?;

    let server_certs = rustls_pemfile::certs(&mut Cursor::new(&cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let server_key =
        rustls_pemfile::private_key(&mut Cursor::new(&key_pem))?.expect("no private key");

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut Cursor::new(&ca_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for cert in &ca_certs {
        root_store.add(cert.clone())?;
    }

    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .allow_unauthenticated()
        .build()
        .unwrap();

    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

async fn register_with_api(
    api_addr: &str,
    api_key: &str,
    ca_path: &Path,
    hostname: &str,
    instance_id: u16,
    advertise_addr: &str,
    tcp_port: u16,
    udp_port: u16,
) -> Result<()> {
    let client = meridian::api::MeridianClient::builder(api_addr, api_key)
        .with_ca_cert_file(ca_path)?
        .danger_accept_invalid_certs(true)
        .build()?;

    // Resolve advertise_addr to an IP if it's a hostname (Docker container names)
    let resolved_addr = tokio::net::lookup_host(format!("{advertise_addr}:{tcp_port}"))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve {advertise_addr}"))?;
    let ip = resolved_addr.ip();

    let name = format!("server-{instance_id}");
    let resp = client
        .register(
            &name,
            hostname,
            format!("{ip}:{tcp_port}"),
            format!("{ip}:{udp_port}"),
            instance_id,
        )
        .await?;

    println!("registered with control plane as {} ({})", resp.name, resp.hostname);
    Ok(())
}
