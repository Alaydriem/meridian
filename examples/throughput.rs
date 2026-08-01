use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(
    name = "throughput",
    about = "High-throughput QUIC test for Meridian proxy"
)]
struct Cli {
    /// Proxy address
    #[arg(long, default_value = "127.0.0.1:4433")]
    proxy: String,

    /// SNI hostnames (comma-separated, one connection per hostname)
    #[arg(long, default_value = "server-1.localhost,server-2.localhost")]
    sni: String,

    /// Messages per second per client
    #[arg(long, default_value = "500")]
    rate: u64,

    /// Test duration in seconds
    #[arg(long, default_value = "5")]
    duration: u64,

    /// Message size in bytes (simulated audio frame)
    #[arg(long, default_value = "160")]
    frame_size: usize,

    /// Path to certs directory
    #[arg(long, default_value = "certs")]
    certs_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let ca_path = cli.certs_dir.join("ca.pem");

    if !ca_path.exists() {
        anyhow::bail!("CA cert not found. Run `cargo run --example gen_certs` first.");
    }

    let hostnames: Vec<&str> = cli.sni.split(',').collect();
    let total_sent = Arc::new(AtomicU64::new(0));
    let total_recv = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));
    let total_latency_us = Arc::new(AtomicU64::new(0));

    println!(
        "throughput test: {} client(s), {} msg/s each, {}B frames, {}s duration",
        hostnames.len(),
        cli.rate,
        cli.frame_size,
        cli.duration,
    );

    let start = Instant::now();
    let test_duration = Duration::from_secs(cli.duration);
    let interval = Duration::from_micros(1_000_000 / cli.rate);

    let api_sent = Arc::new(AtomicU64::new(0));
    let api_ok = Arc::new(AtomicU64::new(0));
    let api_err = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();

    for (idx, hostname) in hostnames.iter().enumerate() {
        let quic_ca = ca_path.clone();
        let https_ca = ca_path.clone();

        let proxy = cli.proxy.clone();
        let sni = hostname.to_string();
        let frame_size = cli.frame_size;
        let sent = total_sent.clone();
        let recv = total_recv.clone();
        let errors = total_errors.clone();
        let latency = total_latency_us.clone();

        handles.push(tokio::spawn(async move {
            // Stagger connection attempts to avoid handshake burst
            tokio::time::sleep(Duration::from_millis(idx as u64 * 100)).await;
            if let Err(e) = run_client(
                idx,
                &proxy,
                &sni,
                &quic_ca,
                frame_size,
                test_duration,
                interval,
                sent,
                recv,
                errors,
                latency,
            )
            .await
            {
                eprintln!("client {idx} ({sni}) error: {e}");
            }
        }));

        // HTTPS client alongside each QUIC client — ~4 requests/sec
        let proxy = cli.proxy.clone();
        let sni = hostname.to_string();
        let a_sent = api_sent.clone();
        let a_ok = api_ok.clone();
        let a_err = api_err.clone();

        handles.push(tokio::spawn(async move {
            run_https_load(
                idx,
                &proxy,
                &sni,
                &https_ca,
                test_duration,
                &a_sent,
                &a_ok,
                &a_err,
            )
            .await;
        }));
    }

    for h in handles {
        h.await?;
    }

    let elapsed = start.elapsed();
    let sent = total_sent.load(Ordering::Relaxed);
    let received = total_recv.load(Ordering::Relaxed);
    let errs = total_errors.load(Ordering::Relaxed);
    let total_lat = total_latency_us.load(Ordering::Relaxed);
    let avg_lat_us = if received > 0 {
        total_lat / received
    } else {
        0
    };
    let h_sent = api_sent.load(Ordering::Relaxed);
    let h_ok = api_ok.load(Ordering::Relaxed);
    let h_err = api_err.load(Ordering::Relaxed);

    println!("\n=== QUIC Results ===");
    println!("duration:      {:.2}s", elapsed.as_secs_f64());
    println!("clients:       {}", hostnames.len());
    println!("sent:          {sent}");
    println!("received:      {received}");
    println!("errors:        {errs}");
    println!(
        "loss:          {:.2}%",
        if sent > 0 {
            (1.0 - received as f64 / sent as f64) * 100.0
        } else {
            0.0
        }
    );
    println!("avg latency:   {avg_lat_us}µs");
    println!(
        "throughput:    {:.0} msg/s (total)",
        received as f64 / elapsed.as_secs_f64()
    );

    println!("\n=== HTTPS Results ===");
    println!("sent:          {h_sent}");
    println!("ok:            {h_ok}");
    println!("errors:        {h_err}");
    println!(
        "throughput:    {:.1} req/s",
        h_ok as f64 / elapsed.as_secs_f64()
    );

    let quic_ok = errs == 0 && sent > 0 && (received as f64 / sent as f64) >= 0.95;
    let https_ok = h_err == 0 && h_ok > 0;

    if quic_ok && https_ok {
        println!("\nPASSED");
    } else {
        println!("\nFAILED");
        if !quic_ok {
            println!("  QUIC: unacceptable loss or errors");
        }
        if !https_ok {
            println!("  HTTPS: errors detected");
        }
        std::process::exit(1);
    }

    Ok(())
}

async fn run_client(
    idx: usize,
    proxy_addr: &str,
    sni: &str,
    ca_path: &std::path::Path,
    frame_size: usize,
    duration: Duration,
    interval: Duration,
    sent: Arc<AtomicU64>,
    recv: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    latency_us: Arc<AtomicU64>,
) -> Result<()> {
    use s2n_quic::provider::datagram::default::{Receiver, Sender};

    let tls = s2n_quic::provider::tls::rustls::Client::builder()
        .with_certificate(ca_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let datagram_endpoint = s2n_quic::provider::datagram::default::Endpoint::builder()
        .with_recv_capacity(200)
        .unwrap()
        .with_send_capacity(200)
        .unwrap()
        .build()
        .unwrap();

    let client = s2n_quic::Client::builder()
        .with_tls(tls)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .with_io("0.0.0.0:0")
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .with_datagram(datagram_endpoint)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .start()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let addr: std::net::SocketAddr = tokio::net::lookup_host(proxy_addr)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve {proxy_addr}"))?;
    let connect = s2n_quic::client::Connect::new(addr).with_server_name(sni);

    let conn = client
        .connect(connect)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;

    let (handle, _acceptor) = conn.split();
    println!("client {idx} ({sni}) connected");

    // Spawn a reader task that polls for received datagrams
    let recv_clone = recv.clone();
    let latency_clone = latency_us.clone();
    let read_handle = handle.clone();
    let reader = tokio::spawn(async move {
        loop {
            let datagram = read_handle.datagram_mut(|recv: &mut Receiver| recv.recv_datagram());

            match datagram {
                Ok(Some(data)) => {
                    // Response: [2-byte id][8-byte seq][8-byte timestamp][padding]
                    if data.len() >= 2 + 16 {
                        let ts_bytes: [u8; 8] = data[2 + 8..2 + 16].try_into().unwrap_or([0; 8]);
                        let send_time_us = u64::from_be_bytes(ts_bytes);
                        let now_us = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_micros() as u64;
                        if now_us > send_time_us {
                            latency_clone.fetch_add(now_us - send_time_us, Ordering::Relaxed);
                        }
                    }
                    recv_clone.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(_) => break,
            }
        }
    });

    // Writer: fire-and-forget datagrams at target rate
    let start = Instant::now();
    let mut seq: u64 = 0;
    let mut next_send = Instant::now();

    while start.elapsed() < duration {
        // Build datagram: [8-byte seq][8-byte timestamp][padding]
        let mut frame = vec![0u8; frame_size.max(16)];
        frame[..8].copy_from_slice(&seq.to_be_bytes());
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        frame[8..16].copy_from_slice(&now_us.to_be_bytes());

        // Send datagram (fire-and-forget, drop oldest if queue full)
        match handle.datagram_mut(|sender: &mut Sender| {
            sender.send_datagram_forced(bytes::Bytes::from(frame))
        }) {
            Ok(Ok(_)) => {
                sent.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        seq += 1;

        // Pace to target rate
        next_send += interval;
        let now = Instant::now();
        if next_send > now {
            tokio::time::sleep(next_send - now).await;
        }
    }

    // Wait briefly for remaining responses
    tokio::time::sleep(Duration::from_secs(1)).await;
    reader.abort();

    println!("client {idx} ({sni}) finished: {seq} datagrams sent");
    Ok(())
}

async fn run_https_load(
    idx: usize,
    proxy_addr: &str,
    sni: &str,
    ca_path: &std::path::Path,
    duration: Duration,
    sent: &AtomicU64,
    ok: &AtomicU64,
    errors: &AtomicU64,
) {
    let ca_pem = match std::fs::read(ca_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("https {idx}: can't read CA: {e}");
            return;
        }
    };

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs: Vec<_> = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_pem))
        .filter_map(|c| c.ok())
        .collect();
    for cert in &ca_certs {
        let _ = root_store.add(cert.clone());
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let interval = Duration::from_millis(250); // ~4 req/sec

    let start = Instant::now();
    while start.elapsed() < duration {
        sent.fetch_add(1, Ordering::Relaxed);

        let server_name = match rustls::pki_types::ServerName::try_from(sni.to_string()) {
            Ok(n) => n,
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };

        match tokio::net::TcpStream::connect(proxy_addr).await {
            Ok(tcp) => match connector.connect(server_name, tcp).await {
                Ok(mut tls) => {
                    let req = format!("GET /health HTTP/1.1\r\nHost: {sni}\r\n\r\n");
                    if tls.write_all(req.as_bytes()).await.is_ok() {
                        let mut buf = vec![0u8; 4096];
                        if let Ok(n) = tls.read(&mut buf).await {
                            if n > 0 && String::from_utf8_lossy(&buf[..n]).contains("backend_id") {
                                ok.fetch_add(1, Ordering::Relaxed);
                            } else {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            },
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        tokio::time::sleep(interval).await;
    }
}
