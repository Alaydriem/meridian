//! Fleet-mode end-to-end tests.
//!
//! These assert the property the ephemeral-socket work exists to produce: that a
//! client whose source address changes does **not** cause the backend to observe a
//! new remote address.
//!
//! Why that framing rather than driving a real QUIC client: a QUIC "path" is
//! identified by the peer's remote address — `s2n-quic-transport`'s
//! `Path::eq_by_handle` compares `remote_address()` and nothing else, and paths are
//! capped at 5 and never reclaimed. So "how many distinct source addresses does the
//! backend see for one connection" *is* the path count, measured directly. Counting
//! it at a plain UDP socket is deterministic, needs no handshake or TLS, and does
//! not depend on a client API that can rebind its local port mid-connection.
//!
//! `examples/backend.rs` carries a real `on_path_created` subscriber for validating
//! the same property against s2n-quic under load; this suite is the CI gate.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use meridian::config::MeridianConfig;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

mod common;

/// A stand-in backend that records every distinct source address it is contacted
/// from. That count is the number of QUIC paths a real backend would have
/// allocated.
struct SpyBackend {
    addr: SocketAddr,
    sources: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl SpyBackend {
    async fn spawn(shutdown: CancellationToken) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let addr = socket.local_addr()?;
        let sources: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));

        let seen = sources.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = socket.recv_from(&mut buf) => {
                        if let Ok((n, from)) = result {
                            seen.lock().await.insert(from);
                            // Echo so the proxy's return path is exercised too.
                            let _ = socket.send_to(&buf[..n], from).await;
                        }
                    }
                }
            }
        });

        Ok(Self { addr, sources })
    }

    async fn distinct_sources(&self) -> usize {
        self.sources.lock().await.len()
    }
}

/// Start Meridian in-process with one backend registered under `instance_id`.
async fn spawn_meridian(
    backend_addr: SocketAddr,
    instance_id: u16,
    workers: usize,
    shutdown: CancellationToken,
) -> Result<SocketAddr> {
    let port = common::free_port().await?;
    let listen = format!("127.0.0.1:{port}");

    let hcl = format!(
        r#"
        listen = "{listen}"
        cid_prefix_length = 2
        workers = {workers}

        backend "spy" {{
            hostname    = "spy.example.com"
            tcp_addr    = "{backend_addr}"
            udp_addr    = "{backend_addr}"
            instance_id = {instance_id}
        }}
        "#
    );

    let config: MeridianConfig = meridian::config::ConfigParser::parse_config(&hcl)?;
    let instance = meridian::MeridianBuilder::new(config).build().await?;

    tokio::spawn(async move {
        if let Err(e) = instance.run(shutdown).await {
            eprintln!("meridian exited: {e}");
        }
    });

    let listen_addr: SocketAddr = listen.parse()?;
    // The UDP datapath has no accept() to poll, so give the workers a moment to
    // bind before sending.
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(listen_addr)
}

/// A short-header QUIC packet carrying `instance_id` in the first two CID bytes,
/// with a full 16-byte CID so the router's length guard accepts it.
fn short_header(instance_id: u16, cid_tail: u8) -> Vec<u8> {
    let mut d = vec![0x40];
    d.extend_from_slice(&instance_id.to_be_bytes());
    d.extend_from_slice(&[cid_tail; 14]);
    d.extend_from_slice(&[0x01, 0x02, 0x03]);
    d
}

/// A client whose source address changes but whose Connection ID does not — a NAT
/// rebind, or an OS interface swap the client never noticed. The proxy must reuse
/// its existing backend-facing socket, otherwise the backend allocates a second
/// QUIC path and the client is one step closer to the hard limit of five.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rebind_does_not_consume_a_backend_path() -> Result<()> {
    let shutdown = CancellationToken::new();
    let backend = SpyBackend::spawn(shutdown.clone()).await?;
    let proxy = spawn_meridian(backend.addr, 7, 3, shutdown.clone()).await?;

    let packet = short_header(7, 0xAB);

    // First contact, from one source address.
    let client_a = UdpSocket::bind("127.0.0.1:0").await?;
    client_a.send_to(&packet, proxy).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        backend.distinct_sources().await,
        1,
        "first contact should establish exactly one backend-facing socket"
    );

    // Rebind: a different source address, the same Connection ID.
    let client_b = UdpSocket::bind("127.0.0.1:0").await?;
    client_b.send_to(&packet, proxy).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let observed = backend.distinct_sources().await;
    shutdown.cancel();

    assert_eq!(
        observed, 1,
        "a rebound client must reuse the proxy's existing backend-facing socket; \
         {observed} distinct sources means {observed} QUIC paths spent of a budget of 5"
    );

    Ok(())
}

/// With `SO_REUSEPORT` the kernel rehashes a client to a different worker when its
/// source address changes — which is exactly when the rebind fix needs to apply. So
/// the socket index has to be shared across workers, not per-worker: otherwise the
/// fix only helps when the rehash happens to land on the same worker.
///
/// Several rebinds so at least one lands elsewhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_rebinds_cost_no_path_at_three_workers() -> Result<()> {
    let shutdown = CancellationToken::new();
    let backend = SpyBackend::spawn(shutdown.clone()).await?;
    let proxy = spawn_meridian(backend.addr, 7, 3, shutdown.clone()).await?;

    let packet = short_header(7, 0xCD);
    let mut clients = Vec::new();

    for _ in 0..8 {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.send_to(&packet, proxy).await?;
        // Hold the socket so the OS cannot reissue its port to a later client.
        clients.push(client);
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    let observed = backend.distinct_sources().await;
    shutdown.cancel();

    assert_eq!(
        observed, 1,
        "shared socket state must make worker rehashing free; {observed} distinct \
         sources means {observed} QUIC paths spent of a budget of 5"
    );

    Ok(())
}

/// Distinct connections must not share a socket — the reuse above must be keyed on
/// the Connection ID, not applied blindly to everything reaching one backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distinct_connections_get_distinct_sockets() -> Result<()> {
    let shutdown = CancellationToken::new();
    let backend = SpyBackend::spawn(shutdown.clone()).await?;
    let proxy = spawn_meridian(backend.addr, 7, 3, shutdown.clone()).await?;

    // Same backend, different Connection IDs, different clients.
    let client_a = UdpSocket::bind("127.0.0.1:0").await?;
    client_a.send_to(&short_header(7, 0x11), proxy).await?;

    let client_b = UdpSocket::bind("127.0.0.1:0").await?;
    client_b.send_to(&short_header(7, 0x22), proxy).await?;

    tokio::time::sleep(Duration::from_millis(400)).await;

    let observed = backend.distinct_sources().await;
    shutdown.cancel();

    assert_eq!(
        observed, 2,
        "two independent connections must not be collapsed onto one socket"
    );

    Ok(())
}
