//! A ClientHello larger than one TCP segment arrives in pieces. A router that reads
//! once and parses whatever showed up routes on a coin flip.

mod common;

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use meridian::MeridianBuilder;
use meridian::config::ConfigParser;
use meridian::tls::TlsAlert;

use common::{free_port, generate_test_certs};

const HOSTNAME: &str = "frag.example.com";

/// A genuine rustls ClientHello, inflated past one MSS with padded ALPN entries.
///
/// Generated rather than hand-built so it is a hello a real client would send: rustls
/// validates the message on the way in, and a synthetic one risks being rejected for
/// reasons unrelated to what is under test.
fn oversized_client_hello(sni: &str, ca_cert_pem: &str) -> Result<Vec<u8>> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut Cursor::new(ca_cert_pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()?
    {
        root_store.add(cert)?;
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = (0..25)
        .map(|i| format!("padding-protocol-{i:0>46}").into_bytes())
        .collect();

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let mut hello = Vec::new();
    conn.write_tls(&mut hello)?;

    assert!(
        hello.len() > 1460,
        "test needs a hello larger than one MSS, got {} bytes",
        hello.len()
    );
    Ok(hello)
}

/// A plain TCP backend that reports the first `expect` bytes it is handed.
async fn start_recording_backend(expect: usize) -> Result<(u16, mpsc::Receiver<Vec<u8>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let (tx, rx) = mpsc::channel(4);

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut got = vec![0u8; expect];
                if stream.read_exact(&mut got).await.is_ok() {
                    let _ = tx.send(got).await;
                }
            });
        }
    });

    Ok((port, rx))
}

async fn start_proxy(backend_port: u16, hostname: &str) -> Result<u16> {
    let proxy_port = free_port().await?;
    let hcl = format!(
        r#"
        listen = "127.0.0.1:{proxy_port}"
        backend "frag" {{
            hostname    = "{hostname}"
            tcp_addr    = "127.0.0.1:{backend_port}"
            udp_addr    = "127.0.0.1:{backend_port}"
            instance_id = 1
        }}
    "#
    );

    let config = ConfigParser::parse_config(&hcl)?;
    let meridian = MeridianBuilder::new(config).build().await?;
    tokio::spawn(async move {
        meridian.run(CancellationToken::new()).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(proxy_port)
}

/// Deliver `hello` in two writes with a gap, so the first read cannot see all of it.
async fn send_split(proxy_port: u16, hello: &[u8], split_at: usize) -> Result<TcpStream> {
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    client.set_nodelay(true)?;

    client.write_all(&hello[..split_at]).await?;
    client.flush().await?;
    tokio::time::sleep(Duration::from_millis(80)).await;
    client.write_all(&hello[split_at..]).await?;
    client.flush().await?;

    Ok(client)
}

/// The realistic case: a post-quantum-sized hello split at one MSS.
#[tokio::test]
async fn hello_split_at_one_mss_still_routes() -> Result<()> {
    let certs = generate_test_certs(HOSTNAME);
    let hello = oversized_client_hello(HOSTNAME, &certs.ca_cert_pem)?;

    let (backend_port, mut received) = start_recording_backend(hello.len()).await?;
    let proxy_port = start_proxy(backend_port, HOSTNAME).await?;

    let _client = send_split(proxy_port, &hello, 1460).await?;

    let got = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .map_err(|_| anyhow::anyhow!("backend never received the ClientHello"))?
        .expect("backend channel closed");

    assert_eq!(
        got, hello,
        "the backend must receive every byte of the hello, unmodified"
    );
    Ok(())
}

/// The first read returning less than a record header must not decide anything.
#[tokio::test]
async fn hello_split_before_the_record_header_still_routes() -> Result<()> {
    let certs = generate_test_certs(HOSTNAME);
    let hello = oversized_client_hello(HOSTNAME, &certs.ca_cert_pem)?;

    let (backend_port, mut received) = start_recording_backend(hello.len()).await?;
    let proxy_port = start_proxy(backend_port, HOSTNAME).await?;

    // Three bytes: not even a complete 5-byte TLS record header.
    let _client = send_split(proxy_port, &hello, 3).await?;

    let got = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .map_err(|_| anyhow::anyhow!("backend never received the ClientHello"))?
        .expect("backend channel closed");

    assert_eq!(got, hello);
    Ok(())
}

/// SNI is case-insensitive (RFC 6066), so the registered casing must not matter.
#[tokio::test]
async fn sni_routes_regardless_of_case() -> Result<()> {
    let certs = generate_test_certs(HOSTNAME);
    let hello = oversized_client_hello(HOSTNAME, &certs.ca_cert_pem)?;

    let (backend_port, mut received) = start_recording_backend(hello.len()).await?;
    // Registered in mixed case; the client sends lowercase.
    let proxy_port = start_proxy(backend_port, "Frag.Example.COM").await?;

    let _client = send_split(proxy_port, &hello, 1460).await?;

    let got = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .map_err(|_| anyhow::anyhow!("mixed-case registration did not route"))?
        .expect("backend channel closed");

    assert_eq!(got, hello);
    Ok(())
}

/// An unroutable SNI must be refused at the TLS layer, not by dropping the socket.
///
/// Dropping with the hello still unread sends RST, which a client reports as a reset
/// mid-handshake with nothing to distinguish it from a network fault.
#[tokio::test]
async fn unknown_sni_receives_a_tls_alert_not_a_reset() -> Result<()> {
    let certs = generate_test_certs(HOSTNAME);
    let hello = oversized_client_hello("stranger.example.com", &certs.ca_cert_pem)?;

    let (backend_port, _received) = start_recording_backend(hello.len()).await?;
    let proxy_port = start_proxy(backend_port, HOSTNAME).await?;

    let mut client = send_split(proxy_port, &hello, 1460).await?;

    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        client.read_to_end(&mut response),
    )
    .await
    .map_err(|_| anyhow::anyhow!("proxy neither answered nor closed"))??;

    assert_eq!(
        response,
        TlsAlert::UNRECOGNIZED_NAME.to_vec(),
        "an unroutable SNI must draw a fatal unrecognized_name alert"
    );
    Ok(())
}
