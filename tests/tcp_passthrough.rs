mod common;

use std::io::Cursor;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use meridian::config::ConfigParser;
use meridian::MeridianBuilder;

use common::{free_port, generate_test_certs};

/// Start a simple TLS echo server that sends back a fixed response.
async fn start_tls_backend(
    certs: &common::TestCerts,
    backend_name: &str,
) -> Result<(u16, CancellationToken)> {
    let server_certs = rustls_pemfile::certs(&mut Cursor::new(&certs.server_cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let server_key = rustls_pemfile::private_key(&mut Cursor::new(&certs.server_key_pem))?
        .expect("no private key");

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut Cursor::new(&certs.ca_cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for cert in &ca_certs {
        root_store.add(cert.clone())?;
    }

    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .unwrap();

    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let name = backend_name.to_string();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                result = listener.accept() => {
                    let (stream, _) = result.unwrap();
                    let acceptor = acceptor.clone();
                    let name = name.clone();
                    tokio::spawn(async move {
                        let mut tls_stream = acceptor.accept(stream).await.unwrap();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"status\":\"ok\",\"backend\":\"{name}\"}}"
                        );
                        // Read the request first
                        let mut buf = vec![0u8; 4096];
                        let _ = tls_stream.read(&mut buf).await;
                        tls_stream.write_all(response.as_bytes()).await.unwrap();
                        tls_stream.shutdown().await.ok();
                    });
                }
            }
        }
    });

    Ok((port, shutdown))
}

#[tokio::test]
async fn test_tcp_passthrough_routes_by_sni() -> Result<()> {
    let hostname = "test-tcp.example.com";
    let certs = generate_test_certs(hostname);

    let (backend_port, backend_shutdown) = start_tls_backend(&certs, "test-backend").await?;
    let backend_addr = format!("127.0.0.1:{backend_port}");

    let proxy_port = free_port().await?;
    let hcl = format!(
        r#"
        listen = "127.0.0.1:{proxy_port}"
        backend "test" {{
            hostname    = "{hostname}"
            tcp_addr    = "{backend_addr}"
            udp_addr    = "{backend_addr}"
            instance_id = 1
        }}
    "#
    );

    let config = ConfigParser::parse_config(&hcl)?;
    let meridian = MeridianBuilder::new(config).build().await?;
    let proxy_shutdown = CancellationToken::new();
    let proxy_token = proxy_shutdown.clone();

    tokio::spawn(async move {
        if let Err(e) = meridian.run(proxy_token).await {
            eprintln!("meridian run error: {e:?}");
        }
    });

    // Wait for proxy to accept connections (up to 5s)
    common::wait_for_server(
        &format!("127.0.0.1:{proxy_port}"),
        std::time::Duration::from_secs(5),
    )
    .await?;

    // Connect through proxy with TLS client
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut Cursor::new(&certs.ca_cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for cert in &ca_certs {
        root_store.add(cert.clone())?;
    }

    let client_certs = rustls_pemfile::certs(&mut Cursor::new(&certs.client_cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let client_key = rustls_pemfile::private_key(&mut Cursor::new(&certs.client_key_pem))?
        .expect("no private key");

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())?;

    let tcp_stream =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Send HTTP request
    tls_stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: test-tcp.example.com\r\n\r\n")
        .await?;

    let mut response = vec![0u8; 4096];
    let n = tls_stream.read(&mut response).await?;
    let body = String::from_utf8_lossy(&response[..n]);

    assert!(body.contains("\"status\":\"ok\""));
    assert!(body.contains("\"backend\":\"test-backend\""));

    // Cleanup
    proxy_shutdown.cancel();
    backend_shutdown.cancel();

    Ok(())
}

#[tokio::test]
async fn test_tcp_unknown_sni_rejected() -> Result<()> {
    let hostname = "known.example.com";
    let certs = generate_test_certs(hostname);

    let (backend_port, backend_shutdown) = start_tls_backend(&certs, "known-backend").await?;

    let proxy_port = free_port().await?;
    let hcl = format!(
        r#"
        listen = "127.0.0.1:{proxy_port}"
        backend "known" {{
            hostname    = "{hostname}"
            tcp_addr    = "127.0.0.1:{backend_port}"
            udp_addr    = "127.0.0.1:{backend_port}"
            instance_id = 1
        }}
    "#
    );

    let config = ConfigParser::parse_config(&hcl)?;
    let meridian = MeridianBuilder::new(config).build().await?;
    let proxy_shutdown = CancellationToken::new();
    let proxy_token = proxy_shutdown.clone();

    tokio::spawn(async move {
        meridian.run(proxy_token).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Connect with an unknown SNI — should fail
    let unknown_certs = generate_test_certs("unknown.example.com");
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut Cursor::new(&unknown_certs.ca_cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for cert in &ca_certs {
        root_store.add(cert.clone())?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("unknown.example.com".to_string())?;

    let tcp_stream =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await?;

    // The TLS handshake should fail because Meridian will close the connection
    let result = connector.connect(server_name, tcp_stream).await;
    assert!(result.is_err());

    proxy_shutdown.cancel();
    backend_shutdown.cancel();

    Ok(())
}
