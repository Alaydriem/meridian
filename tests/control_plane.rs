mod common;

use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use meridian::api::ControlPlane;
use meridian::config::{ApiConfig, TlsConfig};
use meridian::routing::{Backend, RoutingTable};

use common::generate_test_certs;

fn setup_control_plane(certs: &common::TestCerts) -> Result<(u16, String, String, String)> {
    // Write certs to a unique temp dir per invocation
    let temp_dir = std::env::temp_dir().join(format!(
        "meridian-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir)?;

    let cert_path = temp_dir.join("api-cert.pem");
    let key_path = temp_dir.join("api-key.pem");

    std::fs::write(&cert_path, &certs.server_cert_pem)?;
    std::fs::write(&key_path, &certs.server_key_pem)?;

    Ok((
        0, // will use free port
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
        temp_dir.to_string_lossy().into_owned(),
    ))
}

async fn start_control_plane(
    api_key: &str,
    routing_table: Arc<RoutingTable>,
    certs: &common::TestCerts,
) -> Result<(u16, CancellationToken, String)> {
    let (_, cert_path, key_path, temp_dir) = setup_control_plane(certs)?;

    let port = common::free_port().await?;

    let config = ApiConfig {
        listen: format!("127.0.0.1:{port}"),
        api_key: api_key.to_string(),
        tls: TlsConfig {
            certificate: cert_path,
            key: key_path,
        },
    };

    let control_plane = ControlPlane::new(config, routing_table);
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();

    tokio::spawn(async move {
        if let Err(e) = control_plane.run(token).await {
            tracing::error!(error = %e, "control plane failed");
        }
    });

    // Wait for server to accept connections (up to 5s)
    common::wait_for_server(
        &format!("127.0.0.1:{port}"),
        std::time::Duration::from_secs(5),
    )
    .await
    .map_err(|e| anyhow::anyhow!("control plane did not start in time: {e}"))?;

    Ok((port, shutdown, temp_dir))
}

fn build_client(ca_cert_pem: &str) -> Result<reqwest::Client> {
    let ca_cert = reqwest::tls::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .danger_accept_invalid_certs(true) // self-signed certs
        .build()?;
    Ok(client)
}

#[tokio::test]
async fn test_list_backends() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";

    let table = RoutingTable::new();
    table.add_backend(
        "server1".to_string(),
        Backend::new(
            "server1.example.com".to_string(),
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:20001".parse().unwrap(),
            1,
        ),
    );

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    let resp = client
        .get(format!("https://127.0.0.1:{port}/backends"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await?;

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await?;
    let backends = body["backends"].as_array().unwrap();
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0]["name"], "server1");
    assert_eq!(backends[0]["hostname"], "server1.example.com");

    shutdown.cancel();
    Ok(())
}

#[tokio::test]
async fn test_create_and_list_backend() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";
    let table = RoutingTable::new();

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    // Create a backend
    let create_body = serde_json::json!({
        "name": "server3",
        "hostname": "server3.example.com",
        "tcp_addr": "127.0.0.1:10003",
        "udp_addr": "127.0.0.1:20003",
        "instance_id": 3
    });

    let resp = client
        .post(format!("https://127.0.0.1:{port}/backends"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&create_body)
        .send()
        .await?;

    assert_eq!(resp.status(), 201);

    // List and verify it appears
    let resp = client
        .get(format!("https://127.0.0.1:{port}/backends"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let backends = body["backends"].as_array().unwrap();
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0]["name"], "server3");

    shutdown.cancel();
    Ok(())
}

#[tokio::test]
async fn test_update_backend() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";
    let table = RoutingTable::new();
    table.add_backend(
        "server1".to_string(),
        Backend::new(
            "server1.example.com".to_string(),
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:20001".parse().unwrap(),
            1,
        ),
    );

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    let update_body = serde_json::json!({
        "hostname": "server1-updated.example.com",
        "tcp_addr": "127.0.0.1:10099",
        "udp_addr": "127.0.0.1:20099",
        "instance_id": 99
    });

    let resp = client
        .put(format!("https://127.0.0.1:{port}/backends/server1"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&update_body)
        .send()
        .await?;

    assert_eq!(resp.status(), 200);

    // Verify updated
    let resp = client
        .get(format!("https://127.0.0.1:{port}/backends"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let backends = body["backends"].as_array().unwrap();
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0]["hostname"], "server1-updated.example.com");
    assert_eq!(backends[0]["instance_id"], 99);

    shutdown.cancel();
    Ok(())
}

/// A heartbeat uses `PUT` to both register and refresh, so absence must not be an
/// error. Without this, a backend whose record was lost (Meridian restart, lease
/// expiry) could never re-establish itself.
#[tokio::test]
async fn test_put_creates_when_absent_and_is_idempotent() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";
    let table = RoutingTable::new();

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    let body = serde_json::json!({
        "hostname": "up.example.com",
        "tcp_addr": "127.0.0.1:15443",
        "udp_addr": "127.0.0.1:15444",
        "instance_id": 77
    });

    // First PUT for a name that does not exist yet.
    let resp = client
        .put(format!("https://127.0.0.1:{port}/backends/upserted"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await?;
    assert_eq!(
        resp.status(),
        201,
        "PUT must create when the record is absent"
    );

    // Second identical PUT refreshes rather than erroring.
    let resp = client
        .put(format!("https://127.0.0.1:{port}/backends/upserted"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "a repeated PUT must be idempotent");

    // Exactly one record, not two.
    let resp = client
        .get(format!("https://127.0.0.1:{port}/backends"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await?;
    let listed: serde_json::Value = resp.json().await?;
    let backends = listed["backends"].as_array().unwrap();
    assert_eq!(backends.len(), 1, "upsert must not duplicate the record");
    assert_eq!(backends[0]["name"], "upserted");

    shutdown.cancel();
    Ok(())
}

#[tokio::test]
async fn test_delete_backend() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";
    let table = RoutingTable::new();
    table.add_backend(
        "server1".to_string(),
        Backend::new(
            "server1.example.com".to_string(),
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:20001".parse().unwrap(),
            1,
        ),
    );

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    let resp = client
        .delete(format!("https://127.0.0.1:{port}/backends/server1"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await?;

    assert_eq!(resp.status(), 204);

    // Verify deleted
    let resp = client
        .get(format!("https://127.0.0.1:{port}/backends"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let backends = body["backends"].as_array().unwrap();
    assert_eq!(backends.len(), 0);

    shutdown.cancel();
    Ok(())
}

#[tokio::test]
async fn test_unauthorized_no_key() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";
    let table = RoutingTable::new();

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    let resp = client
        .get(format!("https://127.0.0.1:{port}/backends"))
        .send()
        .await?;

    assert_eq!(resp.status(), 401);

    shutdown.cancel();
    Ok(())
}

#[tokio::test]
async fn test_unauthorized_wrong_key() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";
    let table = RoutingTable::new();

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    let resp = client
        .get(format!("https://127.0.0.1:{port}/backends"))
        .header("Authorization", "Bearer wrong-key")
        .send()
        .await?;

    assert_eq!(resp.status(), 401);

    shutdown.cancel();
    Ok(())
}

#[tokio::test]
async fn test_delete_nonexistent() -> Result<()> {
    let certs = generate_test_certs("api.test.local");
    let api_key = "test-secret-key";
    let table = RoutingTable::new();

    let (port, shutdown, _temp_dir) = start_control_plane(api_key, table, &certs).await?;
    let client = build_client(&certs.ca_cert_pem)?;

    let resp = client
        .delete(format!("https://127.0.0.1:{port}/backends/nonexistent"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await?;

    assert_eq!(resp.status(), 404);

    shutdown.cancel();
    Ok(())
}
