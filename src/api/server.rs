use std::io::Cursor;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio_util::sync::CancellationToken;

use crate::config::ApiConfig;
use crate::routing::RoutingTable;

use super::handlers;

pub struct ControlPlane {
    config: ApiConfig,
    routing_table: Arc<RoutingTable>,
}

impl ControlPlane {
    pub fn new(config: ApiConfig, routing_table: Arc<RoutingTable>) -> Self {
        Self {
            config,
            routing_table,
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        let api_key = self.config.api_key.clone();

        let app = Router::new()
            .route("/backends", get(handlers::list_backends))
            .route("/backends", post(handlers::create_backend))
            .route("/backends/{name}", put(handlers::update_backend))
            .route("/backends/{name}", delete(handlers::delete_backend))
            .layer(middleware::from_fn(move |req, next| {
                let key = api_key.clone();
                api_key_middleware(key, req, next)
            }))
            .with_state(self.routing_table.clone());

        // Load TLS certs
        let cert_pem = std::fs::read(&self.config.tls.certificate)
            .with_context(|| format!("failed to read API cert: {}", self.config.tls.certificate))?;
        let key_pem = std::fs::read(&self.config.tls.key)
            .with_context(|| format!("failed to read API key: {}", self.config.tls.key))?;

        let certs = rustls_pemfile::certs(&mut Cursor::new(&cert_pem))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse API certs")?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(&key_pem))
            .context("failed to parse API key")?
            .context("no private key found")?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("failed to build TLS config")?;

        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

        let addr: std::net::SocketAddr = self.config.listen.parse()
            .with_context(|| format!("invalid API listen address: {}", self.config.listen))?;

        tracing::info!(%addr, "control plane listening");

        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();

        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown.cancelled().await;
            shutdown_handle.graceful_shutdown(None);
        });

        axum_server::bind_rustls(addr, rustls_config)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .context("control plane server failed")?;

        Ok(())
    }
}

async fn api_key_middleware(
    expected_key: String,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header == format!("Bearer {expected_key}") => {
            next.run(req).await.into_response()
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}
