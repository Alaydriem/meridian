use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::routing::{Backend, RoutingTable};

use super::dto::{
    BackendListResponse, BackendResponse, CreateBackendRequest, ErrorResponse,
    UpdateBackendRequest,
};

pub async fn list_backends(
    State(table): State<Arc<RoutingTable>>,
) -> impl IntoResponse {
    let backends = table
        .list_backends()
        .into_iter()
        .map(|(name, b)| BackendResponse {
            name,
            hostname: b.hostname,
            tcp_addr: b.tcp_addr.to_string(),
            udp_addr: b.udp_addr.to_string(),
            instance_id: b.instance_id,
        })
        .collect();

    Json(BackendListResponse { backends })
}

pub async fn create_backend(
    State(table): State<Arc<RoutingTable>>,
    Json(req): Json<CreateBackendRequest>,
) -> impl IntoResponse {
    let tcp_addr = match crate::routing::resolve::resolve_addr(&req.tcp_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ErrorResponse {
                    error: format!("invalid tcp_addr: {e}"),
                })
                .unwrap()),
            );
        }
    };

    let udp_addr = match crate::routing::resolve::resolve_addr(&req.udp_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ErrorResponse {
                    error: format!("invalid udp_addr: {e}"),
                })
                .unwrap()),
            );
        }
    };

    let backend = Backend {
        hostname: req.hostname.clone(),
        tcp_addr,
        udp_addr,
        instance_id: req.instance_id,
    };

    table.add_backend(req.name.clone(), backend);
    tracing::info!(name = %req.name, hostname = %req.hostname, "backend added");

    let response = BackendResponse {
        name: req.name,
        hostname: req.hostname,
        tcp_addr: req.tcp_addr,
        udp_addr: req.udp_addr,
        instance_id: req.instance_id,
    };

    (
        StatusCode::CREATED,
        Json(serde_json::to_value(response).unwrap()),
    )
}

pub async fn update_backend(
    State(table): State<Arc<RoutingTable>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateBackendRequest>,
) -> impl IntoResponse {
    let tcp_addr = match crate::routing::resolve::resolve_addr(&req.tcp_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ErrorResponse {
                    error: format!("invalid tcp_addr: {e}"),
                })
                .unwrap()),
            );
        }
    };

    let udp_addr = match crate::routing::resolve::resolve_addr(&req.udp_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ErrorResponse {
                    error: format!("invalid udp_addr: {e}"),
                })
                .unwrap()),
            );
        }
    };

    let backend = Backend {
        hostname: req.hostname.clone(),
        tcp_addr,
        udp_addr,
        instance_id: req.instance_id,
    };

    match table.update_backend(&name, backend) {
        Some(_old) => {
            tracing::info!(%name, hostname = %req.hostname, "backend updated");
            let response = BackendResponse {
                name,
                hostname: req.hostname,
                tcp_addr: req.tcp_addr,
                udp_addr: req.udp_addr,
                instance_id: req.instance_id,
            };
            (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
        }
        None => {
            tracing::warn!(%name, "backend update failed: not found");
            (
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::to_value(ErrorResponse {
                        error: format!("backend '{name}' not found"),
                    })
                    .unwrap(),
                ),
            )
        }
    }
}

pub async fn delete_backend(
    State(table): State<Arc<RoutingTable>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match table.remove_backend(&name) {
        Some(_) => {
            tracing::info!(%name, "backend removed");
            StatusCode::NO_CONTENT.into_response()
        }
        None => {
            tracing::warn!(%name, "backend delete failed: not found");
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("backend '{name}' not found"),
                }),
            )
                .into_response()
        }
    }
}
