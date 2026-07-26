use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::health::DatapathHealth;

use super::backend_service::BackendService;
use super::dto::{CreateBackendRequest, DatapathHealthResponse, UpdateBackendRequest};

/// Datapath readiness. Returns 200 while the instance can serve traffic at all,
/// 503 otherwise.
///
/// Deliberately not sensitive to partial worker loss: a pool below its configured
/// count still serves every connection correctly, and reporting unhealthy there
/// would relocate the ingress and cost every live connection a QUIC path.
pub async fn datapath_health(State(health): State<Arc<DatapathHealth>>) -> impl IntoResponse {
    let can_serve = health.can_serve();
    let body = DatapathHealthResponse {
        live_workers: health.live_workers(),
        configured_workers: health.configured_workers(),
        last_datagram_age_ms: health.last_datagram_age().map(|d| d.as_millis() as u64),
        can_serve,
    };

    let status = if can_serve {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(body))
}

pub async fn list_backends(State(service): State<Arc<BackendService>>) -> impl IntoResponse {
    Json(service.list())
}

pub async fn create_backend(
    State(service): State<Arc<BackendService>>,
    Json(req): Json<CreateBackendRequest>,
) -> impl IntoResponse {
    service
        .create(req)
        .await
        .map(|backend| (StatusCode::CREATED, Json(backend)))
}

pub async fn update_backend(
    State(service): State<Arc<BackendService>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateBackendRequest>,
) -> impl IntoResponse {
    service.upsert(name, req).await.map(|(created, backend)| {
        let status = if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        (status, Json(backend))
    })
}

pub async fn delete_backend(
    State(service): State<Arc<BackendService>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    service.delete(&name).map(|()| StatusCode::NO_CONTENT)
}
