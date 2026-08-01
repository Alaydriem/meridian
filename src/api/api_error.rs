use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::dto::ErrorResponse;

/// A control-plane failure, carrying the status the client should see.
pub enum ApiError {
    InvalidAddress { field: &'static str, detail: String },
    Conflict(String),
    NotFound(String),
}

impl ApiError {
    fn parts(self) -> (StatusCode, String) {
        match self {
            Self::InvalidAddress { field, detail } => (
                StatusCode::BAD_REQUEST,
                format!("invalid {field}: {detail}"),
            ),
            Self::Conflict(message) => (StatusCode::CONFLICT, message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = self.parts();
        (status, Json(ErrorResponse { error })).into_response()
    }
}
