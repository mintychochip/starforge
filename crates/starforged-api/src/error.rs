//! The JSON error envelope: `{"error": {"code": "...", "message": "..."}}`.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use starforged_core::CoreError;

#[derive(Debug)]
pub enum ApiError {
    Unauthenticated,
    Forbidden(String),
    NotFound,
    Invalid(String),
    Conflict(String),
    Internal(String),
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> ApiError {
        match err {
            CoreError::NotFound => ApiError::NotFound,
            CoreError::Forbidden => ApiError::Forbidden("permission denied".into()),
            CoreError::Unauthenticated => ApiError::Unauthenticated,
            CoreError::Invalid(message) => ApiError::Invalid(message),
            CoreError::Conflict(message) => ApiError::Conflict(message),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "a valid token is required".to_owned(),
            ),
            ApiError::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_owned()),
            ApiError::Invalid(message) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid", message),
            ApiError::Conflict(message) => (StatusCode::CONFLICT, "conflict", message),
            ApiError::Internal(message) => {
                tracing::error!(error = %message, "api request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".to_owned(),
                )
            }
        };
        let mut response = (
            status,
            Json(json!({ "error": { "code": code, "message": message } })),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
