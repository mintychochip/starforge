//! The JSON error envelope: `{"error": {"code": "...", "message": "...", "details": null}}`.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use starforged_core::CoreError;

#[derive(Debug)]
pub enum ApiError {
    Unauthenticated,
    Forbidden(String),
    NotFound,
    BadRequest(String),
    Invalid(String),
    Conflict(String),
    PayloadTooLarge(String),
    Internal(String),
    RateLimited {
        retry_after: i64,
        decision: starforged_core::limits::RateDecision,
    },
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> ApiError {
        match err {
            CoreError::NotFound => ApiError::NotFound,
            CoreError::Forbidden => ApiError::Forbidden("permission denied".into()),
            CoreError::Unauthenticated => ApiError::Unauthenticated,
            CoreError::Invalid(message) => ApiError::Invalid(message),
            CoreError::Conflict(message) => ApiError::Conflict(message),
            CoreError::EmailUnverified => ApiError::Forbidden("email address not verified".into()),
            CoreError::RateLimited => ApiError::RateLimited {
                retry_after: 60,
                decision: starforged_core::limits::RateDecision {
                    allowed: false,
                    limit: 0,
                    remaining: 0,
                    reset_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64 + 60)
                        .unwrap_or(60),
                },
            },
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let rate = match &self {
            ApiError::RateLimited {
                retry_after,
                decision,
            } => Some((*retry_after, *decision)),
            _ => None,
        };
        let (status, code, message) = match self {
            ApiError::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "a valid token is required".to_owned(),
            ),
            ApiError::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_owned()),
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            ApiError::Invalid(message) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid", message),
            ApiError::Conflict(message) => (StatusCode::CONFLICT, "conflict", message),
            ApiError::PayloadTooLarge(message) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", message)
            }
            ApiError::Internal(message) => {
                tracing::error!(error = %message, "api request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".to_owned(),
                )
            }
            ApiError::RateLimited {
                retry_after: _,
                decision: _,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "rate limit exceeded".to_owned(),
            ),
        };
        let mut response = (
            status,
            Json(json!({ "error": { "code": code, "message": message, "details": Value::Null } })),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if let Some((retry_after, decision)) = rate {
            insert_rate_headers(response.headers_mut(), retry_after, decision);
        }
        response
    }
}

/// Writes the rate-limit headers (plan M5a): `X-RateLimit-Limit`,
/// `-Remaining`, `-Reset`, and `Retry-After` on 429s.
pub fn insert_rate_headers(
    headers: &mut axum::http::HeaderMap,
    retry_after: i64,
    decision: starforged_core::limits::RateDecision,
) {
    let mut set = |name: &'static str, value: i64| {
        if let Ok(value) = value.to_string().parse::<HeaderValue>() {
            headers.insert(axum::http::HeaderName::from_static(name), value);
        }
    };
    set("x-ratelimit-limit", decision.limit as i64);
    set("x-ratelimit-remaining", decision.remaining as i64);
    set("x-ratelimit-reset", decision.reset_at);
    if !decision.allowed {
        set("retry-after", retry_after.max(1));
    }
}
