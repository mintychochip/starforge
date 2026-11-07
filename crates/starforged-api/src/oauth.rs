//! OAuth device authorization grant (RFC 8628): the two endpoints the CLI drives.
//!
//! Form bodies, not JSON. The token endpoint answers pending states with the
//! flat RFC 8628 body (`{"error": "authorization_pending"}` etc.) — not the
//! `{error: {…}}` envelope — because that is the shape the CLI parses.

use axum::Form;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use starforged_core::CoreError;
use starforged_core::oauth::PollOutcome;

use crate::ApiState;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct DeviceCodeForm {
    client_id: String,
    scope: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct TokenForm {
    grant_type: String,
    device_code: String,
    client_id: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RevokeForm {
    token: String,
}

/// `POST /api/v1/oauth/device/code`: starts a device flow for `starforge-cli`.
#[utoipa::path(
    post,
    path = "/api/v1/oauth/device/code",
    request_body(content = DeviceCodeForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Device authorization response", body = serde_json::Value),
        (status = 400, description = "Bad request", body = serde_json::Value),
    ),
)]

pub async fn device_code(
    State(state): State<ApiState>,
    Form(form): Form<DeviceCodeForm>,
) -> Response {
    match state
        .core
        .create_device_code(&form.client_id, &form.scope)
        .await
    {
        Ok(request) => (
            StatusCode::OK,
            Json(json!({
                "device_code": request.device_code,
                "user_code": request.user_code,
                "verification_uri": request.verification_uri,
                "verification_uri_complete": request.verification_uri_complete,
                "expires_in": request.expires_in,
                "interval": request.interval,
            })),
        )
            .into_response(),
        Err(CoreError::Invalid(message)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "invalid", "message": message } })),
        )
            .into_response(),
        Err(other) => crate::error::ApiError::from(other).into_response(),
    }
}

/// `POST /api/v1/oauth/token`: polls a device flow for its token pair.
#[utoipa::path(
    post,
    path = "/api/v1/oauth/token",
    request_body(content = TokenForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Token response or RFC 8628 pending body", body = serde_json::Value),
        (status = 400, description = "Bad request", body = serde_json::Value),
    ),
)]

pub async fn token(State(state): State<ApiState>, Form(form): Form<TokenForm>) -> Response {
    if form.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return oauth_error("unsupported_grant_type");
    }
    match state
        .core
        .poll_device_code(&form.device_code, &form.client_id)
        .await
    {
        Ok(PollOutcome::Granted {
            access_token,
            refresh_token,
            expires_in,
            scope,
        }) => (
            StatusCode::OK,
            Json(json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": refresh_token,
                "scope": scope,
            })),
        )
            .into_response(),
        Ok(PollOutcome::Pending) => oauth_error("authorization_pending"),
        Ok(PollOutcome::SlowDown) => oauth_error("slow_down"),
        Ok(PollOutcome::Expired) => oauth_error("expired_token"),
        Ok(PollOutcome::Denied) => oauth_error("access_denied"),
        Err(CoreError::Invalid(_)) => oauth_error("invalid_grant"),
        Err(other) => crate::error::ApiError::from(other).into_response(),
    }
}

/// `POST /api/v1/oauth/revoke`: RFC 7009 token revocation. The form body
/// carries `token` (access or refresh); the SHA-256 hash identifies the
/// row. Unknown or already-revoked tokens still answer `200`, so callers
/// never learn whether a token existed; a real DB failure maps to a 5xx
/// through `ApiError` so the caller can warn truthfully that revocation
/// did not happen.
#[utoipa::path(
    post,
    path = "/api/v1/oauth/revoke",
    request_body(content = RevokeForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Revocation accepted (idempotent)", body = serde_json::Value),
    ),
)]
pub async fn revoke(State(state): State<ApiState>, Form(form): Form<RevokeForm>) -> Response {
    let hash = starforged_core::crypto::sha256_hex(&form.token);
    match state.core.revoke_token_hash(&hash).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(other) => crate::error::ApiError::from(other).into_response(),
    }
}

fn oauth_error(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response()
}
