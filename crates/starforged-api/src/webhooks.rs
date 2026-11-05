//! Webhook routes (spec §6.5, M2c H5): `…/hooks` and `…/hooks/{id}`.
//!
//! Handlers authenticate and delegate; all permission, validation, sealing,
//! and fan-out logic lives on [`Core`]. Every route needs `Scope::RepoWrite`
//! first, then `Core` enforces ≥ `Maintain` (`Forbidden` → `403` — even the
//! list is maintainer-only, so membership is never leaked to readers).
//! `CoreError::Invalid` → `422`, all in the `{error:{code,message}}`
//! envelope. Timestamps render as RFC 3339 (`…Z`).
//!
//! The plaintext secret appears exactly once, in the `201` body. Lists and
//! patches carry `has_secret` only.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::tokens::Scope;
use starforged_core::webhooks::{DeliverySummary, WebhookDto};

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize)]
pub struct WebhookJson {
    pub id: i64,
    pub url: String,
    pub events: Vec<String>,
    pub subscription_invalid: bool,
    pub active: bool,
    pub last_status: Option<i64>,
    pub last_error: Option<String>,
    pub has_secret: bool,
    pub created_at: String,
}

fn webhook_json(view: &WebhookDto) -> WebhookJson {
    WebhookJson {
        id: view.id,
        url: view.url.clone(),
        events: view.events.clone(),
        subscription_invalid: view.subscription_invalid,
        active: view.active,
        last_status: view.last_status,
        last_error: view.last_error.clone(),
        has_secret: true,
        created_at: rfc3339(view.created_at),
    }
}

#[derive(Serialize)]
struct DeliverySummaryJson {
    id: i64,
    delivery_id: String,
    attempt: i64,
    event: String,
    action: Option<String>,
    status_code: Option<i64>,
    error: Option<String>,
    duration_ms: i64,
    redelivery: bool,
    delivered_at: String,
}

fn delivery_summary_json(view: &DeliverySummary) -> DeliverySummaryJson {
    DeliverySummaryJson {
        id: view.id,
        delivery_id: view.delivery_id.clone(),
        attempt: view.attempt,
        event: view.event.clone(),
        action: view.action.clone(),
        status_code: view.status_code,
        error: view.error.clone(),
        duration_ms: view.duration_ms,
        redelivery: view.redelivery,
        delivered_at: rfc3339(view.delivered_at),
    }
}

#[derive(Deserialize)]
pub struct DeliveriesQuery {
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct CreateHookBody {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Deserialize)]
pub struct PatchHookBody {
    pub active: bool,
}

/// `GET /repos/{owner}/{repo}/hooks` (200): the repo's hooks in insert
/// order, maintainer-only, never containing secrets.
pub async fn list_hooks(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let views = state
        .core
        .list_webhooks(Some(&auth.user), &owner, &repo)
        .await?;
    Ok(Json(json!({
        "hooks": views.iter().map(webhook_json).collect::<Vec<_>>(),
    })))
}

/// `POST /repos/{owner}/{repo}/hooks` (201): creates a hook and returns it
/// with the plaintext `secret` — the only response that ever carries one.
/// `events` must be a subset of `push, trail, review, check, session`
/// (empty means all); anything else is `422`.
pub async fn create_hook(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<CreateHookBody>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let (view, secret) = state
        .core
        .create_webhook(&auth.user, &owner, &repo, &body.url, &body.events)
        .await?;
    let mut rendered =
        serde_json::to_value(webhook_json(&view)).map_err(|e| ApiError::Internal(e.to_string()))?;
    rendered["secret"] = Value::String(secret);
    Ok((StatusCode::CREATED, Json(rendered)))
}

/// `PATCH /repos/{owner}/{repo}/hooks/{id}` (200): flips the hook's `active`
/// flag (enable/disable).
pub async fn patch_hook(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    body: Result<Json<PatchHookBody>, JsonRejection>,
) -> Result<Json<WebhookJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .set_webhook_active(&auth.user, &owner, &repo, id, body.active)
        .await?;
    Ok(Json(webhook_json(&view)))
}

/// `DELETE /repos/{owner}/{repo}/hooks/{id}` (204): removes the hook.
pub async fn delete_hook(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .delete_webhook(&auth.user, &owner, &repo, id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /repos/{owner}/{repo}/hooks/{id}/deliveries[?limit=]` (200): the
/// hook's logged attempts, newest first (maintainer-only).
pub async fn list_deliveries(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    axum::extract::Query(query): axum::extract::Query<DeliveriesQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let views = state
        .core
        .list_deliveries(&auth.user, &owner, &repo, id, query.limit)
        .await?;
    Ok(Json(json!({
        "deliveries": views.iter().map(delivery_summary_json).collect::<Vec<_>>(),
    })))
}

/// `GET /repos/{owner}/{repo}/hooks/{id}/deliveries/{row}` (200): one
/// logged attempt in full (maintainer-only).
pub async fn get_delivery(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id, row)): Path<(String, String, i64, i64)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let view = state
        .core
        .get_delivery(&auth.user, &owner, &repo, id, row)
        .await?;
    let mut rendered = serde_json::to_value(delivery_summary_json(&view.summary))
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    rendered["request_headers"] =
        serde_json::from_str(&view.request_headers).unwrap_or(Value::Null);
    rendered["request_body"] = Value::String(view.request_body.clone());
    rendered["response_headers"] = view
        .response_headers
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or(Value::Null);
    rendered["response_body"] = view
        .response_body
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);
    Ok(Json(rendered))
}

/// `POST /repos/{owner}/{repo}/hooks/{id}/deliveries/{row}/redeliver`
/// (202): replays the logged attempt as a new delivery (maintainer-only).
pub async fn redeliver(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id, row)): Path<(String, String, i64, i64)>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let delivery_id = state
        .core
        .redeliver(&auth.user, &owner, &repo, id, row)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "delivery_id": delivery_id })),
    ))
}
