//! Gate-rule routes (spec §6.2, M2c H7): `…/gate-rules` and
//! `…/gate-rules/{id}`.
//!
//! Handlers authenticate and delegate; all permission, validation,
//! per-pattern uniqueness, and timeline/audit logic lives on [`Core`].
//! Reads go through `auth.reader()` so non-readers surface as `404`;
//! mutations need `Scope::RepoWrite` first, then `Core` enforces ≥
//! `Maintain` (`Forbidden` → `403`). `CoreError::Invalid` → `422`,
//! `CoreError::Conflict` → `409`, all in the `{error:{code,message}}`
//! envelope. Timestamps render as RFC 3339 (`…Z`).
//!
//! Request bodies deny unknown fields: on a security control a misspelled
//! field (`"required_approval"`) must be a `422`, never a silently weaker
//! gate. `null` for `pattern` (or `""`) means all branches; `null` for any
//! other field is a `422`.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use starforged_core::gate_rules::{GateRuleDto, GateRuleInput};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize, utoipa::ToSchema)]
pub struct GateRuleJson {
    pub id: i64,
    pub pattern: Option<String>,
    pub required_approvals: i64,
    pub dismiss_on_push: bool,
    pub block_on_request_changes: bool,
    pub required_contexts: Vec<String>,
    pub require_up_to_date: bool,
    pub require_threads_resolved: bool,
    pub require_session_evidence: bool,
    pub allowed_methods: Vec<String>,
    pub block_direct_push: bool,
    pub block_force_push: bool,
    pub block_deletion: bool,
    pub push_allowlist: PushAllowlistJson,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PushAllowlistJson {
    pub users: Vec<String>,
    pub teams: Vec<String>,
}

fn gate_rule_json(view: &GateRuleDto) -> GateRuleJson {
    GateRuleJson {
        id: view.id,
        pattern: view.pattern.clone(),
        required_approvals: view.required_approvals,
        dismiss_on_push: view.dismiss_on_push,
        block_on_request_changes: view.block_on_request_changes,
        required_contexts: view.required_contexts.clone(),
        require_up_to_date: view.require_up_to_date,
        require_threads_resolved: view.require_threads_resolved,
        require_session_evidence: view.require_session_evidence,
        allowed_methods: view.allowed_methods.clone(),
        block_direct_push: view.block_direct_push,
        block_force_push: view.block_force_push,
        block_deletion: view.block_deletion,
        push_allowlist: PushAllowlistJson {
            users: view.push_allowlist.users.clone(),
            teams: view.push_allowlist.teams.clone(),
        },
        created_at: rfc3339(view.created_at),
        updated_at: rfc3339(view.updated_at),
    }
}

/// `GET /repos/{owner}/{repo}/gate-rules` (200): the repo's rules in
/// insert order. Any reader may list.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/gate-rules",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Gate rules", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn list_gate_rules(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let views = state
        .core
        .list_gate_rules(auth.reader()?, &owner, &repo)
        .await?;
    Ok(Json(json!({
        "gate_rules": views.iter().map(gate_rule_json).collect::<Vec<_>>(),
    })))
}

/// `POST /repos/{owner}/{repo}/gate-rules` (201): creates a rule and
/// returns it.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/gate-rules",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = serde_json::Value,
    responses(
        (status = 201, description = "Created gate rule", body = GateRuleJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn create_gate_rule(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<GateRuleInput>, JsonRejection>,
) -> Result<(StatusCode, Json<GateRuleJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(input) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .create_gate_rule(&auth.user, &owner, &repo, &input)
        .await?;
    Ok((StatusCode::CREATED, Json(gate_rule_json(&view))))
}

/// `PATCH /repos/{owner}/{repo}/gate-rules/{id}` (200): absent fields are
/// unchanged; the merged result is validated as a whole.
#[utoipa::path(
    patch,
    path = "/api/v1/repos/{owner}/{repo}/gate-rules/{id}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("id" = i64, Path, description = "Gate rule id"),
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Updated gate rule", body = GateRuleJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn patch_gate_rule(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    body: Result<Json<GateRuleInput>, JsonRejection>,
) -> Result<Json<GateRuleJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(input) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .update_gate_rule(&auth.user, &owner, &repo, id, &input)
        .await?;
    Ok(Json(gate_rule_json(&view)))
}

/// `DELETE /repos/{owner}/{repo}/gate-rules/{id}` (204): removes the rule.
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/gate-rules/{id}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("id" = i64, Path, description = "Gate rule id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn delete_gate_rule(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .delete_gate_rule(&auth.user, &owner, &repo, id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
