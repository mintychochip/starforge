//! Commit status routes (spec §6.5, M2c H2, M2d D10/D11):
//! `…/statuses/{sha}` and `…/commits/{ref}/status`.
//!
//! Handlers authenticate (scope checks) and delegate; all permission,
//! validation, and upsert logic lives on [`Core`]. Reads go through
//! `auth.reader()` so non-readers surface as `404` (the service returns
//! `NotFound`, never translated to `403`); submissions require
//! `Scope::RepoWrite` first, then `Core` enforces ≥ `Write`
//! (`Forbidden` → `403`). `CoreError::Invalid` → `422`, all in the
//! `{error:{code,message,details}}` envelope.
//!
//! Timestamps render as RFC 3339 (`…Z`); the service stores unix seconds
//! internally. Status writes are timeline-free and audit-free (see
//! `starforged-core::checks`); reads write nothing.

use axum::Json;
use axum::extract::Path;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::checks::{CombinedDto, StatusDto};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize, utoipa::ToSchema)]
pub struct StatusJson {
    pub sha: String,
    pub context: String,
    pub state: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub creator: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn status_json(view: &StatusDto) -> StatusJson {
    StatusJson {
        sha: view.sha.clone(),
        context: view.context.clone(),
        state: view.state.clone(),
        target_url: view.target_url.clone(),
        description: view.description.clone(),
        creator: view.creator_handle.clone(),
        created_at: rfc3339(view.created_at),
        updated_at: rfc3339(view.updated_at),
    }
}

fn combined_json(view: &CombinedDto) -> Value {
    json!({
        "sha": view.sha,
        "state": view.state,
        "total_count": view.statuses.len() as i64,
        "statuses": view.statuses.iter().map(status_json).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SubmitStatusBody {
    pub state: String,
    pub context: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
}

/// `POST /repos/{owner}/{repo}/statuses/{sha}` (201): upserts the caller's
/// status for `(sha, context)` and returns the current row.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/statuses/{sha}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("sha" = String, Path, description = "Commit SHA"),
    ),
    request_body = SubmitStatusBody,
    responses(
        (status = 201, description = "Submitted status", body = StatusJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn submit_status(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, sha)): Path<(String, String, String)>,
    body: Result<Json<SubmitStatusBody>, JsonRejection>,
) -> Result<(StatusCode, Json<StatusJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .submit_status(
            &auth.user,
            &owner,
            &repo,
            &sha,
            &body.state,
            &body.context,
            body.target_url.as_deref(),
            body.description.as_deref(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(status_json(&view))))
}

/// `GET /repos/{owner}/{repo}/statuses/{sha}` (200): the latest status per
/// context for `sha`, in context order.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/statuses/{sha}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("sha" = String, Path, description = "Commit SHA"),
    ),
    responses(
        (status = 200, description = "Statuses for sha", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn list_statuses(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, sha)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let views = state
        .core
        .list_statuses(auth.reader()?, &owner, &repo, &sha)
        .await?;
    Ok(Json(json!({
        "statuses": views.iter().map(status_json).collect::<Vec<_>>(),
    })))
}

/// `GET /repos/{owner}/{repo}/commits/{ref}/status` (200): the combined
/// status for a SHA, branch, or tag (D10: SHA as-is, then `refs/heads`,
/// then peeled `refs/tags`; a branch shadows a same-named tag; anything
/// else is `404`). The latest-per-context rows fold with error > failure >
/// pending > success precedence; an unknown sha is `pending` with zero rows.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/commits/{reference}/status",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("reference" = String, Path, description = "Commit SHA, branch, or tag"),
    ),
    responses(
        (status = 200, description = "Combined status", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn combined_status(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, reference)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let view = state
        .core
        .combined_status_for_ref(auth.reader()?, &owner, &repo, &reference)
        .await?;
    Ok(Json(combined_json(&view)))
}
