//! Commit status routes (spec §6.5, M2c H2):
//! `…/statuses/{sha}` and `…/commits/{sha}/combined-status`.
//!
//! Handlers authenticate (scope checks) and delegate; all permission,
//! validation, and upsert logic lives on [`Core`]. Reads go through
//! `auth.reader()` so non-readers surface as `404` (the service returns
//! `NotFound`, never translated to `403`); submissions require
//! `Scope::RepoWrite` first, then `Core` enforces ≥ `Write`
//! (`Forbidden` → `403`). `CoreError::Invalid` → `422`, all in the
//! `{error:{code,message}}` envelope.
//!
//! Timestamps render as RFC 3339 (`…Z`); the service stores unix seconds
//! internally. Status writes are timeline-free and audit-free (see
//! `starforged-core::checks`); reads write nothing.

use axum::Json;
use axum::extract::Path;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::checks::{CombinedDto, StatusDto};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize)]
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

#[derive(Deserialize)]
pub struct SubmitStatusBody {
    pub state: String,
    pub context: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
}

/// `POST /repos/{owner}/{repo}/statuses/{sha}` (200): upserts the caller's
/// status for `(sha, context)` and returns the current row.
pub async fn submit_status(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, sha)): Path<(String, String, String)>,
    body: Result<Json<SubmitStatusBody>, JsonRejection>,
) -> Result<Json<StatusJson>, ApiError> {
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
    Ok(Json(status_json(&view)))
}

/// `GET /repos/{owner}/{repo}/statuses/{sha}` (200): the latest status per
/// context for `sha`, in context order.
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

/// `GET /repos/{owner}/{repo}/commits/{sha}/combined-status` (200): the
/// latest-per-context rows folded with error > failure > pending > success
/// precedence; an unknown sha is `pending` with zero rows.
pub async fn combined_status(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, sha)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let view = state
        .core
        .combined_status(auth.reader()?, &owner, &repo, &sha)
        .await?;
    Ok(Json(combined_json(&view)))
}
