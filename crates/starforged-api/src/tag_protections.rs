//! Tag-protection routes (spec §8.2, M3b B2): `…/tag-protections` and
//! `…/tag-protections/{id}`.
//!
//! Handlers authenticate and delegate; all permission, validation,
//! per-pattern uniqueness, and timeline/audit logic lives on [`Core`].
//! Reads and mutations both need ≥ `Maintain`, so non-readers surface as
//! `404` and below-threshold users as `403`; mutations additionally need
//! `Scope::RepoWrite` first. `CoreError::Invalid` → `422`,
//! `CoreError::Conflict` → `409`, all in the `{error:{code,message}}`
//! envelope. Timestamps render as RFC 3339 (`…Z`).
//!
//! Request bodies deny unknown fields: on a security control a misspelled
//! field must be a `422`, never a silently weaker gate.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use starforged_core::protection::{TagProtectionDto, TagProtectionInput};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize)]
pub struct TagProtectionJson {
    pub id: i64,
    pub pattern: String,
    pub created_at: String,
}

fn tag_protection_json(view: &TagProtectionDto) -> TagProtectionJson {
    TagProtectionJson {
        id: view.id,
        pattern: view.pattern.clone(),
        created_at: rfc3339(view.created_at),
    }
}

/// `GET /repos/{owner}/{repo}/tag-protections` (200): the repo's tag
/// protections in insert order. Maintain+ only.
pub async fn list_tag_protections(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let views = state
        .core
        .list_tag_protections(auth.reader()?, &owner, &repo)
        .await?;
    Ok(Json(json!({
        "tag_protections": views.iter().map(tag_protection_json).collect::<Vec<_>>(),
    })))
}

/// `POST /repos/{owner}/{repo}/tag-protections` (201): creates a tag
/// protection and returns it.
pub async fn create_tag_protection(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<TagProtectionInput>, JsonRejection>,
) -> Result<(StatusCode, Json<TagProtectionJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(input) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .create_tag_protection(&auth.user, &owner, &repo, &input)
        .await?;
    Ok((StatusCode::CREATED, Json(tag_protection_json(&view))))
}

/// `DELETE /repos/{owner}/{repo}/tag-protections/{id}` (204): removes the
/// tag protection.
pub async fn delete_tag_protection(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .delete_tag_protection(&auth.user, &owner, &repo, id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
