//! SSH key and deploy key routes (D4): `/user/keys`, `/repos/{owner}/{repo}/keys`.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::sshkeys::{DeployKeyView, SshKeyView};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::{opt_ts, rfc3339};

#[derive(Serialize)]
pub struct KeyJson {
    id: i64,
    title: String,
    algorithm: String,
    fingerprint: String,
    created_at: String,
    last_used_at: Option<String>,
}

fn key_json(view: &SshKeyView) -> KeyJson {
    KeyJson {
        id: view.id,
        title: view.title.clone(),
        algorithm: view.algorithm.clone(),
        fingerprint: view.fingerprint.clone(),
        created_at: rfc3339(view.created_at),
        last_used_at: opt_ts(view.last_used_at),
    }
}

#[derive(Serialize)]
pub struct DeployKeyJson {
    id: i64,
    title: String,
    algorithm: String,
    fingerprint: String,
    read_write: bool,
    created_at: String,
    last_used_at: Option<String>,
}

fn deploy_key_json(view: &DeployKeyView) -> DeployKeyJson {
    DeployKeyJson {
        id: view.id,
        title: view.title.clone(),
        algorithm: view.algorithm.clone(),
        fingerprint: view.fingerprint.clone(),
        read_write: view.read_write,
        created_at: rfc3339(view.created_at),
        last_used_at: opt_ts(view.last_used_at),
    }
}

#[derive(Deserialize)]
pub struct CreateKeyBody {
    pub title: String,
    pub key: String,
}

#[derive(Deserialize)]
pub struct CreateDeployKeyBody {
    pub title: String,
    pub key: String,
    #[serde(default)]
    pub read_write: bool,
}

/// `GET /user/keys` (200).
pub async fn list_user_keys(
    State(state): State<ApiState>,
    auth: ApiAuth,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoRead)?;
    let views = state.core.ssh_keys(&auth.user).await?;
    Ok(Json(
        json!({ "keys": views.iter().map(key_json).collect::<Vec<_>>() }),
    ))
}

/// `POST /user/keys` (201).
pub async fn create_user_key(
    State(state): State<ApiState>,
    auth: ApiAuth,
    body: Result<Json<CreateKeyBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<KeyJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .add_ssh_key(&auth.user, &body.title, &body.key)
        .await?;
    Ok((StatusCode::CREATED, Json(key_json(&view))))
}

/// `DELETE /user/keys/{id}` (204).
pub async fn delete_user_key(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state.core.remove_ssh_key(&auth.user, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /repos/{owner}/{repo}/keys` (200).
pub async fn list_deploy_keys(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let views = state.core.deploy_keys(&auth.user, &owner, &repo).await?;
    Ok(Json(
        json!({ "keys": views.iter().map(deploy_key_json).collect::<Vec<_>>() }),
    ))
}

/// `POST /repos/{owner}/{repo}/keys` (201).
pub async fn create_deploy_key(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<CreateDeployKeyBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<DeployKeyJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .add_deploy_key(
            &auth.user,
            &owner,
            &repo,
            &body.title,
            &body.key,
            body.read_write,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(deploy_key_json(&view))))
}

/// `DELETE /repos/{owner}/{repo}/keys/{id}` (204).
pub async fn delete_deploy_key(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .remove_deploy_key(&auth.user, &owner, &repo, id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
