//! CI runner registration and CRUD routes (spec M6, task A2):
//! `POST /repos/{owner}/{repo}/runners/registration-token`,
//! `POST /runners/register`, `GET /repos/{owner}/{repo}/runners`,
//! `DELETE /runners/{id}`.
//!
//! The registration endpoint carries no `Authorization` header: the
//! registration token in the body is the credential.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::ci::RunnerView;
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegistrationTokenJson {
    /// The `sfrt_…` secret, shown once.
    pub token: String,
    pub expires_at: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateRegistrationTokenBody {
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterRunnerBody {
    pub registration_token: String,
    pub name: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegisteredRunnerJson {
    pub runner_id: i64,
    /// The `sfr_…` auth token, shown once.
    pub auth_token: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RunnerJson {
    pub id: i64,
    pub name: String,
    pub labels: Vec<String>,
    pub ephemeral: bool,
    pub version: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
}

fn runner_json(view: &RunnerView) -> RunnerJson {
    RunnerJson {
        id: view.id,
        name: view.name.clone(),
        labels: view.labels.clone(),
        ephemeral: view.ephemeral,
        version: view.version.clone(),
        last_seen_at: view.last_seen_at.map(crate::time::rfc3339),
        created_at: rfc3339(view.created_at),
    }
}

/// `POST /repos/{owner}/{repo}/runners/registration-token` (201).
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/runners/registration-token",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = CreateRegistrationTokenBody,
    responses(
        (status = 201, description = "Minted registration token", body = RegistrationTokenJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_registration_token(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<CreateRegistrationTokenBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<RegistrationTokenJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let minted = state
        .core
        .create_runner_registration_token(&auth.user, &owner, &repo, &body.labels, body.ephemeral)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(RegistrationTokenJson {
            token: minted.secret,
            expires_at: rfc3339(minted.expires_at),
        }),
    ))
}

/// `POST /runners/register` (201).
#[utoipa::path(
    post,
    path = "/api/v1/runners/register",
    request_body = RegisterRunnerBody,
    responses(
        (status = 201, description = "Registered runner", body = RegisteredRunnerJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
)]
pub async fn register_runner(
    State(state): State<ApiState>,
    body: Result<Json<RegisterRunnerBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<RegisteredRunnerJson>), ApiError> {
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let registered = state
        .core
        .register_runner(
            &body.registration_token,
            &body.name,
            &body.labels,
            &body.version,
            body.ephemeral,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisteredRunnerJson {
            runner_id: registered.runner_id,
            auth_token: registered.auth_secret,
        }),
    ))
}

/// `GET /repos/{owner}/{repo}/runners` (200).
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/runners",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Runners", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_runners(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let views = state
        .core
        .list_runners(Some(&auth.user), &owner, &repo)
        .await?;
    Ok(Json(
        json!({ "runners": views.iter().map(runner_json).collect::<Vec<_>>() }),
    ))
}

/// `DELETE /runners/{id}` (204).
#[utoipa::path(
    delete,
    path = "/api/v1/runners/{id}",
    params(("id" = i64, Path, description = "Runner id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn revoke_runner(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state.core.revoke_runner(&auth.user, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
