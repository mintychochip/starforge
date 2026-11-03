use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::{CreateRepo, RepoAccess};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;

#[derive(Serialize)]
pub struct RepoJson {
    id: i64,
    owner: String,
    name: String,
    full_name: String,
    description: String,
    visibility: &'static str,
    default_branch: String,
    clone_url: String,
    permission: &'static str,
    created_at: i64,
}

fn repo_json(state: &ApiState, access: RepoAccess) -> RepoJson {
    let repo = access.repo;
    RepoJson {
        clone_url: format!("{}/{}/{}.git", state.base_url, repo.owner, repo.name),
        full_name: repo.full_name(),
        id: repo.id,
        description: repo.description,
        visibility: repo.visibility.as_str(),
        default_branch: repo.default_branch,
        permission: access.permission.as_str(),
        created_at: repo.created_at,
        owner: repo.owner,
        name: repo.name,
    }
}

#[derive(Deserialize)]
pub struct CreateRepoBody {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "private")]
    visibility: String,
}

fn private() -> String {
    "private".to_owned()
}

pub async fn create(
    State(state): State<ApiState>,
    auth: ApiAuth,
    body: Result<Json<CreateRepoBody>, JsonRejection>,
) -> Result<(StatusCode, Json<RepoJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let visibility = Visibility::parse(&body.visibility).ok_or_else(|| {
        ApiError::Invalid("visibility must be public, internal, or private".into())
    })?;
    let repo = state
        .core
        .create_repo(
            &auth.user,
            CreateRepo {
                name: body.name,
                description: body.description,
                visibility,
            },
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(repo_json(
            &state,
            RepoAccess {
                repo,
                permission: Permission::Admin,
            },
        )),
    ))
}

pub async fn show(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<RepoJson>, ApiError> {
    let access = state.core.repo_for(auth.reader()?, &owner, &repo).await?;
    Ok(Json(repo_json(&state, access)))
}

#[derive(Serialize)]
pub struct CollaboratorJson {
    handle: String,
    permission: &'static str,
}

pub async fn list_collaborators(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<CollaboratorJson>>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let collaborators = state.core.collaborators(&auth.user, &owner, &repo).await?;
    Ok(Json(
        collaborators
            .into_iter()
            .map(|c| CollaboratorJson {
                handle: c.handle,
                permission: c.permission.as_str(),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct SetCollaboratorBody {
    permission: String,
}

pub async fn set_collaborator(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, handle)): Path<(String, String, String)>,
    body: Result<Json<SetCollaboratorBody>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let permission = Permission::parse(&body.permission).ok_or_else(|| {
        ApiError::Invalid("permission must be read, triage, write, maintain, or admin".into())
    })?;
    state
        .core
        .set_collaborator(&auth.user, &owner, &repo, &handle, permission)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_collaborator(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, handle)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .remove_collaborator(&auth.user, &owner, &repo, &handle)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
