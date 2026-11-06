//! Organizations (M3a A1, D8): org CRUD, members, and org repositories.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use starforged_core::orgs::{NewOrgInput, OrgMemberView, OrgRole, OrgView};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::repos::{RepoJson, repo_json};

#[derive(Serialize)]
pub struct OrgJson {
    handle: String,
    display_name: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_permission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
}

fn org_json(view: OrgView) -> OrgJson {
    OrgJson {
        handle: view.handle,
        display_name: view.display_name,
        description: view.description,
        base_permission: view.base_permission,
        member_count: view.member_count,
        role: view.viewer_role.map(|r| r.as_str()),
    }
}

#[derive(Serialize)]
pub struct OrgMemberJson {
    handle: String,
    display_name: String,
    role: &'static str,
}

fn member_json(view: OrgMemberView) -> OrgMemberJson {
    OrgMemberJson {
        handle: view.handle,
        display_name: view.display_name,
        role: view.role.as_str(),
    }
}

#[derive(Deserialize)]
pub struct CreateOrgBody {
    handle: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    description: String,
}

/// `POST /orgs`: any active signed-in user may create an org and becomes its
/// first owner (D1). Handle clashes and reserved handles are 422.
pub async fn create(
    State(state): State<ApiState>,
    auth: ApiAuth,
    body: Result<Json<CreateOrgBody>, JsonRejection>,
) -> Result<(StatusCode, Json<OrgJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .create_org(
            &auth.user,
            NewOrgInput {
                handle: body.handle,
                display_name: body.display_name,
                description: body.description,
            },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(org_json(view))))
}

/// `GET /orgs/{org}`: the public profile; member-only fields appear for
/// members and site admins.
pub async fn show(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
) -> Result<Json<OrgJson>, ApiError> {
    let view = state.core.org(auth.reader()?, &org).await?;
    Ok(Json(org_json(view)))
}

#[derive(Deserialize)]
pub struct PatchOrgBody {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    base_permission: Option<String>,
}

/// `PATCH /orgs/{org}`: owners only.
pub async fn patch(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
    body: Result<Json<PatchOrgBody>, JsonRejection>,
) -> Result<Json<OrgJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .update_org(
            &auth.user,
            &org,
            starforged_core::orgs::OrgPatch {
                display_name: body.display_name,
                description: body.description,
                base_permission: body.base_permission,
            },
        )
        .await?;
    Ok(Json(org_json(view)))
}

/// `DELETE /orgs/{org}` (D7): owners only, and only when the org owns no
/// repositories (422 otherwise).
pub async fn delete(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state.core.delete_org(&auth.user, &org).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /orgs/{org}/repos`: the org's repositories the viewer can read.
pub async fn list_repos(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
) -> Result<Json<Vec<RepoJson>>, ApiError> {
    let repos = state.core.repos_of(auth.reader()?, &org).await?;
    let mut out = Vec::with_capacity(repos.len());
    for repo in repos {
        let permission = state
            .core
            .permission_on(&repo, auth.reader()?)
            .await?
            .ok_or(ApiError::NotFound)?;
        out.push(repo_json(
            &state,
            starforged_core::repos::RepoAccess { repo, permission },
        ));
    }
    Ok(Json(out))
}

/// `GET /orgs/{org}/members`: members and site admins only, 404 otherwise.
pub async fn list_members(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
) -> Result<Json<Vec<OrgMemberJson>>, ApiError> {
    let Some(user) = auth.reader()? else {
        return Err(ApiError::NotFound);
    };
    let members = state.core.org_members(user, &org).await?;
    Ok(Json(members.into_iter().map(member_json).collect()))
}

#[derive(Deserialize)]
pub struct SetMemberBody {
    role: String,
}

/// `PUT /orgs/{org}/members/{handle}`: owners add users or change roles.
pub async fn set_member(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, handle)): Path<(String, String)>,
    body: Result<Json<SetMemberBody>, JsonRejection>,
) -> Result<Json<OrgMemberJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let role = OrgRole::parse(&body.role)
        .ok_or_else(|| ApiError::Invalid("role must be owner or member".into()))?;
    let view = state
        .core
        .set_org_member(&auth.user, &org, &handle, role)
        .await?;
    Ok(Json(member_json(view)))
}

/// `DELETE /orgs/{org}/members/{handle}`: owners remove anyone, members leave.
pub async fn remove_member(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, handle)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .remove_org_member(&auth.user, &org, &handle)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
