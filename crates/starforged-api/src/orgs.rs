//! Organizations (M3a A1, D8): org CRUD, members, and org repositories.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use starforged_core::orgs::{
    NewOrgInput, NewTeamInput, OrgMemberView, OrgRole, OrgView, TeamPatch, TeamView,
};
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

/// `POST /orgs/{org}/repos` (D5): org owners create repositories in the org.
/// The body matches user repository creation; anything else is 422.
pub async fn create_repo(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
    body: Result<Json<crate::repos::CreateRepoBody>, JsonRejection>,
) -> Result<(StatusCode, Json<RepoJson>), ApiError> {
    use starforged_core::permission::{Permission, Visibility};
    use starforged_core::repos::{CreateRepo, RepoAccess};
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let visibility = Visibility::parse(&body.visibility).ok_or_else(|| {
        ApiError::Invalid("visibility must be public, internal, or private".into())
    })?;
    let repo = state
        .core
        .create_repo(
            &auth.user,
            &org,
            CreateRepo {
                name: body.name,
                description: body.description,
                visibility,
                readme: body.readme,
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

// --- Teams (A2, D8). -----------------------------------------------------------

#[derive(Serialize)]
pub struct TeamJson {
    name: String,
    slug: String,
    description: String,
    permission: String,
    all_repos: bool,
}

fn team_json(view: TeamView) -> TeamJson {
    TeamJson {
        name: view.name,
        slug: view.slug,
        description: view.description,
        permission: view.permission.as_str().to_owned(),
        all_repos: view.all_repos,
    }
}

#[derive(Serialize)]
pub struct TeamMemberJson {
    handle: String,
    display_name: String,
}

#[derive(Serialize)]
pub struct TeamRepoJson {
    owner: String,
    name: String,
    full_name: String,
    description: String,
    visibility: &'static str,
}

#[derive(Deserialize)]
pub struct CreateTeamBody {
    name: String,
    #[serde(default)]
    description: String,
    permission: String,
    #[serde(default)]
    all_repos: bool,
}

/// `POST /orgs/{org}/teams`: org owners only.
pub async fn create_team(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
    body: Result<Json<CreateTeamBody>, JsonRejection>,
) -> Result<(StatusCode, Json<TeamJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .create_team(
            &auth.user,
            &org,
            NewTeamInput {
                name: body.name,
                description: body.description,
                permission: body.permission,
                all_repos: body.all_repos,
            },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(team_json(view))))
}

/// `GET /orgs/{org}/teams`: members and site admins only, 404 otherwise.
pub async fn list_teams(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(org): Path<String>,
) -> Result<Json<Vec<TeamJson>>, ApiError> {
    let Some(user) = auth.reader()? else {
        return Err(ApiError::NotFound);
    };
    let teams = state.core.teams(user, &org).await?;
    Ok(Json(teams.into_iter().map(team_json).collect()))
}

/// `GET /orgs/{org}/teams/{team}`: members and site admins only, 404 otherwise.
pub async fn show_team(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team)): Path<(String, String)>,
) -> Result<Json<TeamJson>, ApiError> {
    let Some(user) = auth.reader()? else {
        return Err(ApiError::NotFound);
    };
    let view = state.core.team(user, &org, &team).await?;
    Ok(Json(team_json(view)))
}

#[derive(Deserialize)]
pub struct PatchTeamBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permission: Option<String>,
    #[serde(default)]
    all_repos: Option<bool>,
}

/// `PATCH /orgs/{org}/teams/{team}`: org owners only.
pub async fn patch_team(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team)): Path<(String, String)>,
    body: Result<Json<PatchTeamBody>, JsonRejection>,
) -> Result<Json<TeamJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .update_team(
            &auth.user,
            &org,
            &team,
            TeamPatch {
                name: body.name,
                description: body.description,
                permission: body.permission,
                all_repos: body.all_repos,
            },
        )
        .await?;
    Ok(Json(team_json(view)))
}

/// `DELETE /orgs/{org}/teams/{team}`: org owners only.
pub async fn delete_team(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state.core.delete_team(&auth.user, &org, &team).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /orgs/{org}/teams/{team}/members`: members and site admins only.
pub async fn list_team_members(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team)): Path<(String, String)>,
) -> Result<Json<Vec<TeamMemberJson>>, ApiError> {
    let Some(user) = auth.reader()? else {
        return Err(ApiError::NotFound);
    };
    let members = state.core.team_members(user, &org, &team).await?;
    Ok(Json(
        members
            .into_iter()
            .map(|m| TeamMemberJson {
                handle: m.handle,
                display_name: m.display_name,
            })
            .collect(),
    ))
}

/// `PUT /orgs/{org}/teams/{team}/members/{handle}`: org owners only.
pub async fn set_team_member(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team, handle)): Path<(String, String, String)>,
) -> Result<Json<TeamMemberJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let view = state
        .core
        .set_team_member(&auth.user, &org, &team, &handle)
        .await?;
    Ok(Json(TeamMemberJson {
        handle: view.handle,
        display_name: view.display_name,
    }))
}

/// `DELETE /orgs/{org}/teams/{team}/members/{handle}`: org owners only.
pub async fn remove_team_member(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team, handle)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .remove_team_member(&auth.user, &org, &team, &handle)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /orgs/{org}/teams/{team}/repos`: members and site admins only.
pub async fn list_team_repos(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team)): Path<(String, String)>,
) -> Result<Json<Vec<TeamRepoJson>>, ApiError> {
    let Some(user) = auth.reader()? else {
        return Err(ApiError::NotFound);
    };
    let repos = state.core.team_repos(user, &org, &team).await?;
    Ok(Json(
        repos
            .into_iter()
            .map(|r| TeamRepoJson {
                full_name: r.full_name(),
                owner: r.owner,
                name: r.name,
                description: r.description,
                visibility: r.visibility.as_str(),
            })
            .collect(),
    ))
}

/// `PUT /orgs/{org}/teams/{team}/repos/{repo}`: org owners only.
pub async fn add_team_repo(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team, repo)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .add_team_repo(&auth.user, &org, &team, &repo)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /orgs/{org}/teams/{team}/repos/{repo}`: org owners only.
pub async fn remove_team_repo(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((org, team, repo)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .remove_team_repo(&auth.user, &org, &team, &repo)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
