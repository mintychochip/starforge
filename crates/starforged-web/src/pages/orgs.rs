//! Organization and team pages (spec §10.1): org creation, the public org
//! profile, org settings (general, base permission, delete), member
//! management, team pages, and the new-team form.
//!
//! The settings-page pattern holds throughout: an `XPage { nav_user, csrf,
//! … }` askama template plus a GET handler, and POST `Form { csrf }`
//! handlers with [`verify_csrf`] answering 303 or a 422 re-render. Every
//! permission decision stays in `starforged-core`; these handlers only map
//! [`CoreError`] to pages.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::orgs::{
    NewOrgInput, NewTeamInput, OrgPatch, OrgRole, OrgView, TeamPatch, team_slug,
};
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, MaybeUser, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoItem, nav};

/// The org profile: public fields for everyone, member counts and links for
/// members. Askama escapes every interpolated string, so hostile display
/// names and descriptions render inert.
#[derive(Template, WebTemplate)]
#[template(path = "org.html")]
pub struct OrgPage {
    nav_user: Option<NavUser>,
    handle: String,
    display_name: String,
    description: String,
    repos: Vec<RepoItem>,
    is_member: bool,
    is_owner: bool,
    member_count: Option<i64>,
    base_permission: Option<String>,
}

pub(crate) fn org_page(
    session: Option<&WebSession>,
    view: OrgView,
    repos: Vec<RepoItem>,
) -> OrgPage {
    OrgPage {
        nav_user: nav(session),
        handle: view.handle,
        display_name: view.display_name,
        description: view.description,
        repos,
        is_owner: view.viewer_role == Some(OrgRole::Owner),
        is_member: view.viewer_role.is_some(),
        member_count: view.member_count,
        base_permission: view.base_permission,
    }
}

/// The org profile when `handle` names an org; `None` for users and unknown
/// handles (other errors propagate).
pub(crate) async fn lookup_org(
    state: &AppState,
    viewer: Option<&starforged_core::accounts::User>,
    handle: &str,
) -> Result<Option<OrgView>, WebError> {
    match state.core.org(viewer, handle).await {
        Ok(view) => Ok(Some(view)),
        Err(CoreError::NotFound) => Ok(None),
        Err(other) => Err(other.into()),
    }
}

/// Owners manage the org; plain members get `Forbidden` (403), everyone else
/// `NotFound` (404). Site admins get no extra mutations (D9). Management
/// pages live under the reserved `/orgs/{org}` prefix, which can never
/// collide with a user or repository path, so no fallback is needed.
async fn require_owner(
    state: &AppState,
    session: &WebSession,
    handle: &str,
) -> Result<OrgView, WebError> {
    let view = state.core.org(Some(&session.user), handle).await?;
    match view.viewer_role {
        Some(OrgRole::Owner) => Ok(view),
        Some(OrgRole::Member) => Err(WebError::Forbidden),
        None => Err(WebError::NotFound),
    }
}

// --- New organization. -----------------------------------------------------

#[derive(Template, WebTemplate)]
#[template(path = "org_new.html")]
pub struct OrgNewPage {
    nav_user: Option<NavUser>,
    csrf: String,
    handle: String,
    display_name: String,
    description: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct NewOrgForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    handle: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    description: String,
}

fn new_page(
    session: &WebSession,
    handle: String,
    display_name: String,
    description: String,
    error: Option<String>,
) -> OrgNewPage {
    OrgNewPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        handle,
        display_name,
        description,
        error,
    }
}

pub async fn new_form(RequireUser(session): RequireUser) -> OrgNewPage {
    new_page(&session, String::new(), String::new(), String::new(), None)
}

pub async fn create(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<NewOrgForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let input = NewOrgInput {
        handle: form.handle.clone(),
        display_name: form.display_name.clone(),
        description: form.description.clone(),
    };
    match state.core.create_org(&session.user, input).await {
        Ok(org) => Ok(Redirect::to(&format!("/{}", org.handle)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = new_page(
                &session,
                form.handle,
                form.display_name,
                form.description,
                Some(message),
            );
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

// --- Org settings: general, base permission, delete. ------------------------

pub struct BaseChoice {
    value: &'static str,
    label: &'static str,
    selected: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "org_settings.html")]
pub struct OrgSettingsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    handle: String,
    display_name: String,
    description: String,
    base_choices: Vec<BaseChoice>,
    member_count: i64,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct GeneralForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
pub struct BaseForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    base_permission: String,
}

#[derive(Deserialize)]
pub struct DeleteOrgForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

async fn settings_page(
    state: &AppState,
    session: &WebSession,
    handle: &str,
    error: Option<String>,
) -> Result<Response, WebError> {
    let view = require_owner(state, session, handle).await?;
    let current = view.base_permission.unwrap_or_else(|| "none".into());
    let page = OrgSettingsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        handle: view.handle,
        display_name: view.display_name,
        description: view.description,
        base_choices: ["none", "read", "write"]
            .into_iter()
            .map(|value| BaseChoice {
                value,
                label: match value {
                    "none" => "No access",
                    "read" => "Read",
                    _ => "Write",
                },
                selected: value == current,
            })
            .collect(),
        member_count: view.member_count.unwrap_or(0),
        error,
    };
    Ok(page.into_response())
}

pub async fn settings(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(org): Path<String>,
) -> Result<Response, WebError> {
    settings_page(&state, &session, &org, None).await
}

pub async fn save_general(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(org): Path<String>,
    Form(form): Form<GeneralForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    let result = state
        .core
        .update_org(
            &session.user,
            &view.handle,
            OrgPatch {
                display_name: Some(form.display_name.clone()),
                description: Some(form.description.clone()),
                base_permission: None,
            },
        )
        .await;
    match result {
        Ok(updated) => {
            Ok(Redirect::to(&format!("/orgs/{}/settings", updated.handle)).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            settings_page(&state, &session, &view.handle, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn save_base(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(org): Path<String>,
    Form(form): Form<BaseForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    let result = state
        .core
        .update_org(
            &session.user,
            &view.handle,
            OrgPatch {
                display_name: None,
                description: None,
                base_permission: Some(form.base_permission.clone()),
            },
        )
        .await;
    match result {
        Ok(updated) => {
            Ok(Redirect::to(&format!("/orgs/{}/settings", updated.handle)).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            settings_page(&state, &session, &view.handle, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(org): Path<String>,
    Form(form): Form<DeleteOrgForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    if form.confirm.trim().to_ascii_lowercase() != view.handle {
        return settings_page(
            &state,
            &session,
            &view.handle,
            Some("type the organization handle to confirm".into()),
        )
        .await;
    }
    match state.core.delete_org(&session.user, &view.handle).await {
        Ok(()) => Ok(Redirect::to("/").into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            settings_page(&state, &session, &view.handle, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

// --- Members. ----------------------------------------------------------------

pub struct MemberRow {
    handle: String,
    display_name: String,
    role: &'static str,
}

#[derive(Template, WebTemplate)]
#[template(path = "org_members.html")]
pub struct OrgMembersPage {
    nav_user: Option<NavUser>,
    csrf: String,
    handle: String,
    members: Vec<MemberRow>,
    can_manage: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct MemberForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    handle: String,
    #[serde(default)]
    role: String,
}

fn member_rows(members: Vec<starforged_core::orgs::OrgMemberView>) -> Vec<MemberRow> {
    members
        .into_iter()
        .map(|m| MemberRow {
            handle: m.handle,
            display_name: m.display_name,
            role: m.role.as_str(),
        })
        .collect()
}

async fn members_page(
    state: &AppState,
    session: &WebSession,
    handle: &str,
    error: Option<String>,
) -> Result<Response, WebError> {
    let view = state.core.org(Some(&session.user), handle).await?;
    // The Core member-only fn 404s outsiders; owners additionally see the
    // management forms (`can_manage`).
    let rows = state.core.org_members(&session.user, &view.handle).await?;
    let page = OrgMembersPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        handle: view.handle,
        members: member_rows(rows),
        can_manage: view.viewer_role == Some(OrgRole::Owner),
        error,
    };
    Ok(page.into_response())
}

/// `/orgs/{org}/members`: members and site admins read; owners manage. The
/// Core member-only fn 404s everyone else, and anonymous viewers get 404,
/// never a login redirect: membership is not public.
pub async fn members(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path(org): Path<String>,
) -> Result<Response, WebError> {
    let Some(session) = session else {
        return Err(WebError::NotFound);
    };
    members_page(&state, &session, &org, None).await
}

pub async fn add_member(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(org): Path<String>,
    Form(form): Form<MemberForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    let role =
        OrgRole::parse(&form.role).ok_or_else(|| WebError::BadRequest("unknown role".into()))?;
    match state
        .core
        .set_org_member(&session.user, &view.handle, &form.handle, role)
        .await
    {
        Ok(_) => Ok(Redirect::to(&format!("/orgs/{}/members", view.handle)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            members_page(&state, &session, &view.handle, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn remove_member(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((org, handle)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    match state
        .core
        .remove_org_member(&session.user, &view.handle, &handle)
        .await
    {
        Ok(()) => Ok(Redirect::to(&format!("/orgs/{}/members", view.handle)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            members_page(&state, &session, &view.handle, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

// --- Teams. ------------------------------------------------------------------

pub struct TeamRow {
    name: String,
    slug: String,
    description: String,
    permission: &'static str,
    all_repos: bool,
}

pub struct TeamMemberRow {
    handle: String,
    display_name: String,
}

pub struct TeamRepoRow {
    name: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "org_teams.html")]
pub struct OrgTeamsPage {
    nav_user: Option<NavUser>,
    handle: String,
    teams: Vec<TeamRow>,
    can_manage: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "team_new.html")]
pub struct TeamNewPage {
    nav_user: Option<NavUser>,
    csrf: String,
    handle: String,
    name: String,
    description: String,
    permission_choices: Vec<&'static str>,
    error: Option<String>,
}

pub struct PermChoice {
    value: &'static str,
    selected: bool,
}

fn perm_choices(current: Permission) -> Vec<PermChoice> {
    Permission::ALL
        .into_iter()
        .map(|p| PermChoice {
            value: p.as_str(),
            selected: p == current,
        })
        .collect()
}

#[derive(Template, WebTemplate)]
#[template(path = "team.html")]
pub struct TeamPage {
    nav_user: Option<NavUser>,
    csrf: String,
    handle: String,
    name: String,
    slug: String,
    description: String,
    permission: &'static str,
    all_repos: bool,
    members: Vec<TeamMemberRow>,
    repos: Vec<TeamRepoRow>,
    permission_choices: Vec<PermChoice>,
    can_manage: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct NewTeamForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    permission: String,
    /// The "all repositories" checkbox: present only when ticked.
    #[serde(default)]
    all_repos: Option<String>,
}

#[derive(Deserialize)]
pub struct TeamSettingsForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    permission: String,
    #[serde(default)]
    all_repos: Option<String>,
}

#[derive(Deserialize)]
pub struct TeamMemberForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    handle: String,
}

#[derive(Deserialize)]
pub struct TeamRepoForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    repo: String,
}

#[derive(Deserialize)]
pub struct DeleteTeamForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

fn team_row(team: starforged_core::orgs::TeamView) -> TeamRow {
    TeamRow {
        name: team.name,
        slug: team.slug,
        description: team.description,
        permission: team.permission.as_str(),
        all_repos: team.all_repos,
    }
}

/// `/orgs/{org}/teams`: members and site admins list; everyone else 404s.
pub async fn teams(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path(org): Path<String>,
) -> Result<Response, WebError> {
    let Some(session) = session else {
        return Err(WebError::NotFound);
    };
    let view = state.core.org(Some(&session.user), &org).await?;
    let rows = state.core.teams(&session.user, &view.handle).await?;
    let page = OrgTeamsPage {
        nav_user: Some(NavUser::from_session(&session)),
        handle: view.handle.clone(),
        teams: rows.into_iter().map(team_row).collect(),
        can_manage: view.viewer_role == Some(OrgRole::Owner),
    };
    Ok(page.into_response())
}

fn team_new_page(
    session: &WebSession,
    handle: &str,
    form: &NewTeamForm,
    error: Option<String>,
) -> TeamNewPage {
    TeamNewPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        handle: handle.to_owned(),
        name: form.name.clone(),
        description: form.description.clone(),
        permission_choices: Permission::ALL
            .into_iter()
            .map(Permission::as_str)
            .collect(),
        error,
    }
}

pub async fn new_team_form(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(org): Path<String>,
) -> Result<Response, WebError> {
    let view = require_owner(&state, &session, &org).await?;
    let empty = NewTeamForm {
        csrf: String::new(),
        name: String::new(),
        description: String::new(),
        permission: String::new(),
        all_repos: None,
    };
    Ok(team_new_page(&session, &view.handle, &empty, None).into_response())
}

pub async fn create_team(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(org): Path<String>,
    Form(form): Form<NewTeamForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    let permission = Permission::parse(&form.permission)
        .ok_or_else(|| WebError::BadRequest("unknown permission".into()))?;
    let input = NewTeamInput {
        name: form.name.clone(),
        description: form.description.clone(),
        permission: permission.as_str().into(),
        all_repos: form.all_repos.is_some(),
    };
    match state
        .core
        .create_team(&session.user, &view.handle, input)
        .await
    {
        Ok(team) => {
            Ok(Redirect::to(&format!("/orgs/{}/teams/{}", view.handle, team.slug)).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = team_new_page(&session, &view.handle, &form, Some(message));
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

async fn team_page(
    state: &AppState,
    session: &WebSession,
    org: &str,
    slug: &str,
    error: Option<String>,
) -> Result<Response, WebError> {
    let view = state.core.org(Some(&session.user), org).await?;
    let team = state.core.team(&session.user, &view.handle, slug).await?;
    let members = state
        .core
        .team_members(&session.user, &view.handle, &team.slug)
        .await?;
    let repos = state
        .core
        .team_repos(&session.user, &view.handle, &team.slug)
        .await?;
    let page = TeamPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        handle: view.handle,
        name: team.name,
        slug: team.slug.clone(),
        description: team.description,
        permission: team.permission.as_str(),
        all_repos: team.all_repos,
        members: members
            .into_iter()
            .map(|m| TeamMemberRow {
                handle: m.handle,
                display_name: m.display_name,
            })
            .collect(),
        repos: repos
            .into_iter()
            .map(|r| TeamRepoRow { name: r.name })
            .collect(),
        permission_choices: perm_choices(team.permission),
        can_manage: view.viewer_role == Some(OrgRole::Owner),
        error,
    };
    Ok(page.into_response())
}

/// `/orgs/{org}/teams/{team}`: members, repositories, and settings. Members and
pub async fn team(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((org, slug)): Path<(String, String)>,
) -> Result<Response, WebError> {
    let Some(session) = session else {
        return Err(WebError::NotFound);
    };
    team_page(&state, &session, &org, &slug, None).await
}

pub async fn save_team(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((org, slug)): Path<(String, String)>,
    Form(form): Form<TeamSettingsForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    let permission = if form.permission.is_empty() {
        None
    } else {
        Some(
            Permission::parse(&form.permission)
                .ok_or_else(|| WebError::BadRequest("unknown permission".into()))?,
        )
    };
    let patch = TeamPatch {
        name: (!form.name.trim().is_empty()).then(|| form.name.clone()),
        description: Some(form.description.clone()),
        permission: permission.map(|p| p.as_str().into()),
        all_repos: Some(form.all_repos.is_some()),
    };
    match state
        .core
        .update_team(&session.user, &view.handle, &slug, patch)
        .await
    {
        Ok(updated) => Ok(
            Redirect::to(&format!("/orgs/{}/teams/{}", view.handle, updated.slug)).into_response(),
        ),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            team_page(&state, &session, &view.handle, &slug, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn delete_team(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((org, slug)): Path<(String, String)>,
    Form(form): Form<DeleteTeamForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    if team_slug(&form.confirm) != slug.trim().to_ascii_lowercase() {
        return team_page(
            &state,
            &session,
            &view.handle,
            &slug,
            Some("type the team slug to confirm".into()),
        )
        .await;
    }
    state
        .core
        .delete_team(&session.user, &view.handle, &slug)
        .await?;
    Ok(Redirect::to(&format!("/orgs/{}/teams", view.handle)).into_response())
}

pub async fn add_team_member(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((org, slug)): Path<(String, String)>,
    Form(form): Form<TeamMemberForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    match state
        .core
        .set_team_member(&session.user, &view.handle, &slug, &form.handle)
        .await
    {
        Ok(_) => Ok(Redirect::to(&format!("/orgs/{}/teams/{}", view.handle, slug)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            team_page(&state, &session, &view.handle, &slug, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn remove_team_member(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((org, slug, handle)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    state
        .core
        .remove_team_member(&session.user, &view.handle, &slug, &handle)
        .await?;
    Ok(Redirect::to(&format!("/orgs/{}/teams/{}", view.handle, slug)).into_response())
}

pub async fn add_team_repo(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((org, slug)): Path<(String, String)>,
    Form(form): Form<TeamRepoForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    match state
        .core
        .add_team_repo(&session.user, &view.handle, &slug, &form.repo)
        .await
    {
        Ok(()) => {
            Ok(Redirect::to(&format!("/orgs/{}/teams/{}", view.handle, slug)).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            team_page(&state, &session, &view.handle, &slug, Some(message)).await
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn remove_team_repo(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((org, slug, repo)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let view = require_owner(&state, &session, &org).await?;
    state
        .core
        .remove_team_repo(&session.user, &view.handle, &slug, &repo)
        .await?;
    Ok(Redirect::to(&format!("/orgs/{}/teams/{}", view.handle, slug)).into_response())
}
