//! The repository settings page (forge-basics design §5.2): general settings for maintainers; visibility and
//! the actions after it for admins.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::Repo;
use starforged_core::sessions::WebSession;
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

pub struct BranchOption {
    name: String,
    selected: bool,
}

pub struct VisibilityChoice {
    value: &'static str,
    label: &'static str,
    checked: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_settings.html")]
pub struct RepoSettingsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    description: String,
    branches: Vec<BranchOption>,
    visibility_choices: Vec<VisibilityChoice>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct GeneralForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    description: String,
    /// Absent while the repository has no branches.
    #[serde(default)]
    default_branch: String,
}

#[derive(Deserialize)]
pub struct VisibilityForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    visibility: String,
}

pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<RepoSettingsPage, WebError> {
    page(&state, &session, &owner, &repo, None).await
}

pub async fn save_general(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<GeneralForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let user = &session.user;
    let result = match state
        .core
        .set_repo_description(user, &owner, &repo, &form.description)
        .await
    {
        Ok(updated) if form.default_branch.is_empty() => Ok(updated),
        Ok(_) => {
            state
                .core
                .set_default_branch(user, &owner, &repo, &form.default_branch)
                .await
        }
        Err(err) => Err(err),
    };
    finish(&state, &session, &owner, &repo, result).await
}

pub async fn change_visibility(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<VisibilityForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let visibility = Visibility::parse(&form.visibility)
        .ok_or_else(|| WebError::BadRequest("unknown visibility".into()))?;
    let result = state
        .core
        .set_visibility(&session.user, &owner, &repo, visibility)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}

#[derive(Deserialize)]
pub struct RenameForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    new_name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<RenameForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state
        .core
        .rename_repo(&session.user, &owner, &repo, &form.new_name)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}

pub async fn archive(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state.core.archive_repo(&session.user, &owner, &repo).await;
    finish(&state, &session, &owner, &repo, result).await
}

pub async fn unarchive(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state
        .core
        .unarchive_repo(&session.user, &owner, &repo)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}

/// After a settings action: back to the settings page under the repository's current name, or this page
/// again with the message when the input was refused.
pub(crate) async fn finish(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    result: CoreResult<Repo>,
) -> Result<Response, WebError> {
    match result {
        Ok(updated) => Ok(
            Redirect::to(&format!("/{}/{}/settings", updated.owner, updated.name)).into_response(),
        ),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(state, session, owner, repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> Result<RepoSettingsPage, WebError> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Maintain)
        .await?;
    let branches = state
        .core
        .branches(&access)
        .await?
        .into_iter()
        .map(|name| BranchOption {
            selected: name == access.repo.default_branch,
            name,
        })
        .collect();
    let current = access.repo.visibility;
    let visibility_choices = [
        (Visibility::Private, "Private"),
        (
            Visibility::Internal,
            "Internal (every signed-in user can read)",
        ),
        (Visibility::Public, "Public"),
    ]
    .into_iter()
    .map(|(visibility, label)| VisibilityChoice {
        value: visibility.as_str(),
        label,
        checked: visibility == current,
    })
    .collect();
    Ok(RepoSettingsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "general",
        description: access.repo.description.clone(),
        branches,
        visibility_choices,
        error,
    })
}
