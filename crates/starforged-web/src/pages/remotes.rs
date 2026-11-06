//! The repository mirrors settings page (M4b D4): the pull mirror's
//! configuration, sync now, and enable/disable. Maintain+ only; credentials
//! are write-only (the page shows `has_credentials`, never the secret).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::permission::Permission;
use starforged_core::remotes::PullMirrorView;
use starforged_core::sessions::WebSession;
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

#[derive(Template, WebTemplate)]
#[template(path = "mirrors.html")]
pub struct MirrorsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    mirror: Option<PullMirrorView>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct MirrorForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    auth: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    interval_secs: i64,
}

pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<MirrorsPage, WebError> {
    page(&state, &session, &owner, &repo, None)
        .await
        .map_err(WebError::from)
}

/// Configures (or updates) the pull mirror. Success redirects 303 back to
/// this page; a policy refusal re-renders with 422.
pub async fn save(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<MirrorForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let auth = match form.auth.trim() {
        "https" => starforged_core::remotes::ImportAuth::Https {
            username: form.username.trim().to_owned(),
            password: form.password.clone(),
        },
        "ssh" => starforged_core::remotes::ImportAuth::Ssh,
        "" | "none" => starforged_core::remotes::ImportAuth::None,
        _ => return Err(WebError::BadRequest("unknown mirror auth".into())),
    };
    let interval = if form.interval_secs == 0 {
        3600
    } else {
        form.interval_secs
    };
    match state
        .core
        .set_pull_mirror(
            &session.user,
            &owner,
            &repo,
            &starforged_core::remotes::PullMirrorInput {
                url: form.url.trim().to_owned(),
                auth,
                interval_secs: interval,
            },
        )
        .await
    {
        Ok(_) => Ok(Redirect::to(&format!("/{owner}/{repo}/settings/mirrors")).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&state, &session, &owner, &repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

/// Queues an immediate sync (deduplicated per repository).
pub async fn sync_now(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .sync_pull_mirror(&session.user, &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}/settings/mirrors")).into_response())
}

/// Toggles the mirror without forgetting its configuration; disabling
/// restores pushes.
pub async fn set_enabled(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<EnabledForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .set_pull_mirror_enabled(&session.user, &owner, &repo, form.enabled.is_some())
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}/settings/mirrors")).into_response())
}

#[derive(Deserialize)]
pub struct EnabledForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    /// A checkbox: present means "enable", absent means "disable".
    #[serde(default)]
    enabled: Option<String>,
}

/// Deletes the pull mirror; pushes are restored.
pub async fn delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .delete_pull_mirror(&session.user, &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}/settings/mirrors")).into_response())
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> CoreResult<MirrorsPage> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Maintain)
        .await?;
    let mirror = state.core.pull_mirror_for(access.repo.id).await?;
    Ok(MirrorsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "mirrors",
        mirror,
        error,
    })
}
