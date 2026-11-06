//! The "Import from GitHub" settings page (M4c G3, spec §8.6): start
//! form (CSRF-gated, admin only), live progress counts, the dropped
//! assignees summary, and the last (scrubbed) error.
//!
//! The GitHub token is write-only: the form takes it in a password
//! input and the page never renders it back. Counts, state, and dropped
//! assignees render escaped (askama); no untrusted HTML is generated
//! here — imported content itself renders only on the Trail pages
//! through the sanitizing Markdown pipeline.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::github::status::GithubImportView;
use starforged_core::sessions::WebSession;
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};
use starforged_core::permission::Permission;

#[derive(Template, WebTemplate)]
#[template(path = "github_import.html")]
pub struct GithubImportPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    import: Option<GithubImportView>,
    dropped: Vec<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct GithubImportForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    repository: String,
    #[serde(default)]
    token: String,
}

pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<GithubImportPage, WebError> {
    page(&state, &session, &owner, &repo, None)
        .await
        .map_err(WebError::from)
}

/// Starts the import. Success redirects 303 back to this page (the
/// progress view); a refusal (archived, already has Trails, bad slug)
/// re-renders with 422. The token is passed straight to core, which
/// seals it; it is never stored in a variable that outlives this call
/// and never rendered.
pub async fn start(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<GithubImportForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .start_github_import(
            &session.user,
            &owner,
            &repo,
            form.repository.trim(),
            form.token.trim(),
        )
        .await
    {
        Ok(_) => {
            Ok(Redirect::to(&format!("/{owner}/{repo}/settings/github-import")).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&state, &session, &owner, &repo, Some(message)).await?;
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
) -> CoreResult<GithubImportPage> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Admin)
        .await?;
    let import = state
        .core
        .github_import_for(Some(&session.user), owner, repo)
        .await?;
    let dropped = import
        .as_ref()
        .map(|row| {
            row.dropped_assignees
                .split(';')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(GithubImportPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "github-import",
        import,
        dropped,
        error,
    })
}
