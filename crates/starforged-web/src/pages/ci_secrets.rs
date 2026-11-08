//! The repository CI secrets settings page: admin-only list of secret
//! names, create-or-rotate, and delete. Values are write-only: they never
//! render, never echo back, and never reach logs.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::ci::{CiSecretInput, SecretView};
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

#[derive(Template, WebTemplate)]
#[template(path = "repo_settings_ci_secrets.html")]
pub struct CiSecretsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    secrets: Vec<SecretView>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct SecretForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

fn settings_url(owner: &str, repo: &str) -> String {
    format!("/{owner}/{repo}/settings/ci-secrets")
}

pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<CiSecretsPage, WebError> {
    page(&state, &session, &owner, &repo, None)
        .await
        .map_err(WebError::from)
}

/// Creates or rotates a secret (admin-only). Success redirects 303 back
/// to the list; validation failures re-render with 422. The submitted
/// value is dropped with the form and never rendered again.
pub async fn create_or_rotate(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<SecretForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .create_ci_secret(
            &session.user,
            &owner,
            &repo,
            CiSecretInput {
                name: &form.name,
                value: &form.value,
                // The settings form sets the value only; the proxy binding
                // is set through the API (empty host = no proxy injection).
                host: "",
                header: "Authorization",
                redact_in_sessions: true,
            },
        )
        .await
    {
        Ok(_) => Ok(Redirect::to(&settings_url(&owner, &repo)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&state, &session, &owner, &repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, name)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .delete_ci_secret(&session.user, &owner, &repo, &name)
        .await?;
    Ok(Redirect::to(&settings_url(&owner, &repo)).into_response())
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> CoreResult<CiSecretsPage> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Admin)
        .await?;
    let secrets = state
        .core
        .list_ci_secrets(&session.user, owner, repo)
        .await?;
    Ok(CiSecretsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "ci-secrets",
        secrets,
        error,
    })
}
