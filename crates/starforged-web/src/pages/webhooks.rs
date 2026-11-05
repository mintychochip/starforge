//! The repository webhooks settings page (M2c H5): maintainer-only list,
//! create (URL + event checkboxes), enable/disable, and delete.
//!
//! The plaintext secret renders exactly once, in the `200` response to the
//! creating POST; later renders carry `has_secret` only (the list DTO never
//! contains it). Validation failures re-render with `422`.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;
use starforged_core::webhooks::{EVENT_TYPES, WebhookDto};
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

#[derive(Template, WebTemplate)]
#[template(path = "webhooks.html")]
pub struct WebhooksPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    hooks: Vec<WebhookDto>,
    all_events: Vec<&'static str>,
    created_url: Option<String>,
    created_secret: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateHookForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    events: Vec<String>,
}
pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<WebhooksPage, WebError> {
    page(&state, &session, &owner, &repo, None, None)
        .await
        .map_err(WebError::from)
}

pub async fn create(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CreateHookForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .create_webhook(&session.user, &owner, &repo, &form.url, &form.events)
        .await
    {
        Ok((view, secret)) => {
            let page = page(
                &state,
                &session,
                &owner,
                &repo,
                None,
                Some((view.url.clone(), secret)),
            )
            .await?;
            Ok((StatusCode::OK, page).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&state, &session, &owner, &repo, Some(message), None).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .delete_webhook(&session.user, &owner, &repo, id)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}/settings/hooks")).into_response())
}

pub async fn toggle(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let hooks = state
        .core
        .list_webhooks(Some(&session.user), &owner, &repo)
        .await?;
    let hook = hooks
        .iter()
        .find(|hook| hook.id == id)
        .ok_or(CoreError::NotFound)?;
    state
        .core
        .set_webhook_active(&session.user, &owner, &repo, id, !hook.active)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}/settings/hooks")).into_response())
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
    created: Option<(String, String)>,
) -> CoreResult<WebhooksPage> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Maintain)
        .await?;
    let hooks = state
        .core
        .list_webhooks(Some(&session.user), owner, repo)
        .await?;
    let (created_url, created_secret) = created
        .map(|(url, secret)| (Some(url), Some(secret)))
        .unwrap_or((None, None));
    Ok(WebhooksPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "hooks",
        hooks,
        all_events: EVENT_TYPES.to_vec(),
        created_url,
        created_secret,
        error,
    })
}
