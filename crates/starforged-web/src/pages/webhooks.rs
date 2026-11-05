//! The repository webhooks settings page (M2c H5): maintainer-only list,
//! create (URL + event checkboxes), enable/disable, and delete.
//!
//! The plaintext secret renders exactly once, in the `200` response to the
//! creating POST; later renders carry `has_secret` only (the list DTO never
//! contains it). Validation failures re-render with `422`.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;
use starforged_core::webhooks::{DeliveryDetail, DeliverySummary, EVENT_TYPES, WebhookDto};
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
    logs: Vec<HookLog>,
    all_events: Vec<&'static str>,
    created_url: Option<String>,
    created_secret: Option<String>,
    error: Option<String>,
}

/// One hook with its last 20 logged attempts, newest first.
pub struct HookLog {
    pub hook: WebhookDto,
    pub deliveries: Vec<DeliverySummary>,
}

#[derive(Template, WebTemplate)]
#[template(path = "webhook_delivery.html")]
pub struct DeliveryPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    hook: WebhookDto,
    delivery: DeliveryDetail,
    redelivered: Option<String>,
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

#[derive(Deserialize)]
pub struct RedeliveredQuery {
    redelivered: Option<String>,
}

/// One logged attempt of a hook in full (maintainer-only), with the stored
/// request and response. Receiver content renders escaped, never as HTML.
pub async fn show_delivery(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id, row)): Path<(String, String, i64, i64)>,
    Query(query): Query<RedeliveredQuery>,
) -> Result<DeliveryPage, WebError> {
    delivery_page(
        &state,
        &session,
        &owner,
        &repo,
        id,
        row,
        query.redelivered,
        None,
    )
    .await
    .map_err(WebError::from)
}

/// Replays a logged attempt as a new delivery (maintainer-only): 303 back
/// to the logged row, naming the new delivery id. Inactive hooks and
/// archived repos re-render with 422.
pub async fn redeliver(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id, row)): Path<(String, String, i64, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .redeliver(&session.user, &owner, &repo, id, row)
        .await
    {
        Ok(delivery_id) => Ok(Redirect::to(&format!(
            "/{owner}/{repo}/settings/hooks/{id}/deliveries/{row}?redelivered={delivery_id}"
        ))
        .into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = delivery_page(
                &state,
                &session,
                &owner,
                &repo,
                id,
                row,
                None,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn delivery_page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    id: i64,
    row: i64,
    redelivered: Option<String>,
    error: Option<String>,
) -> CoreResult<DeliveryPage> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Maintain)
        .await?;
    let hooks = state
        .core
        .list_webhooks(Some(&session.user), owner, repo)
        .await?;
    let hook = hooks
        .iter()
        .find(|hook| hook.id == id)
        .ok_or(CoreError::NotFound)?
        .clone();
    let delivery = state
        .core
        .get_delivery(&session.user, owner, repo, id, row)
        .await?;
    Ok(DeliveryPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "hooks",
        hook,
        delivery,
        redelivered,
        error,
    })
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
    let mut logs = Vec::with_capacity(hooks.len());
    for hook in hooks {
        let deliveries = state
            .core
            .list_deliveries(&session.user, owner, repo, hook.id, Some(20))
            .await?;
        logs.push(HookLog { hook, deliveries });
    }
    let (created_url, created_secret) = created
        .map(|(url, secret)| (Some(url), Some(secret)))
        .unwrap_or((None, None));
    Ok(WebhooksPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "hooks",
        logs,
        all_events: EVENT_TYPES.to_vec(),
        created_url,
        created_secret,
        error,
    })
}
