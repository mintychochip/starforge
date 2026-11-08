//! Notifications inbox and notification settings (Phase 2): the inbox lists
//! rows newest first, `/open` marks one read and redirects to its Trail, and
//! the settings page carries the email toggle and the watched repositories.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::notifications::WatchMode;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, format_age};

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub struct NotificationRow {
    id: i64,
    repository: String,
    label: String,
    open_href: String,
    reason: String,
    actor: String,
    age: String,
    read: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "notifications.html")]
pub struct NotificationsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    rows: Vec<NotificationRow>,
    show_all: bool,
}

#[derive(Deserialize)]
pub struct ListQuery {
    all: Option<String>,
}

/// `GET /notifications` (`?all=1` includes read rows).
pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Query(query): Query<ListQuery>,
) -> Result<NotificationsPage, WebError> {
    let show_all = query.all.as_deref() == Some("1");
    let now = unix_now();
    let views = state
        .core
        .notifications_for(&session.user, show_all, 100)
        .await?;
    Ok(NotificationsPage {
        rows: views
            .into_iter()
            .map(|view| {
                let label = match view.trail_number {
                    Some(number) => format!("#{} {}", number, view.title),
                    None => view.title.clone(),
                };
                NotificationRow {
                    id: view.id,
                    repository: format!("{}/{}", view.owner, view.repo),
                    label,
                    open_href: format!("/notifications/{}/open", view.id),
                    reason: view.reason.clone(),
                    actor: view.actor.clone().unwrap_or_else(|| "starforge".to_owned()),
                    age: format_age(now, view.created_at),
                    read: view.read,
                }
            })
            .collect(),
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        show_all,
    })
}

/// `GET /notifications/{id}/open`: marks the row read and redirects to its URL.
pub async fn open(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    let view = state.core.mark_notification_read(&session.user, id).await?;
    Ok(Redirect::to(&view.url).into_response())
}

/// `POST /notifications/{id}/read`.
pub async fn read(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.mark_notification_read(&session.user, id).await?;
    Ok(Redirect::to("/notifications").into_response())
}

/// `POST /notifications/read-all`.
pub async fn read_all(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .mark_all_notifications_read(&session.user)
        .await?;
    Ok(Redirect::to("/notifications").into_response())
}

pub struct WatchedRow {
    owner: String,
    repo: String,
    mode: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_notifications.html")]
pub struct SettingsNotificationsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    email_enabled: bool,
    watched: Vec<WatchedRow>,
}

async fn settings_page(
    state: &AppState,
    session: &WebSession,
) -> Result<SettingsNotificationsPage, WebError> {
    let email_enabled = state.core.notification_email(&session.user).await?;
    let watched = state
        .core
        .watched_repos(&session.user)
        .await?
        .into_iter()
        .map(|repo| WatchedRow {
            owner: repo.owner,
            repo: repo.repo,
            mode: repo.mode.as_str().to_owned(),
        })
        .collect();
    Ok(SettingsNotificationsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "notifications",
        email_enabled,
        watched,
    })
}

/// `GET /settings/notifications`.
pub async fn settings_show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<SettingsNotificationsPage, WebError> {
    settings_page(&state, &session).await
}

#[derive(Deserialize)]
pub struct SettingsForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    notify_email: Option<String>,
}

/// `POST /settings/notifications`: an unchecked checkbox means off.
pub async fn settings_save(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<SettingsForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let enabled = form.notify_email.is_some();
    state
        .core
        .set_notification_email(&session.user, enabled)
        .await?;
    Ok(Redirect::to("/settings/notifications").into_response())
}

#[derive(Deserialize)]
pub struct WatchForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    mode: String,
}

/// `POST /{owner}/{repo}/watch`: `mode` is `watching`, `ignoring`, or `none`.
/// The core answers `NotFound` for a repository the user cannot read.
pub async fn watch(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<WatchForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let mode = match form.mode.as_str() {
        "watching" => Some(WatchMode::Watching),
        "ignoring" => Some(WatchMode::Ignoring),
        "none" => None,
        _ => return Err(WebError::BadRequest("Unknown watch mode.".to_owned())),
    };
    state
        .core
        .set_repo_watch(&session.user, &owner, &repo, mode)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}")).into_response())
}

#[derive(Deserialize)]
pub struct SubscriptionForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    subscribed: String,
}

/// `POST /{owner}/{repo}/trails/{number}/subscription`: `subscribed` is `1` or `0`.
pub async fn subscription(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<SubscriptionForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let subscribed = match form.subscribed.as_str() {
        "1" => true,
        "0" => false,
        _ => {
            return Err(WebError::BadRequest(
                "Unknown subscription value.".to_owned(),
            ));
        }
    };
    state
        .core
        .set_trail_subscription(&session.user, &owner, &repo, number, subscribed)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}/trails/{number}")).into_response())
}
