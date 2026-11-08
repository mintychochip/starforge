//! Notification routes (spec §10.4): the caller's inbox plus repo and Trail
//! subscription toggles.
//!
//! Handlers authenticate with `Scope::RepoRead` and delegate; all recipient
//! and permission logic lives on [`Core`]. A notification that belongs to
//! another user surfaces as `404` (the service returns `NotFound`).

use axum::Json;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use starforged_core::notifications::{NotificationView, WatchMode};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize, utoipa::ToSchema)]
pub struct NotificationJson {
    pub id: i64,
    pub repository: String,
    pub trail_number: Option<i64>,
    pub title: String,
    pub kind: String,
    pub reason: String,
    pub actor: Option<String>,
    pub url: String,
    pub created_at: String,
    pub read: bool,
}

fn notification_json(view: &NotificationView, base_url: &str) -> NotificationJson {
    NotificationJson {
        id: view.id,
        repository: format!("{}/{}", view.owner, view.repo),
        trail_number: view.trail_number,
        title: view.title.clone(),
        kind: view.kind.clone(),
        reason: view.reason.clone(),
        actor: view.actor.clone(),
        url: format!("{base_url}{}", view.url),
        created_at: rfc3339(view.created_at),
        read: view.read,
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct NotificationsJson {
    pub notifications: Vec<NotificationJson>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    /// `true` includes read rows; anything else (or absent) lists unread only.
    pub all: Option<String>,
    pub limit: Option<i64>,
}

/// `GET /api/v1/user/notifications[?all=true&limit=N]`.
#[utoipa::path(
    get,
    path = "/api/v1/user/notifications",
    params(
        ("all" = Option<String>, Query, description = "Include read notifications"),
        ("limit" = Option<i64>, Query, description = "Maximum rows"),
    ),
    responses(
        (status = 200, description = "Notifications", body = NotificationsJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_notifications(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Query(query): Query<ListQuery>,
) -> Result<Json<NotificationsJson>, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    let include_read = matches!(query.all.as_deref(), Some("true") | Some("1"));
    let limit = query.limit.unwrap_or(50);
    if limit < 0 {
        return Err(ApiError::Invalid("limit must not be negative".to_owned()));
    }
    let rows = state
        .core
        .notifications_for(&user, include_read, limit)
        .await?;
    Ok(Json(NotificationsJson {
        notifications: rows
            .iter()
            .map(|v| notification_json(v, &state.base_url))
            .collect(),
    }))
}

/// `POST /api/v1/user/notifications/{id}/read`.
#[utoipa::path(
    post,
    path = "/api/v1/user/notifications/{id}/read",
    params(("id" = i64, Path, description = "Notification id")),
    responses(
        (status = 200, description = "The notification, now read", body = NotificationJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn mark_notification_read(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(id): Path<i64>,
) -> Result<Json<NotificationJson>, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    let view = state.core.mark_notification_read(&user, id).await?;
    Ok(Json(notification_json(&view, &state.base_url)))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MarkedJson {
    pub marked: u64,
}

/// `POST /api/v1/user/notifications/read-all`.
#[utoipa::path(
    post,
    path = "/api/v1/user/notifications/read-all",
    responses(
        (status = 200, description = "Unread rows marked read", body = MarkedJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn mark_all_read(
    State(state): State<ApiState>,
    auth: ApiAuth,
) -> Result<Json<MarkedJson>, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    let marked = state.core.mark_all_notifications_read(&user).await?;
    Ok(Json(MarkedJson { marked }))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RepoSubscriptionJson {
    pub mode: Option<String>,
}

fn mode_json(mode: Option<WatchMode>) -> RepoSubscriptionJson {
    RepoSubscriptionJson {
        mode: mode.map(|m| m.as_str().to_owned()),
    }
}

/// `GET /api/v1/repos/{owner}/{repo}/subscription`.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/subscription",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Watch state", body = RepoSubscriptionJson),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_repo_subscription(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<RepoSubscriptionJson>, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    let mode = state.core.repo_watch(&user, &owner, &repo).await?;
    Ok(Json(mode_json(mode)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct PutRepoSubscriptionBody {
    pub mode: String,
}

/// `PUT /api/v1/repos/{owner}/{repo}/subscription`.
#[utoipa::path(
    put,
    path = "/api/v1/repos/{owner}/{repo}/subscription",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = PutRepoSubscriptionBody,
    responses(
        (status = 200, description = "Watch state", body = RepoSubscriptionJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Unknown mode", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn put_repo_subscription(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<PutRepoSubscriptionBody>, JsonRejection>,
) -> Result<Json<RepoSubscriptionJson>, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let mode = match body.mode.as_str() {
        "watching" => WatchMode::Watching,
        "ignoring" => WatchMode::Ignoring,
        other => {
            return Err(ApiError::Invalid(format!(
                "invalid mode '{other}': expected watching or ignoring"
            )));
        }
    };
    state
        .core
        .set_repo_watch(&user, &owner, &repo, Some(mode))
        .await?;
    Ok(Json(mode_json(Some(mode))))
}

/// `DELETE /api/v1/repos/{owner}/{repo}/subscription` (204).
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/subscription",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 204, description = "Watch row removed"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_repo_subscription(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    state
        .core
        .set_repo_watch(&user, &owner, &repo, None)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct TrailSubscriptionJson {
    pub subscribed: bool,
}

/// `GET /api/v1/repos/{owner}/{repo}/trails/{number}/subscription`.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/trails/{number}/subscription",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("number" = i64, Path, description = "Trail number"),
    ),
    responses(
        (status = 200, description = "Subscription state", body = TrailSubscriptionJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_trail_subscription(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<TrailSubscriptionJson>, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    let subscribed = state
        .core
        .trail_subscription(&user, &owner, &repo, number)
        .await?;
    Ok(Json(TrailSubscriptionJson { subscribed }))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct PutTrailSubscriptionBody {
    pub subscribed: bool,
}

/// `PUT /api/v1/repos/{owner}/{repo}/trails/{number}/subscription`.
#[utoipa::path(
    put,
    path = "/api/v1/repos/{owner}/{repo}/trails/{number}/subscription",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("number" = i64, Path, description = "Trail number"),
    ),
    request_body = PutTrailSubscriptionBody,
    responses(
        (status = 200, description = "Subscription state", body = TrailSubscriptionJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn put_trail_subscription(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<PutTrailSubscriptionBody>, JsonRejection>,
) -> Result<Json<TrailSubscriptionJson>, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    state
        .core
        .set_trail_subscription(&user, &owner, &repo, number, body.subscribed)
        .await?;
    Ok(Json(TrailSubscriptionJson {
        subscribed: body.subscribed,
    }))
}

/// `DELETE /api/v1/repos/{owner}/{repo}/trails/{number}/subscription` (204):
/// resets to the participation default.
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/trails/{number}/subscription",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("number" = i64, Path, description = "Trail number"),
    ),
    responses(
        (status = 204, description = "Subscription row removed"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_trail_subscription(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<StatusCode, ApiError> {
    let user = auth.require(Scope::RepoRead)?.user.clone();
    state
        .core
        .clear_trail_subscription(&user, &owner, &repo, number)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
