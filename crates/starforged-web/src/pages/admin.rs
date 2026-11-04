//! Site administration (spec §12).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::CoreResult;
use starforged_core::accounts::User;
use starforged_core::admin::{AdminOverview, UserSummary};
use starforged_core::passwords::AdminReset;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, RequireAdmin, verify_csrf};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Template, WebTemplate)]
#[template(path = "admin_overview.html")]
pub struct OverviewPage {
    nav_user: Option<NavUser>,
    // Plan-mandated shape; the overview has no form, so only `nav_user`'s token reaches `base.html`.
    #[allow(dead_code)]
    csrf: String,
    admin_tab: &'static str,
    overview: AdminOverview,
    git_version: String,
    app_version: &'static str,
}

pub async fn overview(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
) -> Result<OverviewPage, WebError> {
    let overview = state.core.admin_overview(&session.user).await?;
    let (major, minor) = starforged_git::command::check_version()
        .await
        .map_err(|e| WebError::Internal(e.to_string()))?;
    Ok(OverviewPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "overview",
        overview,
        git_version: format!("{major}.{minor}"),
        app_version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_users.html")]
pub struct UsersPage {
    nav_user: Option<NavUser>,
    #[allow(dead_code)]
    csrf: String,
    admin_tab: &'static str,
    query: String,
    users: Vec<User>,
}

#[derive(Deserialize)]
pub struct ListParams {
    q: Option<String>,
}

pub async fn users(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<ListParams>,
) -> Result<UsersPage, WebError> {
    let query = params.q.unwrap_or_default();
    let list = state
        .core
        .admin_list_users(&session.user, &query.to_lowercase(), 200)
        .await?;
    Ok(UsersPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "users",
        query,
        users: list,
    })
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_user.html")]
pub struct DetailPage {
    nav_user: Option<NavUser>,
    csrf: String,
    admin_tab: &'static str,
    summary: UserSummary,
    error: Option<String>,
    notice: Option<String>,
}

pub async fn user_detail(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
) -> Result<DetailPage, WebError> {
    detail_page(&state, &session, &handle.to_lowercase(), None, None).await
}

/// Renders the user detail page, with an optional error (input refused, 422)
/// or notice (reset link issued, 200).
async fn detail_page(
    state: &AppState,
    session: &WebSession,
    handle: &str,
    error: Option<String>,
    notice: Option<String>,
) -> Result<DetailPage, WebError> {
    let summary = state.core.admin_get_user(&session.user, handle).await?;
    Ok(DetailPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "users",
        summary,
        error,
        notice,
    })
}

/// After a user action: back to the detail page, or the detail page again with
/// the message when the input was refused (mirrors `repo_settings::finish`).
async fn finish(
    state: &AppState,
    session: &WebSession,
    handle: &str,
    result: CoreResult<()>,
    success_to: String,
) -> Result<Response, WebError> {
    match result {
        Ok(()) => Ok(Redirect::to(&success_to).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = detail_page(state, session, handle, Some(message), None).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

/// Looks up the action target; a missing handle answers `NotFound` (404).
async fn target_id(state: &AppState, session: &WebSession, handle: &str) -> Result<i64, WebError> {
    Ok(state
        .core
        .admin_get_user(&session.user, handle)
        .await?
        .user
        .id)
}

pub async fn suspend(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let handle = handle.to_lowercase();
    let id = target_id(&state, &session, &handle).await?;
    let result = state.core.suspend_user(&session.user, id).await.map(|_| ());
    finish(
        &state,
        &session,
        &handle,
        result,
        format!("/admin/users/{handle}"),
    )
    .await
}

pub async fn unsuspend(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let handle = handle.to_lowercase();
    let id = target_id(&state, &session, &handle).await?;
    let result = state
        .core
        .unsuspend_user(&session.user, id)
        .await
        .map(|_| ());
    finish(
        &state,
        &session,
        &handle,
        result,
        format!("/admin/users/{handle}"),
    )
    .await
}

pub async fn grant_admin(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let handle = handle.to_lowercase();
    let id = target_id(&state, &session, &handle).await?;
    let result = state.core.grant_admin(&session.user, id).await.map(|_| ());
    finish(
        &state,
        &session,
        &handle,
        result,
        format!("/admin/users/{handle}"),
    )
    .await
}

pub async fn revoke_admin(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let handle = handle.to_lowercase();
    let id = target_id(&state, &session, &handle).await?;
    let result = state.core.revoke_admin(&session.user, id).await.map(|_| ());
    finish(
        &state,
        &session,
        &handle,
        result,
        format!("/admin/users/{handle}"),
    )
    .await
}

#[derive(Deserialize)]
pub struct DeleteUserForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

/// Deleting removes the account, so success lands on the users list: the detail page is gone.
pub async fn delete_user(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
    Form(form): Form<DeleteUserForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let handle = handle.to_lowercase();
    if form.confirm.trim().to_lowercase() != handle {
        return finish(
            &state,
            &session,
            &handle,
            Err(CoreError::Invalid(format!("Type {handle} to confirm."))),
            "/admin/users".to_owned(),
        )
        .await;
    }
    let id = target_id(&state, &session, &handle).await?;
    let result = state.core.admin_delete_user(&session.user, id).await;
    finish(&state, &session, &handle, result, "/admin/users".to_owned()).await
}

/// Issues a password reset for the account and shows the outcome once: the emailed
/// confirmation, or the one-time link for the admin to pass on.
pub async fn reset_password(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let handle = handle.to_lowercase();
    let summary = state.core.admin_get_user(&session.user, &handle).await?;
    match state
        .core
        .admin_password_reset(&session.user, &summary.user)
        .await
    {
        Ok(AdminReset::Emailed) => {
            let notice = match &summary.user.email {
                Some(email) => format!("A reset link was emailed to {email}."),
                None => "A reset link was emailed.".to_owned(),
            };
            Ok(detail_page(&state, &session, &handle, None, Some(notice))
                .await?
                .into_response())
        }
        Ok(AdminReset::Link(link)) => {
            let notice = format!("Share this one-time link with them: {link}");
            Ok(detail_page(&state, &session, &handle, None, Some(notice))
                .await?
                .into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = detail_page(&state, &session, &handle, Some(message), None).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}
