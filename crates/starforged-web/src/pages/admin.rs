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
use starforged_core::accounts::CreateUser;
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
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct ListParams {
    q: Option<String>,
}

async fn users_page(
    state: &AppState,
    session: &WebSession,
    query: String,
    error: Option<String>,
) -> Result<UsersPage, WebError> {
    let list = state
        .core
        .admin_list_users(&session.user, &query.to_lowercase(), 200)
        .await?;
    Ok(UsersPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "users",
        query,
        users: list,
        error,
    })
}

pub async fn users(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<ListParams>,
) -> Result<UsersPage, WebError> {
    users_page(&state, &session, params.q.unwrap_or_default(), None).await
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    handle: String,
    display_name: String,
    email: String,
    password: String,
    admin: Option<String>, // Checkbox: `Some("on")` when ticked.
}

/// Creates an account directly: the address is trusted, so it starts verified.
/// Success lands on the new account's detail page; refused input re-renders the
/// users list (422) with the message and a pointer at invites.
pub async fn create_user(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<CreateUserForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let email = form.email.trim();
    let input = CreateUser {
        handle: form.handle.trim().to_owned(),
        display_name: form.display_name.trim().to_owned(),
        email: if email.is_empty() {
            None
        } else {
            Some(email.to_owned())
        },
        email_verified: false, // `admin_create_user` vouches for the address.
        password: Some(form.password.clone()),
        is_admin: form.admin.is_some(),
    };
    match state.core.admin_create_user(&session.user, input).await {
        Ok(user) => Ok(Redirect::to(&format!("/admin/users/{}", user.handle)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = users_page(&state, &session, String::new(), Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
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

/// One invite row for the list: the status is the lowercase `InviteStatus` name.
pub struct InviteRow {
    id: i64,
    email: Option<String>,
    status: String,
    created: String,
    expires: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_invites.html")]
pub struct InvitesPage {
    nav_user: Option<NavUser>,
    csrf: String,
    admin_tab: &'static str,
    invites: Vec<InviteRow>,
    created_link: Option<String>,
    emailed: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateInviteForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    email: String,
}

async fn invites_page(
    state: &AppState,
    session: &WebSession,
    created_link: Option<String>,
    emailed: bool,
    error: Option<String>,
) -> Result<InvitesPage, WebError> {
    let invites = state
        .core
        .list_invites(&session.user)
        .await?
        .into_iter()
        .map(|info| InviteRow {
            id: info.id,
            email: info.email,
            status: info.status.as_str().to_owned(),
            created: crate::views::format_time(info.created_at),
            expires: crate::views::format_time(info.expires_at),
        })
        .collect();
    Ok(InvitesPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "invites",
        invites,
        created_link,
        emailed,
        error,
    })
}

pub async fn invites(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
) -> Result<InvitesPage, WebError> {
    invites_page(&state, &session, None, false, None).await
}

/// Issues an invite and shows the one-time link: it is rendered only in this
/// response, never in the list.
pub async fn create_invite(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<CreateInviteForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let email = form.email.trim();
    let email = if email.is_empty() { None } else { Some(email) };
    match state.core.create_invite(&session.user, email).await {
        Ok(created) => {
            Ok(
                invites_page(&state, &session, Some(created.link), created.emailed, None)
                    .await?
                    .into_response(),
            )
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = invites_page(&state, &session, None, false, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn revoke_invite(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state.core.revoke_invite(&session.user, id).await {
        Ok(()) => Ok(Redirect::to("/admin/invites").into_response()),
        Err(CoreError::NotFound) => Err(WebError::NotFound),
        Err(other) => Err(other.into()),
    }
}
