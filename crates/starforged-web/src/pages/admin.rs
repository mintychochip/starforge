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
use starforged_core::admin::{AdminOverview, JobInfo, UserSummary};
use starforged_core::audit::AuditQuery;
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

/// Resets a user's two-factor authentication (site admin, CSRF, audited as
/// `user.2fa_reset`): the secret and recovery codes are deleted.
pub async fn reset_2fa(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let handle = handle.to_lowercase();
    let id = target_id(&state, &session, &handle).await?;
    let result = state.core.admin_reset_2fa(&session.user, id).await;
    match result {
        Ok(()) => {
            let page = detail_page(
                &state,
                &session,
                &handle,
                None,
                Some("Two-factor authentication was reset.".to_owned()),
            )
            .await?;
            Ok(page.into_response())
        }
        Err(other) => Err(other.into()),
    }
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
/// One live repository row: no actions, just the owner/name link, visibility, and archive badge.
pub struct LiveRow {
    owner: String,
    name: String,
    visibility: String,
    archived: bool,
}

/// One deleted repository row with restore and purge-now forms.
pub struct DeletedRow {
    id: i64,
    owner: String,
    name: String,
    deleted: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_repos.html")]
pub struct ReposPage {
    nav_user: Option<NavUser>,
    csrf: String,
    admin_tab: &'static str,
    live: Vec<LiveRow>,
    deleted: Vec<DeletedRow>,
}

pub async fn repositories(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
) -> Result<ReposPage, WebError> {
    let live = state
        .core
        .admin_all_repos(&session.user)
        .await?
        .into_iter()
        .map(|r| LiveRow {
            owner: r.owner,
            name: r.name,
            visibility: r.visibility,
            archived: r.archived,
        })
        .collect();
    let deleted = state
        .core
        .admin_deleted_repos(&session.user)
        .await?
        .into_iter()
        .map(|r| DeletedRow {
            id: r.id,
            owner: r.owner,
            name: r.name,
            deleted: r
                .deleted_at
                .map(crate::views::format_time)
                .unwrap_or_default(),
        })
        .collect();
    Ok(ReposPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "repositories",
        live,
        deleted,
    })
}

/// One org row: the handle links to the org page; counts are live members
/// and live repositories.
pub struct OrgRow {
    handle: String,
    display_name: String,
    member_count: i64,
    repo_count: i64,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_orgs.html")]
pub struct OrgsPage {
    nav_user: Option<NavUser>,
    admin_tab: &'static str,
    orgs: Vec<OrgRow>,
}

/// `/admin/orgs`: every org for site admins; anyone else gets 404 from
/// [`RequireAdmin`] like every other admin page.
pub async fn orgs(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
) -> Result<OrgsPage, WebError> {
    let orgs = state
        .core
        .org_summaries(&session.user)
        .await?
        .into_iter()
        .map(|o| OrgRow {
            handle: o.handle,
            display_name: o.display_name,
            member_count: o.member_count,
            repo_count: o.repo_count,
        })
        .collect();
    Ok(OrgsPage {
        nav_user: Some(NavUser::from_session(&session)),
        admin_tab: "orgs",
        orgs,
    })
}

pub async fn restore_repo(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.restore_repo(&session.user, id).await?;
    Ok(Redirect::to("/admin/repositories").into_response())
}

pub async fn purge_repo(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.purge_repo_now(&session.user, id).await?;
    Ok(Redirect::to("/admin/repositories").into_response())
}

/// One background job row: the last error is truncated in the handler to keep
/// template logic trivial. Payloads are never rendered (mail bodies hold secrets).
pub struct JobRow {
    id: i64,
    kind: String,
    state: String,
    attempts: i64,
    short_error: String,
    run_at: String,
    created_at: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_jobs.html")]
pub struct JobsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    admin_tab: &'static str,
    jobs: Vec<JobRow>,
}

/// Truncates the last error to 200 chars without splitting a char boundary.
fn short_error(info: &JobInfo) -> String {
    const MAX: usize = 200;
    let truncated: String = info.last_error.chars().take(MAX).collect();
    if truncated.len() < info.last_error.len() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

pub async fn jobs(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
) -> Result<JobsPage, WebError> {
    let jobs = state
        .core
        .admin_list_jobs(&session.user)
        .await?
        .iter()
        .map(|info| JobRow {
            id: info.id,
            kind: info.kind.clone(),
            state: info.state.clone(),
            attempts: info.attempts,
            short_error: short_error(info),
            run_at: crate::views::format_time(info.run_at),
            created_at: crate::views::format_time(info.created_at),
        })
        .collect();
    Ok(JobsPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "jobs",
        jobs,
    })
}

pub async fn retry_job(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state.core.retry_job(&session.user, id).await {
        Ok(()) => Ok(Redirect::to("/admin/jobs").into_response()),
        Err(CoreError::NotFound) => Err(WebError::NotFound),
        Err(other) => Err(other.into()),
    }
}

pub async fn delete_job(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state.core.delete_job(&session.user, id).await {
        Ok(()) => Ok(Redirect::to("/admin/jobs").into_response()),
        Err(CoreError::NotFound) => Err(WebError::NotFound),
        Err(other) => Err(other.into()),
    }
}

/// One audit row for the page: every column is rendered escaped by the template.
pub struct AuditRowView {
    id: i64,
    time: String,
    actor: String,
    action: String,
    target: String,
    ip: String,
    user_agent: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_audit.html")]
pub struct AuditPage {
    nav_user: Option<NavUser>,
    #[allow(dead_code)]
    csrf: String,
    admin_tab: &'static str,
    actor: String,
    action: String,
    target: String,
    from: String,
    to: String,
    entries: Vec<AuditRowView>,
    next_after: Option<i64>,
}

#[derive(Deserialize)]
pub struct AuditParams {
    actor: Option<String>,
    action: Option<String>,
    target: Option<String>,
    from: Option<String>,
    to: Option<String>,
    after: Option<i64>,
}

/// `/admin/audit`: newest first, 50 per page with a keyset cursor (D3).
pub async fn audit_page(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<AuditParams>,
) -> Result<AuditPage, WebError> {
    let non_empty = |value: Option<String>| value.filter(|v| !v.is_empty());
    let actor = non_empty(params.actor.clone()).unwrap_or_default();
    let action = non_empty(params.action.clone()).unwrap_or_default();
    let target = non_empty(params.target.clone()).unwrap_or_default();
    let from = non_empty(params.from.clone()).unwrap_or_default();
    let to = non_empty(params.to.clone()).unwrap_or_default();
    // Fetch one extra row: its presence means another page follows.
    let mut entries = state
        .core
        .admin_audit(
            &session.user,
            &AuditQuery {
                actor: non_empty(params.actor),
                action: non_empty(params.action),
                target: non_empty(params.target),
                from: non_empty(params.from),
                to: non_empty(params.to),
                after: params.after,
                limit: 51,
            },
        )
        .await?
        .into_iter()
        .map(|entry| AuditRowView {
            id: entry.id,
            time: crate::views::format_time(entry.created_at),
            actor: entry.actor.unwrap_or_else(|| "—".to_owned()),
            action: entry.action,
            target: entry.target,
            ip: entry.ip,
            user_agent: entry.user_agent,
        })
        .collect::<Vec<_>>();
    let next_after = if entries.len() > 50 {
        entries.truncate(50);
        entries.last().map(|row| row.id)
    } else {
        None
    };
    Ok(AuditPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "audit",
        actor,
        action,
        target,
        from,
        to,
        entries,
        next_after,
    })
}
