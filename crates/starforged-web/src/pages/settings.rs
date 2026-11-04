//! Account settings pages (forge-basics design §4.6).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::account::EmailChange;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, SESSION_COOKIE, removal, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, format_time};

pub async fn index() -> Redirect {
    Redirect::to("/settings/profile")
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_profile.html")]
pub struct ProfilePage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    handle: String,
    display_name: String,
    notice: Option<&'static str>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct ProfileForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    display_name: String,
}

fn profile_page(
    session: &WebSession,
    display_name: String,
    notice: Option<&'static str>,
    error: Option<String>,
) -> ProfilePage {
    ProfilePage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "profile",
        handle: session.user.handle.clone(),
        display_name,
        notice,
        error,
    }
}

pub async fn profile(RequireUser(session): RequireUser) -> ProfilePage {
    let display_name = session.user.display_name.clone();
    profile_page(&session, display_name, None, None)
}

pub async fn save_profile(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<ProfileForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .update_profile(&session.user, &form.display_name)
        .await
    {
        Ok(user) => Ok(
            profile_page(&session, user.display_name, Some("Profile saved."), None).into_response(),
        ),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            profile_page(&session, form.display_name, None, Some(message)),
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_email.html")]
pub struct EmailPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    email: Option<String>,
    verified: bool,
    new_email: String,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct EmailForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    email: String,
}

async fn email_page(
    state: &AppState,
    session: &WebSession,
    new_email: String,
    notice: Option<String>,
    error: Option<String>,
) -> Result<EmailPage, WebError> {
    // Read the account again: this request may have just changed the address.
    let user = state
        .core
        .user_by_id(session.user.id)
        .await?
        .ok_or(WebError::NotFound)?;
    Ok(EmailPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "email",
        email: user.email,
        verified: user.email_verified,
        new_email,
        notice,
        error,
    })
}

pub async fn email(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<EmailPage, WebError> {
    email_page(&state, &session, String::new(), None, None).await
}

pub async fn change_email(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<EmailForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let notice = match state.core.change_email(&session.user, &form.email).await {
        Ok(EmailChange::Changed) => {
            "Your email address is changed. It stays unverified, because this Starforge does not send email."
                .to_owned()
        }
        Ok(EmailChange::ConfirmationSent) => format!(
            "We sent a confirmation link to {}. Your address changes when you open it.",
            form.email.trim().to_ascii_lowercase()
        ),
        Ok(EmailChange::Throttled) => {
            "We sent a confirmation link a few minutes ago. Check your inbox, or try again later.".to_owned()
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = email_page(&state, &session, form.email, None, Some(message)).await?;
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response());
        }
        Err(other) => return Err(other.into()),
    };
    Ok(
        email_page(&state, &session, String::new(), Some(notice), None)
            .await?
            .into_response(),
    )
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_password.html")]
pub struct PasswordPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    notice: Option<&'static str>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    current: String,
    password: String,
    confirm: String,
}

fn password_page(
    session: &WebSession,
    notice: Option<&'static str>,
    error: Option<String>,
) -> PasswordPage {
    PasswordPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "password",
        notice,
        error,
    }
}

pub async fn password(RequireUser(session): RequireUser) -> PasswordPage {
    password_page(&session, None, None)
}

pub async fn change_password(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<PasswordForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = if form.password != form.confirm {
        Err(CoreError::Invalid(
            "The two new passwords do not match.".into(),
        ))
    } else {
        state
            .core
            .change_password(
                &session.user,
                session.session_id,
                &form.current,
                &form.password,
            )
            .await
    };
    match result {
        Ok(()) => Ok(password_page(
            &session,
            Some("Password changed. Your other sessions were signed out."),
            None,
        )
        .into_response()),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            password_page(&session, None, Some(message)),
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

pub struct SessionRow {
    id: i64,
    browser: String,
    ip: String,
    signed_in: String,
    last_active: String,
    current: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_sessions.html")]
pub struct SessionsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    sessions: Vec<SessionRow>,
}

pub async fn sessions(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<SessionsPage, WebError> {
    let sessions = state
        .core
        .list_sessions(&session.user)
        .await?
        .into_iter()
        .map(|s| SessionRow {
            id: s.id,
            browser: if s.user_agent.is_empty() {
                "Unknown browser".to_owned()
            } else {
                s.user_agent
            },
            ip: s.ip,
            signed_in: format_time(s.created_at),
            last_active: format_time(s.last_seen_at),
            current: s.id == session.session_id,
        })
        .collect();
    Ok(SessionsPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "sessions",
        sessions,
    })
}

pub async fn revoke_session(
    State(state): State<AppState>,
    jar: CookieJar,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.revoke_session(&session.user, id).await?;
    if id == session.session_id {
        return Ok((jar.remove(removal(SESSION_COOKIE)), Redirect::to("/login")).into_response());
    }
    Ok(Redirect::to("/settings/sessions").into_response())
}

pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .revoke_other_sessions(&session.user, session.session_id)
        .await?;
    Ok(Redirect::to("/settings/sessions"))
}

pub struct DeletedRow {
    id: i64,
    name: String,
    deleted: String,
    purge_after: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_repositories.html")]
pub struct RepositoriesPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    handle: String,
    deleted: Vec<DeletedRow>,
}

/// `/settings/repositories`: the user's deleted repositories that can still be restored.
pub async fn repositories(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<RepositoriesPage, WebError> {
    let deleted = state
        .core
        .deleted_repos(&session.user)
        .await?
        .into_iter()
        .map(|d| DeletedRow {
            id: d.id,
            name: d.name,
            deleted: format_time(d.deleted_at),
            purge_after: format_time(d.purge_after),
        })
        .collect();
    Ok(RepositoriesPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "repositories",
        handle: session.user.handle.clone(),
        deleted,
    })
}

pub async fn restore_repository(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let repo = state.core.restore_repo(&session.user, id).await?;
    Ok(Redirect::to(&format!("/{}/{}", repo.owner, repo.name)).into_response())
}
