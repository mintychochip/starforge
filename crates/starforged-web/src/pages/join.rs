//! Sign-up (forge-basics design §4.1).

use std::net::SocketAddr;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::registration::{SignUp, SignedUp};

use crate::AppState;
use crate::auth::{
    LOGIN_CSRF_COOKIE, MaybeUser, anonymous_csrf, removal, session_cookie, verify_anonymous_csrf,
};
use crate::error::WebError;
use crate::pages::message::MessagePage;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct JoinQuery {
    invite: Option<String>,
}

#[derive(Deserialize)]
pub struct JoinForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    invite: String,
    handle: String,
    email: String,
    #[serde(default)]
    display_name: String,
    password: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "join.html")]
pub struct JoinPage {
    nav_user: Option<NavUser>,
    csrf: String,
    invite: String,
    handle: String,
    email: String,
    /// The invite is bound to `email`, which cannot be changed.
    email_locked: bool,
    display_name: String,
    error: Option<String>,
}

pub async fn form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Query(query): Query<JoinQuery>,
) -> Result<Response, WebError> {
    if session.is_some() {
        return Ok(Redirect::to("/").into_response());
    }
    if state.core.sso_only() {
        let page = MessagePage::new(
            None,
            "Sign-up is disabled",
            "This Starforge only creates accounts through single sign-on. Sign in with SSO instead.",
        );
        return Ok((StatusCode::FORBIDDEN, page).into_response());
    }
    let invite = query.invite.unwrap_or_default();
    let bound_email = if invite.is_empty() {
        if !state.core.sign_up_open() {
            let page = MessagePage::new(
                None,
                "Sign-up is by invitation",
                "Ask an administrator of this Starforge for an invite link.",
            );
            return Ok((StatusCode::FORBIDDEN, page).into_response());
        }
        None
    } else {
        match state.core.invite_email(&invite).await {
            Ok(email) => email,
            Err(CoreError::Invalid(message)) => {
                let page = MessagePage::new(None, "Invite not valid", message);
                return Ok((StatusCode::NOT_FOUND, page).into_response());
            }
            Err(other) => return Err(other.into()),
        }
    };
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    let page = JoinPage {
        nav_user: None,
        csrf,
        invite,
        handle: String::new(),
        email_locked: bound_email.is_some(),
        email: bound_email.unwrap_or_default(),
        display_name: String::new(),
        error: None,
    };
    Ok((jar, page).into_response())
}

pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<JoinForm>,
) -> Result<Response, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    let input = SignUp {
        handle: form.handle.clone(),
        email: form.email.clone(),
        password: form.password.clone(),
        display_name: form.display_name.clone(),
        invite: Some(form.invite.clone()),
    };
    match state.core.sign_up(input).await {
        Ok(SignedUp::VerificationSent(user)) => Ok(MessagePage::new(
            None,
            "Check your email",
            format!(
                "We sent a link to {} to verify your address. It expires in 24 hours.",
                user.email.unwrap_or_default()
            ),
        )
        .into_response()),
        Ok(SignedUp::Active(user)) => {
            let user_agent = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let (_, session) = state
                .core
                .login(
                    &user.handle,
                    &form.password,
                    user_agent,
                    &addr.ip().to_string(),
                )
                .await?
                .into_session();
            let cookie = session_cookie(
                session.cookie_value,
                state.settings.secure_cookies,
                session.max_age_secs,
            );
            let jar = jar.remove(removal(LOGIN_CSRF_COOKIE)).add(cookie);
            Ok((jar, Redirect::to("/")).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let bound = if form.invite.is_empty() {
                None
            } else {
                state.core.invite_email(&form.invite).await.ok().flatten()
            };
            let page = JoinPage {
                nav_user: None,
                csrf: form.csrf,
                invite: form.invite,
                handle: form.handle,
                email_locked: bound.is_some(),
                email: bound.unwrap_or(form.email),
                display_name: form.display_name,
                error: Some(message),
            };
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}
