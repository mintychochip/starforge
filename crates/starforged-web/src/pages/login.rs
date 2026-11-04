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

use crate::AppState;
use crate::auth::{
    CsrfForm, LOGIN_CSRF_COOKIE, MaybeUser, RequireUser, SESSION_COOKIE, anonymous_csrf, removal,
    safe_next, session_cookie, verify_anonymous_csrf, verify_csrf,
};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    next: String,
    login: String,
    password: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginPage {
    nav_user: Option<NavUser>,
    csrf: String,
    next: String,
    login: String,
    error: Option<String>,
    /// The password was right but the address is unverified: show the resend form.
    unverified: bool,
}

pub async fn form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = safe_next(query.next.as_deref());
    if session.is_some() {
        return Redirect::to(&next).into_response();
    }
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    (
        jar,
        LoginPage {
            nav_user: None,
            csrf,
            next,
            login: String::new(),
            error: None,
            unverified: false,
        },
    )
        .into_response()
}

pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let next = safe_next(Some(&form.next));
    match state
        .core
        .login(
            &form.login,
            &form.password,
            user_agent,
            &addr.ip().to_string(),
        )
        .await
    {
        Ok((_, session)) => {
            let cookie = session_cookie(
                session.cookie_value,
                state.settings.secure_cookies,
                session.max_age_secs,
            );
            let jar = jar.remove(removal(LOGIN_CSRF_COOKIE)).add(cookie);
            Ok((jar, Redirect::to(&next)).into_response())
        }
        Err(CoreError::Unauthenticated) => {
            let page = LoginPage {
                nav_user: None,
                csrf: form.csrf,
                next,
                login: form.login,
                error: Some("Incorrect handle, email, or password.".into()),
                unverified: false,
            };
            Ok((StatusCode::UNAUTHORIZED, page).into_response())
        }
        Err(CoreError::EmailUnverified) => {
            let page = LoginPage {
                nav_user: None,
                csrf: form.csrf,
                next,
                login: form.login,
                error: None,
                unverified: true,
            };
            Ok((StatusCode::FORBIDDEN, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    RequireUser(session): RequireUser,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        state.core.logout(cookie.value()).await?;
    }
    Ok((jar.remove(removal(SESSION_COOKIE)), Redirect::to("/")).into_response())
}
