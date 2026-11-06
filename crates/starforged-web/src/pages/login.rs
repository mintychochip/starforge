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
use starforged_core::oidc::{OidcIntent, OidcLoginOutcome};
use starforged_core::sessions::LoginOutcome;

use crate::AppState;
use crate::auth::{
    CHALLENGE_COOKIE, CsrfForm, LOGIN_CSRF_COOKIE, MaybeUser, OIDC_COOKIE, RequireUser,
    SESSION_COOKIE, anonymous_csrf, challenge_cookie, oidc_cookie, removal, safe_next,
    session_cookie, verify_anonymous_csrf, verify_csrf,
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
    forgot_password: bool,
    sign_up_open: bool,
    oidc_enabled: bool,
    oidc_button_label: String,
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
            forgot_password: state.core.mail_enabled(),
            sign_up_open: state.core.sign_up_open(),
            oidc_enabled: state.core.oidc_enabled(),
            oidc_button_label: state.core.oidc_button_label(),
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
        Ok(LoginOutcome::Session(_, session)) => {
            let cookie = session_cookie(
                session.cookie_value,
                state.settings.secure_cookies,
                session.max_age_secs,
            );
            let jar = jar.remove(removal(LOGIN_CSRF_COOKIE)).add(cookie);
            Ok((jar, Redirect::to(&next)).into_response())
        }
        Ok(LoginOutcome::NeedsSecondFactor(token)) => {
            let cookie = challenge_cookie(token, state.settings.secure_cookies);
            let jar = jar.add(cookie);
            Ok((jar, Redirect::to(&format!("/login/two-factor?next={next}"))).into_response())
        }
        Err(CoreError::Unauthenticated) => {
            let page = LoginPage {
                nav_user: None,
                csrf: form.csrf,
                next,
                login: form.login,
                error: Some("Incorrect handle, email, or password.".into()),
                unverified: false,
                forgot_password: state.core.mail_enabled(),
                sign_up_open: state.core.sign_up_open(),
                oidc_enabled: state.core.oidc_enabled(),
                oidc_button_label: state.core.oidc_button_label(),
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
                forgot_password: state.core.mail_enabled(),
                sign_up_open: state.core.sign_up_open(),
                oidc_enabled: state.core.oidc_enabled(),
                oidc_button_label: state.core.oidc_button_label(),
            };
            Ok((StatusCode::FORBIDDEN, page).into_response())
        }
        Err(CoreError::RateLimited) => {
            let page = LoginPage {
                nav_user: None,
                csrf: form.csrf,
                next,
                login: form.login,
                error: Some("Too many login attempts. Please try again later.".into()),
                unverified: false,
                forgot_password: state.core.mail_enabled(),
                sign_up_open: state.core.sign_up_open(),
                oidc_enabled: state.core.oidc_enabled(),
                oidc_button_label: state.core.oidc_button_label(),
            };
            Ok((StatusCode::TOO_MANY_REQUESTS, page).into_response())
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

#[derive(Deserialize)]
pub struct TwoFactorForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    next: String,
    code: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_two_factor.html")]
struct TwoFactorPage {
    nav_user: Option<NavUser>,
    csrf: String,
    next: String,
    error: Option<String>,
}

pub async fn two_factor_form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = safe_next(query.next.as_deref());
    if session.is_some() {
        return Redirect::to(&next).into_response();
    }
    if jar
        .get(CHALLENGE_COOKIE)
        .map(|c| c.value())
        .unwrap_or("")
        .is_empty()
    {
        return Redirect::to("/login").into_response();
    }
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    (
        jar,
        TwoFactorPage {
            nav_user: None,
            csrf,
            next,
            error: None,
        },
    )
        .into_response()
}

pub async fn two_factor_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<TwoFactorForm>,
) -> Result<Response, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    let next = safe_next(Some(&form.next));
    let token = jar
        .get(CHALLENGE_COOKIE)
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    if token.is_empty() {
        return Ok(Redirect::to("/login").into_response());
    }
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match state
        .core
        .complete_second_factor(&token, &form.code, user_agent, &addr.ip().to_string())
        .await
    {
        Ok((_, session)) => {
            let cookie = session_cookie(
                session.cookie_value,
                state.settings.secure_cookies,
                session.max_age_secs,
            );
            let jar = jar
                .remove(removal(CHALLENGE_COOKIE))
                .remove(removal(LOGIN_CSRF_COOKIE))
                .add(cookie);
            Ok((jar, Redirect::to(&next)).into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page = TwoFactorPage {
                nav_user: None,
                csrf: form.csrf,
                next,
                error: Some(message),
            };
            Ok((StatusCode::UNAUTHORIZED, page).into_response())
        }
        Err(CoreError::Unauthenticated) => {
            let jar = jar.remove(removal(CHALLENGE_COOKIE));
            Ok((jar, Redirect::to("/login")).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /login/oidc`: starts an authorization-code flow and redirects to
/// the provider. The browser carries only the challenge token (plan D5).
pub async fn oidc_begin(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = safe_next(query.next.as_deref());
    if session.is_some() {
        return Redirect::to(&next).into_response();
    }
    match state.core.oidc_begin(OidcIntent::Login).await {
        Ok((challenge, url)) => {
            let cookie = oidc_cookie(challenge, state.settings.secure_cookies);
            (CookieJar::new().add(cookie), Redirect::to(&url)).into_response()
        }
        Err(_) => oidc_failed(None).into_response(),
    }
}

/// `GET /login/oidc/callback`: finishes the flow and resolves the
/// identity (plan D5). A `link`-intent callback needs the signed-in
/// session it was started from.
pub async fn oidc_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    MaybeUser(session): MaybeUser,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Response, WebError> {
    let challenge = jar
        .get(OIDC_COOKIE)
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    let jar = jar.remove(removal(OIDC_COOKIE));
    if challenge.is_empty() {
        return Ok((jar, oidc_failed(None)).into_response());
    }
    let (code, callback_state) = match (query.code, query.state, query.error) {
        (Some(code), Some(callback_state), None) => (code, callback_state),
        _ => return Ok((jar, oidc_failed(None)).into_response()),
    };
    let (claims, intent_user) = match state
        .core
        .oidc_finish_with_user(&challenge, &code, &callback_state)
        .await
    {
        Ok(done) => done,
        Err(_) => return Ok((jar, oidc_failed(None)).into_response()),
    };
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(user_id) = intent_user {
        let Some(session) = session else {
            return Ok((jar, oidc_failed(None)).into_response());
        };
        if session.user.id != user_id {
            return Ok((jar, oidc_failed(None)).into_response());
        }
        match state
            .core
            .oidc_link(&claims, user_id, user_agent, &addr.ip().to_string())
            .await
        {
            Ok(()) => Ok((jar, Redirect::to("/settings/identities")).into_response()),
            Err(_) => Ok((jar, oidc_failed(Some(NavUser::from_session(&session)))).into_response()),
        }
    } else {
        match state
            .core
            .oidc_login(&claims, user_agent, &addr.ip().to_string())
            .await
        {
            Ok(OidcLoginOutcome::Session(_, new_session)) => {
                let cookie = session_cookie(
                    new_session.cookie_value,
                    state.settings.secure_cookies,
                    new_session.max_age_secs,
                );
                let jar = jar.remove(removal(LOGIN_CSRF_COOKIE)).add(cookie);
                Ok((jar, Redirect::to("/")).into_response())
            }
            Ok(OidcLoginOutcome::NeedsSecondFactor(token)) => {
                let cookie = challenge_cookie(token, state.settings.secure_cookies);
                let jar = jar.add(cookie);
                Ok((jar, Redirect::to("/login/two-factor")).into_response())
            }
            Ok(OidcLoginOutcome::NoAccount) => Ok((
                jar,
                (
                    StatusCode::UNAUTHORIZED,
                    crate::pages::message::MessagePage::new(
                        None,
                        "No account for this sign-in",
                        "No account on this Starforge is linked to this sign-in, and automatic account creation is off. Ask an administrator for help.",
                    )
                    .with_link("/login", "Back to sign in"),
                ),
            )
                .into_response()),
            Err(CoreError::Unauthenticated) => Ok((jar, oidc_failed(None)).into_response()),
            Err(CoreError::RateLimited) => Ok((
                jar,
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    crate::pages::message::MessagePage::new(
                        None,
                        "Too many attempts",
                        "Too many login attempts. Please try again later.",
                    )
                    .with_link("/login", "Back to sign in"),
                ),
            )
                .into_response()),
            Err(other) => Err(other.into()),
        }
    }
}

/// The generic single-sign-on failure page: one message for every
/// failure, so provider-supplied strings never reach the browser.
fn oidc_failed(nav_user: Option<NavUser>) -> (StatusCode, crate::pages::message::MessagePage) {
    (
        StatusCode::UNAUTHORIZED,
        crate::pages::message::MessagePage::new(
            nav_user,
            "Single sign-on failed",
            "Single sign-on failed. Please try again, or sign in with your password.",
        )
        .with_link("/login", "Back to sign in"),
    )
}
