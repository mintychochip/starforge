//! Session cookies, signed-in-user extractors, and CSRF checks (spec §9).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use starforged_core::sessions::WebSession;
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::error::WebError;

pub const SESSION_COOKIE: &str = "sf_session";
pub const LOGIN_CSRF_COOKIE: &str = "sf_login_csrf";

/// The signed-in user, if any.
pub struct MaybeUser(pub Option<WebSession>);

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = WebError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        match jar.get(SESSION_COOKIE) {
            Some(cookie) => Ok(MaybeUser(state.core.web_session(cookie.value()).await?)),
            None => Ok(MaybeUser(None)),
        }
    }
}

/// A signed-in user. Anonymous requests are redirected to `/login?next=<path>`.
pub struct RequireUser(pub WebSession);

impl FromRequestParts<AppState> for RequireUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match MaybeUser::from_request_parts(parts, state).await {
            Ok(MaybeUser(Some(session))) => Ok(RequireUser(session)),
            Ok(MaybeUser(None)) => {
                let next = utf8_percent_encode(parts.uri.path(), NON_ALPHANUMERIC);
                Err(Redirect::to(&format!("/login?next={next}")).into_response())
            }
            Err(err) => Err(err.into_response()),
        }
    }
}

/// A form body carrying only the CSRF token.
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(rename = "_csrf")]
    pub csrf: String,
}

/// Constant-time comparison; an empty expected token never matches.
pub fn verify_csrf(expected: &str, submitted: &str) -> Result<(), WebError> {
    if !expected.is_empty() && bool::from(expected.as_bytes().ct_eq(submitted.as_bytes())) {
        Ok(())
    } else {
        Err(WebError::Forbidden)
    }
}

/// Keeps only same-site absolute paths; anything else becomes `/` (no open redirects). Control characters
/// are refused too: `Redirect::to` panics on values that are not valid header text.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(path)
            if path.starts_with('/')
                && !path.starts_with("//")
                && !path.contains('\\')
                && !path.chars().any(char::is_control) =>
        {
            path.to_owned()
        }
        _ => "/".to_owned(),
    }
}

pub fn session_cookie(value: String, secure: bool, max_age_secs: i64) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::seconds(max_age_secs));
    cookie
}

/// Double-submit CSRF cookie for the anonymous login form.
pub fn login_csrf_cookie(value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(LOGIN_CSRF_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::hours(1));
    cookie
}

/// Pass to `CookieJar::remove` to clear the cookie `name` (path `/`).
pub fn removal(name: &'static str) -> Cookie<'static> {
    let mut cookie = Cookie::from(name);
    cookie.set_path("/");
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_paths_stay_on_site() {
        assert_eq!(safe_next(Some("/alice/proj")), "/alice/proj");
        let unsafe_paths = [
            None,
            Some(""),
            Some("//evil.example"),
            Some("https://evil.example"),
            Some("/\\evil.example"),
            Some("x"),
            Some("/a\r\nSet-Cookie: x=1"),
        ];
        for unsafe_next in unsafe_paths {
            assert_eq!(safe_next(unsafe_next), "/", "{unsafe_next:?}");
        }
    }

    #[test]
    fn csrf_tokens_must_match_exactly() {
        assert!(verify_csrf("abc", "abc").is_ok());
        assert!(verify_csrf("abc", "abd").is_err());
        assert!(verify_csrf("", "").is_err());
    }
}
