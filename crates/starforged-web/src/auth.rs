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
pub const CHALLENGE_COOKIE: &str = "sf_login_challenge";
pub const OIDC_COOKIE: &str = "sf_oidc_challenge";

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

/// A site administrator. Anyone else — anonymous or signed-in — gets `NotFound`,
/// so the admin area is indistinguishable from a missing page (spec §12).
pub struct RequireAdmin(pub WebSession);

impl FromRequestParts<AppState> for RequireAdmin {
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, WebError> {
        let session = MaybeUser::from_request_parts(parts, state).await?.0;
        match session {
            Some(session) if session.user.is_admin => Ok(RequireAdmin(session)),
            _ => Err(WebError::NotFound),
        }
    }
}

/// A form body carrying only the CSRF token. A missing field deserializes to
/// `""`, which [`verify_csrf`] rejects with `403` — a form without a token
/// is a forged form, not a malformed one.
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(rename = "_csrf", default)]
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

/// The second-factor challenge cookie: the random token naming the pending
/// `login_challenges` row. `HttpOnly` + `SameSite=Lax`, `Secure` on https,
/// expiring with the challenge.
pub fn challenge_cookie(value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(CHALLENGE_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::seconds(
        starforged_core::sessions::SECOND_FACTOR_TTL_SECS,
    ));
    cookie
}

/// The OIDC challenge cookie: the random token naming the pending
/// authorization-code-flow row. Same flags as the second-factor cookie,
/// expiring with the OIDC challenge.
pub fn oidc_cookie(value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(OIDC_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::seconds(
        starforged_core::oidc::CHALLENGE_TTL_SECS,
    ));
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
/// The CSRF token for a form shown to signed-out visitors, kept in the double-submit cookie `sf_login_csrf`.
/// An existing cookie is reused (and its lifetime renewed), so several such forms can be open at once.
pub fn anonymous_csrf(jar: CookieJar, secure: bool) -> (CookieJar, String) {
    let csrf = jar
        .get(LOGIN_CSRF_COOKIE)
        .map(|c| c.value().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| starforged_core::crypto::random_hex(32));
    (jar.add(login_csrf_cookie(csrf.clone(), secure)), csrf)
}

/// Checks a signed-out form's `_csrf` field against its cookie.
pub fn verify_anonymous_csrf(jar: &CookieJar, submitted: &str) -> Result<(), WebError> {
    let expected = jar
        .get(LOGIN_CSRF_COOKIE)
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    verify_csrf(&expected, submitted)
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
    #[test]
    fn anonymous_csrf_reuses_its_cookie() {
        let (jar, first) = anonymous_csrf(CookieJar::new(), false);
        assert_eq!(first.len(), 64);
        let (jar, second) = anonymous_csrf(jar, false);
        assert_eq!(
            first, second,
            "open forms keep working when another one is loaded"
        );
        assert!(verify_anonymous_csrf(&jar, &first).is_ok());
        assert!(verify_anonymous_csrf(&jar, "forged").is_err());
        assert!(verify_anonymous_csrf(&CookieJar::new(), "").is_err());
    }
}
