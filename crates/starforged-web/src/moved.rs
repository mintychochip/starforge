//! Old repository names answer 301 with the new name (forge-basics design §5.3).

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use starforged_core::accounts::User;
use starforged_core::repos::split_repo_path;

use crate::AppState;
use crate::auth::SESSION_COOKIE;
use crate::githttp::basic_password;

/// After a `GET` or `HEAD` under `/{owner}/{repo}` answers 404, or git's `info/refs` answers 401 (what
/// anonymous git clients get for a repository they cannot see), answers 301 to the same path and query under
/// the repository's new name when it was renamed and the viewer can read it. Everything else passes through.
pub async fn redirect_renamed(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let uri = request.uri().clone();
    let session = CookieJar::from_headers(request.headers())
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let token = basic_password(request.headers());
    let response = next.run(request).await;
    let status = response.status();
    let refused = status == StatusCode::NOT_FOUND
        || (status == StatusCode::UNAUTHORIZED && uri.path().ends_with("/info/refs"));
    if !refused {
        return response;
    }
    let Some((owner, segment, rest)) = split_repo_path(uri.path()) else {
        return response;
    };
    let (name, suffix) = match segment.strip_suffix(".git") {
        Some(name) => (name, ".git"),
        None => (segment, ""),
    };
    let viewer = viewer(&state, session.as_deref(), token.as_deref()).await;
    let target = match state.core.moved_repo(viewer.as_ref(), owner, name).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return response,
        Err(err) => {
            tracing::warn!(error = %err, "looking up a renamed repository");
            return response;
        }
    };
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let location = format!("/{}/{}{suffix}{rest}{query}", target.owner, target.name);
    match HeaderValue::from_str(&location) {
        Ok(value) => (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, value)]).into_response(),
        Err(_) => response,
    }
}

/// The signed-in user (session cookie), else the user of an HTTP Basic token (what git sends).
async fn viewer(state: &AppState, session: Option<&str>, token: Option<&str>) -> Option<User> {
    if let Some(cookie) = session
        && let Ok(Some(session)) = state.core.web_session(cookie).await
    {
        return Some(session.user);
    }
    match token {
        Some(secret) => state
            .core
            .authenticate_token(secret)
            .await
            .ok()
            .map(|auth| auth.user),
        None => None,
    }
}
