//! Old repository names answer 301 for API reads (forge-basics design §5.3).

use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use starforged_core::repos::split_repo_path;

use crate::ApiState;
use crate::auth::bearer_token;

/// After a `GET` or `HEAD` of `/repos/{owner}/{repo}…` answers 404, answers 301 to the same path and query
/// under the repository's new name when it was renamed and the caller can read it.
pub async fn redirect_renamed(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let uri = request.uri().clone();
    // The path as the client sent it, before `nest("/api/v1", …)` removed the prefix.
    let original = request
        .extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.clone())
        .unwrap_or_else(|| uri.clone());
    let token = bearer_token(request.headers()).map(str::to_owned);
    // The rate-limit middleware parks the authenticated token in the
    // extensions: reuse it instead of authenticating again here.
    let parked = request
        .extensions()
        .get::<starforged_core::tokens::TokenAuth>()
        .map(|auth| auth.user.clone());
    let response = next.run(request).await;
    if response.status() != StatusCode::NOT_FOUND {
        return response;
    }
    let Some(repo_path) = uri.path().strip_prefix("/repos") else {
        return response;
    };
    let Some((owner, name, rest)) = split_repo_path(repo_path) else {
        return response;
    };
    let viewer = match parked {
        Some(user) => Some(user),
        None => match token {
            Some(secret) => state
                .core
                .authenticate_token(&secret)
                .await
                .ok()
                .map(|auth| auth.user),
            None => None,
        },
    };
    let target = match state.core.moved_repo(viewer.as_ref(), owner, name).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return response,
        Err(err) => {
            tracing::warn!(error = %err, "looking up a renamed repository");
            return response;
        }
    };
    let prefix = original.path().strip_suffix(uri.path()).unwrap_or("");
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let location = format!(
        "{prefix}/repos/{}/{}{rest}{query}",
        target.owner, target.name
    );
    match HeaderValue::from_str(&location) {
        Ok(value) => (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, value)]).into_response(),
        Err(_) => response,
    }
}
