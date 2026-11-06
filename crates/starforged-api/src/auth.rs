//! Bearer-token authentication and per-token rate limiting (plan M5a).

use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::header;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use starforged_core::accounts::User;
use starforged_core::limits::RateDecision;
use starforged_core::tokens::{self, Scope, TokenAuth};

use crate::ApiState;
use crate::error::{ApiError, insert_rate_headers};

/// The caller's token when `Authorization: Bearer …` was sent; a header with a bad token is rejected.
/// The second field is the token's rate-limit decision for this request
/// (set by the rate-limit middleware, or counted here when it is absent).
pub struct ApiAuth(pub Option<TokenAuth>, pub Option<RateDecision>);

impl FromRequestParts<ApiState> for ApiAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        if !parts.headers.contains_key(header::AUTHORIZATION) {
            return Ok(ApiAuth(None, None));
        }
        let token = bearer_token(&parts.headers).ok_or(ApiError::Unauthenticated)?;
        let auth = state.core.authenticate_token(token).await?;
        let decision = match parts.extensions.get::<RateDecision>() {
            Some(decision) => *decision,
            None => state.core.check_api_rate(auth.token_id),
        };
        if !decision.allowed {
            return Err(ApiError::RateLimited {
                retry_after: (decision.reset_at - starforged_core::limits::now_secs()).max(1),
                decision,
            });
        }
        Ok(ApiAuth(Some(auth), Some(decision)))
    }
}

/// Middleware: counts one request per valid token ([`Core::check_api_rate`]),
/// answers `429` with `Retry-After` when the hourly budget is spent, and
/// adds `X-RateLimit-*` headers to every token-authenticated response.
/// Requests without a valid token pass through untouched (the extractor
/// owns the 401). API 429s are never audited (too noisy); the token id is
/// logged at `info`, never the token.
pub async fn rate_limit(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let Some(token) = bearer_token(request.headers()).map(str::to_owned) else {
        return next.run(request).await;
    };
    let Ok(auth) = state.core.authenticate_token(&token).await else {
        return next.run(request).await;
    };
    let decision = state.core.check_api_rate(auth.token_id);
    tracing::info!(token_id = auth.token_id, "api request rate check");
    if !decision.allowed {
        let retry_after = (decision.reset_at - starforged_core::limits::now_secs()).max(1);
        return ApiError::RateLimited {
            retry_after,
            decision,
        }
        .into_response();
    }
    let mut request = request;
    request.extensions_mut().insert(decision);
    let mut response = next.run(request).await;
    insert_rate_headers(response.headers_mut(), 0, decision);
    response
}

/// The token in `Authorization: Bearer …` (or `token …`); `None` without the header or with another scheme.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("token "))
        .map(str::trim)
}

impl ApiAuth {
    /// The authenticated caller, who must hold `scope`.
    pub fn require(&self, scope: Scope) -> Result<&TokenAuth, ApiError> {
        let auth = self.0.as_ref().ok_or(ApiError::Unauthenticated)?;
        if tokens::grants(&auth.scopes, scope) {
            Ok(auth)
        } else {
            Err(ApiError::Forbidden(format!(
                "this token lacks the {} scope",
                scope.as_str()
            )))
        }
    }

    /// For read endpoints: anonymous callers are fine, but a token must carry `repo:read`.
    pub fn reader(&self) -> Result<Option<&User>, ApiError> {
        match &self.0 {
            None => Ok(None),
            Some(_) => Ok(Some(&self.require(Scope::RepoRead)?.user)),
        }
    }
}
