//! Bearer-token authentication.

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header;
use axum::http::request::Parts;
use starforged_core::accounts::User;
use starforged_core::tokens::{self, Scope, TokenAuth};

use crate::ApiState;
use crate::error::ApiError;

/// The caller's token when `Authorization: Bearer …` was sent; a header with a bad token is rejected.
pub struct ApiAuth(pub Option<TokenAuth>);

impl FromRequestParts<ApiState> for ApiAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        if !parts.headers.contains_key(header::AUTHORIZATION) {
            return Ok(ApiAuth(None));
        }
        let token = bearer_token(&parts.headers).ok_or(ApiError::Unauthenticated)?;
        Ok(ApiAuth(Some(state.core.authenticate_token(token).await?)))
    }
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
