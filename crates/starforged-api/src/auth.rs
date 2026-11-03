//! Bearer-token authentication.

use axum::extract::FromRequestParts;
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
        let Some(value) = parts.headers.get(header::AUTHORIZATION) else {
            return Ok(ApiAuth(None));
        };
        let token = value
            .to_str()
            .ok()
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("token "))
            })
            .ok_or(ApiError::Unauthenticated)?;
        Ok(ApiAuth(Some(
            state.core.authenticate_token(token.trim()).await?,
        )))
    }
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
