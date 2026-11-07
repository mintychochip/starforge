//! CI bearer extractors (M6-0 F2, spec M6 decision 6): [`RunnerAuth`],
//! [`JobAuth`], and [`SessionAuth`] beside [`crate::auth::ApiAuth`].
//!
//! Each extractor resolves the `Authorization: Bearer …` token to one
//! principal and fails with `401` for anything else — including a token of
//! the wrong kind. A job token (`sfj_`) is accepted only where [`JobAuth`]
//! or [`SessionAuth`] is used, a runner token (`sfr_`) only on runner
//! routes ([`RunnerAuth`]), and a PAT (`sfp_`) only through [`ApiAuth`] or
//! the PAT arm of [`SessionAuth`]. The PAT rate-limit middleware skips
//! `sfj_`/`sfr_` tokens, so CI traffic never spends the PAT hourly budget.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use starforged_core::ci::{JOB_TOKEN_PREFIX, JobPrincipal, RUNNER_TOKEN_PREFIX, RunnerPrincipal};
use starforged_core::limits::RateDecision;
use starforged_core::tokens::{TOKEN_PREFIX, TokenAuth};

use crate::ApiState;
use crate::auth::bearer_token;
use crate::error::ApiError;

/// An authenticated CI runner: `sfr_` token, for runner routes only.
pub struct RunnerAuth(pub RunnerPrincipal);

impl FromRequestParts<ApiState> for RunnerAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)
            .ok_or(ApiError::Unauthenticated)?
            .to_owned();
        if !token.starts_with(RUNNER_TOKEN_PREFIX) {
            return Err(ApiError::Unauthenticated);
        }
        Ok(RunnerAuth(state.core.authenticate_runner(&token).await?))
    }
}

/// An authenticated CI job execution: `sfj_` token, for job routes only.
pub struct JobAuth(pub JobPrincipal);

impl FromRequestParts<ApiState> for JobAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)
            .ok_or(ApiError::Unauthenticated)?
            .to_owned();
        if !token.starts_with(JOB_TOKEN_PREFIX) {
            return Err(ApiError::Unauthenticated);
        }
        Ok(JobAuth(state.core.authenticate_job(&token).await?))
    }
}

/// Session-upload authentication: a PAT (`sfp_`, still gated on the
/// `session:upload` scope by the handlers) or a CI job token (`sfj_`) for a
/// job execution uploading its own sessions (M6-0 F3). Runner tokens are
/// refused here: they belong to runner routes only.
pub enum SessionAuth {
    /// A PAT caller; the middleware's rate-limit decision was already
    /// checked by the extractor.
    Pat(TokenAuth),
    Job(JobPrincipal),
}

impl FromRequestParts<ApiState> for SessionAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)
            .ok_or(ApiError::Unauthenticated)?
            .to_owned();
        if token.starts_with(TOKEN_PREFIX) {
            // The rate-limit middleware already authenticated the token and
            // parked the result in the request extensions: reuse it instead
            // of authenticating twice per request (same pattern as `ApiAuth`).
            let auth = match parts.extensions.get::<TokenAuth>() {
                Some(auth) => auth.clone(),
                None => state.core.authenticate_token(&token).await?,
            };
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
            Ok(SessionAuth::Pat(auth))
        } else if token.starts_with(JOB_TOKEN_PREFIX) {
            Ok(SessionAuth::Job(state.core.authenticate_job(&token).await?))
        } else {
            Err(ApiError::Unauthenticated)
        }
    }
}
