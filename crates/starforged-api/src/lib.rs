//! starforged-api: the JSON REST API under `/api/v1` (spec §10.4). A thin layer over `starforged-core`.

pub mod auth;
pub mod error;
mod repos;
mod user;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post, put};
use starforged_core::Core;

use crate::error::ApiError;

#[derive(Clone)]
pub struct ApiState {
    pub core: Core,
    /// Public URL without a trailing slash, for `clone_url`.
    pub base_url: Arc<str>,
}

/// Routes relative to `/api/v1`; the caller nests them there.
pub fn router(core: Core, base_url: String) -> Router {
    Router::new()
        .route("/user", get(user::show))
        .route("/user/repos", post(repos::create))
        .route("/repos/{owner}/{repo}", get(repos::show))
        .route(
            "/repos/{owner}/{repo}/collaborators",
            get(repos::list_collaborators),
        )
        .route(
            "/repos/{owner}/{repo}/collaborators/{handle}",
            put(repos::set_collaborator).delete(repos::remove_collaborator),
        )
        .fallback(|| async { ApiError::NotFound })
        .with_state(ApiState {
            core,
            base_url: Arc::from(base_url),
        })
}
