//! starforged-web: HTML pages and git smart HTTP (spec §8.1, §10.1).

pub mod githttp;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use starforged_core::Core;

#[derive(Debug, Clone)]
pub struct WebSettings {
    /// Public URL without a trailing slash.
    pub base_url: String,
    pub secure_cookies: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub core: Core,
    pub settings: Arc<WebSettings>,
}

pub fn router(core: Core, settings: WebSettings) -> Router {
    let state = AppState {
        core,
        settings: Arc::new(settings),
    };
    git_routes().with_state(state)
}

/// Smart HTTP. Pushes can be arbitrarily large, so the request body limit is disabled here.
fn git_routes() -> Router<AppState> {
    Router::new()
        .route("/{owner}/{repo}/info/refs", get(githttp::info_refs))
        .route(
            "/{owner}/{repo}/git-upload-pack",
            post(githttp::upload_pack),
        )
        .route(
            "/{owner}/{repo}/git-receive-pack",
            post(githttp::receive_pack),
        )
        .layer(DefaultBodyLimit::disable())
}
