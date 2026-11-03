//! starforged-web: HTML pages and git smart HTTP (spec §8.1, §10.1).

pub mod auth;
pub mod error;
pub mod githttp;
mod pages;
pub mod views;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
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
    Router::new()
        .merge(page_routes())
        .merge(git_routes())
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::dashboard::show))
        .route("/login", get(pages::login::form).post(pages::login::submit))
        .route("/logout", post(pages::login::logout))
        .route(
            "/new",
            get(pages::repo_new::form).post(pages::repo_new::submit),
        )
        .route(
            "/settings/tokens",
            get(pages::tokens::list).post(pages::tokens::create),
        )
        .route("/settings/tokens/{id}/revoke", post(pages::tokens::revoke))
        .route("/static/starforge.css", get(stylesheet))
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

async fn stylesheet() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../static/starforge.css"),
    )
}

/// Default security headers (spec §11.1); handlers that set their own (raw files) keep them.
async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.entry(header::CONTENT_SECURITY_POLICY).or_insert(HeaderValue::from_static(
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ));
    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("same-origin"));
    headers
        .entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    response
}
