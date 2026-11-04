//! starforged-web: HTML pages and git smart HTTP (spec §8.1, §10.1).

pub mod auth;
pub mod error;
pub mod githttp;
pub mod markdown;
mod moved;
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            moved::redirect_renamed,
        ))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::dashboard::show))
        .route("/login", get(pages::login::form).post(pages::login::submit))
        .route("/join", get(pages::join::form).post(pages::join::submit))
        .route("/logout", post(pages::login::logout))
        .route("/verify/resend", post(pages::verify::resend))
        .route(
            "/verify/{token}",
            get(pages::verify::confirm_form).post(pages::verify::confirm),
        )
        .route(
            "/forgot",
            get(pages::password::forgot_form).post(pages::password::forgot),
        )
        .route(
            "/reset/{token}",
            get(pages::password::reset_form).post(pages::password::reset),
        )
        .route(
            "/new",
            get(pages::repo_new::form).post(pages::repo_new::submit),
        )
        .route("/settings", get(pages::settings::index))
        .route(
            "/settings/profile",
            get(pages::settings::profile).post(pages::settings::save_profile),
        )
        .route(
            "/settings/email",
            get(pages::settings::email).post(pages::settings::change_email),
        )
        .route(
            "/settings/password",
            get(pages::settings::password).post(pages::settings::change_password),
        )
        .route("/settings/sessions", get(pages::settings::sessions))
        .route(
            "/settings/sessions/revoke-others",
            post(pages::settings::revoke_other_sessions),
        )
        .route(
            "/settings/sessions/{id}/revoke",
            post(pages::settings::revoke_session),
        )
        .route(
            "/settings/tokens",
            get(pages::tokens::list).post(pages::tokens::create),
        )
        .route("/settings/tokens/{id}/revoke", post(pages::tokens::revoke))
        .route("/{owner}", get(pages::owner::show))
        .route(
            "/{owner}/{repo}/settings",
            get(pages::repo_settings::show).post(pages::repo_settings::save_general),
        )
        .route(
            "/{owner}/{repo}/settings/visibility",
            post(pages::repo_settings::change_visibility),
        )
        .route(
            "/{owner}/{repo}/settings/rename",
            post(pages::repo_settings::rename),
        )
        .route(
            "/{owner}/{repo}/settings/archive",
            post(pages::repo_settings::archive),
        )
        .route(
            "/{owner}/{repo}/settings/unarchive",
            post(pages::repo_settings::unarchive),
        )
        .route(
            "/{owner}/{repo}/settings/collaborators",
            get(pages::collaborators::list).post(pages::collaborators::add),
        )
        .route(
            "/{owner}/{repo}/settings/collaborators/{handle}/remove",
            post(pages::collaborators::remove),
        )
        .route("/{owner}/{repo}", get(pages::code::repo_home))
        .route("/{owner}/{repo}/tree/{*rest}", get(pages::code::tree))
        .route("/{owner}/{repo}/blob/{*rest}", get(pages::code::blob))
        .route("/{owner}/{repo}/raw/{*rest}", get(pages::code::raw))
        .route(
            "/{owner}/{repo}/commits",
            get(pages::history::default_commits),
        )
        .route(
            "/{owner}/{repo}/commits/{*rest}",
            get(pages::history::commits),
        )
        .route("/{owner}/{repo}/commit/{id}", get(pages::history::commit))
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
