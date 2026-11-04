//! starforged-api: the JSON REST API under `/api/v1` (spec §10.4). A thin layer over `starforged-core`.

pub mod auth;
pub mod error;
mod moved;
mod oauth;
mod repos;
mod sessions;
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
/// Headroom above the configured segment cap for the transport body limit: the segment body
/// itself has no framing, so this only absorbs chunked-encoding overhead.
const SEGMENT_BODY_SLACK: u64 = 8 * 1024;

pub fn router(core: Core, base_url: String) -> Router {
    // The segment body streams straight into the handler, so the transport limit must bound it:
    // without one, any session:upload token holder could stream gigabytes and OOM the server
    // before the handler's length check ever runs. The handler's `body.len() > cap` check stays
    // the second line of defense for bodies that slip through under the transport limit.
    let segment_limit = usize::try_from(
        core.config()
            .max_segment_bytes
            .saturating_add(SEGMENT_BODY_SLACK),
    )
    .unwrap_or(usize::MAX);
    let state = ApiState {
        core,
        base_url: Arc::from(base_url),
    };
    Router::new()
        .route("/user", get(user::show))
        .route("/user/repos", post(repos::create))
        .route("/oauth/device/code", post(oauth::device_code))
        .route("/oauth/token", post(oauth::token))
        .route("/repos/{owner}/{repo}", get(repos::show))
        .route(
            "/repos/{owner}/{repo}/collaborators",
            get(repos::list_collaborators),
        )
        .route(
            "/repos/{owner}/{repo}/collaborators/{handle}",
            put(repos::set_collaborator).delete(repos::remove_collaborator),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}",
            put(sessions::put_meta),
        )
        .route(
            "/repos/{owner}/{repo}/sessions",
            get(sessions::list_sessions),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}",
            put(sessions::put_segment)
                .route_layer(axum::extract::DefaultBodyLimit::max(segment_limit)),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/complete",
            post(sessions::post_complete),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/links",
            post(sessions::post_links),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/release",
            post(sessions::release_session),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/purge",
            post(sessions::purge_session),
        )
        .fallback(|| async { ApiError::NotFound })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            moved::redirect_renamed,
        ))
        .with_state(state)
}
