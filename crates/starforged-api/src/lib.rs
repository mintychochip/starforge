//! starforged-api: the JSON REST API under `/api/v1` (spec §10.4). A thin layer over `starforged-core`.

pub mod auth;
mod changes;
pub mod error;
mod gate_rules;
mod moved;
mod oauth;
mod orgs;
mod repos;
mod sessions;
mod statuses;
mod time;
mod trails;
mod user;
mod webhooks;

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, patch, post, put};
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
        .route("/orgs", post(orgs::create))
        .route(
            "/orgs/{org}",
            get(orgs::show).patch(orgs::patch).delete(orgs::delete),
        )
        .route(
            "/orgs/{org}/repos",
            get(orgs::list_repos).post(orgs::create_repo),
        )
        .route(
            "/orgs/{org}/teams",
            get(orgs::list_teams).post(orgs::create_team),
        )
        .route(
            "/orgs/{org}/teams/{team}",
            get(orgs::show_team)
                .patch(orgs::patch_team)
                .delete(orgs::delete_team),
        )
        .route(
            "/orgs/{org}/teams/{team}/members",
            get(orgs::list_team_members),
        )
        .route(
            "/orgs/{org}/teams/{team}/members/{handle}",
            put(orgs::set_team_member).delete(orgs::remove_team_member),
        )
        .route("/orgs/{org}/teams/{team}/repos", get(orgs::list_team_repos))
        .route(
            "/orgs/{org}/teams/{team}/repos/{repo}",
            put(orgs::add_team_repo).delete(orgs::remove_team_repo),
        )
        .route("/orgs/{org}/members", get(orgs::list_members))
        .route(
            "/orgs/{org}/members/{handle}",
            put(orgs::set_member).delete(orgs::remove_member),
        )
        .route("/oauth/device/code", post(oauth::device_code))
        .route("/oauth/token", post(oauth::token))
        .route(
            "/repos/{owner}/{repo}",
            get(repos::show).patch(repos::patch),
        )
        .route(
            "/repos/{owner}/{repo}/collaborators",
            get(repos::list_collaborators),
        )
        .route(
            "/repos/{owner}/{repo}/collaborators/{handle}",
            put(repos::set_collaborator).delete(repos::remove_collaborator),
        )
        .route("/repos/{owner}/{repo}/transfer", post(repos::transfer))
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}",
            put(sessions::put_meta)
                .get(sessions::get_session)
                .delete(sessions::delete_session),
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
            "/repos/{owner}/{repo}/sessions/{ulid}/events",
            get(sessions::get_events),
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
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/publish",
            post(sessions::publish_session),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/unpublish",
            post(sessions::unpublish_session),
        )
        .route(
            "/repos/{owner}/{repo}/sessions/{ulid}/rescan",
            post(sessions::rescan_session),
        )
        .route(
            "/repos/{owner}/{repo}/trails",
            get(trails::list_trails).post(trails::create_trail),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}",
            get(trails::get_trail).patch(trails::patch_trail),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/comments",
            get(trails::list_comments).post(trails::post_comment),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/comments/{id}",
            patch(trails::patch_comment),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/labels",
            post(trails::add_label).delete(trails::remove_label),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/assignees",
            post(trails::add_assignee).delete(trails::remove_assignee),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/review-requests",
            post(trails::add_review_request).delete(trails::remove_review_request),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/sessions",
            get(trails::get_trail_sessions).post(trails::link_trail_session),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/sessions/{ulid}",
            delete(trails::unlink_trail_session),
        )
        .route(
            "/repos/{owner}/{repo}/changes",
            get(changes::list_changes_by_head),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes",
            get(changes::list_changes).post(changes::create_change),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}",
            get(changes::get_change).patch(changes::patch_change),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/state",
            post(changes::post_state),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/diff",
            get(changes::get_diff),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/revisions",
            get(changes::list_revisions),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/revisions/{r}",
            get(changes::get_revision),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews",
            get(changes::list_reviews).post(changes::submit_review),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews/pending",
            get(changes::get_pending_review).delete(changes::discard_pending_review),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews/{id}/dismiss",
            post(changes::dismiss_review),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/threads",
            get(changes::list_threads).post(changes::create_thread),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/resolve",
            post(changes::resolve_thread),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/comments",
            post(changes::add_comment),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/gates",
            get(changes::get_gates),
        )
        .route(
            "/repos/{owner}/{repo}/trails/{n}/changes/{k}/merge",
            post(changes::merge_change),
        )
        .route(
            "/repos/{owner}/{repo}/statuses/{sha}",
            post(statuses::submit_status).get(statuses::list_statuses),
        )
        .route(
            "/repos/{owner}/{repo}/commits/{reference}/status",
            get(statuses::combined_status),
        )
        .route(
            "/repos/{owner}/{repo}/hooks",
            get(webhooks::list_hooks).post(webhooks::create_hook),
        )
        .route(
            "/repos/{owner}/{repo}/hooks/{id}",
            patch(webhooks::patch_hook).delete(webhooks::delete_hook),
        )
        .route(
            "/repos/{owner}/{repo}/hooks/{id}/deliveries",
            get(webhooks::list_deliveries),
        )
        .route(
            "/repos/{owner}/{repo}/hooks/{id}/deliveries/{row}",
            get(webhooks::get_delivery),
        )
        .route(
            "/repos/{owner}/{repo}/hooks/{id}/deliveries/{row}/redeliver",
            post(webhooks::redeliver),
        )
        .route(
            "/repos/{owner}/{repo}/gate-rules",
            get(gate_rules::list_gate_rules).post(gate_rules::create_gate_rule),
        )
        .route(
            "/repos/{owner}/{repo}/gate-rules/{id}",
            patch(gate_rules::patch_gate_rule).delete(gate_rules::delete_gate_rule),
        )
        .fallback(|| async { ApiError::NotFound })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            moved::redirect_renamed,
        ))
        .with_state(state)
}
