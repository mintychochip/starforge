//! starforged-api: the JSON REST API under `/api/v1` (spec §10.4). A thin layer over `starforged-core`.

mod admin;
pub mod auth;
mod changes;
pub mod ci;
pub mod ci_auth;
pub mod error;
mod gate_rules;
mod github_import;
mod moved;
mod oauth;
pub mod openapi;
mod orgs;
mod repos;
mod search;
mod sessions;
mod sshkeys;
mod statuses;
mod tag_protections;
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
        .route("/openapi.json", get(openapi::openapi_json))
        .route("/admin/audit", get(admin::audit))
        .route("/user", get(user::show))
        .route("/user/repos", post(repos::create))
        .route(
            "/user/keys",
            get(sshkeys::list_user_keys).post(sshkeys::create_user_key),
        )
        .route("/user/keys/{id}", delete(sshkeys::delete_user_key))
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
        .route("/search/trails", get(search::search_trails))
        .route("/search/sessions", get(search::search_sessions))
        .route(
            "/repos/{owner}/{repo}/search/code",
            get(search::search_code),
        )
        .route("/oauth/device/code", post(oauth::device_code))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke))
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
        .route(
            "/repos/{owner}/{repo}/keys",
            get(sshkeys::list_deploy_keys).post(sshkeys::create_deploy_key),
        )
        .route(
            "/repos/{owner}/{repo}/keys/{id}",
            delete(sshkeys::delete_deploy_key),
        )
        .route("/repos/{owner}/{repo}/transfer", post(repos::transfer))
        .route(
            "/repos/{owner}/{repo}/import",
            get(repos::get_import).delete(repos::delete_import),
        )
        .route(
            "/repos/{owner}/{repo}/import/start",
            post(repos::start_import),
        )
        .route(
            "/repos/{owner}/{repo}/import/github",
            post(github_import::start_github_import).get(github_import::get_github_import),
        )
        .route(
            "/repos/{owner}/{repo}/mirror/pull",
            put(repos::put_pull_mirror)
                .get(repos::get_pull_mirror)
                .delete(repos::delete_pull_mirror),
        )
        .route(
            "/repos/{owner}/{repo}/mirror/pull/sync",
            post(repos::sync_pull_mirror),
        )
        .route(
            "/repos/{owner}/{repo}/mirror/push",
            post(repos::add_push_mirror).get(repos::list_push_mirrors),
        )
        .route(
            "/repos/{owner}/{repo}/mirror/push/{id}",
            delete(repos::delete_push_mirror),
        )
        .route(
            "/repos/{owner}/{repo}/mirror/push/{id}/sync",
            post(repos::sync_push_mirror),
        )
        .route(
            "/repos/{owner}/{repo}/mirror/pull/enabled",
            post(repos::set_pull_mirror_enabled),
        )
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
                .get(sessions::get_segment)
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
            post(sessions::post_links).get(sessions::get_links),
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
        .route(
            "/repos/{owner}/{repo}/tag-protections",
            get(tag_protections::list_tag_protections).post(tag_protections::create_tag_protection),
        )
        .route(
            "/repos/{owner}/{repo}/tag-protections/{id}",
            delete(tag_protections::delete_tag_protection),
        )
        .route(
            "/repos/{owner}/{repo}/runners/registration-token",
            post(ci::create_registration_token),
        )
        .route("/repos/{owner}/{repo}/runners", get(ci::list_runners))
        .route("/runners/register", post(ci::register_runner))
        .route("/runners/{id}", delete(ci::revoke_runner))
        .fallback(|| async { ApiError::NotFound })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            moved::redirect_renamed,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::rate_limit,
        ))
        .with_state(state)
}
