//! starforged-web: HTML pages and git smart HTTP (spec §8.1, §10.1).

pub mod auth;
pub mod error;
pub mod githttp;
pub mod highlight;
pub mod markdown;
mod moved;
mod pages;
pub mod session_render;
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
    /// `ssh://git@<host>:<port>` prefix for SSH clone URLs; `None` when SSH is disabled.
    pub ssh_clone_base: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub core: Core,
    pub settings: Arc<WebSettings>,
}

pub fn router(core: Core, settings: WebSettings) -> Router {
    std::sync::LazyLock::force(&highlight::STYLESHEET);
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
        .route("/search", get(pages::search::show))
        .route("/login", get(pages::login::form).post(pages::login::submit))
        .route(
            "/login/two-factor",
            get(pages::login::two_factor_form).post(pages::login::two_factor_submit),
        )
        .route("/login/oidc", get(pages::login::oidc_begin))
        .route("/login/oidc/callback", get(pages::login::oidc_callback))
        .route("/join", get(pages::join::form).post(pages::join::submit))
        .route("/logout", post(pages::login::logout))
        .route("/oauth/device", get(pages::device::show))
        .route("/oauth/device/approve", post(pages::device::approve))
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
        .route(
            "/orgs/new",
            get(pages::orgs::new_form).post(pages::orgs::create),
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
        .route(
            "/settings/keys",
            get(pages::sshkeys::user_list).post(pages::sshkeys::user_add),
        )
        .route(
            "/settings/keys/{id}/remove",
            post(pages::sshkeys::user_remove),
        )
        .route("/settings/repositories", get(pages::settings::repositories))
        .route(
            "/settings/repositories/{id}/restore",
            post(pages::settings::restore_repository),
        )
        .route(
            "/settings/delete",
            get(pages::settings::delete_account_form).post(pages::settings::delete_account),
        )
        .route(
            "/settings/two-factor",
            get(pages::settings_2fa::index).post(pages::settings_2fa::submit),
        )
        .route("/settings/identities", get(pages::identities::index))
        .route("/settings/identities/link", post(pages::identities::link))
        .route(
            "/settings/identities/{id}/unlink",
            post(pages::identities::unlink),
        )
        .route("/admin", get(pages::admin::overview))
        .route(
            "/admin/users",
            get(pages::admin::users).post(pages::admin::create_user),
        )
        .route("/admin/users/{handle}", get(pages::admin::user_detail))
        .route("/admin/users/{handle}/suspend", post(pages::admin::suspend))
        .route(
            "/admin/users/{handle}/unsuspend",
            post(pages::admin::unsuspend),
        )
        .route(
            "/admin/users/{handle}/grant",
            post(pages::admin::grant_admin),
        )
        .route(
            "/admin/users/{handle}/revoke",
            post(pages::admin::revoke_admin),
        )
        .route(
            "/admin/users/{handle}/delete",
            post(pages::admin::delete_user),
        )
        .route(
            "/admin/users/{handle}/reset-password",
            post(pages::admin::reset_password),
        )
        .route(
            "/admin/users/{handle}/reset-2fa",
            post(pages::admin::reset_2fa),
        )
        .route(
            "/admin/invites",
            get(pages::admin::invites).post(pages::admin::create_invite),
        )
        .route(
            "/admin/invites/{id}/revoke",
            post(pages::admin::revoke_invite),
        )
        .route("/admin/repositories", get(pages::admin::repositories))
        .route("/admin/orgs", get(pages::admin::orgs))
        .route(
            "/admin/repositories/{id}/restore",
            post(pages::admin::restore_repo),
        )
        .route(
            "/admin/repositories/{id}/purge",
            post(pages::admin::purge_repo),
        )
        .route("/admin/jobs", get(pages::admin::jobs))
        .route("/admin/audit", get(pages::admin::audit_page))
        .route("/admin/quarantine", get(pages::admin::quarantine_page))
        .route(
            "/admin/quarantine/{id}/release",
            post(pages::admin::release_quarantine),
        )
        .route(
            "/admin/quarantine/{id}/purge",
            post(pages::admin::purge_quarantine),
        )
        .route("/admin/health", get(pages::admin::health_page))
        .route("/admin/sandboxes", get(pages::admin::sandboxes))
        .route(
            "/admin/sandboxes/{id}/kill",
            post(pages::admin::kill_sandbox),
        )
        .route("/admin/jobs/{id}/retry", post(pages::admin::retry_job))
        .route("/admin/jobs/{id}/delete", post(pages::admin::delete_job))
        .route(
            "/admin/jobs/rebuild-index",
            post(pages::admin::rebuild_index),
        )
        .route(
            "/orgs/{org}/settings",
            get(pages::orgs::settings).post(pages::orgs::save_general),
        )
        .route(
            "/orgs/{org}/settings/base-permission",
            post(pages::orgs::save_base),
        )
        .route("/orgs/{org}/settings/delete", post(pages::orgs::delete))
        .route(
            "/orgs/{org}/members",
            get(pages::orgs::members).post(pages::orgs::add_member),
        )
        .route(
            "/orgs/{org}/members/{handle}/remove",
            post(pages::orgs::remove_member),
        )
        .route("/orgs/{org}/teams", get(pages::orgs::teams))
        .route(
            "/orgs/{org}/teams/new",
            get(pages::orgs::new_team_form).post(pages::orgs::create_team),
        )
        .route("/orgs/{org}/teams/{team}", get(pages::orgs::team))
        .route(
            "/orgs/{org}/teams/{team}/settings",
            post(pages::orgs::save_team),
        )
        .route(
            "/orgs/{org}/teams/{team}/delete",
            post(pages::orgs::delete_team),
        )
        .route(
            "/orgs/{org}/teams/{team}/members",
            post(pages::orgs::add_team_member),
        )
        .route(
            "/orgs/{org}/teams/{team}/members/{handle}/remove",
            post(pages::orgs::remove_team_member),
        )
        .route(
            "/orgs/{org}/teams/{team}/repos",
            post(pages::orgs::add_team_repo),
        )
        .route(
            "/orgs/{org}/teams/{team}/repos/{repo}/remove",
            post(pages::orgs::remove_team_repo),
        )
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
            "/{owner}/{repo}/settings/hooks",
            get(pages::webhooks::show).post(pages::webhooks::create),
        )
        .route(
            "/{owner}/{repo}/settings/hooks/{id}/delete",
            post(pages::webhooks::delete),
        )
        .route(
            "/{owner}/{repo}/settings/hooks/{id}/toggle",
            post(pages::webhooks::toggle),
        )
        .route(
            "/{owner}/{repo}/settings/hooks/{id}/deliveries/{row}",
            get(pages::webhooks::show_delivery),
        )
        .route(
            "/{owner}/{repo}/settings/hooks/{id}/deliveries/{row}/redeliver",
            post(pages::webhooks::redeliver),
        )
        .route(
            "/{owner}/{repo}/settings/mirrors",
            get(pages::remotes::show).post(pages::remotes::save),
        )
        .route(
            "/{owner}/{repo}/settings/mirrors/sync",
            post(pages::remotes::sync_now),
        )
        .route(
            "/{owner}/{repo}/settings/mirrors/enabled",
            post(pages::remotes::set_enabled),
        )
        .route(
            "/{owner}/{repo}/settings/mirrors/delete",
            post(pages::remotes::delete),
        )
        .route(
            "/{owner}/{repo}/settings/mirrors/push",
            post(pages::remotes::add_push),
        )
        .route(
            "/{owner}/{repo}/settings/mirrors/push/{id}/sync",
            post(pages::remotes::sync_push),
        )
        .route(
            "/{owner}/{repo}/settings/mirrors/push/{id}/delete",
            post(pages::remotes::delete_push),
        )
        .route(
            "/{owner}/{repo}/settings/github-import",
            get(pages::github_import::show).post(pages::github_import::start),
        )
        .route(
            "/{owner}/{repo}/settings/refs-for-access",
            post(pages::repo_settings::change_refs_for_access),
        )
        .route(
            "/{owner}/{repo}/settings/gate-rules",
            post(pages::repo_settings::create_gate_rule),
        )
        .route(
            "/{owner}/{repo}/settings/gate-rules/{id}",
            post(pages::repo_settings::update_gate_rule),
        )
        .route(
            "/{owner}/{repo}/settings/gate-rules/{id}/delete",
            post(pages::repo_settings::delete_gate_rule),
        )
        .route(
            "/{owner}/{repo}/settings/protection",
            get(pages::protection::show).post(pages::protection::create_rule),
        )
        .route(
            "/{owner}/{repo}/settings/protection/rules/{id}",
            post(pages::protection::update_rule),
        )
        .route(
            "/{owner}/{repo}/settings/protection/rules/{id}/delete",
            post(pages::protection::delete_rule),
        )
        .route(
            "/{owner}/{repo}/settings/protection/tags",
            post(pages::protection::create_tag),
        )
        .route(
            "/{owner}/{repo}/settings/protection/tags/{id}/delete",
            post(pages::protection::delete_tag),
        )
        .route(
            "/{owner}/{repo}/settings/rename",
            post(pages::repo_settings::rename),
        )
        .route(
            "/{owner}/{repo}/settings/transfer",
            post(pages::repo_settings::transfer),
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
            "/{owner}/{repo}/settings/delete",
            post(pages::repo_settings::delete),
        )
        .route(
            "/{owner}/{repo}/settings/collaborators",
            get(pages::collaborators::list).post(pages::collaborators::add),
        )
        .route(
            "/{owner}/{repo}/settings/collaborators/{handle}/remove",
            post(pages::collaborators::remove),
        )
        .route(
            "/{owner}/{repo}/settings/keys",
            get(pages::sshkeys::deploy_list).post(pages::sshkeys::deploy_add),
        )
        .route(
            "/{owner}/{repo}/settings/keys/{id}/remove",
            post(pages::sshkeys::deploy_remove),
        )
        .route(
            "/{owner}/{repo}/import/start",
            post(pages::repo_new::import_start),
        )
        .route(
            "/{owner}/{repo}/import/delete",
            post(pages::repo_new::import_delete),
        )
        .route("/{owner}/{repo}", get(pages::code::repo_home))
        .route("/{owner}/{repo}/search", get(pages::search::code_search))
        .route("/{owner}/{repo}/tree/{*rest}", get(pages::code::tree))
        .route("/{owner}/{repo}/blob/{*rest}", get(pages::code::blob))
        .route("/{owner}/{repo}/raw/{*rest}", get(pages::code::raw))
        .route("/{owner}/{repo}/blame/{*rest}", get(pages::blame::show))
        .route(
            "/{owner}/{repo}/commits",
            get(pages::history::default_commits),
        )
        .route(
            "/{owner}/{repo}/commits/{*rest}",
            get(pages::history::commits),
        )
        .route("/{owner}/{repo}/commit/{id}", get(pages::history::commit))
        .route("/{owner}/{repo}/ci", get(pages::ci::runs))
        .route("/{owner}/{repo}/ci/{id}", get(pages::ci::run))
        .route("/{owner}/{repo}/ci/{id}/logs", get(pages::ci::logs))
        .route("/{owner}/{repo}/ci/{id}/cancel", post(pages::ci::cancel))
        .route("/{owner}/{repo}/sessions", get(pages::sessions::list))
        .route("/{owner}/{repo}/sessions/{ulid}", get(pages::session::show))
        .route(
            "/{owner}/{repo}/sessions/{ulid}/download",
            get(pages::session::download),
        )
        .route(
            "/{owner}/{repo}/sessions/{ulid}/release",
            post(pages::session::release),
        )
        .route(
            "/{owner}/{repo}/sessions/{ulid}/purge",
            post(pages::session::purge),
        )
        .route(
            "/{owner}/{repo}/sessions/{ulid}/publish",
            post(pages::session::publish),
        )
        .route(
            "/{owner}/{repo}/sessions/{ulid}/unpublish",
            post(pages::session::unpublish),
        )
        .route(
            "/{owner}/{repo}/sessions/{ulid}/delete",
            post(pages::session::delete),
        )
        .route(
            "/{owner}/{repo}/sessions/{ulid}/rescan",
            post(pages::session::rescan),
        )
        .route("/{owner}/{repo}/trails", get(pages::trails::list))
        .route(
            "/{owner}/{repo}/trails/new",
            get(pages::trails::new_form).post(pages::trails::create),
        )
        .route(
            "/{owner}/{repo}/trails/{number}",
            get(pages::trails::detail),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes",
            get(pages::trails::changes_list),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/sessions",
            get(pages::trails::sessions).post(pages::trails::link_session),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/sessions/{ulid}/unlink",
            post(pages::trails::unlink_session),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/comment",
            post(pages::trails::comment),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/edit",
            post(pages::trails::edit),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/state",
            post(pages::trails::set_state),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/labels",
            post(pages::trails::set_label),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/assignees",
            post(pages::trails::set_assignee),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/review-requests",
            post(pages::trails::set_review_request),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/comments/{id}/edit",
            post(pages::trails::edit_comment),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/new",
            post(pages::changes::create_branch),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}",
            get(pages::changes::detail),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/reviews",
            post(pages::changes::submit_review),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/reviews/pending",
            post(pages::changes::discard_pending_review),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/reviews/{id}/dismiss",
            post(pages::changes::dismiss_review),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/threads",
            post(pages::changes::create_thread),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/threads/{id}/resolve",
            post(pages::changes::resolve_thread),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/threads/{id}/comments",
            post(pages::changes::add_thread_comment),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/viewed",
            post(pages::changes::set_viewed),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/state",
            post(pages::changes::set_state),
        )
        .route(
            "/{owner}/{repo}/trails/{number}/changes/{k}/merge",
            post(pages::changes::merge),
        )
        .route("/{owner}/{repo}/compare", get(pages::compare::pick))
        .route(
            "/{owner}/{repo}/compare/{*spec}",
            get(pages::compare::compare),
        )
        .route("/{owner}/{repo}/branches", get(pages::refs::branches))
        .route("/{owner}/{repo}/tags", get(pages::refs::tags))
        .route("/static/starforge.css", get(stylesheet))
        .route("/static/highlight.css", get(highlight_stylesheet))
        .route("/static/session-viewer.js", get(session_viewer_js))
        .route("/.well-known/starforge.json", get(pages::well_known::show))
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

async fn highlight_stylesheet() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        highlight::STYLESHEET.as_str(),
    )
}

async fn session_viewer_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../static/session-viewer.js"),
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
