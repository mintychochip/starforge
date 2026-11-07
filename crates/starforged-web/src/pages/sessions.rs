//! Repository sessions list (`GET /{owner}/{repo}/sessions`): the sessions
//! the viewer may read under §6.4, newest first, with top-level-by-default
//! and agent/state filters. Unreadable sessions never reach the template —
//! the core applies the same per-row check as the viewer and the API list.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use starforged_core::read::{RepoSessionFilter, RepoSessionItem};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoHead, display_title, format_time, nav};

/// Sessions per list page, matching the commits list convention.
pub const PER_PAGE: usize = 50;

#[derive(Deserialize)]
pub struct SessionsQuery {
    page: Option<i64>,
    all: Option<String>,
    agent: Option<String>,
    state: Option<String>,
}

pub struct SessionRowView {
    ulid: String,
    title: String,
    agent_name: String,
    agent_version: String,
    started: String,
    ended: String,
    turns: i64,
    tool_calls: i64,
    subagent_count: usize,
}

#[derive(Template, WebTemplate)]
#[template(path = "sessions.html")]
pub struct SessionsPageView {
    nav_user: Option<NavUser>,
    head: RepoHead,
    rows: Vec<SessionRowView>,
    agent: String,
    state: String,
    all: bool,
    total: i64,
    page: i64,
    pages: i64,
    prev_href: Option<String>,
    next_href: Option<String>,
}

fn enc(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn list_href(owner: &str, repo: &str, agent: &str, state: &str, all: bool, page: i64) -> String {
    let mut query = String::new();
    if !agent.is_empty() {
        query.push_str(&format!("agent={}", enc(agent)));
    }
    if !state.is_empty() {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(&format!("state={}", enc(state)));
    }
    if all {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str("all=1");
    }
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(&format!("page={page}"));
    format!("/{owner}/{repo}/sessions?{query}")
}

fn row_view(item: &RepoSessionItem) -> SessionRowView {
    let session = &item.session;
    SessionRowView {
        ulid: session.ulid.clone(),
        title: display_title(&session.title),
        agent_name: session.agent_name.clone(),
        agent_version: session.agent_version.clone(),
        started: format_time(session.started_at),
        ended: session
            .ended_at
            .map(format_time)
            .unwrap_or_else(|| "in progress".to_owned()),
        turns: session.turn_count,
        tool_calls: session.tool_call_count,
        subagent_count: item.subagent_count,
    }
}

/// `GET /{owner}/{repo}/sessions?page=N&all=1&agent=<name>&state=<lifecycle>`:
/// newest first, 50 per page. By default only top-level sessions (no readable
/// parent in this repository); `?all=1` lists every readable session.
pub async fn list(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<SessionsQuery>,
) -> Result<impl IntoResponse, WebError> {
    let user = session.as_ref().map(|s| &s.user);
    // Same repository-read gate as the viewer: private repositories 404 for
    // non-readers (the ULIDs inside stay undiscoverable regardless).
    let access = state.core.repo_for(user, &owner, &repo).await?;
    let all = query.all.as_deref() == Some("1");
    let agent = query.agent.clone().filter(|s| !s.is_empty());
    let state_filter = query
        .state
        .clone()
        .filter(|s| s == "receiving" || s == "complete");
    let filter = RepoSessionFilter {
        top_level_only: !all,
        agent,
        state: state_filter,
    };
    let page = query.page.unwrap_or(1).max(1);
    let (items, total) = state
        .core
        .list_repo_sessions_page(user, &access, &filter, page, PER_PAGE)
        .await?;
    let pages = (total.max(0) as u64).div_ceil(PER_PAGE as u64).max(1) as i64;
    if page > pages {
        return Err(WebError::NotFound);
    }
    let rows = items.iter().map(row_view).collect::<Vec<_>>();
    let agent_value = query.agent.clone().unwrap_or_default();
    let state_value = filter.state.clone().unwrap_or_default();
    let owner_name = access.repo.owner.clone();
    let repo_name = access.repo.name.clone();
    let prev_href = (page > 1).then(|| {
        list_href(
            &owner_name,
            &repo_name,
            &agent_value,
            &state_value,
            all,
            page - 1,
        )
    });
    let next_href = (page < pages).then(|| {
        list_href(
            &owner_name,
            &repo_name,
            &agent_value,
            &state_value,
            all,
            page + 1,
        )
    });
    let view = SessionsPageView {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "sessions", None),
        rows,
        agent: agent_value,
        state: state_value,
        all,
        total,
        page,
        pages,
        prev_href,
        next_href,
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    Ok((headers, view))
}
