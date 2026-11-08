//! Trail web UI (spec §6.2, M2a): list with filters, new form, and detail
//! with discussion plus triage-gated controls. Reads 404 for non-readers
//! so trail numbers stay undiscoverable; mutations answer 403 below their
//! threshold. Intent and comment bodies render through
//! [`crate::markdown::render_prose`]; everything else relies on askama escaping.

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;

use crate::AppState;
use crate::auth::{MaybeUser, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::markdown;
use crate::views::{
    GatePanel, NavUser, RepoHead, STRICT_CSP, SessionChip, TrailTabs, format_age, format_time, nav,
};
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;
use starforged_core::trails::{
    TimelineCheck, TimelineSession, TokenTotals, TrailFilterInput, TrailSessions,
    TrailTimelineEntry,
};

/// Trails per web page; the API stays keyset-based.
const PAGE_SIZE: i64 = 30;
/// `?page` beyond this 404s without walking cursors (DoS guard).
const MAX_PAGE: i64 = 1000;

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// `X-Robots-Tag: noindex` on every trail page, matching the session pages.
fn noindex_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers
}

/// Noindex plus the strict CSP for every trail page, whose intent and
/// comments are attacker-influenced Markdown (same combination as the
/// session viewer).
fn detail_headers() -> HeaderMap {
    let mut headers = noindex_headers();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STRICT_CSP),
    );
    headers
}

#[derive(Deserialize)]
pub struct ListQuery {
    state: Option<String>,
    label: Option<String>,
    assignee: Option<String>,
    author: Option<String>,
    has_changes: Option<String>,
    has_sessions: Option<String>,
    review_requested: Option<String>,
    page: Option<i64>,
}

pub struct TrailRow {
    number: i64,
    title: String,
    state: String,
    ready: bool,
    labels: Vec<String>,
    assignees: Vec<String>,
    age: String,
    author_handle: String,
    imported_author: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "trails.html")]
pub struct TrailsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    rows: Vec<TrailRow>,
    state: String,
    label: String,
    assignee: String,
    author: String,
    has_changes: String,
    has_sessions: String,
    review_requested: String,
    page: i64,
    prev_href: Option<String>,
    next_href: Option<String>,
}
/// `GET /{owner}/{repo}/trails[?state=&label=&assignee=&author=&has_changes=&has_sessions=&review_requested=&page=]`.
/// Non-readers 404, exactly like every other trail read.
pub async fn list(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, WebError> {
    let user = session.as_ref().map(|s| &s.user);
    let access = state.core.repo_for(user, &owner, &repo).await?;
    let repo_owner = access.repo.owner.clone();
    let repo_name = access.repo.name.clone();
    let filter_state = query.state.clone().filter(|s| !s.is_empty());
    let filter_label = query.label.clone().filter(|s| !s.is_empty());
    let filter_assignee = query.assignee.clone().filter(|s| !s.is_empty());
    let filter_author = query.author.clone().filter(|s| !s.is_empty());
    let filter_has_changes = query.has_changes.clone().filter(|s| !s.is_empty());
    let filter_has_sessions = query.has_sessions.clone().filter(|s| !s.is_empty());
    let filter_review_requested = query.review_requested.clone().filter(|s| !s.is_empty());
    let page_no = query.page.unwrap_or(1).max(1);
    if page_no > MAX_PAGE {
        return Err(WebError::NotFound);
    }

    // The service is keyset-paged; walk cursors to reach `?page=N`.
    let mut listed = fetch_page(
        &state,
        user,
        &owner,
        &repo,
        &filter_state,
        &filter_label,
        &filter_assignee,
        &filter_author,
        &filter_has_changes,
        &filter_has_sessions,
        &filter_review_requested,
        None,
    )
    .await?;
    if listed.trails.is_empty() && page_no > 1 {
        return Err(WebError::NotFound);
    }
    for _ in 1..page_no {
        let Some(cursor) = listed.next_after else {
            return Err(WebError::NotFound);
        };
        listed = fetch_page(
            &state,
            user,
            &owner,
            &repo,
            &filter_state,
            &filter_label,
            &filter_assignee,
            &filter_author,
            &filter_has_changes,
            &filter_has_sessions,
            &filter_review_requested,
            Some(cursor),
        )
        .await?;
        if listed.trails.is_empty() {
            return Err(WebError::NotFound);
        }
    }

    let now = unix_now();
    let rows = listed
        .trails
        .into_iter()
        .map(|t| TrailRow {
            number: t.number,
            title: t.title,
            state: t.state,
            ready: t.ready,
            labels: t.labels,
            assignees: t.assignees,
            age: format_age(now, t.created_at),
            author_handle: t.author_handle.clone(),
            imported_author: t.imported_author.clone(),
        })
        .collect();
    let prev_href = (page_no > 1).then(|| {
        list_href(
            &repo_owner,
            &repo_name,
            filter_state.as_deref().unwrap_or_default(),
            filter_label.as_deref().unwrap_or_default(),
            filter_assignee.as_deref().unwrap_or_default(),
            filter_author.as_deref().unwrap_or_default(),
            filter_has_changes.as_deref().unwrap_or_default(),
            filter_has_sessions.as_deref().unwrap_or_default(),
            filter_review_requested.as_deref().unwrap_or_default(),
            page_no - 1,
        )
    });
    let next_href = listed.next_after.is_some().then(|| {
        list_href(
            &repo_owner,
            &repo_name,
            filter_state.as_deref().unwrap_or_default(),
            filter_label.as_deref().unwrap_or_default(),
            filter_assignee.as_deref().unwrap_or_default(),
            filter_author.as_deref().unwrap_or_default(),
            filter_has_changes.as_deref().unwrap_or_default(),
            filter_has_sessions.as_deref().unwrap_or_default(),
            filter_review_requested.as_deref().unwrap_or_default(),
            page_no + 1,
        )
    });
    Ok((
        detail_headers(),
        TrailsPage {
            nav_user: nav(session.as_ref()),
            head: RepoHead::new(&access, "trails", None),
            rows,
            state: filter_state.unwrap_or_default(),
            label: filter_label.unwrap_or_default(),
            assignee: filter_assignee.unwrap_or_default(),
            author: filter_author.unwrap_or_default(),
            has_changes: filter_has_changes.unwrap_or_default(),
            has_sessions: filter_has_sessions.unwrap_or_default(),
            review_requested: filter_review_requested.unwrap_or_default(),
            page: page_no,
            prev_href,
            next_href,
        },
    ))
}

/// Filter-preserving pager links; values come from constrained charsets
/// (states, lowercased labels, handles), and askama escapes them in `href`.
#[allow(clippy::too_many_arguments)]
fn list_href(
    owner: &str,
    repo: &str,
    state: &str,
    label: &str,
    assignee: &str,
    author: &str,
    has_changes: &str,
    has_sessions: &str,
    review_requested: &str,
    page: i64,
) -> String {
    let mut query = String::new();
    for (key, value) in [
        ("state", state),
        ("label", label),
        ("assignee", assignee),
        ("author", author),
        ("has_changes", has_changes),
        ("has_sessions", has_sessions),
        ("review_requested", review_requested),
    ] {
        if !value.is_empty() {
            if !query.is_empty() {
                query.push('&');
            }
            query.push_str(key);
            query.push('=');
            query.push_str(value);
        }
    }
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(&format!("page={page}"));
    format!("/{owner}/{repo}/trails?{query}")
}
/// One keyset page of the trail list, mapped from web filters.
#[allow(clippy::too_many_arguments)]
async fn fetch_page(
    state: &AppState,
    user: Option<&starforged_core::accounts::User>,
    owner: &str,
    repo: &str,
    filter_state: &Option<String>,
    filter_label: &Option<String>,
    filter_assignee: &Option<String>,
    filter_author: &Option<String>,
    filter_has_changes: &Option<String>,
    filter_has_sessions: &Option<String>,
    filter_review_requested: &Option<String>,
    after: Option<i64>,
) -> Result<starforged_core::trails::ListPage, WebError> {
    // The selects post "true"/"false"; anything else means no filter.
    let has_changes = match filter_has_changes.as_deref() {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };
    let has_sessions = match filter_has_sessions.as_deref() {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };
    Ok(state
        .core
        .list_trails(
            user,
            owner,
            repo,
            &TrailFilterInput {
                state: filter_state.clone(),
                label: filter_label.clone(),
                assignee: filter_assignee.clone(),
                author: filter_author.clone(),
                has_changes,
                has_sessions,
                review_requested: filter_review_requested.clone(),
                after,
                limit: Some(PAGE_SIZE),
            },
        )
        .await?)
}

#[derive(Template, WebTemplate)]
#[template(path = "trail_new.html")]
pub struct TrailNewPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    csrf: String,
    title: String,
    intent: String,
    head_branch: String,
    base_branch: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct NewQuery {
    head: Option<String>,
    base: Option<String>,
}

/// `GET /{owner}/{repo}/trails/new`: signed-in readers only (anonymous
/// requests redirect to sign-in via `RequireUser`; other non-readers 404).
/// `?head=` and `?base=` prefill the branch fields; `base` defaults to the
/// default branch.
pub async fn new_form(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<NewQuery>,
) -> Result<impl IntoResponse, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    let base_branch = query
        .base
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| access.repo.default_branch.clone());
    Ok((
        detail_headers(),
        TrailNewPage {
            nav_user: Some(NavUser::from_session(&session)),
            head: RepoHead::new(&access, "trails", None),
            csrf: session.csrf_token.clone(),
            title: String::new(),
            intent: String::new(),
            head_branch: query.head.unwrap_or_default(),
            base_branch,
            error: None,
        },
    ))
}

#[derive(Deserialize)]
pub struct NewForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    intent: String,
    #[serde(default)]
    head: String,
    #[serde(default)]
    base: String,
}

/// `POST /{owner}/{repo}/trails/new`: creates the trail and redirects to it.
/// A non-empty `head` first validates that `head` and `base` name existing,
/// differing branches before anything is written, then tracks `head` into
/// `base` as a change on the new trail; an empty `base` defaults to the
/// default branch. `Invalid` re-renders the form with 422 instead of
/// dropping the input.
pub async fn create(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<NewForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let head_branch = form.head.trim().to_owned();
    let base_branch = match form.base.trim() {
        "" => access.repo.default_branch.clone(),
        base => base.to_owned(),
    };
    if !head_branch.is_empty() {
        // Tracking a branch as a change needs `Triage` (the same minimum
        // `create_branch_change` enforces); without it, refuse before the
        // trail exists, with the same 403 the Trail pages answer.
        let rejection = if access.permission < Permission::Triage {
            Some((
                StatusCode::FORBIDDEN,
                "You do not have permission to do that.".to_owned(),
            ))
        } else {
            validate_branches(&state, &access, &head_branch, &base_branch)
                .await?
                .map(|message| (StatusCode::UNPROCESSABLE_ENTITY, message))
        };
        if let Some((status, message)) = rejection {
            return Ok((
                status,
                detail_headers(),
                TrailNewPage {
                    nav_user: Some(NavUser::from_session(&session)),
                    head: RepoHead::new(&access, "trails", None),
                    csrf: session.csrf_token.clone(),
                    title: form.title.clone(),
                    intent: form.intent.clone(),
                    head_branch,
                    base_branch,
                    error: Some(message),
                },
            )
                .into_response());
        }
    }
    match state
        .core
        .create_trail(&session.user, &owner, &repo, &form.title, &form.intent)
        .await
    {
        Ok(view) => {
            if !head_branch.is_empty() {
                state
                    .core
                    .create_branch_change(
                        &session.user,
                        &owner,
                        &repo,
                        view.number,
                        &head_branch,
                        &base_branch,
                    )
                    .await?;
            }
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{}",
                access.repo.owner, access.repo.name, view.number
            ))
            .into_response())
        }
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            detail_headers(),
            TrailNewPage {
                nav_user: Some(NavUser::from_session(&session)),
                head: RepoHead::new(&access, "trails", None),
                csrf: session.csrf_token.clone(),
                title: form.title.clone(),
                intent: form.intent.clone(),
                head_branch,
                base_branch,
                error: Some(message),
            },
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

/// `Some(message)` when `head`/`base` do not name existing, differing
/// branches: nothing may be created on such input.
async fn validate_branches(
    state: &AppState,
    access: &starforged_core::repos::RepoAccess,
    head: &str,
    base: &str,
) -> Result<Option<String>, WebError> {
    if head == base {
        return Ok(Some("head and base branches must differ".to_owned()));
    }
    let branches = state.core.branches(access).await?;
    if !branches.iter().any(|b| b == head) {
        return Ok(Some(format!("unknown head branch '{head}'")));
    }
    if !branches.iter().any(|b| b == base) {
        return Ok(Some(format!("unknown base branch '{base}'")));
    }
    Ok(None)
}

pub struct CommentItem {
    id: i64,
    author_handle: String,
    imported_author: Option<String>,
    body_html: String,
    body_raw: String,
    created: String,
    edited: Option<String>,
    can_edit: bool,
}

/// One Conversation timeline row: a sentence plus an optional outbound link
/// (a check's `http(s)` target, or a readable session's viewer page). The
/// URL is only ever an `http(s)` check target or a same-origin session
/// path built from the repo coordinates and a ULID; askama escapes both.
pub struct TimelineLink {
    url: String,
    label: String,
}

pub struct TimelineItem {
    text: String,
    time: String,
    link: Option<TimelineLink>,
}

/// One change on a trail, as the trail page's Changes section renders it.
pub struct TrailChangeItem {
    k: i64,
    kind: String,
    head_branch: Option<String>,
    /// The `refs/for` push topic for `agit` changes; `None` otherwise.
    topic: Option<String>,
    base_branch: String,
    current_revision: i64,
    state: String,
    mergeability: String,
}

/// The D6 header shared by every Trail tab (`trail_header.html`): tabs with
/// live counts, intent, labels, assignees, reviewers, and a gate panel per
/// open change.
pub struct TrailHeader {
    tabs: TrailTabs,
    csrf: String,
    number: i64,
    title: String,
    state: String,
    ready: bool,
    author_handle: String,
    imported_author: Option<String>,
    labels: Vec<String>,
    assignees: Vec<String>,
    review_requests: Vec<String>,
    created: String,
    updated: String,
    closed: Option<String>,
    intent_html: String,
    intent_raw: String,
    changes: Vec<TrailChangeItem>,
    gate_panels: Vec<GatePanel>,
    can_edit: bool,
    can_triage: bool,
    can_comment: bool,
    can_create_change: bool,
    can_link: bool,
    is_open: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "trail.html")]
pub struct TrailPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    header: TrailHeader,
    tabs: TrailTabs,
    comments: Vec<CommentItem>,
    timeline: Vec<TimelineItem>,
    error: Option<String>,
}

/// One change row on the D6 changes list page, with its gate summary.
pub struct ChangeListItem {
    k: i64,
    kind: String,
    head_branch: Option<String>,
    /// The `refs/for` push topic for `agit` changes; `None` otherwise.
    topic: Option<String>,
    base_branch: String,
    current_revision: i64,
    state: String,
    mergeability: String,
    gates_passed: bool,
    gate_summary: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "trail_changes.html")]
pub struct TrailChangesPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    header: TrailHeader,
    tabs: TrailTabs,
    items: Vec<ChangeListItem>,
    error: Option<String>,
}

/// One Trail commit with its readable sessions on the D5 Sessions tab.
pub struct SessionGroupView {
    sha: String,
    short: String,
    subject: String,
    change: i64,
    revision: i64,
    first_seen: String,
    sessions: Vec<SessionChip>,
    totals: TokenTotals,
}

#[derive(Template, WebTemplate)]
#[template(path = "trail_sessions.html")]
pub struct TrailSessionsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    header: TrailHeader,
    tabs: TrailTabs,
    groups: Vec<SessionGroupView>,
    linked: Vec<SessionChip>,
    totals: TokenTotals,
    error: Option<String>,
}

/// Builds the D6 header shared by every Trail tab, plus the viewer's
/// readable linked sessions (D5) for the Sessions tab and per-change
/// session evidence. Shared by the viewer, the tab pages, and the 422
/// re-renders.
pub(crate) async fn header_data(
    state: &AppState,
    session: Option<&WebSession>,
    owner: &str,
    repo: &str,
    number: i64,
    active: &str,
) -> Result<(RepoHead, TrailHeader, TrailSessions), WebError> {
    let user = session.map(|s| &s.user);
    let access = state.core.repo_for(user, owner, repo).await?;
    let detail = state
        .core
        .trail_by_number(user, owner, repo, number)
        .await?;
    let trail = &detail.trail;
    let changes = state
        .core
        .list_changes(user, owner, repo, number, None)
        .await?;
    let sessions = state.core.trail_sessions(user, owner, repo, number).await?;
    let mut seen: Vec<&str> = sessions
        .commits
        .iter()
        .flat_map(|g| g.sessions.iter().map(|s| s.ulid.as_str()))
        .chain(sessions.linked.iter().map(|s| s.ulid.as_str()))
        .collect();
    seen.sort_unstable();
    seen.dedup();
    let mut gate_panels = Vec::new();
    for c in &changes {
        if c.state != "open" {
            continue;
        }
        let change_detail = state
            .core
            .get_change(user, owner, repo, number, c.k, None)
            .await?;
        let (approvals, request_changes) =
            super::changes::count_votes(state, &access, &change_detail.reviews).await?;
        let session_count: usize = sessions
            .commits
            .iter()
            .filter(|g| g.change == c.k)
            .map(|g| g.sessions.len())
            .sum();
        gate_panels.push(
            super::changes::gate_panel(
                state,
                session,
                &access,
                &change_detail,
                approvals,
                request_changes,
                session_count,
            )
            .await?,
        );
    }
    let head = RepoHead::new(&access, "trails", None);
    let header = TrailHeader {
        tabs: TrailTabs {
            owner: access.repo.owner.clone(),
            repo: access.repo.name.clone(),
            number,
            active: active.to_owned(),
            changes_count: changes.len(),
            sessions_count: seen.len(),
        },
        csrf: session.map(|s| s.csrf_token.clone()).unwrap_or_default(),
        number: trail.number,
        title: trail.title.clone(),
        state: trail.state.clone(),
        ready: trail.ready,
        author_handle: trail.author_handle.clone(),
        imported_author: trail.imported_author.clone(),
        labels: trail.labels.clone(),
        assignees: trail.assignees.clone(),
        review_requests: trail.review_requests.clone(),
        created: format_time(trail.created_at),
        updated: format_time(trail.updated_at),
        closed: trail.closed_at.map(format_time),
        intent_html: markdown::render_prose(&trail.intent),
        intent_raw: trail.intent.clone(),
        changes: changes
            .into_iter()
            .map(|c| TrailChangeItem {
                k: c.k,
                kind: c.kind,
                head_branch: c.head_branch,
                topic: c.topic,
                base_branch: c.base_branch,
                current_revision: c.current_revision,
                state: c.state,
                mergeability: c.mergeability,
            })
            .collect(),
        gate_panels,
        can_edit: detail.can_edit,
        can_triage: detail.can_triage,
        can_comment: session.is_some(),
        can_create_change: detail.can_triage,
        can_link: detail.can_triage
            || session.is_some_and(|s| detail.trail.author_id == Some(s.user.id)),
        is_open: trail.state == "open",
    };
    Ok((head, header, sessions))
}

/// Builds the detail view; shared by the viewer and the 422 re-renders.
pub(crate) async fn detail_view(
    state: &AppState,
    session: Option<&WebSession>,
    owner: &str,
    repo: &str,
    number: i64,
    error: Option<String>,
) -> Result<TrailPage, WebError> {
    let user = session.map(|s| &s.user);
    let access = state.core.repo_for(user, owner, repo).await?;
    let detail = state
        .core
        .trail_by_number(user, owner, repo, number)
        .await?;
    let entries = state.core.trail_timeline(user, owner, repo, number).await?;
    let (head, header, sessions) =
        header_data(state, session, owner, repo, number, "conversation").await?;
    // §6.4: stored session-link rows name the session only when the viewer
    // can read it; everything else in `sessions` is already filtered.
    let readable: HashSet<&str> = sessions
        .commits
        .iter()
        .flat_map(|g| g.sessions.iter().map(|s| s.ulid.as_str()))
        .chain(sessions.linked.iter().map(|s| s.ulid.as_str()))
        .collect();
    let mut handles: HashMap<i64, String> = HashMap::new();
    for id in entries.iter().filter_map(|entry| match entry {
        TrailTimelineEntry::Stored(event) => event.actor_id,
        TrailTimelineEntry::Session(_) => None,
        TrailTimelineEntry::Check(check) => check.row.creator_id,
    }) {
        if let Entry::Vacant(slot) = handles.entry(id) {
            let handle = state
                .core
                .user_by_id(id)
                .await?
                .map(|u| u.handle)
                .unwrap_or_else(|| "someone".to_owned());
            slot.insert(handle);
        }
    }
    let owner_name = header.tabs.owner.clone();
    let repo_name = header.tabs.repo.clone();
    let mut timeline = Vec::with_capacity(entries.len());
    for entry in &entries {
        match entry {
            TrailTimelineEntry::Stored(event) => {
                let actor = event
                    .actor_id
                    .and_then(|id| handles.get(&id).cloned())
                    .or_else(|| {
                        // A `trail.imported` event on a placeholder-author
                        // Trail names the original GitHub login (M4c D1).
                        if event.kind == "trail.imported" {
                            detail.trail.imported_author.clone()
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "starforge".to_owned());
                let (text, link) = stored_timeline_item(
                    &readable,
                    &owner_name,
                    &repo_name,
                    &event.kind,
                    &event.payload,
                    &actor,
                );
                timeline.push(TimelineItem {
                    text,
                    time: format_time(event.created_at),
                    link,
                });
            }
            TrailTimelineEntry::Session(entry) => {
                timeline.push(session_timeline_item(&owner_name, &repo_name, entry));
            }
            TrailTimelineEntry::Check(entry) => {
                let creator = entry
                    .row
                    .creator_id
                    .and_then(|id| handles.get(&id).cloned())
                    .unwrap_or_else(|| "someone".to_owned());
                timeline.push(check_timeline_item(entry, &creator));
            }
        }
    }
    let comments = detail
        .comments
        .iter()
        .map(|c| CommentItem {
            id: c.id,
            author_handle: c.author_handle.clone(),
            imported_author: c.imported_author.clone(),
            body_html: markdown::render_prose(&c.body),
            body_raw: c.body.clone(),
            created: format_time(c.created_at),
            edited: c.edited_at.map(format_time),
            can_edit: session.is_some_and(|s| {
                c.author_id == Some(s.user.id)
                    || access.permission >= Permission::Admin
                    || s.user.is_admin
            }),
        })
        .collect();
    Ok(TrailPage {
        nav_user: session.map(NavUser::from_session),
        head,
        tabs: header.tabs.clone(),
        header,
        comments,
        timeline,
        error,
    })
}

/// The `session` ULID in a `trail.session_linked/unlinked` payload, if it
/// parses. Untrusted JSON falls back to no identifier.
fn session_payload_ulid(payload: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()?
        .get("session")?
        .as_str()
        .map(str::to_owned)
}

/// A stored event's timeline row. `trail.session_linked/unlinked` rows name
/// and link the session only when the viewer can read it (§6.4); otherwise
/// the sentence carries no identifier.
fn stored_timeline_item(
    readable: &HashSet<&str>,
    owner: &str,
    repo: &str,
    kind: &str,
    payload: &str,
    actor: &str,
) -> (String, Option<TimelineLink>) {
    if matches!(kind, "trail.session_linked" | "trail.session_unlinked") {
        let linked = session_payload_ulid(payload).filter(|ulid| readable.contains(ulid.as_str()));
        match linked {
            Some(ulid) => {
                let link = TimelineLink {
                    url: format!("/{owner}/{repo}/sessions/{ulid}"),
                    label: "view session".to_owned(),
                };
                (timeline_text(kind, payload, actor), Some(link))
            }
            None => {
                let verb = if kind == "trail.session_linked" {
                    "linked"
                } else {
                    "unlinked"
                };
                (format!("{actor} {verb} a session"), None)
            }
        }
    } else {
        (timeline_text(kind, payload, actor), None)
    }
}

/// A derived session row: the readable session's preview, agent, and the
/// commit (with change/revision) that links it, plus a viewer deep link.
fn session_timeline_item(owner: &str, repo: &str, entry: &TimelineSession) -> TimelineItem {
    let short: String = entry.sha.chars().take(7).collect();
    let text = format!(
        "Session \"{}\" ({} {}) linked through commit {short} (change {}, revision {})",
        entry.row.title, entry.row.agent, entry.row.agent_version, entry.change, entry.revision
    );
    let mut url = format!("/{owner}/{repo}/sessions/{}", entry.row.ulid);
    if let Some(seq) = entry.row.seq_start {
        url.push_str(&format!("#turn-{seq}"));
    }
    TimelineItem {
        text,
        time: format_time(entry.at),
        link: Some(TimelineLink {
            url,
            label: "view session".to_owned(),
        }),
    }
}

/// A derived check row: creator, state, context, and change/revision label,
/// with the description appended and the target linked only for `http(s)`.
fn check_timeline_item(entry: &TimelineCheck, creator: &str) -> TimelineItem {
    let row = &entry.row;
    let mut text = format!(
        "{creator} reported {} for {} on change {} (revision {})",
        row.state, row.context, entry.change, entry.revision
    );
    if let Some(description) = row.description.as_deref().filter(|d| !d.is_empty()) {
        text.push_str(": ");
        text.push_str(description);
    }
    let link = row
        .target_url
        .as_deref()
        .filter(|url| http_link(url))
        .map(|url| TimelineLink {
            url: url.to_owned(),
            label: "details".to_owned(),
        });
    TimelineItem {
        text,
        time: format_time(entry.at),
        link,
    }
}

/// Target URLs become links only when they are `http`/`https`.
fn http_link(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Builds the D6 changes list page: every change with its gate summary.
pub(crate) async fn changes_view(
    state: &AppState,
    session: Option<&WebSession>,
    owner: &str,
    repo: &str,
    number: i64,
    error: Option<String>,
) -> Result<TrailChangesPage, WebError> {
    let user = session.map(|s| &s.user);
    let (head, header, _) = header_data(state, session, owner, repo, number, "changes").await?;
    let mut items = Vec::new();
    for c in state
        .core
        .list_changes(user, owner, repo, number, None)
        .await?
    {
        let gates = state
            .core
            .evaluate_gates(user, owner, repo, number, c.k)
            .await?;
        let summary = if gates.results.is_empty() {
            "No gate rules match this change — gates pass.".to_owned()
        } else if gates.passed {
            "All gates pass.".to_owned()
        } else {
            gates
                .results
                .iter()
                .filter(|g| !g.passed)
                .map(|g| g.reason.clone())
                .collect::<Vec<_>>()
                .join("; ")
        };
        items.push(ChangeListItem {
            k: c.k,
            kind: c.kind,
            head_branch: c.head_branch,
            topic: c.topic,
            base_branch: c.base_branch,
            current_revision: c.current_revision,
            state: c.state,
            mergeability: c.mergeability,
            gates_passed: gates.passed,
            gate_summary: summary,
        });
    }
    Ok(TrailChangesPage {
        nav_user: session.map(NavUser::from_session),
        head,
        tabs: header.tabs.clone(),
        header,
        items,
        error,
    })
}

/// Builds the D5 Sessions tab: commit groups with per-group totals, the
/// hand-linked group, and Trail-wide totals — all §6.4-filtered by Core.
pub(crate) async fn sessions_view(
    state: &AppState,
    session: Option<&WebSession>,
    owner: &str,
    repo: &str,
    number: i64,
    error: Option<String>,
) -> Result<TrailSessionsPage, WebError> {
    let (head, header, sessions) =
        header_data(state, session, owner, repo, number, "sessions").await?;
    let owner_name = header.tabs.owner.clone();
    let repo_name = header.tabs.repo.clone();
    let mut groups = Vec::new();
    for g in &sessions.commits {
        let chips = g
            .sessions
            .iter()
            .map(|s| SessionChip::from_link_row(&owner_name, &repo_name, s, ""))
            .collect::<Vec<_>>();
        let mut totals = TokenTotals::default();
        for s in &g.sessions {
            totals.add(&s.totals);
        }
        groups.push(SessionGroupView {
            sha: g.sha.clone(),
            short: g.sha.chars().take(7).collect(),
            subject: g.subject.clone(),
            change: g.change,
            revision: g.revision,
            first_seen: format_time(g.first_seen_at),
            sessions: chips,
            totals,
        });
    }
    let linked = sessions
        .linked
        .iter()
        .map(|s| SessionChip::from_link_row(&owner_name, &repo_name, s, ""))
        .collect();
    Ok(TrailSessionsPage {
        nav_user: session.map(NavUser::from_session),
        head,
        tabs: header.tabs.clone(),
        header,
        groups,
        linked,
        totals: sessions.totals,
        error,
    })
}

/// Human-readable timeline lines. The payload is untrusted JSON, so unknown
/// shapes fall back to the bare kind; askama escapes the result.
fn timeline_text(kind: &str, payload: &str, actor: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(payload).unwrap_or(serde_json::Value::Null);
    let field = |name: &str| value.get(name).and_then(|v| v.as_str());
    let num = |name: &str| value.get(name).and_then(|v| v.as_i64());
    match kind {
        "trail.open" => format!("{actor} opened this trail"),
        "trail.state" => match field("to") {
            Some("closed") => format!("{actor} closed this trail"),
            Some("open") => format!("{actor} reopened this trail"),
            _ => format!("{actor} changed the state"),
        },
        "trail.comment" => format!("{actor} commented"),
        "trail.label" => {
            let name = field("name").unwrap_or("a label");
            match field("action") {
                Some("remove") => format!("{actor} removed label {name}"),
                _ => format!("{actor} added label {name}"),
            }
        }
        "trail.assignee" => {
            let who = field("user").unwrap_or("someone");
            match field("action") {
                Some("remove") => format!("{actor} unassigned {who}"),
                _ => format!("{actor} assigned {who}"),
            }
        }
        "trail.review_requested" => {
            let who = field("user").unwrap_or("someone");
            format!("{actor} requested a review from {who}")
        }
        "trail.review_request_removed" => {
            let who = field("user").unwrap_or("someone");
            format!("{actor} removed the review request for {who}")
        }
        "trail.session_linked" => {
            let ulid = field("session").unwrap_or("a session");
            format!("{actor} linked session {ulid}")
        }
        "trail.session_unlinked" => {
            let ulid = field("session").unwrap_or("a session");
            format!("{actor} unlinked session {ulid}")
        }
        "trail.edit" => {
            let fields = value
                .get("fields")
                .and_then(|v| v.as_array())
                .map(|fields| {
                    fields
                        .iter()
                        .filter_map(|f| f.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "the trail".to_owned());
            format!("{actor} edited {fields}")
        }
        "trail.merged" => format!("{actor} merged this trail"),
        "change.open" => match (num("change"), field("kind")) {
            (Some(k), Some("agit")) => match (field("topic"), field("base")) {
                (Some(topic), Some(base)) => {
                    format!("{actor} opened change {k} ({topic} onto {base})")
                }
                _ => format!("{actor} opened change {k}"),
            },
            (Some(k), _) => match (field("head"), field("base")) {
                (Some(head), Some(base)) => {
                    format!("{actor} opened change {k} from branch {head} onto {base}")
                }
                _ => format!("{actor} opened change {k}"),
            },
            _ => format!("{actor} opened a change"),
        },
        "change.revision" => match (num("change"), num("revision")) {
            (Some(k), Some(r)) => format!("{actor} pushed revision {r} to change {k}"),
            _ => format!("{actor} pushed a revision"),
        },
        "change.mergeability" => match (num("change"), field("from"), field("to")) {
            (Some(k), Some(from), Some(to)) => {
                format!("{actor} change {k} merge status changed from {from} to {to}")
            }
            _ => format!("{actor} recomputed mergeability"),
        },
        "change.state" => match (num("change"), field("to")) {
            (Some(k), Some("closed")) => format!("{actor} closed change {k}"),
            (Some(k), Some("open")) => format!("{actor} reopened change {k}"),
            (Some(k), _) => format!("{actor} changed the state of change {k}"),
            _ => format!("{actor} changed a change's state"),
        },
        "change.merge" => match (num("change"), field("method")) {
            (Some(k), Some(method)) => format!("{actor} merged change {k} ({method})"),
            (Some(k), None) => format!("{actor} merged change {k}"),
            _ => format!("{actor} merged a change"),
        },
        "review.submitted" => match (num("change"), num("revision"), field("verdict")) {
            (Some(k), Some(r), Some("approve")) => {
                format!("{actor} approved change {k} (revision {r})")
            }
            (Some(k), Some(r), Some("request_changes")) => {
                format!("{actor} requested changes on change {k} (revision {r})")
            }
            (Some(k), Some(r), _) => format!("{actor} reviewed change {k} (revision {r})"),
            _ => format!("{actor} submitted a review"),
        },
        "review.dismissed" => match (num("change"), field("reason")) {
            (Some(k), Some(reason)) => {
                format!("{actor} dismissed a review on change {k} ({reason})")
            }
            (Some(k), None) => format!("{actor} dismissed a review on change {k}"),
            _ => format!("{actor} dismissed a review"),
        },
        "thread.open" => match (num("change"), field("path")) {
            (Some(k), Some(path)) => format!("{actor} opened a thread on change {k} ({path})"),
            (Some(k), None) => format!("{actor} opened a thread on change {k}"),
            _ => format!("{actor} opened a thread"),
        },
        "trail.imported" => format!("{actor} imported this trail"),
        "thread.resolved" => {
            let resolved = value
                .get("resolved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            match (num("change"), resolved) {
                (Some(k), true) => format!("{actor} resolved a thread on change {k}"),
                (Some(k), false) => format!("{actor} reopened a thread on change {k}"),
                _ => format!("{actor} changed a thread"),
            }
        }
        "thread.comment" => match num("change") {
            Some(k) => format!("{actor} commented on a thread on change {k}"),
            None => format!("{actor} commented on a thread"),
        },
        _ => format!("{actor} {kind}"),
    }
}

/// `GET /{owner}/{repo}/trails/{number}`.
pub async fn detail(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<impl IntoResponse, WebError> {
    let page = detail_view(&state, session.as_ref(), &owner, &repo, number, None).await?;
    Ok((detail_headers(), page))
}

/// `GET /{owner}/{repo}/trails/{number}/changes`: the D6 changes list page.
/// Non-readers 404, exactly like the conversation page.
pub async fn changes_list(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<impl IntoResponse, WebError> {
    let page = changes_view(&state, session.as_ref(), &owner, &repo, number, None).await?;
    Ok((detail_headers(), page))
}

/// `GET /{owner}/{repo}/trails/{number}/sessions`: the D5 Sessions tab.
/// Every row is §6.4-filtered for the viewer by Core; non-readers 404.
pub async fn sessions(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<impl IntoResponse, WebError> {
    let page = sessions_view(&state, session.as_ref(), &owner, &repo, number, None).await?;
    Ok((detail_headers(), page))
}

#[derive(Deserialize)]
pub struct TrailSessionLinkForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    session: String,
}

/// `POST /{owner}/{repo}/trails/{number}/sessions`: links a session by hand
/// (D3). Non-readers 404 before the CSRF check; `Invalid`/`Conflict`
/// re-render the tab with 422.
pub async fn link_session(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<TrailSessionLinkForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .link_trail_session(&session.user, &owner, &repo, number, form.session.trim())
        .await
    {
        Ok(()) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/sessions",
            access.repo.owner, access.repo.name
        ))
        .into_response()),
        Err(
            starforged_core::CoreError::Invalid(message)
            | starforged_core::CoreError::Conflict(message),
        ) => {
            let page =
                sessions_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct TrailSessionUnlinkForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
}

/// `POST /{owner}/{repo}/trails/{number}/sessions/{ulid}/unlink`: removes a
/// hand link (D3). Same visibility and error rules as the link form.
pub async fn unlink_session(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, ulid)): Path<(String, String, i64, String)>,
    Form(form): Form<TrailSessionUnlinkForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .unlink_trail_session(&session.user, &owner, &repo, number, ulid.trim())
        .await
    {
        Ok(()) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/sessions",
            access.repo.owner, access.repo.name
        ))
        .into_response()),
        Err(
            starforged_core::CoreError::Invalid(message)
            | starforged_core::CoreError::Conflict(message),
        ) => {
            let page =
                sessions_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct CommentForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    body: String,
}

/// `POST /{owner}/{repo}/trails/{number}/comment`: any signed-in reader.
/// `Invalid` re-renders the detail with 422.
pub async fn comment(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<CommentForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .add_comment(&session.user, &owner, &repo, number, &form.body)
        .await
    {
        Ok(saved) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}#comment-{}",
                access.repo.owner, access.repo.name, saved.id
            ))
            .into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page =
                detail_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct EditForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    title: Option<String>,
    intent: Option<String>,
    ready: Option<String>,
}

/// `POST /{owner}/{repo}/trails/{number}/edit`: the author (title/intent)
/// or triage (anything, including the ready toggle). `Invalid` re-renders.
pub async fn edit(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<EditForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let ready = match form.ready.as_deref() {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return Err(WebError::BadRequest("invalid ready value".into())),
    };
    match state
        .core
        .update_trail(
            &session.user,
            &owner,
            &repo,
            number,
            form.title.as_deref(),
            form.intent.as_deref(),
            ready,
        )
        .await
    {
        Ok(_) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}",
                access.repo.owner, access.repo.name
            ))
            .into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page =
                detail_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct CommentEditForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    body: String,
}

/// `POST /{owner}/{repo}/trails/{number}/comments/{id}/edit`: the comment
/// author or an admin. `Invalid` re-renders the detail with 422.
pub async fn edit_comment(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, id)): Path<(String, String, i64, i64)>,
    Form(form): Form<CommentEditForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .edit_comment(&session.user, &owner, &repo, number, id, &form.body)
        .await
    {
        Ok(_) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}#comment-{id}",
                access.repo.owner, access.repo.name
            ))
            .into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page =
                detail_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct StateForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    state: String,
}

/// `POST /{owner}/{repo}/trails/{number}/state`: triage-only close/reopen.
/// `merged` is owned by the merge path and rejected with 400.
pub async fn set_state(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<StateForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .set_trail_state(&session.user, &owner, &repo, number, &form.state)
        .await?;
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct LabelForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    name: String,
}

/// `POST /{owner}/{repo}/trails/{number}/labels`: triage-only add/remove
/// via the `action` field. Bad labels are 400.
pub async fn set_label(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<LabelForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match form.action.as_str() {
        "add" => {
            state
                .core
                .add_label(&session.user, &owner, &repo, number, &form.name)
                .await?;
        }
        "remove" => {
            state
                .core
                .remove_label(&session.user, &owner, &repo, number, &form.name)
                .await?;
        }
        _ => return Err(WebError::BadRequest("unknown action".into())),
    }
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct AssigneeForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    handle: String,
}

/// `POST /{owner}/{repo}/trails/{number}/assignees`: triage-only add/remove
/// via the `action` field. Unknown users are 400.
pub async fn set_assignee(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<AssigneeForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match form.action.as_str() {
        "add" => {
            state
                .core
                .add_assignee(&session.user, &owner, &repo, number, &form.handle)
                .await?;
        }
        "remove" => {
            state
                .core
                .remove_assignee(&session.user, &owner, &repo, number, &form.handle)
                .await?;
        }
        _ => return Err(WebError::BadRequest("unknown action".into())),
    }
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct ReviewerForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    handle: String,
}

/// `POST /{owner}/{repo}/trails/{number}/review-requests`: triage-only
/// add/remove via the `action` field. Unknown users are 400.
pub async fn set_review_request(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<ReviewerForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match form.action.as_str() {
        "add" => {
            state
                .core
                .request_review(&session.user, &owner, &repo, number, &form.handle)
                .await?;
        }
        "remove" => {
            state
                .core
                .remove_review_request(&session.user, &owner, &repo, number, &form.handle)
                .await?;
        }
        _ => return Err(WebError::BadRequest("unknown action".into())),
    }
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}
