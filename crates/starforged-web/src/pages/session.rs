//! Session viewer page (spec §6.4, §10.2): one authorized read, paged
//! transcript, quarantine banner with admin-only release/purge forms.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::permission::Permission;
use starforged_core::read::SessionPageItem;

use crate::AppState;
use crate::auth::{CsrfForm, MaybeUser, verify_csrf};
use crate::error::WebError;
use crate::session_render::render_event;
use crate::views::{NavUser, RepoHead, format_time, nav};

#[derive(Deserialize)]
pub struct SessionQuery {
    page: Option<i64>,
    focus: Option<i64>,
}

/// One rendered transcript slot: an event (`turn-<seq>`) or an undecodable
/// segment (`segment-<n>`).
pub struct EventView {
    anchor: String,
    html: String,
    focused: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "session.html")]
pub struct SessionPageView {
    nav_user: Option<NavUser>,
    head: RepoHead,
    ulid: String,
    title: String,
    agent_name: String,
    agent_version: String,
    adapter_verified: bool,
    models: String,
    branch: String,
    head_sha: String,
    started: String,
    ended: String,
    usage: String,
    redaction_fingerprint: String,
    redaction_counts: String,
    capture_mode: String,
    visibility: String,
    quarantined: bool,
    quarantine_reason: String,
    quarantine_detail: String,
    can_admin: bool,
    csrf: String,
    events: Vec<EventView>,
    page: i64,
    pages: i64,
    total: i64,
    prev: Option<i64>,
    next: Option<i64>,
}

/// `GET /{owner}/{repo}/sessions/{ulid}?page=N&focus=seq`.
pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    Query(query): Query<SessionQuery>,
) -> Result<impl IntoResponse, WebError> {
    // The single authorization check: repo readability, session lookup, and
    // the §6.4 read rule. Denials are 404 (ULIDs stay undiscoverable).
    let user = session.as_ref().map(|s| &s.user);
    let (access, session_row) = state
        .core
        .authorize_session_read_by_ulid(user, &owner, &repo, &ulid)
        .await?;
    // `?focus=<seq>` wins over `?page=`: it resolves to the containing page.
    let (page, focus) = match query.focus {
        Some(seq) => {
            let (page, found) = state.core.page_for_seq(session_row.id, seq).await?;
            (page, found.then_some(seq))
        }
        None => (query.page.unwrap_or(1), None),
    };
    let view = state.core.read_session_page(session_row.id, page).await?;
    let mut events = Vec::with_capacity(view.items.len());
    for item in &view.items {
        match item {
            SessionPageItem::Event(event) => {
                let focused = focus.is_some_and(|seq| event.seq as i64 == seq);
                events.push(EventView {
                    anchor: format!("turn-{}", event.seq),
                    html: render_event(event),
                    focused,
                });
            }
            SessionPageItem::UnreadableSegment { n } => events.push(EventView {
                anchor: format!("segment-{n}"),
                html: format!(
                    "<div class=\"notice\">unreadable segment {n}: its bytes could not be decoded</div>"
                ),
                focused: false,
            }),
        }
    }
    let models = serde_json::from_str::<Vec<String>>(&session_row.models)
        .map(|models| models.join(", "))
        .unwrap_or_else(|_| session_row.models.clone());
    let page_view = SessionPageView {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "sessions", None),
        ulid: session_row.ulid.clone(),
        title: session_row.title.clone(),
        agent_name: session_row.agent_name.clone(),
        agent_version: session_row.agent_version.clone(),
        adapter_verified: session_row.adapter_verified != 0,
        models,
        branch: session_row.branch.clone(),
        head_sha: session_row.head_sha.clone(),
        started: format_time(session_row.started_at),
        ended: session_row
            .ended_at
            .map(format_time)
            .unwrap_or_else(|| "in progress".to_owned()),
        usage: format!(
            "{} input · {} output · {} cache read · {} cache write · {} reasoning",
            session_row.usage_input,
            session_row.usage_output,
            session_row.usage_cache_read,
            session_row.usage_cache_write,
            session_row.usage_reasoning
        ),
        redaction_fingerprint: session_row.redaction_fingerprint.clone(),
        redaction_counts: session_row.redaction_counts.clone(),
        capture_mode: session_row.capture_mode.clone(),
        visibility: session_row.visibility.clone(),
        quarantined: session_row.quarantine == "quarantined",
        quarantine_reason: session_row.quarantine_reason.clone(),
        quarantine_detail: session_row.quarantine_detail.clone(),
        can_admin: access.permission >= Permission::Admin,
        csrf: session
            .as_ref()
            .map(|s| s.csrf_token.clone())
            .unwrap_or_default(),
        events,
        page: view.page,
        pages: view.pages,
        total: view.total,
        prev: (view.page > 1).then_some(view.page - 1),
        next: (view.page < view.pages).then_some(view.page + 1),
    };
    // Sessions never reach search indexes (spec §11.1).
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    Ok((headers, page_view))
}

/// `POST /{owner}/{repo}/sessions/{ulid}/release`: clears a quarantine back
/// to `released` (evidence columns stay for forensics). Repo admins only;
/// everyone else 404s, exactly like the viewer itself.
pub async fn release(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    let session = session.as_ref().ok_or(WebError::NotFound)?;
    let (access, _) = state
        .core
        .authorize_session_read_by_ulid(Some(&session.user), &owner, &repo, &ulid)
        .await?;
    if access.permission < Permission::Admin {
        return Err(WebError::NotFound);
    }
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .release_session(&session.user, &access, &ulid)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/sessions/{ulid}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

/// `POST /{owner}/{repo}/sessions/{ulid}/purge`: deletes the session, its
/// segments, and its commit links. Repo admins only.
pub async fn purge(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    let session = session.as_ref().ok_or(WebError::NotFound)?;
    let (access, _) = state
        .core
        .authorize_session_read_by_ulid(Some(&session.user), &owner, &repo, &ulid)
        .await?;
    if access.permission < Permission::Admin {
        return Err(WebError::NotFound);
    }
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .purge_session(&session.user, &access, &ulid)
        .await?;
    Ok(Redirect::to(&format!("/{}/{}", access.repo.owner, access.repo.name)).into_response())
}
/// `GET /{owner}/{repo}/sessions/{ulid}/download`: the full normalized
/// transcript (the same redacted bytes the viewer renders) as an attachment.
/// Same single read-rule check as the viewer; non-readers 404.
pub async fn download(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<Response, WebError> {
    let user = session.as_ref().map(|s| &s.user);
    let (_, session_row) = state
        .core
        .authorize_session_read_by_ulid(user, &owner, &repo, &ulid)
        .await?;
    let jsonl = state.core.read_session_jsonl(session_row.id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{}.jsonl\"",
            session_row.ulid
        ))
        .unwrap_or(HeaderValue::from_static("attachment")),
    );
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    Ok((headers, jsonl).into_response())
}
