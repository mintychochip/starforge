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
use crate::session_render::{render_event, render_marker};
use crate::views::{
    FileView, NavUser, RepoHead, STRICT_CSP, display_title, file_views, format_time, nav,
};

#[derive(Deserialize)]
pub struct SessionQuery {
    page: Option<i64>,
    focus: Option<i64>,
    q: Option<String>,
    split: Option<String>,
}

/// One in-session search hit (D3): a `turn-<seq>` deep link (to the page
/// holding the event) with a server-redacted snippet. The template escapes
/// `preview` (numeric entities); nothing here is `|safe`.
pub struct SearchHitView {
    seq: u64,
    page: i64,
    preview: String,
}

/// One rendered transcript slot: an event (`turn-<seq>`) or an undecodable
/// segment (`segment-<n>`).
pub struct EventView {
    anchor: String,
    html: String,
    focused: bool,
}

/// One linked session heading: the readable parent (when present) and each
/// readable direct child. Titles fall back to `Untitled session`.
pub struct RelatedSessionView {
    ulid: String,
    title: String,
    agent_name: String,
    lifecycle: String,
}

fn related_view(
    ulid: String,
    title: &str,
    agent_name: String,
    lifecycle: String,
) -> RelatedSessionView {
    RelatedSessionView {
        ulid,
        title: display_title(title),
        agent_name,
        lifecycle,
    }
}

/// One checkpoint row on the session page.
pub struct CheckpointItem {
    n: i64,
    commit: String,
    short: String,
    label: String,
    source: String,
    created: String,
    parent: Option<String>,
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
    is_published: bool,
    quarantined: bool,
    quarantine_reason: String,
    quarantine_detail: String,
    can_admin: bool,
    can_maintain: bool,
    can_delete: bool,
    csrf: String,
    events: Vec<EventView>,
    page: i64,
    pages: i64,
    total: i64,
    prev: Option<i64>,
    next: Option<i64>,
    /// The echoed `?q=` (empty when absent); the template escapes it.
    q: String,
    searched: bool,
    hit_count: usize,
    search_hits: Vec<SearchHitView>,
    /// `?split=<sha>` when active: the linked commit's sha and its diff
    /// (`files`/`truncated` feed the shared `diff_files.html` partial).
    split_sha: Option<String>,
    files: Vec<FileView>,
    truncated: bool,
    /// The readable parent, when this session names one the viewer may
    /// read; unreadable or absent parents stay hidden.
    parent: Option<RelatedSessionView>,
    /// Readable direct subagent sessions, oldest first.
    children: Vec<RelatedSessionView>,
    /// True when exactly the display cap of children is shown: the list
    /// may be truncated (no total or candidate count is ever revealed).
    child_truncated: bool,
    /// Checkpoints of this session, ascending.
    checkpoints: Vec<CheckpointItem>,
}

/// `GET /{owner}/{repo}/sessions/{ulid}?page=N&focus=seq&q=needle&split=<sha>`:
/// paged transcript with in-session search (`q`) and, for a linked commit
/// sha (`split`), the split view beside the transcript. All server-rendered;
/// the page is complete without JS.
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
    // Commit markers (D3): group by `seq_end`; each renders immediately
    // after the event at that seq, linking to the commit page and split view.
    let markers = state.core.commit_markers(session_row.id).await?;
    let mut markers_by_seq: std::collections::HashMap<
        i64,
        Vec<&starforged_core::read::CommitMarker>,
    > = std::collections::HashMap::new();
    for marker in &markers {
        markers_by_seq
            .entry(marker.seq_end)
            .or_default()
            .push(marker);
    }
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
                if let Some(linked) = markers_by_seq.get(&(event.seq as i64)) {
                    for marker in linked {
                        events.push(EventView {
                            anchor: format!("commit-{}", marker.short_sha),
                            html: render_marker(
                                &marker.sha,
                                &marker.short_sha,
                                &format!("/{owner}/{repo}/commit/{}", marker.sha),
                                &format!("?split={}", marker.sha),
                            ),
                            focused: false,
                        });
                    }
                }
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
    // In-session search (D3): server-side results over the redacted stream;
    // the GET form works without JS. The query echo is template-escaped.
    let q = query.q.clone().unwrap_or_default();
    let searched = !q.trim().is_empty();
    let search_hits = if searched {
        state
            .core
            .search_session(session_row.id, &q)
            .await?
            .into_iter()
            .map(|hit| SearchHitView {
                seq: hit.seq,
                page: hit.page,
                preview: hit.preview,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    // Split view (D3): `?split=<sha>` renders the linked commit's diff
    // beside the transcript. The sha must be one of this session's linked
    // commits in this repository (404 otherwise); the session-read
    // authorization above already implies repository read.
    let split_sha = query.split.clone().filter(|sha| !sha.is_empty());
    let (split_sha, files, truncated) = match &split_sha {
        Some(sha) => {
            let links = state.core.session_links(session_row.id).await?;
            if !links.iter().any(|link| link.sha == *sha) {
                return Err(WebError::NotFound);
            }
            let info = state.core.commit(&access, sha).await?;
            let diff = state.core.diff(&access, &info.id).await?;
            (Some(sha.clone()), file_views(diff.files), diff.truncated)
        }
        None => (None, Vec::new(), false),
    };
    let models = serde_json::from_str::<Vec<String>>(&session_row.models)
        .map(|models| models.join(", "))
        .unwrap_or_else(|_| session_row.models.clone());
    // Parent/children links (§6.4-checked in core): an unreadable parent is
    // hidden rather than shown as a locked placeholder.
    let parent_row = state
        .core
        .readable_parent_session(user, &access, &session_row)
        .await?;
    let parent = parent_row.map(|row| {
        related_view(
            row.ulid.clone(),
            &row.title,
            row.agent_name.clone(),
            row.lifecycle.clone(),
        )
    });
    // One parent may have hundreds of children: cap candidates at the
    // display cap so neither the query nor the per-row auth checks grow
    // with the family size. Only the shown count is ever rendered.
    let child_rows = state
        .core
        .readable_child_sessions(user, &access, &session_row.ulid, 50)
        .await?;
    let child_truncated = child_rows.len() == 50;
    let children = child_rows
        .iter()
        .map(|row| {
            related_view(
                row.ulid.clone(),
                &row.title,
                row.agent_name.clone(),
                row.lifecycle.clone(),
            )
        })
        .collect::<Vec<_>>();
    let checkpoints = state
        .core
        .list_session_checkpoints(user, &owner, &repo, &ulid)
        .await?
        .into_iter()
        .map(|c| CheckpointItem {
            n: c.n,
            short: c.commit_sha.chars().take(10).collect(),
            commit: c.commit_sha,
            label: c.label,
            source: c.source,
            created: format_time(c.created_at),
            parent: c.parent_sha,
        })
        .collect::<Vec<_>>();
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
        is_published: session_row.visibility == "published",
        quarantined: session_row.quarantine == "quarantined",
        quarantine_reason: session_row.quarantine_reason.clone(),
        quarantine_detail: session_row.quarantine_detail.clone(),
        can_admin: access.permission >= Permission::Admin,
        can_maintain: access.permission >= Permission::Maintain,
        can_delete: session.as_ref().is_some_and(|s| {
            session_row.uploader_id == s.user.id
                || access.permission >= Permission::Admin
                || s.user.is_admin
        }),
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
        hit_count: search_hits.len(),
        q,
        searched,
        search_hits,
        split_sha,
        files,
        truncated,
        parent,
        children,
        child_truncated,
        checkpoints,
    };
    // Sessions never reach search indexes (spec §11.1). The transcript is
    // attacker-influenced, so the viewer also carries the strict CSP (it
    // wins over the middleware default, which uses `or_insert`). Session
    // routes must never be stored (M6c C6): `no-store, private`, `no-cache`,
    // and `Vary: Cookie, Authorization` — the page, search hits, and the
    // transcript preview are per-viewer and secret-bearing.
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    headers.insert(
        axum::http::header::PRAGMA,
        HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        axum::http::header::VARY,
        HeaderValue::from_static("Cookie, Authorization"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STRICT_CSP),
    );
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
/// `POST /{owner}/{repo}/sessions/{ulid}/publish`: flips `visibility` to
/// `published` (public repositories only). Repo `maintain` or above;
/// everyone else 404s, exactly like the viewer itself.
pub async fn publish(
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
    if access.permission < Permission::Maintain {
        return Err(WebError::NotFound);
    }
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .publish_session(&session.user, &access, &ulid)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/sessions/{ulid}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

/// `POST /{owner}/{repo}/sessions/{ulid}/unpublish`: the mirror of
/// [`publish`], back to `inherit` (an `Ok` no-op when the session was never
/// published). Same auth.
pub async fn unpublish(
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
    if access.permission < Permission::Maintain {
        return Err(WebError::NotFound);
    }
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .unpublish_session(&session.user, &access, &ulid)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/sessions/{ulid}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

/// `POST /{owner}/{repo}/sessions/{ulid}/delete`: the user-facing delete
/// path (forms cannot `DELETE`). The uploader, a repo admin, or a site admin
/// removes the session; everyone else 404s. Redirects to the repo page.
pub async fn delete(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    let session = session.as_ref().ok_or(WebError::NotFound)?;
    let (access, row) = state
        .core
        .authorize_session_read_by_ulid(Some(&session.user), &owner, &repo, &ulid)
        .await?;
    if row.uploader_id != session.user.id
        && access.permission < Permission::Admin
        && !session.user.is_admin
    {
        return Err(WebError::NotFound);
    }
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .delete_session(&session.user, &access, &ulid)
        .await?;
    Ok(Redirect::to(&format!("/{}/{}", access.repo.owner, access.repo.name)).into_response())
}

/// `POST /{owner}/{repo}/sessions/{ulid}/rescan`: re-runs the rule scan over
/// the stored segments and returns to the viewer, which shows the new
/// quarantine banner. Repo admins only; everyone else 404s.
pub async fn rescan(
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
        .admin_rescan_session(&session.user, &access, &ulid)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/sessions/{ulid}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
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
    // M6c C6: one of the session routes — never stored by any cache.
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    headers.insert(
        axum::http::header::PRAGMA,
        HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        axum::http::header::VARY,
        HeaderValue::from_static("Cookie, Authorization"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STRICT_CSP),
    );
    Ok((headers, jsonl).into_response())
}
