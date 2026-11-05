//! Change web UI (spec §6.2, §8, M2b G5 + M2c H4): change detail with
//! revision selector, unified diff, review summary and forms, file/line
//! threads, plus triage-gated dismiss and creator-or-triage state controls.
//! Reads 404 for non-readers so change numbers stay undiscoverable;
//! mutations answer 403 below their threshold. Review bodies and thread
//! comments render through [`crate::markdown::render_prose`]; everything
//! else relies on askama escaping. The merge form offers the gate-rule
//! allowed methods and submits only while the freshly evaluated gate set
//! passes; the server re-checks everything at merge time.

use std::collections::BTreeSet;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::changes::{ChangeDetail, ReviewView};
use starforged_core::permission::Permission;
use starforged_core::repos::RepoAccess;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{MaybeUser, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::markdown;
use crate::views::{
    FileView, GatePanel, GatePanelGate, InlineCommentView, InlineThreadView, NavUser, RepoHead,
    STRICT_CSP, TrailTabs, file_views_with, format_time, nav,
};

/// `X-Robots-Tag: noindex` on every change page, matching the trail pages.
fn noindex_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers
}

/// Noindex plus the strict CSP: review bodies and thread comments are
/// attacker-influenced Markdown (same combination as the session viewer).
fn detail_headers() -> HeaderMap {
    let mut headers = noindex_headers();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STRICT_CSP),
    );
    headers
}

fn short_sha(sha: &str) -> String {
    sha.chars().take(7).collect()
}

/// The literal disabled-merge reason: every requirement (open change, write
/// access, passing gates, an allowed method) must hold to enable the button.
const MERGE_TITLE: &str =
    "Merge needs an open change, write access, passing gates, and an allowed method.";

pub struct RevisionOption {
    r: i64,
    short: String,
    time: String,
    selected: bool,
}

pub struct ReviewItem {
    id: i64,
    revision: i64,
    author_handle: String,
    verdict: String,
    body_html: String,
    created: String,
    state: String,
    counting: bool,
    can_dismiss: bool,
}

pub struct ThreadCommentItem {
    author_handle: String,
    body_html: String,
    created: String,
}

pub struct ThreadItem {
    id: i64,
    path: String,
    side: String,
    start_line: i64,
    end_line: i64,
    revision: i64,
    resolved: bool,
    outdated: bool,
    comments: Vec<ThreadCommentItem>,
    can_resolve: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "change.html")]
pub struct ChangePage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    csrf: String,
    trail_number: i64,
    k: i64,
    kind: String,
    head_branch: Option<String>,
    base_branch: String,
    state: String,
    creator_handle: String,
    current_revision: i64,
    created: String,
    updated: String,
    revisions: Vec<RevisionOption>,
    selected_r: i64,
    files: Vec<FileView>,
    truncated: bool,
    /// Inter-revision view (D8): when `is_compare`, the diff is the tree diff
    /// between `compare_from` and `compare_to`, and every thread lists below.
    /// Otherwise threads anchored on the displayed revision render inline.
    is_compare: bool,
    compare_from: i64,
    compare_to: i64,
    /// Signed-in readers see per-file viewed toggles; anonymous viewers see none.
    show_toggles: bool,
    approvals: usize,
    request_changes: usize,
    reviewers: Vec<String>,
    reviews: Vec<ReviewItem>,
    /// The viewer's draft review (D9): the "Finish your review" panel shows
    /// while they hold pending comments.
    pending: Option<PendingPanel>,
    /// Threads that did not attach inline (or every thread in the
    /// inter-revision view), in creation order.
    threads: Vec<ThreadItem>,
    panel: GatePanel,
    tabs: TrailTabs,
    can_review: bool,
    can_triage: bool,
    can_close: bool,
    is_open: bool,
    error: Option<String>,
}

/// The "Finish your review" panel (D9): how many draft comments the viewer
/// holds on the change. Submitting the review form above attaches them;
/// the Discard form removes them.
pub struct PendingPanel {
    pub count: usize,
}

/// Counting votes for a change: live `submitted` `approve`s and
/// `request_changes` from authors holding Write+ (drafts never count; the
/// same rule the change page has always used). Shared with the Trail header
/// gate panels.
pub(crate) async fn count_votes(
    state: &AppState,
    access: &RepoAccess,
    reviews: &[ReviewView],
) -> Result<(usize, usize), WebError> {
    let mut approvals = 0;
    let mut request_changes = 0;
    for r in reviews {
        let author = state.core.user_by_handle(&r.author_handle).await?;
        let counting = state
            .core
            .permission_on(&access.repo, author.as_ref())
            .await?
            .is_some_and(|p| p >= Permission::Write);
        if r.state == "submitted" && counting {
            match r.verdict.as_str() {
                "approve" => approvals += 1,
                "request_changes" => request_changes += 1,
                _ => {}
            }
        }
    }
    Ok((approvals, request_changes))
}

/// The D6 header gate panel for one open change: approvals counted like the
/// change page, gates freshly evaluated (no new gate logic), merge offered
/// exactly while the viewer may merge.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn gate_panel(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    detail: &ChangeDetail,
    approvals: usize,
    request_changes: usize,
    session_count: usize,
) -> Result<GatePanel, WebError> {
    let user = session.map(|s| &s.user);
    let change = &detail.change;
    let gates = state
        .core
        .evaluate_gates(
            user,
            &access.repo.owner,
            &access.repo.name,
            change.trail_number,
            change.k,
        )
        .await?;
    // The merge form offers the matching rules' allowed methods (all three
    // when no rule matches). The button enables only while the fresh gate
    // set passes; the POST re-checks everything server-side anyway.
    let merge_methods = state
        .core
        .allowed_merge_methods(
            user,
            &access.repo.owner,
            &access.repo.name,
            change.trail_number,
            change.k,
        )
        .await?;
    let show_merge_form = access.permission >= Permission::Write
        && access.repo.archived_at.is_none()
        && change.state == "open";
    let merge_enabled = show_merge_form && gates.passed && !merge_methods.is_empty();
    Ok(GatePanel {
        owner: access.repo.owner.clone(),
        repo: access.repo.name.clone(),
        trail_number: change.trail_number,
        k: change.k,
        csrf: session.map(|s| s.csrf_token.clone()).unwrap_or_default(),
        kind: change.kind.clone(),
        head_branch: change.head_branch.clone(),
        base_branch: change.base_branch.clone(),
        state: change.state.clone(),
        current_revision: change.current_revision,
        mergeability: change.mergeability.clone(),
        conflict_paths: change.conflict_paths.clone(),
        approvals,
        request_changes,
        gates_passed: gates.passed,
        gates: gates
            .results
            .into_iter()
            .map(|g| GatePanelGate {
                rule: g.rule,
                passed: g.passed,
                reason: g.reason,
            })
            .collect(),
        merge_methods,
        show_merge_form,
        merge_enabled,
        merge_title: MERGE_TITLE,
        session_count,
    })
}

/// Builds the detail view; shared by the viewer and the 422 re-renders.
/// With `range = Some((from, to))` the diff is the tree diff between those
/// revisions' heads and every thread lists below; otherwise threads anchored
/// on the displayed revision render inline under their diff line (D8).
#[allow(clippy::too_many_arguments)]
async fn change_view(
    state: &AppState,
    session: Option<&WebSession>,
    owner: &str,
    repo: &str,
    number: i64,
    k: i64,
    rev: Option<i64>,
    range: Option<(i64, i64)>,
    error: Option<String>,
) -> Result<ChangePage, WebError> {
    let user = session.map(|s| &s.user);
    let access: RepoAccess = state.core.repo_for(user, owner, repo).await?;
    let detail: ChangeDetail = state
        .core
        .get_change(
            user,
            owner,
            repo,
            number,
            k,
            rev.or(range.map(|(_, to)| to)),
        )
        .await?;
    let diff = state
        .core
        .change_diff_files(user, owner, repo, number, k, rev, range)
        .await?;
    let change = &detail.change;
    let revisions = detail
        .revisions
        .iter()
        .map(|r| RevisionOption {
            r: r.r,
            short: short_sha(&r.head_sha),
            time: format_time(r.created_at),
            selected: r.r == detail.selected.r,
        })
        .collect();
    let mut reviews = Vec::new();
    let mut approvals = 0;
    let mut request_changes = 0;
    let mut reviewers = BTreeSet::new();
    for r in &detail.reviews {
        reviewers.insert(r.author_handle.clone());
        // Only write+ reviews count toward merge gates (counted in M2c);
        // everyone at read or above may still record a verdict.
        let author = state.core.user_by_handle(&r.author_handle).await?;
        let counting = state
            .core
            .permission_on(&access.repo, author.as_ref())
            .await?
            .is_some_and(|p| p >= Permission::Write);
        let live = r.state == "submitted";
        if live && counting {
            match r.verdict.as_str() {
                "approve" => approvals += 1,
                "request_changes" => request_changes += 1,
                _ => {}
            }
        }
        reviews.push(ReviewItem {
            id: r.id,
            revision: r.revision,
            author_handle: r.author_handle.clone(),
            verdict: r.verdict.clone(),
            body_html: markdown::render_prose(&r.body),
            created: format_time(r.created_at),
            state: r.state.clone(),
            counting,
            can_dismiss: detail.can_triage,
        });
    }
    let viewer_handle = session.map(|s| s.user.handle.as_str());
    let mut items = Vec::new();
    for t in &detail.threads {
        let comments = t
            .comments
            .iter()
            .map(|c| ThreadCommentItem {
                author_handle: c.author_handle.clone(),
                body_html: markdown::render_prose(&c.body),
                created: format_time(c.created_at),
            })
            .collect::<Vec<_>>();
        // The thread author (first comment) or triage may resolve.
        let can_resolve = detail.can_triage
            || t.comments
                .first()
                .is_some_and(|c| Some(c.author_handle.as_str()) == viewer_handle);
        items.push(ThreadItem {
            id: t.id,
            path: t.path.clone(),
            side: t.side.clone(),
            start_line: t.start_line,
            end_line: t.end_line,
            revision: t.revision,
            resolved: t.resolved,
            outdated: t.outdated,
            comments,
            can_resolve,
        });
    }
    // Inline threads (D8): only in the default single-revision view, only
    // for threads anchored on the displayed revision. Attachment drains the
    // map, so whatever never matched a displayed hunk line falls back
    // below. The inter-revision view lists every thread below.
    let mut inline: std::collections::HashMap<(String, String, i64), Vec<InlineThreadView>> =
        std::collections::HashMap::new();
    let mut held: std::collections::HashMap<i64, ThreadItem> = std::collections::HashMap::new();
    let mut below = Vec::new();
    if range.is_none() {
        for item in items {
            if item.revision == detail.selected.r {
                let view = InlineThreadView {
                    id: item.id,
                    resolved: item.resolved,
                    outdated: item.outdated,
                    can_resolve: item.can_resolve,
                    comments: item
                        .comments
                        .iter()
                        .map(|c| InlineCommentView {
                            author_handle: c.author_handle.clone(),
                            body_html: c.body_html.clone(),
                            created: c.created.clone(),
                        })
                        .collect(),
                };
                inline
                    .entry((item.path.clone(), item.side.clone(), item.end_line))
                    .or_default()
                    .push(view);
                held.insert(item.id, item);
            } else {
                below.push(item);
            }
        }
    } else {
        below = items;
    }
    let viewed = diff
        .files
        .iter()
        .map(|f| (f.file.display_path().to_owned(), f.viewed))
        .collect::<std::collections::HashMap<_, _>>();
    let files = file_views_with(
        diff.files.into_iter().map(|f| f.file).collect(),
        &viewed,
        &mut inline,
    );
    for threads in inline.into_values() {
        for view in threads {
            if let Some(item) = held.remove(&view.id) {
                below.push(item);
            }
        }
    }
    below.sort_by_key(|t| t.id);
    let sessions = state.core.trail_sessions(user, owner, repo, number).await?;
    let changes = state
        .core
        .list_changes(user, owner, repo, number, None)
        .await?;
    let session_count: usize = sessions
        .commits
        .iter()
        .filter(|g| g.change == change.k)
        .map(|g| g.sessions.len())
        .sum();
    let panel = gate_panel(
        state,
        session,
        &access,
        &detail,
        approvals,
        request_changes,
        session_count,
    )
    .await?;
    let mut seen: Vec<&str> = sessions
        .commits
        .iter()
        .flat_map(|g| g.sessions.iter().map(|s| s.ulid.as_str()))
        .chain(sessions.linked.iter().map(|s| s.ulid.as_str()))
        .collect();
    seen.sort_unstable();
    seen.dedup();
    let tabs = TrailTabs {
        owner: access.repo.owner.clone(),
        repo: access.repo.name.clone(),
        number,
        active: "changes".to_owned(),
        changes_count: changes.len(),
        sessions_count: seen.len(),
    };
    // D9: the "Finish your review" panel shows while the signed-in viewer
    // holds draft comments on the change.
    let pending = match session {
        Some(s) => state
            .core
            .pending_review(Some(&s.user), owner, repo, number, k)
            .await?
            .map(|draft| PendingPanel {
                count: draft.comments.len(),
            }),
        None => None,
    };
    Ok(ChangePage {
        nav_user: nav(session),
        head: RepoHead::new(&access, "trails", None),
        csrf: session.map(|s| s.csrf_token.clone()).unwrap_or_default(),
        trail_number: change.trail_number,
        k: change.k,
        kind: change.kind.clone(),
        head_branch: change.head_branch.clone(),
        base_branch: change.base_branch.clone(),
        state: change.state.clone(),
        creator_handle: change.creator_handle.clone(),
        current_revision: change.current_revision,
        created: format_time(change.created_at),
        updated: format_time(change.updated_at),
        revisions,
        selected_r: detail.selected.r,
        files,
        truncated: diff.truncated,
        is_compare: range.is_some(),
        compare_from: range.map(|(from, _)| from).unwrap_or(0),
        compare_to: range.map(|(_, to)| to).unwrap_or(0),
        show_toggles: session.is_some(),
        approvals,
        request_changes,
        reviewers: reviewers.into_iter().collect(),
        reviews,
        pending,
        threads: below,
        panel,
        tabs,
        can_review: session.is_some(),
        can_triage: detail.can_triage,
        can_close: detail.can_close,
        is_open: change.state == "open",
        error,
    })
}

#[derive(Deserialize)]
pub struct RevQuery {
    #[serde(default)]
    rev: Option<i64>,
    #[serde(default)]
    from: Option<i64>,
    #[serde(default)]
    to: Option<i64>,
}

/// Resolves the revision selector: one revision (`rev`), the inter-revision
/// pair (`from` + `to`), or neither (the current revision). Mixing `rev`
/// with the pair, or giving half the pair, is 400.
#[allow(clippy::type_complexity)]
fn select_range(query: &RevQuery) -> Result<(Option<i64>, Option<(i64, i64)>), WebError> {
    match (query.rev, query.from, query.to) {
        (rev, None, None) => Ok((rev, None)),
        (None, Some(from), Some(to)) => Ok((None, Some((from, to)))),
        _ => Err(starforged_core::CoreError::Invalid(
            "from and to must be given together, without rev".into(),
        )
        .into()),
    }
}

/// `GET /{owner}/{repo}/trails/{n}/changes/{k}[?rev=][?from=&to=]`.
pub async fn detail(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Query(query): Query<RevQuery>,
) -> Result<impl IntoResponse, WebError> {
    let (rev, range) = select_range(&query)?;
    if let Some((from, to)) = range
        && from == to
    {
        return Err(crate::error::WebError::Unprocessable(
            "identical revisions have no inter-revision diff".into(),
        ));
    }
    let page = change_view(
        &state,
        session.as_ref(),
        &owner,
        &repo,
        number,
        k,
        rev,
        range,
        None,
    )
    .await?;
    Ok((detail_headers(), page))
}

#[derive(Deserialize)]
pub struct BranchChangeForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    head: String,
    #[serde(default)]
    base: String,
}

/// `POST /{owner}/{repo}/trails/{n}/changes/new`: triage+ tracks a head
/// branch as a change. `Invalid` re-renders the trail page with 422.
pub async fn create_branch(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<BranchChangeForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .create_branch_change(&session.user, &owner, &repo, number, &form.head, &form.base)
        .await
    {
        Ok(saved) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{}",
            access.repo.owner, access.repo.name, saved.k
        ))
        .into_response()),
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = crate::pages::trails::detail_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct ReviewForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    r: Option<i64>,
    #[serde(default)]
    session: Option<String>,
}

/// `POST /{owner}/{repo}/trails/{n}/changes/{k}/reviews`: any signed-in
/// reader may submit any verdict. `Invalid` re-renders with 422.
pub async fn submit_review(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Form(form): Form<ReviewForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let session_ulid = form.session.filter(|s| !s.trim().is_empty());
    match state
        .core
        .submit_review(
            &session.user,
            &owner,
            &repo,
            number,
            k,
            form.r,
            &form.verdict,
            &form.body,
            session_ulid.as_deref(),
            &[],
        )
        .await
    {
        Ok((saved, _)) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{k}#review-{}",
            access.repo.owner, access.repo.name, saved.id
        ))
        .into_response()),
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                form.r,
                None,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct DismissForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
}

/// `POST …/reviews/{id}/dismiss`: triage-only. Dismissing a pending review
/// is 422 (`Invalid` re-renders like every other review form error).
pub async fn dismiss_review(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k, id)): Path<(String, String, i64, i64, i64)>,
    Form(form): Form<DismissForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .dismiss_review(&session.user, &owner, &repo, number, k, id)
        .await
    {
        Ok(_review) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{k}#review-{id}",
            access.repo.owner, access.repo.name
        ))
        .into_response()),
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                None,
                None,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

/// `POST …/reviews/pending`: discards the signed-in reader's draft review
/// (D9). Readers only: non-readers 404 before the CSRF check. No draft is
/// 404; `Invalid` (archived repos) re-renders with 422.
pub async fn discard_pending_review(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Form(form): Form<DismissForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .discard_pending_review(&session.user, &owner, &repo, number, k)
        .await
    {
        Ok(()) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{k}",
            access.repo.owner, access.repo.name
        ))
        .into_response()),
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                None,
                None,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct ThreadForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    side: String,
    #[serde(default)]
    start: Option<i64>,
    #[serde(default)]
    end: Option<i64>,
    #[serde(default)]
    body: String,
    #[serde(default)]
    r: Option<i64>,
    /// D9: "Add to review" attaches the first comment to the actor's draft.
    #[serde(default)]
    pending: bool,
}

/// `POST …/threads`: any signed-in reader opens a thread with `body` as
/// its first comment. `Invalid` re-renders with 422.
pub async fn create_thread(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Form(form): Form<ThreadForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let (start, end) = (form.start.unwrap_or(0), form.end.unwrap_or(0));
    match state
        .core
        .create_thread(
            &session.user,
            &owner,
            &repo,
            number,
            k,
            form.r,
            &form.path,
            &form.side,
            start,
            end,
            &form.body,
            form.pending,
        )
        .await
    {
        Ok(saved) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{k}#thread-{}",
            access.repo.owner, access.repo.name, saved.id
        ))
        .into_response()),
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                form.r,
                None,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct ResolveForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    action: String,
}

/// `POST …/threads/{id}/resolve`: the thread author or triage resolves
/// (`action=resolve`) or reopens (anything else).
pub async fn resolve_thread(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k, id)): Path<(String, String, i64, i64, i64)>,
    Form(form): Form<ResolveForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .resolve_thread(
            &session.user,
            &owner,
            &repo,
            number,
            k,
            id,
            form.action == "resolve",
        )
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}/changes/{k}#thread-{id}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct ThreadCommentForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    body: String,
    /// D9: "Add to review" attaches the comment to the actor's draft.
    #[serde(default)]
    pending: bool,
}

/// `POST …/threads/{id}/comments`: any signed-in reader appends a comment —
/// or, with `pending`, attaches it to their draft review. `Invalid`
/// re-renders with 422.
pub async fn add_thread_comment(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k, id)): Path<(String, String, i64, i64, i64)>,
    Form(form): Form<ThreadCommentForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .add_thread_comment(
            &session.user,
            &owner,
            &repo,
            number,
            k,
            id,
            &form.body,
            None,
            form.pending,
        )
        .await
    {
        Ok(_) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{k}#thread-{id}",
            access.repo.owner, access.repo.name
        ))
        .into_response()),
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                None,
                None,
                Some(message),
            )
            .await?;
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

/// `POST …/state`: the creator or triage closes/reopens. `merged` is
/// owned by the merge path and rejected.
pub async fn set_state(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Form(form): Form<StateForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .set_change_state(&session.user, &owner, &repo, number, k, &form.state)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}/changes/{k}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct MergeForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    method: String,
}

/// `POST …/merge`: server-side merge with the requested method. The form
/// only enables while the fresh gate set passes, but the POST re-checks
/// everything (gates, permission, method) — a stale page authorizes
/// nothing. Gate and conflict failures re-render the change with `422`.
pub async fn merge(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Form(form): Form<MergeForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .merge_change(&session.user, &owner, &repo, number, k, &form.method)
        .await
    {
        Ok(_) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{k}",
            access.repo.owner, access.repo.name
        ))
        .into_response()),
        Err(
            starforged_core::CoreError::Invalid(message)
            | starforged_core::CoreError::Conflict(message),
        ) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                None,
                None,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct ViewedForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    viewed: String,
}

/// `POST …/changes/{k}/viewed`: marks a file viewed (`viewed=1`) or
/// un-viewed (`viewed=0`) for the signed-in reader (D8). Readers only:
/// non-readers 404 before the CSRF check. `Invalid` (archived repos,
/// unknown files, bad values) re-renders with 422.
pub async fn set_viewed(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Form(form): Form<ViewedForm>,
) -> Result<Response, WebError> {
    // Non-readers 404 before the CSRF check, matching the trail pages: a
    // forged POST must not distinguish "exists" from "missing".
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let viewed = match form.viewed.as_str() {
        "1" => true,
        "0" => false,
        _ => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                None,
                None,
                Some("viewed must be 0 or 1".to_owned()),
            )
            .await?;
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response());
        }
    };
    match state
        .core
        .set_file_viewed(&session.user, &owner, &repo, number, k, &form.path, viewed)
        .await
    {
        Ok(()) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{number}/changes/{k}",
            access.repo.owner, access.repo.name
        ))
        .into_response()),
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                None,
                None,
                Some(message),
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}
