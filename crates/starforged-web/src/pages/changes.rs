//! Change web UI (spec §6.2, §8, M2b G5): change detail with revision
//! selector, unified diff, review summary and forms, file/line threads,
//! plus triage-gated dismiss and creator-or-triage state controls. Reads
//! 404 for non-readers so change numbers stay undiscoverable; mutations
//! answer 403 below their threshold. Review bodies and thread comments
//! render through [`crate::markdown::render_prose`]; everything else
//! relies on askama escaping. The merge button is always disabled: merge
//! execution and gates belong to M2c.

use std::collections::BTreeSet;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::changes::ChangeDetail;
use starforged_core::permission::Permission;
use starforged_core::repos::RepoAccess;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{MaybeUser, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::markdown;
use crate::views::{FileView, NavUser, RepoHead, STRICT_CSP, file_views, format_time, nav};

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

/// The literal disabled-merge reason. Merging (gates + execution) is M2c.
const MERGE_TITLE: &str =
    "Merging lands in M2c — gates and merge execution are not implemented yet.";

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
    mergeability: String,
    conflict_paths: Vec<String>,
    created: String,
    updated: String,
    revisions: Vec<RevisionOption>,
    selected_r: i64,
    files: Vec<FileView>,
    truncated: bool,
    approvals: usize,
    request_changes: usize,
    reviewers: Vec<String>,
    reviews: Vec<ReviewItem>,
    threads: Vec<ThreadItem>,
    can_review: bool,
    can_triage: bool,
    can_close: bool,
    is_open: bool,
    merge_title: &'static str,
    error: Option<String>,
}

/// Builds the detail view; shared by the viewer and the 422 re-renders.
#[allow(clippy::too_many_arguments)]
async fn change_view(
    state: &AppState,
    session: Option<&WebSession>,
    owner: &str,
    repo: &str,
    number: i64,
    k: i64,
    rev: Option<i64>,
    error: Option<String>,
) -> Result<ChangePage, WebError> {
    let user = session.map(|s| &s.user);
    let access: RepoAccess = state.core.repo_for(user, owner, repo).await?;
    let detail: ChangeDetail = state
        .core
        .get_change(user, owner, repo, number, k, rev)
        .await?;
    let diff = state
        .core
        .change_diff_files(user, owner, repo, number, k, rev)
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
        let live = r.state != "dismissed";
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
    let threads = detail
        .threads
        .iter()
        .map(|t| ThreadItem {
            id: t.id,
            path: t.path.clone(),
            side: t.side.clone(),
            start_line: t.start_line,
            end_line: t.end_line,
            revision: t.revision,
            resolved: t.resolved,
            outdated: t.outdated,
            comments: t
                .comments
                .iter()
                .map(|c| ThreadCommentItem {
                    author_handle: c.author_handle.clone(),
                    body_html: markdown::render_prose(&c.body),
                    created: format_time(c.created_at),
                })
                .collect(),
            // The thread author (first comment) or triage may resolve.
            can_resolve: detail.can_triage
                || t.comments
                    .first()
                    .is_some_and(|c| Some(c.author_handle.as_str()) == viewer_handle),
        })
        .collect();
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
        mergeability: change.mergeability.clone(),
        conflict_paths: change.conflict_paths.clone(),
        created: format_time(change.created_at),
        updated: format_time(change.updated_at),
        revisions,
        selected_r: detail.selected.r,
        files: file_views(diff.files),
        truncated: diff.truncated,
        approvals,
        request_changes,
        reviewers: reviewers.into_iter().collect(),
        reviews,
        threads,
        can_review: session.is_some(),
        can_triage: detail.can_triage,
        can_close: detail.can_close,
        is_open: change.state == "open",
        merge_title: MERGE_TITLE,
        error,
    })
}

#[derive(Deserialize)]
pub struct RevQuery {
    #[serde(default)]
    rev: Option<i64>,
}

/// `GET /{owner}/{repo}/trails/{n}/changes/{k}[?rev=]`.
pub async fn detail(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Query(query): Query<RevQuery>,
) -> Result<impl IntoResponse, WebError> {
    let page = change_view(
        &state,
        session.as_ref(),
        &owner,
        &repo,
        number,
        k,
        query.rev,
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
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .create_branch_change(&session.user, &owner, &repo, number, &form.head, &form.base)
        .await
    {
        Ok(saved) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}/changes/{}",
                access.repo.owner, access.repo.name, saved.k
            ))
            .into_response())
        }
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
        )
        .await
    {
        Ok(saved) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}/changes/{k}#review-{}",
                access.repo.owner, access.repo.name, saved.id
            ))
            .into_response())
        }
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                form.r,
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

/// `POST …/reviews/{id}/dismiss`: triage-only.
pub async fn dismiss_review(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k, id)): Path<(String, String, i64, i64, i64)>,
    Form(form): Form<DismissForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .dismiss_review(&session.user, &owner, &repo, number, k, id)
        .await?;
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}/changes/{k}#review-{id}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
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
}

/// `POST …/threads`: any signed-in reader opens a thread with `body` as
/// its first comment. `Invalid` re-renders with 422.
pub async fn create_thread(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k)): Path<(String, String, i64, i64)>,
    Form(form): Form<ThreadForm>,
) -> Result<Response, WebError> {
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
        )
        .await
    {
        Ok(saved) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}/changes/{k}#thread-{}",
                access.repo.owner, access.repo.name, saved.id
            ))
            .into_response())
        }
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
                form.r,
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
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
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
}

/// `POST …/threads/{id}/comments`: any signed-in reader appends a comment.
/// `Invalid` re-renders with 422.
pub async fn add_thread_comment(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, k, id)): Path<(String, String, i64, i64, i64)>,
    Form(form): Form<ThreadCommentForm>,
) -> Result<Response, WebError> {
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
        )
        .await
    {
        Ok(_) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}/changes/{k}#thread-{id}",
                access.repo.owner, access.repo.name
            ))
            .into_response())
        }
        Err(starforged_core::CoreError::Invalid(message)) => {
            let page = change_view(
                &state,
                Some(&session),
                &owner,
                &repo,
                number,
                k,
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
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .set_change_state(&session.user, &owner, &repo, number, k, &form.state)
        .await?;
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}/changes/{k}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}
