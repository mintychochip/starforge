//! Change, revision, review, and thread routes (spec §6.2, M2b G4):
//! `…/trails/{n}/changes` and below.
//!
//! Handlers authenticate (scope checks) and delegate; all permission,
//! validation, numbering, and timeline logic lives on [`Core`]. Reads go
//! through `auth.reader()` so non-readers surface as `404` (the service
//! returns `NotFound`, never translated to `403`); every mutation requires
//! `Scope::TrailWrite` first, then `Core` enforces the repo-permission
//! threshold (`Forbidden` → `403`). `CoreError::Invalid` → `422`,
//! `Conflict` → `409`, all in the `{error:{code,message}}` envelope.
//!
//! Timestamps render as RFC 3339 (`…Z`); the service stores unix seconds
//! internally.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::changes::{
    ChangeDetail, ChangeView, ReviewView, RevisionView, ThreadCommentView, ThreadView,
};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ` (same civil-from-days shape as trails).
fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[derive(Serialize)]
pub struct ChangeJson {
    pub trail: i64,
    pub k: i64,
    pub kind: String,
    pub head_branch: Option<String>,
    pub base_branch: String,
    pub current_revision: i64,
    pub state: String,
    pub creator: String,
    pub mergeability: String,
    pub conflict_paths: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn change_json(view: &ChangeView) -> ChangeJson {
    ChangeJson {
        trail: view.trail_number,
        k: view.k,
        kind: view.kind.clone(),
        head_branch: view.head_branch.clone(),
        base_branch: view.base_branch.clone(),
        current_revision: view.current_revision,
        state: view.state.clone(),
        creator: view.creator_handle.clone(),
        mergeability: view.mergeability.clone(),
        conflict_paths: view.conflict_paths.clone(),
        created_at: rfc3339(view.created_at),
        updated_at: rfc3339(view.updated_at),
    }
}

#[derive(Serialize)]
pub struct RevisionJson {
    pub r: i64,
    pub head_sha: String,
    pub base_sha: String,
    pub merge_base: Option<String>,
    pub pusher: Option<String>,
    pub created_at: String,
    pub mergeability: String,
    pub conflict_paths: Vec<String>,
}

fn revision_json(view: &RevisionView) -> RevisionJson {
    RevisionJson {
        r: view.r,
        head_sha: view.head_sha.clone(),
        base_sha: view.base_sha.clone(),
        merge_base: view.merge_base_sha.clone(),
        pusher: view.pusher_handle.clone(),
        created_at: rfc3339(view.created_at),
        mergeability: view.mergeability.clone(),
        conflict_paths: view.conflict_paths.clone(),
    }
}

#[derive(Serialize)]
pub struct ReviewJson {
    pub id: i64,
    pub revision: i64,
    pub author: String,
    pub verdict: String,
    pub body: String,
    pub session: Option<String>,
    pub state: String,
    pub created_at: String,
}

fn review_json(view: &ReviewView) -> ReviewJson {
    ReviewJson {
        id: view.id,
        revision: view.revision,
        author: view.author_handle.clone(),
        verdict: view.verdict.clone(),
        body: view.body.clone(),
        session: view.session_ulid.clone(),
        state: view.state.clone(),
        created_at: rfc3339(view.created_at),
    }
}

#[derive(Serialize)]
pub struct ThreadCommentJson {
    pub id: i64,
    pub review_id: Option<i64>,
    pub author: String,
    pub body: String,
    pub created_at: String,
}

fn thread_comment_json(view: &ThreadCommentView) -> ThreadCommentJson {
    ThreadCommentJson {
        id: view.id,
        review_id: view.review_id,
        author: view.author_handle.clone(),
        body: view.body.clone(),
        created_at: rfc3339(view.created_at),
    }
}

#[derive(Serialize)]
pub struct ThreadJson {
    pub id: i64,
    pub revision: i64,
    pub path: String,
    pub side: String,
    pub start_line: i64,
    pub end_line: i64,
    pub resolved: bool,
    pub outdated: bool,
    pub comments: Vec<ThreadCommentJson>,
}

fn thread_json(view: &ThreadView) -> ThreadJson {
    ThreadJson {
        id: view.id,
        revision: view.revision,
        path: view.path.clone(),
        side: view.side.clone(),
        start_line: view.start_line,
        end_line: view.end_line,
        resolved: view.resolved,
        outdated: view.outdated,
        comments: view.comments.iter().map(thread_comment_json).collect(),
    }
}

fn detail_json(detail: &ChangeDetail, diff: Value) -> Value {
    json!({
        "change": change_json(&detail.change),
        "revisions": detail.revisions.iter().map(revision_json).collect::<Vec<_>>(),
        "selected": revision_json(&detail.selected),
        "files": diff["files"],
        "truncated": diff["truncated"],
        "reviews": detail.reviews.iter().map(review_json).collect::<Vec<_>>(),
        "threads": detail.threads.iter().map(thread_json).collect::<Vec<_>>(),
        "can_review": detail.can_review,
        "can_triage": detail.can_triage,
        "can_close": detail.can_close,
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct LimitQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RevQuery {
    pub rev: Option<i64>,
}

/// `GET /repos/{owner}/{repo}/trails/{n}/changes[?limit=]`.
pub async fn list_changes(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n)): Path<(String, String, i64)>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<Value>, ApiError> {
    let views = state
        .core
        .list_changes(auth.reader()?, &owner, &repo, n, query.limit)
        .await?;
    Ok(Json(json!({
        "changes": views.iter().map(change_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub struct CreateChangeBody {
    pub kind: String,
    pub head_branch: Option<String>,
    pub base_branch: Option<String>,
}

/// `POST /repos/{owner}/{repo}/trails/{n}/changes` (201): only `branch`
/// changes exist in M2b; the body names its head and base branches.
pub async fn create_change(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n)): Path<(String, String, i64)>,
    body: Result<Json<CreateChangeBody>, JsonRejection>,
) -> Result<(StatusCode, Json<ChangeJson>), ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    if body.kind != "branch" {
        return Err(ApiError::Invalid(format!(
            "invalid change kind '{}'",
            body.kind
        )));
    }
    let (Some(head), Some(base)) = (body.head_branch, body.base_branch) else {
        return Err(ApiError::Invalid(
            "head_branch and base_branch are required".into(),
        ));
    };
    let view = state
        .core
        .create_branch_change(&auth.user, &owner, &repo, n, &head, &base)
        .await?;
    Ok((StatusCode::CREATED, Json(change_json(&view))))
}

/// `GET /repos/{owner}/{repo}/trails/{n}/changes/{k}[?rev=]`: the change with
/// its revisions, the selected revision's diff, discussion, and capabilities.
pub async fn get_change(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    Query(query): Query<RevQuery>,
) -> Result<Json<Value>, ApiError> {
    let viewer = auth.reader()?;
    let detail = state
        .core
        .get_change(viewer, &owner, &repo, n, k, query.rev)
        .await?;
    let diff = state
        .core
        .change_diff_json(viewer, &owner, &repo, n, k, query.rev)
        .await?;
    Ok(Json(detail_json(&detail, diff)))
}

#[derive(Deserialize)]
pub struct ChangeStateBody {
    pub state: String,
}

async fn set_state(
    state: &ApiState,
    auth: &ApiAuth,
    owner: &str,
    repo: &str,
    n: i64,
    k: i64,
    next: &str,
) -> Result<ChangeJson, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    Ok(change_json(
        &state
            .core
            .set_change_state(&auth.user, owner, repo, n, k, next)
            .await?,
    ))
}

/// `PATCH /repos/{owner}/{repo}/trails/{n}/changes/{k}` (`{"state": …}`):
/// closes or reopens. `merged` answers 422 — the merge path owns it.
pub async fn patch_change(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    body: Result<Json<ChangeStateBody>, JsonRejection>,
) -> Result<Json<ChangeJson>, ApiError> {
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    Ok(Json(
        set_state(&state, &auth, &owner, &repo, n, k, &body.state).await?,
    ))
}

/// `POST /repos/{owner}/{repo}/trails/{n}/changes/{k}/state`: the same
/// transition as `PATCH …/changes/{k}`.
pub async fn post_state(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    body: Result<Json<ChangeStateBody>, JsonRejection>,
) -> Result<Json<ChangeJson>, ApiError> {
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    Ok(Json(
        set_state(&state, &auth, &owner, &repo, n, k, &body.state).await?,
    ))
}

/// `GET /repos/{owner}/{repo}/trails/{n}/changes/{k}/revisions[?limit=]`.
pub async fn list_revisions(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<Value>, ApiError> {
    let views = state
        .core
        .list_revisions(auth.reader()?, &owner, &repo, n, k, query.limit)
        .await?;
    Ok(Json(json!({
        "revisions": views.iter().map(revision_json).collect::<Vec<_>>(),
    })))
}

/// `GET …/changes/{k}/revisions/{r}`: the revision with its diff summary —
/// changed files with add/modify/delete status and per-file unified hunks
/// (binary files carry metadata with empty hunks), capped at 256 KiB total.
pub async fn get_revision(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k, r)): Path<(String, String, i64, i64, i64)>,
) -> Result<Json<Value>, ApiError> {
    let viewer = auth.reader()?;
    let views = state
        .core
        .list_revisions(viewer, &owner, &repo, n, k, None)
        .await?;
    let selected = views
        .into_iter()
        .find(|v| v.r == r)
        .ok_or(ApiError::NotFound)?;
    let mut diff = state
        .core
        .change_diff_json(viewer, &owner, &repo, n, k, Some(r))
        .await?;
    let mut out = json!({ "revision": revision_json(&selected) });
    out["files"] = diff["files"].take();
    out["truncated"] = diff["truncated"].take();
    Ok(Json(out))
}

/// `GET …/changes/{k}/diff[?rev=]`: the selected revision's diff alone.
pub async fn get_diff(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    Query(query): Query<RevQuery>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        state
            .core
            .change_diff_json(auth.reader()?, &owner, &repo, n, k, query.rev)
            .await?,
    ))
}

#[derive(Deserialize)]
pub struct SubmitReviewBody {
    pub revision: Option<i64>,
    pub verdict: String,
    pub body: String,
    pub session: Option<String>,
}

/// `POST …/changes/{k}/reviews` (201): any reader may submit any verdict;
/// gate counting is M2c's problem. `session`, when given, must name a live
/// (non-quarantined) session in this repo.
pub async fn submit_review(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    body: Result<Json<SubmitReviewBody>, JsonRejection>,
) -> Result<(StatusCode, Json<ReviewJson>), ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .submit_review(
            &auth.user,
            &owner,
            &repo,
            n,
            k,
            body.revision,
            &body.verdict,
            &body.body,
            body.session.as_deref(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(review_json(&view))))
}

/// `GET …/changes/{k}/reviews[?limit=]`.
pub async fn list_reviews(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<Value>, ApiError> {
    let views = state
        .core
        .list_reviews(auth.reader()?, &owner, &repo, n, k, query.limit)
        .await?;
    Ok(Json(json!({
        "reviews": views.iter().map(review_json).collect::<Vec<_>>(),
    })))
}

/// `POST …/changes/{k}/reviews/{id}/dismiss`: triage+ only.
pub async fn dismiss_review(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k, id)): Path<(String, String, i64, i64, i64)>,
) -> Result<Json<ReviewJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    Ok(Json(review_json(
        &state
            .core
            .dismiss_review(&auth.user, &owner, &repo, n, k, id)
            .await?,
    )))
}

#[derive(Deserialize)]
pub struct CreateThreadBody {
    pub revision: Option<i64>,
    pub path: String,
    pub side: String,
    pub start_line: i64,
    pub end_line: i64,
    pub body: String,
}

/// `POST …/changes/{k}/threads` (201): any reader may open a thread; the
/// body becomes its first comment.
pub async fn create_thread(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    body: Result<Json<CreateThreadBody>, JsonRejection>,
) -> Result<(StatusCode, Json<ThreadJson>), ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .create_thread(
            &auth.user,
            &owner,
            &repo,
            n,
            k,
            body.revision,
            &body.path,
            &body.side,
            body.start_line,
            body.end_line,
            &body.body,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(thread_json(&view))))
}

/// `GET …/changes/{k}/threads[?limit=]`.
pub async fn list_threads(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k)): Path<(String, String, i64, i64)>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<Value>, ApiError> {
    let views = state
        .core
        .list_threads(auth.reader()?, &owner, &repo, n, k, query.limit)
        .await?;
    Ok(Json(json!({
        "threads": views.iter().map(thread_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize, Default)]
pub struct ResolveBody {
    pub resolved: Option<bool>,
}

/// `POST …/threads/{t}/resolve`: the thread author or triage+. A missing
/// body resolves.
pub async fn resolve_thread(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k, t)): Path<(String, String, i64, i64, i64)>,
    body: Option<Json<ResolveBody>>,
) -> Result<Json<ThreadJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let resolved = body.and_then(|b| b.0.resolved).unwrap_or(true);
    Ok(Json(thread_json(
        &state
            .core
            .resolve_thread(&auth.user, &owner, &repo, n, k, t, resolved)
            .await?,
    )))
}

#[derive(Deserialize)]
pub struct CommentBody {
    pub body: String,
    pub review_id: Option<i64>,
}

/// `POST …/threads/{t}/comments` (201): any reader may comment; `review_id`,
/// when given, must name a review on the same change.
pub async fn add_comment(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, n, k, t)): Path<(String, String, i64, i64, i64)>,
    body: Result<Json<CommentBody>, JsonRejection>,
) -> Result<(StatusCode, Json<ThreadCommentJson>), ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .add_thread_comment(
            &auth.user,
            &owner,
            &repo,
            n,
            k,
            t,
            &body.body,
            body.review_id,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(thread_comment_json(&view))))
}
