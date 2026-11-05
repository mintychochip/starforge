//! Trail discussion routes (spec §6.2): list/create/get/patch plus comments, labels, and assignees.
//!
//! Handlers authenticate (scope checks) and delegate; all permission,
//! validation, numbering, and timeline logic lives on [`Core`]. Reads go
//! through `auth.reader()` so non-readers surface as `404` (the service
//! returns `NotFound`, never translated to `403`); every mutation requires
//! `Scope::TrailWrite` first, then `Core` enforces the repo-permission
//! threshold (`Forbidden` → `403`).
//!
//! DTO decisions: the list wraps `{"trails", "next_after"}`; the detail route
//! returns the trail view flattened at the top level with `comments` and
//! `timeline` siblings (PATCH returns the flat view without them). Timestamps
//! render as RFC 3339 (`…Z`); the service stores unix seconds internally.

use axum::Json;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::Core;
use starforged_core::tokens::Scope;
use starforged_core::trails::{CommentView, TrailDetail, TrailFilterInput, TrailView};

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::{opt_ts, rfc3339};

#[derive(Serialize)]
pub struct TrailJson {
    pub number: i64,
    pub title: String,
    pub intent: String,
    pub state: String,
    pub ready: bool,
    pub author: String,
    pub author_id: Option<i64>,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub review_requests: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub closed_at: Option<String>,
    pub merged_at: Option<String>,
}

fn trail_json(view: &TrailView) -> TrailJson {
    TrailJson {
        number: view.number,
        title: view.title.clone(),
        intent: view.intent.clone(),
        state: view.state.clone(),
        ready: view.ready,
        author: view.author_handle.clone(),
        author_id: view.author_id,
        labels: view.labels.clone(),
        assignees: view.assignees.clone(),
        review_requests: view.review_requests.clone(),
        created_at: rfc3339(view.created_at),
        updated_at: rfc3339(view.updated_at),
        closed_at: opt_ts(view.closed_at),
        merged_at: opt_ts(view.merged_at),
    }
}

#[derive(Serialize)]
pub struct CommentJson {
    pub id: i64,
    pub author: String,
    pub author_id: Option<i64>,
    pub body: String,
    pub created_at: String,
    pub edited_at: Option<String>,
}

fn comment_json(view: &CommentView) -> CommentJson {
    CommentJson {
        id: view.id,
        author: view.author_handle.clone(),
        author_id: view.author_id,
        body: view.body.clone(),
        created_at: rfc3339(view.created_at),
        edited_at: opt_ts(view.edited_at),
    }
}

#[derive(Serialize)]
pub struct TimelineJson {
    pub id: i64,
    pub kind: String,
    pub actor: Option<String>,
    pub payload: Value,
    pub created_at: String,
}

/// The detail route: flat trail fields plus discussion.
#[derive(Serialize)]
pub struct TrailDetailJson {
    #[serde(flatten)]
    pub trail: TrailJson,
    pub comments: Vec<CommentJson>,
    pub timeline: Vec<TimelineJson>,
}

async fn detail_json(core: &Core, detail: &TrailDetail) -> Result<TrailDetailJson, ApiError> {
    let mut timeline = Vec::with_capacity(detail.timeline.len());
    for event in &detail.timeline {
        let actor = match event.actor_id {
            None => None,
            Some(id) => match core.user_by_id(id).await? {
                Some(user) => Some(user.handle),
                None => None,
            },
        };
        timeline.push(TimelineJson {
            id: event.id,
            kind: event.kind.clone(),
            actor,
            payload: serde_json::from_str(&event.payload)
                .unwrap_or_else(|_| Value::String(event.payload.clone())),
            created_at: rfc3339(event.created_at),
        });
    }
    Ok(TrailDetailJson {
        trail: trail_json(&detail.trail),
        comments: detail.comments.iter().map(comment_json).collect(),
        timeline,
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    pub state: Option<String>,
    pub label: Option<String>,
    pub assignee: Option<String>,
    pub author: Option<String>,
    /// `true` keeps Trails with at least one change, `false` those with
    /// none; anything else is a 422.
    pub has_changes: Option<String>,
    /// `true` keeps Trails with at least one session the viewer may read
    /// (§6.4), `false` those without; anything else is a 422.
    pub has_sessions: Option<String>,
    pub review_requested: Option<String>,
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

/// `GET /repos/{owner}/{repo}/trails[?state=&label=&assignee=&author=&has_changes=&has_sessions=&review_requested=&after=&limit=]`.
pub async fn list_trails(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let has_changes = match query.has_changes.as_deref() {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(other) => {
            return Err(ApiError::Invalid(format!(
                "invalid has_changes '{other}': expected true or false"
            )));
        }
    };
    let has_sessions = match query.has_sessions.as_deref() {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(other) => {
            return Err(ApiError::Invalid(format!(
                "invalid has_sessions '{other}': expected true or false"
            )));
        }
    };
    let page = state
        .core
        .list_trails(
            auth.reader()?,
            &owner,
            &repo,
            &TrailFilterInput {
                state: query.state,
                label: query.label,
                assignee: query.assignee,
                author: query.author,
                has_changes,
                has_sessions,
                review_requested: query.review_requested,
                after: query.after,
                limit: query.limit,
            },
        )
        .await?;
    Ok(Json(json!({
        "trails": page.trails.iter().map(trail_json).collect::<Vec<_>>(),
        "next_after": page.next_after,
    })))
}

#[derive(Deserialize)]
pub struct CreateTrailBody {
    pub title: String,
    pub intent: String,
}

/// `POST /repos/{owner}/{repo}/trails` (201).
pub async fn create_trail(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<CreateTrailBody>, JsonRejection>,
) -> Result<(StatusCode, Json<TrailJson>), ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .create_trail(&auth.user, &owner, &repo, &body.title, &body.intent)
        .await?;
    Ok((StatusCode::CREATED, Json(trail_json(&view))))
}

/// `GET /repos/{owner}/{repo}/trails/{n}`.
pub async fn get_trail(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<TrailDetailJson>, ApiError> {
    let detail = state
        .core
        .trail_by_number(auth.reader()?, &owner, &repo, number)
        .await?;
    Ok(Json(detail_json(&state.core, &detail).await?))
}

#[derive(Debug, Deserialize, Default)]
pub struct PatchTrailBody {
    pub title: Option<String>,
    pub intent: Option<String>,
    pub ready: Option<bool>,
    pub state: Option<String>,
}

/// `PATCH /repos/{owner}/{repo}/trails/{n}`: title/intent/ready edits and/or a
/// state transition. `{"state": "merged"}` answers `422` — the merge path owns
/// that transition (the message surfaces verbatim).
///
/// Every supplied field is validated before anything is written: a rejected
/// patch leaves the trail and its timeline untouched.
pub async fn patch_trail(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<PatchTrailBody>, JsonRejection>,
) -> Result<Json<TrailJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    state
        .core
        .check_patch(
            &auth.user,
            &owner,
            &repo,
            number,
            body.title.as_deref(),
            body.intent.as_deref(),
            body.ready,
            body.state.as_deref(),
        )
        .await?;
    if let Some(next) = body.state.as_deref() {
        state
            .core
            .set_trail_state(&auth.user, &owner, &repo, number, next)
            .await?;
    }
    if body.title.is_some() || body.intent.is_some() || body.ready.is_some() {
        let view = state
            .core
            .update_trail(
                &auth.user,
                &owner,
                &repo,
                number,
                body.title.as_deref(),
                body.intent.as_deref(),
                body.ready,
            )
            .await?;
        return Ok(Json(trail_json(&view)));
    }
    let detail = state
        .core
        .trail_by_number(Some(&auth.user), &owner, &repo, number)
        .await?;
    Ok(Json(trail_json(&detail.trail)))
}

/// `GET /repos/{owner}/{repo}/trails/{n}/comments`.
pub async fn list_comments(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<Value>, ApiError> {
    let detail = state
        .core
        .trail_by_number(auth.reader()?, &owner, &repo, number)
        .await?;
    Ok(Json(json!({
        "comments": detail.comments.iter().map(comment_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub struct CreateCommentBody {
    pub body: String,
}

/// `POST /repos/{owner}/{repo}/trails/{n}/comments` (201).
pub async fn post_comment(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<CreateCommentBody>, JsonRejection>,
) -> Result<(StatusCode, Json<CommentJson>), ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .add_comment(&auth.user, &owner, &repo, number, &body.body)
        .await?;
    Ok((StatusCode::CREATED, Json(comment_json(&view))))
}

#[derive(Deserialize)]
pub struct EditCommentBody {
    pub body: String,
}

/// `PATCH /repos/{owner}/{repo}/trails/{n}/comments/{id}`: the comment author
/// or a repo/site admin.
pub async fn patch_comment(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number, id)): Path<(String, String, i64, i64)>,
    body: Result<Json<EditCommentBody>, JsonRejection>,
) -> Result<Json<CommentJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .edit_comment(&auth.user, &owner, &repo, number, id, &body.body)
        .await?;
    Ok(Json(comment_json(&view)))
}

#[derive(Deserialize)]
pub struct LabelBody {
    pub name: String,
}

/// `POST /repos/{owner}/{repo}/trails/{n}/labels`: idempotent add.
pub async fn add_label(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<LabelBody>, JsonRejection>,
) -> Result<Json<TrailJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .add_label(&auth.user, &owner, &repo, number, &body.name)
        .await?;
    Ok(Json(trail_json(&view)))
}

/// `DELETE /repos/{owner}/{repo}/trails/{n}/labels`: the name travels in the
/// JSON body (symmetric with POST — no URL-encoding pitfalls). Idempotent.
pub async fn remove_label(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<LabelBody>, JsonRejection>,
) -> Result<Json<TrailJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .remove_label(&auth.user, &owner, &repo, number, &body.name)
        .await?;
    Ok(Json(trail_json(&view)))
}

#[derive(Deserialize)]
pub struct AssigneeBody {
    pub user: String,
}

/// `POST /repos/{owner}/{repo}/trails/{n}/assignees`: idempotent add. The
/// handle must belong to a repository member; unknown handles and strangers
/// answer `422`, never `404`.
pub async fn add_assignee(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<AssigneeBody>, JsonRejection>,
) -> Result<Json<TrailJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .add_assignee(&auth.user, &owner, &repo, number, &body.user)
        .await?;
    Ok(Json(trail_json(&view)))
}

/// `DELETE /repos/{owner}/{repo}/trails/{n}/assignees`: symmetric with POST.
pub async fn remove_assignee(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<AssigneeBody>, JsonRejection>,
) -> Result<Json<TrailJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .remove_assignee(&auth.user, &owner, &repo, number, &body.user)
        .await?;
    Ok(Json(trail_json(&view)))
}

#[derive(Deserialize)]
pub struct ReviewRequestBody {
    pub user: String,
}

/// `POST /repos/{owner}/{repo}/trails/{n}/review-requests`: idempotent add.
/// The handle must belong to a repository member and not be the Trail author;
/// unknown handles, strangers, and the author answer `422`, never `404`.
pub async fn add_review_request(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<ReviewRequestBody>, JsonRejection>,
) -> Result<Json<TrailJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .request_review(&auth.user, &owner, &repo, number, &body.user)
        .await?;
    Ok(Json(trail_json(&view)))
}

/// `DELETE /repos/{owner}/{repo}/trails/{n}/review-requests`: symmetric with POST.
pub async fn remove_review_request(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<ReviewRequestBody>, JsonRejection>,
) -> Result<Json<TrailJson>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .remove_review_request(&auth.user, &owner, &repo, number, &body.user)
        .await?;
    Ok(Json(trail_json(&view)))
}

fn totals_json(totals: &starforged_core::trails::TokenTotals) -> Value {
    json!({
        "input": totals.input,
        "output": totals.output,
        "cache_read": totals.cache_read,
        "cache_write": totals.cache_write,
        "reasoning": totals.reasoning,
        "total": totals.total,
    })
}

fn session_link_json(row: &starforged_core::trails::SessionLinkRow) -> Value {
    json!({
        "ulid": row.ulid,
        "agent": row.agent,
        "agent_version": row.agent_version,
        "models": serde_json::from_str::<Value>(&row.models)
            .unwrap_or_else(|_| Value::String(row.models.clone())),
        "title": row.title,
        "uploader": row.uploader,
        "started_at": row.started_at,
        "created_at": row.created_at,
        "confidence": row.confidence,
        "seq_start": row.seq_start,
        "totals": totals_json(&row.totals),
    })
}

fn trail_sessions_json(view: &starforged_core::trails::TrailSessions) -> Value {
    json!({
        "commits": view.commits.iter().map(|commit| json!({
            "sha": commit.sha,
            "subject": commit.subject,
            "change": commit.change,
            "revision": commit.revision,
            "first_seen_at": commit.first_seen_at,
            "sessions": commit.sessions.iter().map(session_link_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "linked": view.linked.iter().map(session_link_json).collect::<Vec<_>>(),
        "totals": totals_json(&view.totals),
    })
}

/// `GET /repos/{owner}/{repo}/trails/{n}/sessions`: the Trail's readable
/// linked sessions (D5 JSON), applying §6.4 for the current viewer.
pub async fn get_trail_sessions(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<Value>, ApiError> {
    let view = state
        .core
        .trail_sessions(auth.reader()?, &owner, &repo, number)
        .await?;
    Ok(Json(trail_sessions_json(&view)))
}

#[derive(Deserialize)]
pub struct TrailSessionLinkBody {
    pub session: String,
}

/// `POST /repos/{owner}/{repo}/trails/{n}/sessions`: an explicit hand link
/// (D3). Returns the Trail sessions JSON.
pub async fn link_trail_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    body: Result<Json<TrailSessionLinkBody>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    state
        .core
        .link_trail_session(&auth.user, &owner, &repo, number, &body.session)
        .await?;
    let view = state
        .core
        .trail_sessions(Some(&auth.user), &owner, &repo, number)
        .await?;
    Ok(Json(trail_sessions_json(&view)))
}

/// `DELETE /repos/{owner}/{repo}/trails/{n}/sessions/{ulid}`: removes an
/// explicit hand link (D3). Returns the Trail sessions JSON.
pub async fn unlink_trail_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, number, ulid)): Path<(String, String, i64, String)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::TrailWrite)?;
    state
        .core
        .unlink_trail_session(&auth.user, &owner, &repo, number, &ulid)
        .await?;
    let view = state
        .core
        .trail_sessions(Some(&auth.user), &owner, &repo, number)
        .await?;
    Ok(Json(trail_sessions_json(&view)))
}
