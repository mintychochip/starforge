//! Session upload routes (spec §6.3): the four ingest endpoints the CLI drives.
//!
//! Handlers check the `session:upload` scope, authorize `write` on the
//! repository through [`Core::authorize_upload`], and delegate to `Core`. D4
//! validates hashes/sizes/sequence numbers; D5 re-scans for quarantine.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use starforged_core::ingest::SegmentPut;
use starforged_core::permission::Permission;
use starforged_core::read::SessionPageItem;
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;

fn session_json(id: i64, ulid: &str, lifecycle: &str, quarantine: &str) -> Value {
    json!({ "id": id, "ulid": ulid, "lifecycle": lifecycle, "quarantine": quarantine })
}

/// Sessions never reach search indexes (spec §11.1): every session response
/// carries the header, including these JSON endpoints.
fn noindex_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers
}

/// Query for the session listing: only the quarantine queue exists in M1d.
#[derive(Debug, Deserialize)]
pub struct SessionListQuery {
    pub quarantined: Option<bool>,
}

/// `PUT /repos/{owner}/{repo}/sessions/{ulid}`: creates the session row from
/// `SessionMeta` JSON (201), or refreshes it on re-PUT (200).
pub async fn put_meta(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let ingest = state.core.authorize_upload(token, &owner, &repo).await?;
    let meta: Value =
        serde_json::from_slice(&body).map_err(|_| ApiError::Invalid("body must be JSON".into()))?;
    if !meta.is_object() {
        return Err(ApiError::Invalid(
            "session metadata must be a JSON object".into(),
        ));
    }
    let (row, created) = state
        .core
        .upsert_session_meta(&ingest, &ulid, &meta)
        .await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(session_json(
            row.id,
            &row.ulid,
            &row.lifecycle,
            &row.quarantine,
        )),
    ))
}

/// `PUT /repos/{owner}/{repo}/sessions/{ulid}/segments/{n}`: stores one
/// compressed segment body. `X-Starforge-Blake3` must carry the lowercase
/// BLAKE3 hex of the body (missing → 400, mismatch → 422). Identical
/// re-uploads succeed idempotently (200); different bytes at the same number
/// answer `409 {"hash": "<stored hex>"}` — exactly that shape, not the error
/// envelope, so the CLI can tell the cases apart. Bodies over the configured
/// cap answer `413`.
pub async fn put_segment(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid, n)): Path<(String, String, String, i64)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let ingest = state.core.authorize_upload(token, &owner, &repo).await?;
    let cap = state.core.config().max_segment_bytes;
    if body.len() as u64 > cap {
        return Err(ApiError::PayloadTooLarge(format!(
            "segment body is {} bytes, over the {}-byte limit",
            body.len(),
            cap
        )));
    }
    let claimed = match headers.get("x-starforge-blake3") {
        None => {
            return Err(ApiError::BadRequest(
                "missing X-Starforge-Blake3 header".into(),
            ));
        }
        Some(value) => value
            .to_str()
            .map_err(|_| ApiError::BadRequest("invalid X-Starforge-Blake3 header".into()))?
            .to_owned(),
    };
    match state
        .core
        .put_segment(&ingest, &ulid, n, &body, Some(claimed))
        .await?
    {
        SegmentPut::Stored(session) | SegmentPut::Unchanged(session) => Ok((
            StatusCode::OK,
            Json(session_json(
                session.id,
                &session.ulid,
                &session.lifecycle,
                &session.quarantine,
            )),
        )
            .into_response()),
        SegmentPut::Conflict { stored_hash, .. } => {
            Ok((StatusCode::CONFLICT, Json(json!({ "hash": stored_hash }))).into_response())
        }
    }
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/complete`: flips the session to
/// `complete`. The body must be an empty JSON object (`{}`); anything else is
/// `422`. The server never auto-completes (the CLI owns the idle rule).
pub async fn post_complete(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let ingest = state.core.authorize_upload(token, &owner, &repo).await?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| ApiError::Invalid("body must be JSON".into()))?;
    if value.as_object().is_none_or(|o| !o.is_empty()) {
        return Err(ApiError::Invalid(
            "complete takes an empty JSON object".into(),
        ));
    }
    let session = state.core.complete_session(&ingest, &ulid).await?;
    Ok(Json(session_json(
        session.id,
        &session.ulid,
        &session.lifecycle,
        &session.quarantine,
    )))
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/links`: records the CLI's
/// commit claims (`{"links": [...]}`). Re-posts merge idempotently through
/// `upsert_claim_links` (one transaction); answers `{"accepted": k}`.
pub async fn post_links(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let ingest = state.core.authorize_upload(token, &owner, &repo).await?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| ApiError::Invalid("body must be JSON".into()))?;
    let links = value
        .get("links")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::Invalid("body must be {\"links\": [...]}".into()))?;
    let accepted = state.core.claim_links(&ingest, &ulid, links).await?;
    Ok(Json(json!({ "accepted": accepted })))
}

/// `GET /repos/{owner}/{repo}/sessions?quarantined=true`: the admin
/// quarantine queue. Repo-`admin` only (visible-but-insufficient answers
/// `403`, invisible repositories `404`); anything but `?quarantined=true`
/// answers `422` — the full session listing lands with the M1e read path.
pub async fn list_sessions(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<SessionListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let access = state
        .core
        .require_repo(Some(&token.user), &owner, &repo, Permission::Admin)
        .await?;
    if query.quarantined != Some(true) {
        return Err(ApiError::Invalid(
            "only ?quarantined=true is supported".into(),
        ));
    }
    let sessions = state.core.list_quarantined(&access).await?;
    Ok(Json(json!({ "sessions": sessions })))
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/release`: clears a quarantine
/// back to `released` (the evidence columns stay for forensics) and audits
/// `session.quarantine.released`. A session that is not quarantined answers
/// `422`.
pub async fn release_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let access = state
        .core
        .require_repo(Some(&token.user), &owner, &repo, Permission::Admin)
        .await?;
    let view = state
        .core
        .release_session(&token.user, &access, &ulid)
        .await?;
    Ok(Json(view))
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/purge`: deletes the session
/// row, its segment rows (blob refcounts decremented), and its commit links,
/// then audits `session.purged`. Answers `204`; an unknown session is `404`.
pub async fn purge_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let access = state
        .core
        .require_repo(Some(&token.user), &owner, &repo, Permission::Admin)
        .await?;
    state
        .core
        .purge_session(&token.user, &access, &ulid)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
/// Query for the event page: 1-based, default 1.
#[derive(Debug, Deserialize)]
pub struct SessionEventsQuery {
    pub page: Option<i64>,
}

/// Parses a JSON-encoded row column back to a value (raw string fallback).
fn json_column(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

/// `GET /repos/{owner}/{repo}/sessions/{ulid}`: session metadata plus its
/// commit links. One [`Core::authorize_session_read_by_ulid`] check —
/// non-readers get `404`, never `403`.
pub async fn get_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth.reader()?;
    let (_, row) = state
        .core
        .authorize_session_read_by_ulid(user, &owner, &repo, &ulid)
        .await?;
    let links = state.core.session_links(row.id).await?;
    let body = json!({
        "ulid": row.ulid,
        "agent": {"name": row.agent_name, "version": row.agent_version},
        "adapter_version_verified": row.adapter_verified != 0,
        "models": json_column(&row.models),
        "title": row.title,
        "branch": row.branch,
        "head": row.head_sha,
        "started_at": row.started_at,
        "ended_at": row.ended_at,
        "usage": {
            "input": row.usage_input,
            "output": row.usage_output,
            "cache_read": row.usage_cache_read,
            "cache_write": row.usage_cache_write,
            "reasoning": row.usage_reasoning,
        },
        "visibility": row.visibility,
        "quarantine": {
            "state": row.quarantine,
            "reason": row.quarantine_reason,
            "detail": row.quarantine_detail,
        },
        "redaction": {
            "fingerprint": row.redaction_fingerprint,
            "counts": json_column(&row.redaction_counts),
        },
        "capture": {"mode": row.capture_mode, "cli_version": row.cli_version},
        "links": links
            .iter()
            .map(|link| {
                json!({
                    "sha": link.sha,
                    "confidence": link.confidence,
                    "seq_start": link.seq_start,
                    "seq_end": link.seq_end,
                })
            })
            .collect::<Vec<_>>(),
    });
    Ok((noindex_headers(), Json(body)))
}

/// `GET /repos/{owner}/{repo}/sessions/{ulid}/events?page=N`: the same
/// 200-event page the viewer renders, as JSON. Undecodable segments appear
/// as `{"kind": "unreadable_segment", "n": N}` placeholders.
pub async fn get_events(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
    Query(query): Query<SessionEventsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth.reader()?;
    let (_, row) = state
        .core
        .authorize_session_read_by_ulid(user, &owner, &repo, &ulid)
        .await?;
    let view = state
        .core
        .read_session_page(row.id, query.page.unwrap_or(1))
        .await?;
    let events = view
        .items
        .iter()
        .map(|item| match item {
            SessionPageItem::Event(event) => serde_json::to_value(event).unwrap_or(Value::Null),
            SessionPageItem::UnreadableSegment { n } => {
                json!({"kind": "unreadable_segment", "n": n})
            }
        })
        .collect::<Vec<_>>();
    Ok((
        noindex_headers(),
        Json(json!({
            "events": events,
            "page": view.page,
            "pages": view.pages,
            "total": view.total,
        })),
    ))
}
