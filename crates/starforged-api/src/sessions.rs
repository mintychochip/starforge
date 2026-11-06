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
use starforged_core::rescan::QuarantineOutcome;
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
#[utoipa::path(
    put,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Session metadata", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    put,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
        ("n" = i64, Path, description = "Segment number"),
    ),
    responses(
        (status = 200, description = "Segment stored", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
    state
        .core
        .metrics()
        .add_session_upload_bytes(body.len() as u64);
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
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/complete",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Session completed", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/links",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Links recorded", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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

/// `GET /repos/{owner}/{repo}/sessions`: the sessions the caller may read
/// under the §6.4 rule (ULIDs of unreadable sessions stay undiscoverable),
/// oldest first. `truncated` is `true` when the listing hit the candidate
/// cap. `?quarantined=true` keeps its older meaning — the admin quarantine
/// queue (repo `admin` only; visible-but-insufficient answers `403`,
/// invisible repositories `404`). `?quarantined=false` answers `422`
/// (after authentication, like every other validation here).
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/sessions",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Sessions", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn list_sessions(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<SessionListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    match query.quarantined {
        Some(true) => {
            let token = auth.require(Scope::SessionUpload)?;
            let access = state
                .core
                .require_repo(Some(&token.user), &owner, &repo, Permission::Admin)
                .await?;
            let sessions = state.core.list_quarantined(&access).await?;
            Ok((noindex_headers(), Json(json!({ "sessions": sessions }))).into_response())
        }
        Some(false) => {
            // Authenticate before validating: no token answers `401`, a token
            // without the upload scope `403` — only then the `422` below.
            auth.require(Scope::SessionUpload)?;
            Err(ApiError::Invalid(
                "only ?quarantined=true is supported".into(),
            ))
        }
        None => {
            let user = auth.reader()?;
            let access = state.core.repo_for(user, &owner, &repo).await?;
            let sessions = state.core.list_readable_sessions(user, &access).await?;
            let truncated =
                sessions.len() >= starforged_core::read::READABLE_SESSION_LIST_LIMIT as usize;
            let rows = sessions
                .iter()
                .map(|row| {
                    json!({
                        "ulid": row.ulid,
                        "agent": {"name": row.agent_name, "version": row.agent_version},
                        "title": row.title,
                        "visibility": row.visibility,
                        "lifecycle": row.lifecycle,
                        "started_at": row.started_at,
                        "ended_at": row.ended_at,
                    })
                })
                .collect::<Vec<_>>();
            Ok((
                noindex_headers(),
                Json(json!({ "sessions": rows, "truncated": truncated })),
            )
                .into_response())
        }
    }
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/release`: clears a quarantine
/// back to `released` (the evidence columns stay for forensics) and audits
/// `session.quarantine.released`. A session that is not quarantined answers
/// `422`.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/release",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 200, description = "Quarantine released", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/purge",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 204, description = "Purged"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/publish`: flips `visibility`
/// to `published` (public repositories only — elsewhere `422`, since
/// publishing would have no effect) and audits `session.publish`. Repo
/// `maintain` or above; visible-but-insufficient answers `403`, invisible
/// repositories `404`.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/publish",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 200, description = "Published", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn publish_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let access = state
        .core
        .require_repo(Some(&token.user), &owner, &repo, Permission::Maintain)
        .await?;
    let row = state
        .core
        .publish_session(&token.user, &access, &ulid)
        .await?;
    Ok((
        noindex_headers(),
        Json(json!({ "ulid": row.ulid, "visibility": row.visibility })),
    ))
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/unpublish`: the mirror of
/// [`publish_session`], back to `inherit` (an `Ok` no-op when the session was
/// never published). Same auth; audits `session.unpublish`.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/unpublish",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 200, description = "Unpublished", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn unpublish_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let access = state
        .core
        .require_repo(Some(&token.user), &owner, &repo, Permission::Maintain)
        .await?;
    let row = state
        .core
        .unpublish_session(&token.user, &access, &ulid)
        .await?;
    Ok((
        noindex_headers(),
        Json(json!({ "ulid": row.ulid, "visibility": row.visibility })),
    ))
}

/// `DELETE /repos/{owner}/{repo}/sessions/{ulid}`: the user-facing delete
/// path — the uploader, a repo admin, or a site admin removes the session,
/// its segments (blob refcounts decremented), and its commit links, auditing
/// `session.deleted`. Answers `204`; anyone else (and unknown ULIDs) answer
/// `404`, so session ULIDs stay undiscoverable.
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn delete_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let access = state
        .core
        .require_repo(Some(&token.user), &owner, &repo, Permission::Read)
        .await?;
    state
        .core
        .delete_session(&token.user, &access, &ulid)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/rescan`: re-runs the rule
/// scan over the stored segments (filling the M1d gap — `Core::rescan_session`
/// had no HTTP route) and answers the new quarantine verdict. Repo `admin`
/// only; audits `session.rescan`; idempotent.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/rescan",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 200, description = "Rescan verdict", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn rescan_session(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let access = state
        .core
        .require_repo(Some(&token.user), &owner, &repo, Permission::Admin)
        .await?;
    let outcome = state
        .core
        .admin_rescan_session(&token.user, &access, &ulid)
        .await?;
    let body = match outcome {
        QuarantineOutcome::Clean => json!({"quarantine": "none", "reason": null, "detail": null}),
        QuarantineOutcome::Quarantined { reason, detail } => {
            json!({"quarantine": "quarantined", "reason": reason, "detail": detail})
        }
    };
    Ok((noindex_headers(), Json(body)))
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
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 200, description = "Session metadata and links", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/events",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 200, description = "Session events", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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

/// `GET /repos/{owner}/{repo}/sessions/{ulid}/links`: the session's commit
/// links (the `links` array of [`get_session`], standalone for export).
/// One [`Core::authorize_session_read_by_ulid`] check — non-readers get
/// `404`, never `403`.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/links",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
    ),
    responses(
        (status = 200, description = "Session links", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn get_links(
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
    let links = links
        .iter()
        .map(|link| {
            json!({
                "sha": link.sha,
                "confidence": link.confidence,
                "seq_start": link.seq_start,
                "seq_end": link.seq_end,
            })
        })
        .collect::<Vec<_>>();
    Ok((noindex_headers(), Json(json!({ "links": links }))))
}

/// `GET /repos/{owner}/{repo}/sessions/{ulid}/segments/{n}`: the exact
/// stored bytes of segment `n` (the compressed JSONL blob, verbatim) as
/// `application/octet-stream` — the raw segment download, gated behind the
/// raw-storage gate ([`Core::authorize_raw_segment_read`]: raw storage
/// enabled and the uploader or a site admin). Stored bytes are
/// as-uploaded and never re-redacted, while every other read path renders
/// server-redacted content (§11.2), so weaker readers answer `404` here
/// even for sessions they could read through `/events`.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ulid" = String, Path, description = "Session ULID"),
        ("n" = i64, Path, description = "Segment number"),
    ),
    responses(
        (status = 200, description = "Raw segment bytes", body = Vec<u8>),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn get_segment(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid, n)): Path<(String, String, String, i64)>,
) -> Result<Response, ApiError> {
    let user = auth.reader()?;
    let (_, row) = state
        .core
        .authorize_raw_segment_read(user, &owner, &repo, &ulid)
        .await?;
    let bytes = state.core.session_segment_bytes(row.id, n).await?;
    let mut headers = noindex_headers();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((headers, bytes).into_response())
}
