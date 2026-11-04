//! Session upload routes (spec §6.3): the four ingest endpoints the CLI drives.
//!
//! Handlers check the `session:upload` scope, authorize `write` on the
//! repository through [`Core::authorize_upload`], and delegate to `Core`. D4
//! validates hashes/sizes/sequence numbers; D5 re-scans for quarantine.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use starforged_core::ingest::SegmentPut;
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;

fn session_json(id: i64, ulid: &str, state: &str) -> Value {
    json!({ "id": id, "ulid": ulid, "state": state })
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
        Json(session_json(row.id, &row.ulid, &row.lifecycle)),
    ))
}

/// `PUT /repos/{owner}/{repo}/sessions/{ulid}/segments/{n}`: stores one
/// compressed segment body. Identical re-uploads succeed idempotently (200);
/// different bytes at the same number answer `409 {"hash": "<stored hex>"}` —
/// exactly that shape, not the error envelope, so the CLI can tell the cases
/// apart. Bodies over the configured cap answer `413`.
pub async fn put_segment(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, ulid, n)): Path<(String, String, String, i64)>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let token = auth.require(Scope::SessionUpload)?;
    let ingest = state.core.authorize_upload(token, &owner, &repo).await?;
    // D4 validates the `X-Starforge-Blake3` header against the stored bytes;
    // D3 deliberately ignores it and addresses content by what was stored.
    let cap = state.core.config().max_segment_bytes;
    if body.len() as u64 > cap {
        return Err(ApiError::PayloadTooLarge(format!(
            "segment body is {} bytes, over the {}-byte limit",
            body.len(),
            cap
        )));
    }
    match state.core.put_segment(&ingest, &ulid, n, &body).await? {
        SegmentPut::Stored(session) | SegmentPut::Unchanged(session) => Ok((
            StatusCode::OK,
            Json(session_json(session.id, &session.ulid, &session.lifecycle)),
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
    )))
}

/// `POST /repos/{owner}/{repo}/sessions/{ulid}/links`: records the CLI's
/// commit claims (`{"links": [...]}`). Re-posts merge idempotently through
/// `upsert_claim_link`; answers `{"accepted": k}`.
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
