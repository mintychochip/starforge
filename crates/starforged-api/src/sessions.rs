//! Session upload routes (spec §6.3): the four ingest endpoints the CLI drives.
//!
//! Handlers check the `session:upload` scope, authorize `write` on the
//! repository through [`Core::authorize_upload`], and delegate to `Core`. D4
//! validates hashes/sizes/sequence numbers; D5 re-scans for quarantine.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use starforged_core::ingest::SegmentPut;
use starforged_core::permission::Permission;
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;

fn session_json(id: i64, ulid: &str, state: &str, quarantine: &str) -> Value {
    json!({ "id": id, "ulid": ulid, "state": state, "quarantine": quarantine })
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
