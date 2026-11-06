//! Git smart HTTP (spec §8.1). Fetching public repositories is anonymous; everything else uses HTTP Basic
//! with a personal access token as the password.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures_util::TryStreamExt;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::accounts::User;
use starforged_core::jobs::Job;
use starforged_core::repos::RepoAccess;
use starforged_core::tokens::{self, Scope};
use starforged_git::http::{self as smart, Service};
use starforged_git::pushsidecar;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::AppState;

#[derive(Debug)]
pub enum GitHttpError {
    Unauthorized,
    Forbidden,
    Archived,
    NotFound,
    BadRequest(&'static str),
    Internal(String),
}

impl IntoResponse for GitHttpError {
    fn into_response(self) -> Response {
        match self {
            GitHttpError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"Starforge\""),
                )],
                "authentication required\n",
            )
                .into_response(),
            GitHttpError::Forbidden => {
                (StatusCode::FORBIDDEN, "permission denied\n").into_response()
            }
            GitHttpError::Archived => (
                StatusCode::FORBIDDEN,
                "This repository is archived; pushes are disabled.\n",
            )
                .into_response(),
            GitHttpError::NotFound => {
                (StatusCode::NOT_FOUND, "repository not found\n").into_response()
            }
            GitHttpError::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            GitHttpError::Internal(message) => {
                tracing::error!(%message, "git smart HTTP failure");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
            }
        }
    }
}

#[derive(Deserialize)]
pub struct InfoRefsQuery {
    service: Option<String>,
}

/// The password of `Authorization: Basic …`; the username is ignored.
pub fn basic_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (_, password) = text.split_once(':')?;
    Some(password.to_owned())
}

fn git_protocol(headers: &HeaderMap) -> Option<String> {
    headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Maps a `require_repo` failure to the HTTP error for an authenticated caller.
fn map_repo_error(e: CoreError) -> GitHttpError {
    match e {
        CoreError::NotFound => GitHttpError::NotFound,
        CoreError::Forbidden => GitHttpError::Forbidden,
        CoreError::Unauthenticated => GitHttpError::Unauthorized,
        other => GitHttpError::Internal(other.to_string()),
    }
}

/// Authenticates (optional for fetch), checks token scope and repository permission.
/// Anonymous requests that fail get 401 so git prompts for credentials; authenticated ones get 404 or 403.
///
/// Receive-pack has two entry tiers: writers (`repo:write` scope + `Write`
/// permission, as before) and readers (`repo:read` scope + `Read` permission,
/// only when the repo's `refs_for_access` opens `refs/for` to them). The bool
/// reports the write tier; the pre-receive hook enforces the split (branches
/// and tags need the write tier, `refs/for` needs the read tier), because the
/// RPC never sees the pushed refs.
async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    repo_segment: &str,
    service: Service,
) -> Result<(RepoAccess, Option<User>, bool), GitHttpError> {
    let auth = match basic_password(headers) {
        Some(secret) => Some(
            state
                .core
                .authenticate_token(&secret)
                .await
                .map_err(|_| GitHttpError::Unauthorized)?,
        ),
        None => None,
    };
    let actor = match &auth {
        Some(auth) => starforged_core::gitaccess::GitActor::User {
            user: auth.user.clone(),
            scope_read: tokens::grants(&auth.scopes, Scope::RepoRead),
            scope_write: tokens::grants(&auth.scopes, Scope::RepoWrite),
        },
        None => starforged_core::gitaccess::GitActor::Anonymous {
            // Anonymous fetches carry no token to scope-check; a real token
            // with a missing scope is `User` and refused inside `git_access`.
            scope_read: true,
            scope_write: false,
        },
    };
    let service = match service {
        Service::UploadPack => starforged_core::gitaccess::GitService::UploadPack,
        Service::ReceivePack => starforged_core::gitaccess::GitService::ReceivePack,
    };
    let result = state
        .core
        .git_access(&actor, owner, repo_segment, service)
        .await;
    let grant = match result {
        Ok(grant) => grant,
        Err(CoreError::NotFound | CoreError::Unauthenticated) if auth.is_none() => {
            return Err(GitHttpError::Unauthorized);
        }
        Err(e) => return Err(map_repo_error(e)),
    };
    if service == starforged_core::gitaccess::GitService::ReceivePack
        && grant.access.repo.archived_at.is_some()
    {
        return Err(GitHttpError::Archived);
    }
    Ok((grant.access, grant.user, grant.write_path))
}

pub async fn info_refs(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Result<Response, GitHttpError> {
    let service = query
        .service
        .as_deref()
        .and_then(Service::from_query)
        .ok_or(GitHttpError::BadRequest(
            "only the smart HTTP protocol is supported\n",
        ))?;
    let (access, _, _) = authorize(&state, &headers, &owner, &repo, service).await?;
    let path = state.core.repo_path(access.repo.id);
    // The per-service env tells push clients that `-o` options are accepted
    // and hides the server-only namespaces (`refs/for`, `refs/trails`) from
    // fetches. Push-side hiding would deny refs/for updates, so the
    // receive-pack advertisement stays complete.
    let env = smart::rpc_env(service);
    let body = smart::advertisement(&path, service, git_protocol(&headers).as_deref(), &env)
        .await
        .map_err(|e| GitHttpError::Internal(e.to_string()))?;
    Ok((
        [
            (header::CONTENT_TYPE, service.advertisement_content_type()),
            (header::CACHE_CONTROL, "no-cache".to_owned()),
        ],
        body,
    )
        .into_response())
}

pub async fn upload_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, GitHttpError> {
    rpc(state, &owner, &repo, headers, body, Service::UploadPack).await
}

pub async fn receive_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, GitHttpError> {
    rpc(state, &owner, &repo, headers, body, Service::ReceivePack).await
}

/// Streams the request body into `git <service> --stateless-rpc` and its stdout back out.
async fn rpc(
    state: AppState,
    owner: &str,
    repo: &str,
    headers: HeaderMap,
    body: Body,
    service: Service,
) -> Result<Response, GitHttpError> {
    let (access, user, write_path) = authorize(&state, &headers, owner, repo, service).await?;
    let path = state.core.repo_path(access.repo.id);
    // Snapshot every ref tip before spawning receive-pack: the post-push task
    // diffs per ref and enumerates the newly reachable commits for the trailer
    // scan. A failed snapshot disables the scan for this push.
    let before = if service == Service::ReceivePack {
        state.core.snapshot_refs(&path).await
    } else {
        None
    };
    // Pre-receive policy snapshot: the hook process never opens the database,
    // so the RPC layer passes identity, permission, and refs/for mode down as
    // env, plus the git-config entries that advertise push options and hide
    // the server-only namespaces. [`Core::git_rpc_env`] builds the whole
    // block (SSH reuses it); this layer only adds the transport entries.
    let mut env: Vec<(&str, String)> = smart::rpc_env(service);
    // The nonce keys the push-option sidecars the hook writes per accepted
    // `refs/for` line; the post-push scan consumes exactly this push's files.
    let mut scan_nonce: Option<String> = None;
    if service == Service::ReceivePack {
        let nonce = pushsidecar::new_nonce();
        env.extend(
            state
                .core
                .git_rpc_env(&access, user.as_ref(), write_path, &nonce)
                .await
                .map_err(|e| GitHttpError::Internal(e.to_string()))?,
        );
        scan_nonce = Some(nonce);
    }
    let gzip = headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    let process = smart::spawn_rpc(&path, service, git_protocol(&headers).as_deref(), &env)
        .map_err(|e| GitHttpError::Internal(e.to_string()))?;

    let mut input = request_reader(body, gzip);
    let mut stdin = process.stdin;
    tokio::spawn(async move {
        if let Err(err) = tokio::io::copy(&mut input, &mut stdin).await {
            tracing::warn!(%err, "copying the git request body failed");
        }
    });

    let mut stderr = process.stderr;
    let mut child = process.child;
    // A successful push queues `git maintenance` for the repository (one pending run per repository).
    let maintenance =
        (service == Service::ReceivePack).then(|| (state.core.clone(), access.repo.id));
    // ... and ingests the pushed refs in the background: session trailers,
    // `refs/for` changes, and branch-head moves.
    let scan = (service == Service::ReceivePack).then(|| {
        (
            state.core.clone(),
            access.repo.id,
            path,
            user,
            scan_nonce,
            before,
        )
    });
    tokio::spawn(async move {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        let status = child.wait().await;
        let failed = !matches!(&status, Ok(s) if s.success());
        if failed || !text.trim().is_empty() {
            tracing::warn!(stderr = %text.trim(), ?status, "git rpc finished");
        }
        if !failed {
            if let Some((core, repo_id)) = maintenance
                && let Err(err) = core.enqueue(&Job::GitMaintenance { repo_id }).await
            {
                tracing::warn!(error = %err, repo_id, "queueing git maintenance failed");
            }
            if let Some((core, repo_id, repo, pusher, nonce, before)) = scan {
                core.scan_push_changes(repo_id, repo, pusher, nonce, before)
                    .await;
            }
        }
    });

    Ok((
        [
            (header::CONTENT_TYPE, service.result_content_type()),
            (header::CACHE_CONTROL, "no-cache".to_owned()),
        ],
        Body::from_stream(ReaderStream::new(process.stdout)),
    )
        .into_response())
}

/// The request body as bytes, gunzipped when the client sent `Content-Encoding: gzip`.
pub fn request_reader(body: Body, gzip: bool) -> Box<dyn AsyncRead + Send + Unpin> {
    let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    if gzip {
        Box::new(async_compression::tokio::bufread::GzipDecoder::new(reader))
    } else {
        Box::new(reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn basic_password_extraction() {
        let mut headers = HeaderMap::new();
        assert_eq!(basic_password(&headers), None);
        let encoded = base64::engine::general_purpose::STANDARD.encode("git:sfp_secret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert_eq!(basic_password(&headers).as_deref(), Some("sfp_secret"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sfp_secret"),
        );
        assert_eq!(basic_password(&headers), None);
    }

    #[tokio::test]
    async fn request_reader_gunzips_when_asked() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"0032want 0123456789abcdef\n").unwrap();
        let compressed = encoder.finish().unwrap();
        let mut out = Vec::new();
        request_reader(Body::from(compressed), true)
            .read_to_end(&mut out)
            .await
            .unwrap();
        assert_eq!(out, b"0032want 0123456789abcdef\n");
        let mut plain = Vec::new();
        request_reader(Body::from("abc"), false)
            .read_to_end(&mut plain)
            .await
            .unwrap();
        assert_eq!(plain, b"abc");
    }
}
