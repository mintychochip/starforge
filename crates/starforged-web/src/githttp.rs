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
use starforged_core::permission::Permission;
use starforged_core::repos::RepoAccess;
use starforged_core::tokens::{self, Scope};
use starforged_git::http::{self as smart, Service};
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

/// Authenticates (optional for fetch), checks token scope and repository permission.
/// Anonymous requests that fail get 401 so git prompts for credentials; authenticated ones get 404 or 403.
async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    repo_segment: &str,
    service: Service,
) -> Result<RepoAccess, GitHttpError> {
    let name = repo_segment.strip_suffix(".git").unwrap_or(repo_segment);
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
    let (needed, scope) = match service {
        Service::UploadPack => (Permission::Read, Scope::RepoRead),
        Service::ReceivePack => (Permission::Write, Scope::RepoWrite),
    };
    if let Some(auth) = &auth
        && !tokens::grants(&auth.scopes, scope)
    {
        return Err(GitHttpError::Forbidden);
    }
    let user: Option<&User> = auth.as_ref().map(|a| &a.user);
    match state.core.require_repo(user, owner, name, needed).await {
        Ok(access) if service == Service::ReceivePack && access.repo.archived_at.is_some() => {
            Err(GitHttpError::Archived)
        }
        Ok(access) => Ok(access),
        Err(CoreError::NotFound | CoreError::Unauthenticated) if user.is_none() => {
            Err(GitHttpError::Unauthorized)
        }
        Err(CoreError::NotFound) => Err(GitHttpError::NotFound),
        Err(CoreError::Forbidden) => Err(GitHttpError::Forbidden),
        Err(other) => Err(GitHttpError::Internal(other.to_string())),
    }
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
    let access = authorize(&state, &headers, &owner, &repo, service).await?;
    let path = state.core.repo_path(access.repo.id);
    let body = smart::advertisement(&path, service, git_protocol(&headers).as_deref())
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
    let access = authorize(&state, &headers, owner, repo, service).await?;
    let path = state.core.repo_path(access.repo.id);
    let gzip = headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    let process = smart::spawn_rpc(&path, service, git_protocol(&headers).as_deref(), &[])
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
    tokio::spawn(async move {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        let status = child.wait().await;
        let failed = !matches!(&status, Ok(s) if s.success());
        if failed || !text.trim().is_empty() {
            tracing::warn!(stderr = %text.trim(), ?status, "git rpc finished");
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
