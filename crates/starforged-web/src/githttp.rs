//! Git smart HTTP (spec §8.1). Fetching public repositories is anonymous; everything else uses HTTP Basic
//! with a personal access token as the password.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures_util::TryStreamExt;
use serde::Deserialize;
use starforged_core::accounts::User;
use starforged_core::jobs::Job;
use starforged_core::permission::Permission;
use starforged_core::repos::RepoAccess;
use starforged_core::tokens::{self, Scope};
use starforged_core::{Core, CoreError};
use starforged_git::http::{self as smart, Service};
use starforged_git::{command, read};
use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path as StdPath, PathBuf};
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
) -> Result<(RepoAccess, Option<User>), GitHttpError> {
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
        Ok(access) => Ok((access, user.cloned())),
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
    let (access, _) = authorize(&state, &headers, &owner, &repo, service).await?;
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
    let (access, user) = authorize(&state, &headers, owner, repo, service).await?;
    let path = state.core.repo_path(access.repo.id);
    // Snapshot every ref tip before spawning receive-pack: the post-push task
    // diffs per ref and enumerates the newly reachable commits for the trailer
    // scan. A failed snapshot disables the scan for this push.
    let before = if service == Service::ReceivePack {
        list_refs(&path).await
    } else {
        None
    };
    // Pre-receive policy snapshot: the hook process never opens the database,
    // so the RPC layer passes identity, permission, and refs/for mode down as
    // env, plus the git-config entries that advertise push options and hide
    // the server-only namespaces.
    let mut env: Vec<(&str, String)> = smart::receive_pack_env();
    if service == Service::ReceivePack {
        let refs_for = state
            .core
            .refs_for_access(access.repo.id)
            .await
            .map_err(|e| GitHttpError::Internal(e.to_string()))?;
        let is_member = match &user {
            Some(user) => state
                .core
                .is_repo_member(access.repo.id, user.id)
                .await
                .map_err(|e| GitHttpError::Internal(e.to_string()))?,
            None => false,
        };
        env.push(("STARFORGE_REPO_ID", access.repo.id.to_string()));
        if let Some(user) = &user {
            env.push(("STARFORGE_USER_ID", user.id.to_string()));
            env.push(("STARFORGE_USER_HANDLE", user.handle.clone()));
        }
        env.push((
            "STARFORGE_PERMISSION",
            access.permission.as_str().to_owned(),
        ));
        env.push((
            "STARFORGE_IS_MEMBER",
            if is_member {
                "1".to_owned()
            } else {
                "0".to_owned()
            },
        ));
        env.push(("STARFORGE_REFS_FOR", refs_for));
        env.push((
            "STARFORGE_PUSH_NONCE",
            starforged_git::pushsidecar::new_nonce(),
        ));
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
    // ... and scans the pushed commits for session trailers in the background.
    let scan = (service == Service::ReceivePack)
        .then(|| (state.core.clone(), access.repo.id, path, before));
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
            if let Some((core, repo_id, repo, before)) = scan {
                scan_push_trailers(core, repo_id, repo, before).await;
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

/// Upper bound on commits read per push for the trailer scan: a push can only
/// add so many commits, and the scan must stay bounded. This is a *commit* cap
/// over the union of every changed ref's new commits, not a ref cap.
const MAX_SCAN_COMMITS: usize = 1_000;

/// Upper bound on pre-push ref tips passed as `rev-list --not` exclusions for a
/// brand-new ref. Past this many refs the exclusion list could bust `ARG_MAX`,
/// so the scan falls back to the new tip alone (with a warning).
const MAX_EXCLUSIONS: usize = 10_000;

/// Refname → tip sha snapshot of `repo`; `None` when the snapshot itself fails (the
/// scan is skipped rather than treating the whole repository as new).
async fn list_refs(repo: &StdPath) -> Option<BTreeMap<String, String>> {
    match command::run([
        OsStr::new("-C"),
        repo.as_os_str(),
        OsStr::new("for-each-ref"),
        OsStr::new("--format=%(refname)%00%(objectname)"),
    ])
    .await
    {
        Ok(out) => {
            let mut refs = BTreeMap::new();
            for line in String::from_utf8_lossy(&out).lines() {
                let (name, sha) = line.split_once('\0').unwrap_or(("", ""));
                if !name.is_empty() && !sha.trim().is_empty() {
                    refs.insert(name.to_owned(), sha.trim().to_owned());
                }
            }
            Some(refs)
        }
        Err(err) => {
            tracing::warn!(%err, "trailer scan: ref snapshot failed");
            None
        }
    }
}

/// One ref to scan: `(refname, old tip or `None` when the ref is new, new tip)`,
/// in sorted refname order. Deleted refs and unchanged tips contribute nothing.
fn changed_refs(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<(String, Option<String>, String)> {
    let mut changes = Vec::new();
    for (name, new) in after {
        match before.get(name) {
            Some(old) if old == new => {}
            old => changes.push((name.clone(), old.cloned(), new.clone())),
        }
    }
    changes
}

/// Commits to scan: for each changed ref, `rev-list new --not old` (moved tip) or
/// `rev-list new --not <pre-push tips>` (brand-new ref; an empty pre-push snapshot
/// means the full history). Unioned across refs in sorted order, deduplicated, and
/// capped at [`MAX_SCAN_COMMITS`] total; hitting the cap warns with the cap and the
/// ref it cut off at. Per-ref failures warn and are skipped.
async fn new_commits(
    repo: &StdPath,
    before: &BTreeMap<String, String>,
    changes: &[(String, Option<String>, String)],
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    // The ref whose enumeration the commit cap cut off, if any — warned once below.
    let mut truncated: Option<&str> = None;
    for (name, old, new) in changes {
        if out.len() >= MAX_SCAN_COMMITS {
            truncated = Some(name.as_str());
            break;
        }
        let mut args: Vec<OsString> = vec![
            OsString::from("-C"),
            OsString::from(repo),
            OsString::from("rev-list"),
            OsString::from(new),
            OsString::from("--not"),
        ];
        match old {
            Some(old) => args.push(OsString::from(old)),
            None if before.is_empty() => {
                args.pop();
            }
            None if before.len() <= MAX_EXCLUSIONS => {
                args.extend(before.values().map(OsString::from));
            }
            None => {
                tracing::warn!(%name, tips = before.len(), "trailer scan: too many tips to exclude; scanning the tip alone");
                if seen.insert(new.clone()) {
                    out.push(new.clone());
                }
                continue;
            }
        }
        match command::run(args).await {
            Ok(bytes) => {
                for line in String::from_utf8_lossy(&bytes).lines() {
                    if out.len() >= MAX_SCAN_COMMITS {
                        truncated = Some(name.as_str());
                        break;
                    }
                    let sha = line.trim();
                    if !sha.is_empty() && seen.insert(sha.to_owned()) {
                        out.push(sha.to_owned());
                    }
                }
            }
            Err(err) => tracing::warn!(%name, %err, "trailer scan: rev-list failed"),
        }
        if truncated.is_some() {
            break;
        }
    }
    if let Some(refname) = truncated {
        tracing::warn!(
            %refname,
            cap = MAX_SCAN_COMMITS,
            enumerated = out.len(),
            "trailer scan: commit cap cut the scan; trailers past the cap were not scanned"
        );
    }
    out
}

/// Records trailer links for the commits a push added: every commit newly reachable
/// from a changed ref (not just the new tips), so multi-commit pushes and new branches
/// scan fully. Failures only warn: a push never fails because of links.
async fn scan_push_trailers(
    core: Core,
    repo_id: i64,
    repo: PathBuf,
    before: Option<BTreeMap<String, String>>,
) {
    let Some(before) = before else { return };
    let Some(after) = list_refs(&repo).await else {
        return;
    };
    let changes = changed_refs(&before, &after);
    if changes.is_empty() {
        return;
    }
    let shas = new_commits(&repo, &before, &changes).await;
    if shas.is_empty() {
        return;
    }
    let messages = tokio::task::spawn_blocking(move || {
        let mut out = Vec::with_capacity(shas.len());
        for sha in &shas {
            match read::commit(&repo, sha) {
                Ok(Some(info)) => out.push((sha.clone(), info.message.clone())),
                Ok(None) => tracing::warn!(%sha, "trailer scan: pushed commit not found"),
                Err(err) => tracing::warn!(%sha, %err, "trailer scan: commit read failed"),
            }
        }
        out
    })
    .await;
    let messages = match messages {
        Ok(messages) => messages,
        Err(err) => {
            tracing::warn!(%err, "trailer scan: commit read task failed");
            return;
        }
    };
    if messages.is_empty() {
        return;
    }
    if let Err(err) = core.record_trailer_links(repo_id, &messages).await {
        tracing::warn!(repo_id, %err, "trailer scan: storing links failed");
    }
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

    #[test]
    fn changed_refs_reports_updates_and_new_refs_in_order() {
        let before: BTreeMap<String, String> = [
            ("refs/heads/aaa".to_owned(), "tip-a".to_owned()),
            ("refs/heads/gone".to_owned(), "tip-g".to_owned()),
            ("refs/heads/main".to_owned(), "tip-1".to_owned()),
        ]
        .into_iter()
        .collect();
        let after: BTreeMap<String, String> = [
            ("refs/heads/aaa".to_owned(), "tip-a".to_owned()),
            ("refs/heads/feature".to_owned(), "tip-f".to_owned()),
            ("refs/heads/main".to_owned(), "tip-2".to_owned()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            changed_refs(&before, &after),
            vec![
                ("refs/heads/feature".to_owned(), None, "tip-f".to_owned()),
                (
                    "refs/heads/main".to_owned(),
                    Some("tip-1".to_owned()),
                    "tip-2".to_owned()
                ),
            ],
            "new and moved refs scan; unchanged and deleted refs add nothing"
        );
        assert!(changed_refs(&before, &before).is_empty());
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
