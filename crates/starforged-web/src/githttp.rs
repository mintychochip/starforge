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
use starforged_core::changes::IngestSidecar;
use starforged_core::jobs::Job;
use starforged_core::permission::Permission;
use starforged_core::repos::RepoAccess;
use starforged_core::tokens::{self, Scope};
use starforged_core::{Core, CoreError};
use starforged_git::http::{self as smart, Service};
use starforged_git::{command, pushsidecar, read, refpolicy, write};
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

/// Maps a `require_repo` failure to the HTTP error for an authenticated caller.
fn map_repo_error(e: CoreError) -> GitHttpError {
    match e {
        CoreError::NotFound => GitHttpError::NotFound,
        CoreError::Forbidden => GitHttpError::Forbidden,
        CoreError::Unauthenticated => GitHttpError::Unauthorized,
        other => GitHttpError::Internal(other.to_string()),
    }
}

fn map_repo_access(result: Result<RepoAccess, CoreError>) -> Result<RepoAccess, GitHttpError> {
    result.map_err(map_repo_error)
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
    if service == Service::UploadPack {
        if let Some(auth) = &auth
            && !tokens::grants(&auth.scopes, Scope::RepoRead)
        {
            return Err(GitHttpError::Forbidden);
        }
        let user: Option<&User> = auth.as_ref().map(|a| &a.user);
        return match state
            .core
            .require_repo(user, owner, name, Permission::Read)
            .await
        {
            Ok(access) => Ok((access, user.cloned(), false)),
            Err(CoreError::NotFound | CoreError::Unauthenticated) if user.is_none() => {
                Err(GitHttpError::Unauthorized)
            }
            Err(CoreError::NotFound) => Err(GitHttpError::NotFound),
            Err(CoreError::Forbidden) => Err(GitHttpError::Forbidden),
            Err(other) => Err(GitHttpError::Internal(other.to_string())),
        };
    }
    // Receive-pack: anonymous pushes stay rejected (401 prompts for credentials).
    let Some(auth) = auth else {
        return Err(GitHttpError::Unauthorized);
    };
    let write_path = tokens::grants(&auth.scopes, Scope::RepoWrite);
    let read_path = tokens::grants(&auth.scopes, Scope::RepoRead);
    // The write tier is tried first; a reader holding a write-scoped token
    // falls through to the read tier instead of failing here (the hook still
    // rejects their branch pushes per ref).
    let (access, write_path) = if write_path {
        match state
            .core
            .require_repo(Some(&auth.user), owner, name, Permission::Write)
            .await
        {
            Ok(access) => (access, true),
            Err(e)
                if read_path
                    && matches!(
                        e,
                        CoreError::NotFound | CoreError::Forbidden | CoreError::Unauthenticated
                    ) =>
            {
                let access = map_repo_access(
                    state
                        .core
                        .require_repo(Some(&auth.user), owner, name, Permission::Read)
                        .await,
                )?;
                (access, false)
            }
            Err(e) => return Err(map_repo_error(e)),
        }
    } else {
        let access = map_repo_access(
            state
                .core
                .require_repo(Some(&auth.user), owner, name, Permission::Read)
                .await,
        )?;
        (access, false)
    };
    if access.repo.archived_at.is_some() {
        return Err(GitHttpError::Archived);
    }
    if !write_path {
        // Read tier: `refs/for` only, and only when the repo opens it to this
        // user — the same rule the hook enforces per ref (`anyone_with_read`
        // admits any reader; `members` needs an explicit grant).
        let refs_for = state
            .core
            .refs_for_access(access.repo.id)
            .await
            .map_err(|e| GitHttpError::Internal(e.to_string()))?;
        let allowed = match refs_for.as_str() {
            "anyone_with_read" => true,
            "members" => state
                .core
                .is_repo_member(access.repo.id, auth.user.id)
                .await
                .map_err(|e| GitHttpError::Internal(e.to_string()))?,
            _ => false,
        };
        if !allowed {
            return Err(GitHttpError::Forbidden);
        }
    }
    Ok((access, Some(auth.user.clone()), write_path))
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
        list_refs(&path).await
    } else {
        None
    };
    // Pre-receive policy snapshot: the hook process never opens the database,
    // so the RPC layer passes identity, permission, and refs/for mode down as
    // env, plus the git-config entries that advertise push options and hide
    // the server-only namespaces.
    let mut env: Vec<(&str, String)> = smart::rpc_env(service);
    // The nonce keys the push-option sidecars the hook writes per accepted
    // `refs/for` line; the post-push scan consumes exactly this push's files.
    let mut scan_nonce: Option<String> = None;
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
        // The write tier admits branch/tag pushes in the hook; the read tier
        // is `refs/for`-only down there too.
        env.push((
            "STARFORGE_SCOPE_WRITE",
            if write_path {
                "1".to_owned()
            } else {
                "0".to_owned()
            },
        ));
        // The nonce keys the push-option sidecars the hook writes per accepted
        // `refs/for` line; the post-push scan consumes exactly this push's files.
        let nonce = pushsidecar::new_nonce();
        env.push(("STARFORGE_PUSH_NONCE", nonce.clone()));
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
                scan_push_changes(core, repo_id, repo, pusher, nonce, before).await;
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

/// Post-push ingest for one successful receive-pack: session trailers, accepted
/// `refs/for` tips (agit changes + revisions + trail refs), and branch-head
/// moves. The `before` snapshot was taken before the push ran; `pusher` is the
/// authenticated user and `nonce` keys this push's pre-receive sidecars.
/// Failures only warn: a push never fails because of the scan.
async fn scan_push_changes(
    core: Core,
    repo_id: i64,
    repo: PathBuf,
    pusher: Option<User>,
    nonce: Option<String>,
    before: Option<BTreeMap<String, String>>,
) {
    let Some(before) = before else { return };
    let Some(after) = list_refs(&repo).await else {
        return;
    };
    // Orphaned sidecars (a scan that never ran) must not accumulate.
    pushsidecar::reap(&repo, pushsidecar::MAX_AGE_SECS);
    let changes = changed_refs(&before, &after);
    // Deleted branches never appear in `changed_refs` (it only walks `after`
    // — see its unit test); collect them separately so base deletions still
    // recompute mergeability.
    let deletes: Vec<(&str, &str)> = before
        .iter()
        .filter(|(name, _)| name.starts_with("refs/heads/") && !after.contains_key(*name))
        .map(|(name, old)| (name.as_str(), old.as_str()))
        .collect();
    if changes.is_empty() && deletes.is_empty() {
        return;
    }
    if !changes.is_empty() {
        scan_push_trailers(&core, repo_id, &repo, &before, &changes).await;
        ingest_for_refs(
            &core,
            repo_id,
            &repo,
            pusher.as_ref(),
            nonce.as_deref(),
            &after,
            &changes,
        )
        .await;
    }
    for (name, old, new) in &changes {
        let Some(branch) = name.strip_prefix("refs/heads/") else {
            continue;
        };
        if refpolicy::is_zero_oid(new) {
            continue;
        }
        if let Err(err) = core
            .record_branch_move(repo_id, branch, old.as_deref(), new)
            .await
        {
            tracing::warn!(repo_id, branch, error = %err, "push scan: branch move ingest failed");
        }
    }
    // Report the deletions collected above: no revision is recorded for a
    // delete (the zero oid marks it as one), but base deletions recompute.
    for (name, old) in &deletes {
        let Some(branch) = name.strip_prefix("refs/heads/") else {
            continue;
        };
        if let Err(err) = core
            .record_branch_move(repo_id, branch, Some(*old), &"0".repeat(40))
            .await
        {
            tracing::warn!(repo_id, branch, error = %err, "push scan: branch delete ingest failed");
        }
    }
}

/// Ingests every new `refs/for/*` tip: change + revision + trail refs via
/// [`Core::record_agit_push`]. The consumed pseudo-ref (the hook accepted it
/// so receive-pack stored it; it is never kept) is deleted first, so every
/// row the scan's readers can observe implies the cleanup already happened.
/// The head ingested is the current tip from `after`, never a stale sidecar
/// address; the sidecar only supplies base/topic/options and is consumed
/// (deleted) either way.
async fn ingest_for_refs(
    core: &Core,
    repo_id: i64,
    repo: &StdPath,
    pusher: Option<&User>,
    nonce: Option<&str>,
    after: &BTreeMap<String, String>,
    changes: &[(String, Option<String>, String)],
) {
    let mut branches: Option<Vec<String>> = None;
    for (name, _old, new) in changes {
        if !name.starts_with("refs/for/") {
            continue;
        }
        if refpolicy::is_zero_oid(new) {
            continue;
        }
        if refpolicy::parse_for_ref(name).is_none() {
            tracing::warn!(
                repo_id,
                refname = name,
                "push scan: ignoring malformed refs/for ref"
            );
            continue;
        }
        let sidecar = load_sidecar(repo, nonce, name);
        let (user_id, sc) = match sidecar {
            Some(sidecar) => (
                sidecar.user_id,
                IngestSidecar {
                    base: sidecar.base,
                    topic: sidecar.topic,
                    trail: sidecar.trail,
                    title: sidecar.title,
                },
            ),
            None => {
                // No sidecar for this push's nonce: skip the options (never
                // borrow another push's file) and ingest optionless.
                tracing::warn!(
                    repo_id,
                    refname = name,
                    "push scan: no sidecar for this push; ingesting without options"
                );
                let Some(pusher) = pusher else {
                    tracing::warn!(
                        repo_id,
                        refname = name,
                        "push scan: no sidecar and no pusher; skipping"
                    );
                    continue;
                };
                if branches.is_none() {
                    let repo_path = repo.to_path_buf();
                    branches = tokio::task::spawn_blocking(move || {
                        read::branches(&repo_path).unwrap_or_default()
                    })
                    .await
                    .ok();
                }
                let remainder = name.strip_prefix("refs/for/").unwrap_or_default();
                let default = refpolicy::default_topic(&pusher.handle);
                match refpolicy::split_for(remainder, branches.as_deref().unwrap_or(&[]), &default)
                {
                    Ok((base, topic)) => (
                        Some(pusher.id),
                        IngestSidecar {
                            base,
                            topic,
                            trail: None,
                            title: None,
                        },
                    ),
                    Err(err) => {
                        tracing::warn!(repo_id, refname = name, error = %err, "push scan: cannot resolve refs/for target; skipping");
                        continue;
                    }
                }
            }
        };
        let Some(user_id) = user_id else {
            tracing::warn!(
                repo_id,
                refname = name,
                "push scan: sidecar has no user; skipping"
            );
            continue;
        };
        // Delete the consumed pseudo-ref BEFORE ingesting: the hook accepted
        // it so receive-pack stored it, and it is never kept. Deleting first
        // means every row the scan's readers can observe implies the cleanup
        // already happened (readers poll rows, never refs). A failed ingest
        // still warns loudly; re-pushing recreates the ref and its sidecar.
        if let Err(err) = write::delete_ref(repo, name).await {
            tracing::warn!(repo_id, refname = name, error = %err, "push scan: the refs/for pseudo-ref survived; it will be retried on the next push");
        }
        let base_tip = after
            .get(&format!("refs/heads/{}", sc.base))
            .cloned()
            .unwrap_or_else(|| new.clone());
        if let Err(err) = core
            .record_agit_push(repo_id, user_id, &sc, new, &base_tip)
            .await
        {
            tracing::warn!(repo_id, refname = name, error = %err, "push scan: refs/for ingest failed");
        }
    }
}

/// The sidecar for this push's `(nonce, refname)` pair, consumed exactly once.
/// Strictly the RPC-generated file: a missing file means the options are
/// skipped (the caller falls back to optionless addressing), never borrowed
/// from another push's sidecar for the same refname.
fn load_sidecar(
    repo: &StdPath,
    nonce: Option<&str>,
    refname: &str,
) -> Option<pushsidecar::Sidecar> {
    let nonce = nonce.filter(|nonce| pushsidecar::valid_nonce(nonce))?;
    let path = repo
        .join(pushsidecar::DIR_NAME)
        .join(pushsidecar::sidecar_name(nonce, refname));
    pushsidecar::consume_sidecar(&path).ok()
}

/// from a changed ref (not just the new tips), so multi-commit pushes and new branches
/// scan fully. Failures only warn: a push never fails because of links.
async fn scan_push_trailers(
    core: &Core,
    repo_id: i64,
    repo: &StdPath,
    before: &BTreeMap<String, String>,
    changes: &[(String, Option<String>, String)],
) {
    let shas = new_commits(repo, before, changes).await;
    if shas.is_empty() {
        return;
    }
    let repo = repo.to_path_buf();
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
