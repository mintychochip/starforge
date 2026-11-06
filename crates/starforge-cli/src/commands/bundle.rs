//! `export`/`import`: portable session bundles (D2).
//!
//! Bundle layout under `<dir>`:
//!
//! ```text
//! bundle.json                              format version 1, server, exported_at
//! <owner>__<repo>/<ulid>/session.json      the API metadata, as returned
//! <owner>__<repo>/<ulid>/events.jsonl      the normalized transcript (via /events)
//! <owner>__<repo>/<ulid>/segments/<n>.raw.zst   only when the API serves raw
//! <owner>__<repo>/<ulid>/links.json        commit links (via /links)
//! ```
//!
//! `export` writes exactly what the API returns to the caller: when the
//! caller cannot read a session the API answers `404` and the CLI reports
//! `cannot export <ulid>: session not found or not readable` (it never
//! fabricates bundle content). `import` re-uploads each session through the
//! normal upload API (meta, re-segmented events, complete), preserving the
//! ULID, and re-creates `cli_claim` links from `links.json`; a ULID already
//! present in the target repository is reported `exists` and skipped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use starforge_format::{
    Agent, AgentName, CaptureInfo, CaptureMode, DEFAULT_SEGMENT_CAP, FORMAT_TAG, RedactionSummary,
    RepoInfo, SessionMeta, Usage,
};
use ulid::Ulid;

use crate::api::{ApiClient, ApiError};
use crate::config::CliPaths;
use crate::upload::UploadClient;

/// Injected context for bundle commands: the read client, the upload
/// client (same server + token), the server origin, and the effective
/// `owner/repo`. [`Debug`] is redacted by hand: the token must never reach
/// logs.
pub struct BundleCtx {
    pub api: ApiClient,
    pub upload: UploadClient,
    pub api_url: String,
    pub owner_repo: String,
}

impl std::fmt::Debug for BundleCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleCtx")
            .field("api", &self.api)
            .field("upload", &"<redacted>")
            .field("api_url", &self.api_url)
            .field("owner_repo", &self.owner_repo)
            .finish()
    }
}

impl BundleCtx {
    /// Resolve server + token for `repo_dir` (see
    /// [`crate::commands::session_admin::resolve_parts`]); `repo_override`
    /// (`--repo`) replaces the discovered `owner/repo`.
    pub async fn resolve(
        repo_dir: &Path,
        paths: &CliPaths,
        repo_override: Option<&str>,
    ) -> Result<BundleCtx, String> {
        let (api_url, owner_repo, token) =
            crate::commands::session_admin::resolve_parts(repo_dir, paths, repo_override).await?;
        let api = ApiClient::new(&api_url, &owner_repo, &token).map_err(|err| err.to_string())?;
        Ok(BundleCtx::new(api, &api_url, &owner_repo, &token))
    }

    /// Build a context with everything injected (no env, no I/O); tests use
    /// this. `token` feeds both clients.
    pub fn new(api: ApiClient, api_url: &str, owner_repo: &str, token: &str) -> BundleCtx {
        BundleCtx {
            upload: UploadClient::new(api_url.to_string(), token.to_string()),
            api,
            api_url: api_url.to_string(),
            owner_repo: owner_repo.to_string(),
        }
    }
}

/// Segment-probe bound: a session past this many segments is truncated and
/// reported, never probed forever.
const MAX_SEGMENTS_PROBED: i64 = 10_000;

/// `export`: write every readable session of the repository (or only the
/// `--session` ULIDs) under `dir/<owner>__<repo>/`, then `bundle.json`.
/// Output is one `exported <ulid>` line per session plus a summary; any
/// unreadable session aborts with a clear error.
pub async fn export(ctx: &BundleCtx, sessions: &[String], dir: &Path) -> (String, u8) {
    let ulids = if sessions.is_empty() {
        match list_session_ulids(&ctx.api).await {
            Ok(ulids) => ulids,
            Err(err) => return (err, 1),
        }
    } else {
        sessions.to_vec()
    };
    let (owner, repo) = ctx
        .owner_repo
        .split_once('/')
        .expect("owner_repo validated at resolve time");
    let root = dir.join(format!("{owner}__{repo}"));
    let mut lines = Vec::new();
    for ulid in &ulids {
        match export_one(ctx, ulid, &root).await {
            Ok(()) => lines.push(format!("exported {ulid}")),
            Err(err) => return (err, 1),
        }
    }
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let bundle = serde_json::json!({
        "format_version": 1,
        "server": ctx.api_url,
        "exported_at": now,
    });
    if let Err(err) = write_file(
        &dir.join("bundle.json"),
        &serde_json::to_string_pretty(&bundle).unwrap_or_default(),
    ) {
        return (err, 1);
    }
    lines.push(format!(
        "exported {} session(s) to {}",
        ulids.len(),
        dir.display()
    ));
    (lines.join("\n"), 0)
}

/// The readable sessions of the repository, oldest first, via the listing
/// endpoint. Errors are pre-formatted `error: …` strings.
async fn list_session_ulids(api: &ApiClient) -> Result<Vec<String>, String> {
    let value = api
        .get("sessions", &[])
        .await
        .map_err(|err| api.render_error(err).0)?;
    let sessions = value
        .get("sessions")
        .and_then(Value::as_array)
        .ok_or_else(|| "error: unexpected response: missing sessions array".to_string())?;
    Ok(sessions
        .iter()
        .filter_map(|session| {
            session
                .get("ulid")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect())
}

/// Export one session under `root/<ulid>/`. A `404` anywhere in the read
/// path means the caller cannot read the session.
async fn export_one(ctx: &BundleCtx, ulid: &str, root: &Path) -> Result<(), String> {
    let meta = ctx
        .api
        .get(&format!("sessions/{ulid}"), &[])
        .await
        .map_err(|err| readable_error(&ctx.api, err, ulid))?;
    let events = fetch_events(&ctx.api, ulid)
        .await
        .map_err(|err| readable_error(&ctx.api, err, ulid))?;
    let links = ctx
        .api
        .get(&format!("sessions/{ulid}/links"), &[])
        .await
        .map_err(|err| readable_error(&ctx.api, err, ulid))?;
    let session_dir = root.join(ulid);
    let mut events_text = String::new();
    for event in &events {
        events_text.push_str(
            &serde_json::to_string(event)
                .map_err(|err| format!("error: cannot encode event of session {ulid}: {err}"))?,
        );
        events_text.push('\n');
    }
    let mut segments = Vec::new();
    for n in 0..MAX_SEGMENTS_PROBED {
        match ctx
            .api
            .get_bytes(&format!("sessions/{ulid}/segments/{n}"), &[])
            .await
        {
            Ok(bytes) => {
                segments.push((n, bytes));
            }
            Err(ApiError::Status { status: 404, .. }) => break,
            Err(err) => return Err(readable_error(&ctx.api, err, ulid)),
        }
    }
    std::fs::create_dir_all(&session_dir)
        .map_err(|err| format!("error: cannot create {}: {err}", session_dir.display()))?;
    write_file(
        &session_dir.join("session.json"),
        &serde_json::to_string_pretty(&meta)
            .map_err(|err| format!("error: cannot encode session {ulid}: {err}"))?,
    )?;
    write_file(&session_dir.join("events.jsonl"), &events_text)?;
    let links = links
        .get("links")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    write_file(
        &session_dir.join("links.json"),
        &serde_json::to_string_pretty(&links)
            .map_err(|err| format!("error: cannot encode links of session {ulid}: {err}"))?,
    )?;
    if !segments.is_empty() {
        let dir = session_dir.join("segments");
        std::fs::create_dir_all(&dir)
            .map_err(|err| format!("error: cannot create {}: {err}", dir.display()))?;
        for (n, bytes) in &segments {
            write_bytes(&dir.join(format!("{n}.raw.zst")), bytes)?;
        }
    }
    Ok(())
}

/// Every event of the session, page by page. `unreadable_segment`
/// placeholders are skipped: they are no content, and writing them would
/// corrupt the import.
async fn fetch_events(api: &ApiClient, ulid: &str) -> Result<Vec<Value>, ApiError> {
    let mut events = Vec::new();
    let mut page: i64 = 1;
    loop {
        let value = api
            .get(
                &format!("sessions/{ulid}/events"),
                &[("page", page.to_string())],
            )
            .await?;
        let pages = value.get("pages").and_then(Value::as_i64).unwrap_or(1);
        let items = value
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for event in items {
            let unreadable = event
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "unreadable_segment");
            if !unreadable {
                events.push(event);
            }
        }
        if page >= pages {
            break;
        }
        page += 1;
    }
    Ok(events)
}

/// Render a read failure for `ulid`: `404` becomes the clear
/// not-found-or-not-readable error; everything else is the standard API
/// rendering.
fn readable_error(api: &ApiClient, err: ApiError, ulid: &str) -> String {
    match err {
        ApiError::Status { status: 404, .. } => {
            format!("error: cannot export session {ulid}: session not found or not readable")
        }
        other => api.render_error(other).0,
    }
}

/// `import`: upload every session in the bundle at `dir` into
/// `ctx.owner_repo`, preserving ULIDs. Existing ULIDs are reported
/// `exists, skipped`; the first hard failure aborts with its error.
pub async fn import(ctx: &BundleCtx, dir: &Path) -> (String, u8) {
    let session_dirs = match discover_session_dirs(dir) {
        Ok(dirs) => dirs,
        Err(err) => return (err, 1),
    };
    let mut lines = Vec::new();
    let mut imported = 0usize;
    let mut exists = 0usize;
    for session_dir in &session_dirs {
        match import_one(ctx, session_dir).await {
            Ok(Outcome::Imported(ulid)) => {
                lines.push(format!("{ulid}: imported"));
                imported += 1;
            }
            Ok(Outcome::Exists(ulid)) => {
                lines.push(format!("{ulid}: exists, skipped"));
                exists += 1;
            }
            Err(err) => return (err, 1),
        }
    }
    lines.push(format!(
        "imported {imported} session(s), {exists} already present"
    ));
    (lines.join("\n"), 0)
}

enum Outcome {
    Imported(String),
    Exists(String),
}

/// Session directories of the bundle at `dir`, sorted by ULID. Validates
/// `bundle.json` (presence + format version) and that each directory holds
/// a `session.json` whose `ulid` field matches the directory name.
pub fn discover_session_dirs(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let bundle_path = dir.join("bundle.json");
    let bundle_text = std::fs::read_to_string(&bundle_path).map_err(|_| {
        format!(
            "error: {} is not a starforge export bundle (missing bundle.json)",
            dir.display()
        )
    })?;
    let bundle: Value = serde_json::from_str(&bundle_text)
        .map_err(|err| format!("error: invalid bundle.json in {}: {err}", dir.display()))?;
    let version = bundle.get("format_version").and_then(Value::as_i64);
    if version != Some(1) {
        return Err(format!(
            "error: unsupported bundle format version {} (want 1)",
            version.map_or_else(|| "missing".to_string(), |v| v.to_string())
        ));
    }
    let mut dirs = Vec::new();
    let repo_dirs = std::fs::read_dir(dir)
        .map_err(|err| format!("error: cannot read {}: {err}", dir.display()))?;
    for repo_dir in repo_dirs {
        let repo_dir = repo_dir
            .map_err(|err| format!("error: cannot read {}: {err}", dir.display()))?
            .path();
        if !repo_dir.is_dir() {
            continue;
        }
        let sessions = std::fs::read_dir(&repo_dir)
            .map_err(|err| format!("error: cannot read {}: {err}", repo_dir.display()))?;
        for session in sessions {
            let session_dir = session
                .map_err(|err| format!("error: cannot read {}: {err}", repo_dir.display()))?
                .path();
            if !session_dir.is_dir() || !session_dir.join("session.json").is_file() {
                continue;
            }
            let ulid = session_dir
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let meta_text = std::fs::read_to_string(session_dir.join("session.json"))
                .map_err(|err| format!("error: cannot read {}: {err}", session_dir.display()))?;
            let meta: Value = serde_json::from_str(&meta_text).map_err(|err| {
                format!(
                    "error: invalid session.json in {}: {err}",
                    session_dir.display()
                )
            })?;
            let recorded = meta.get("ulid").and_then(Value::as_str).unwrap_or("");
            if recorded != ulid {
                return Err(format!(
                    "error: session.json ulid '{recorded}' does not match directory '{ulid}'"
                ));
            }
            dirs.push(session_dir);
        }
    }
    dirs.sort_by_key(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    if dirs.is_empty() {
        return Err(format!("error: no sessions found in {}", dir.display()));
    }
    Ok(dirs)
}

/// Import one session directory: skip when the ULID already exists in the
/// target repository, else upload meta + re-segmented events + complete +
/// links.
async fn import_one(ctx: &BundleCtx, session_dir: &Path) -> Result<Outcome, String> {
    let ulid = session_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    match ctx.api.get(&format!("sessions/{ulid}"), &[]).await {
        Ok(_) => return Ok(Outcome::Exists(ulid)),
        Err(ApiError::Status { status: 404, .. }) => {}
        Err(err) => return Err(ctx.api.render_error(err).0),
    }
    let meta_text = std::fs::read_to_string(session_dir.join("session.json"))
        .map_err(|err| format!("error: cannot read {}: {err}", session_dir.display()))?;
    let meta: Value = serde_json::from_str(&meta_text).map_err(|err| {
        format!(
            "error: invalid session.json in {}: {err}",
            session_dir.display()
        )
    })?;
    let events_text = read_text(&session_dir.join("events.jsonl"))?;
    let links_text = read_text(&session_dir.join("links.json"))?;
    let links: Value = serde_json::from_str(&links_text).map_err(|err| {
        format!(
            "error: invalid links.json in {}: {err}",
            session_dir.display()
        )
    })?;
    let links = links.as_array().cloned().unwrap_or_default();
    let session_meta = build_meta(&ulid, &meta, &events_text)?;
    ctx.upload
        .put_meta(&ctx.owner_repo, &session_meta)
        .await
        .map_err(|err| format!("error: importing {ulid}: {err}"))?;
    for (n, bytes) in starforge_format::split_jsonl(&events_text, DEFAULT_SEGMENT_CAP)
        .into_iter()
        .enumerate()
    {
        ctx.upload
            .put_segment(&ctx.owner_repo, &ulid, n as u64, &bytes)
            .await
            .map_err(|err| format!("error: importing {ulid}: {err}"))?;
    }
    ctx.upload
        .post_complete(&ctx.owner_repo, &ulid)
        .await
        .map_err(|err| format!("error: importing {ulid}: {err}"))?;
    if !links.is_empty() {
        ctx.upload
            .post_links(&ctx.owner_repo, &ulid, &links)
            .await
            .map_err(|err| format!("error: importing {ulid}: {err}"))?;
    }
    Ok(Outcome::Imported(ulid))
}

/// Rebuild the upload [`SessionMeta`] from exported API metadata plus the
/// exported events (files touched derive from tool calls and file changes,
/// in first-seen order, exactly as the spool records them).
fn build_meta(ulid: &str, meta: &Value, events_text: &str) -> Result<SessionMeta, String> {
    let id = Ulid::from_string(ulid)
        .map_err(|err| format!("error: invalid session ULID '{ulid}': {err}"))?;
    let agent_name = meta
        .get("agent")
        .and_then(|agent| agent.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let agent = Agent {
        name: parse_agent_name(agent_name)?,
        version: meta
            .get("agent")
            .and_then(|agent| agent.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    };
    let usage = meta.get("usage");
    let usage_u64 = |key: &str| {
        usage
            .and_then(|u| u.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let redaction = meta.get("redaction");
    let mut counts = BTreeMap::new();
    if let Some(object) = redaction
        .and_then(|r| r.get("counts"))
        .and_then(Value::as_object)
    {
        for (key, value) in object {
            counts.insert(key.clone(), value.as_u64().unwrap_or(0));
        }
    }
    let mode = meta
        .get("capture")
        .and_then(|capture| capture.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let capture = CaptureInfo {
        mode: match mode {
            "hook" => CaptureMode::Hook,
            "discovery" => CaptureMode::Discovery,
            other => {
                return Err(format!(
                    "error: unknown capture mode '{other}' in bundle for session {ulid}"
                ));
            }
        },
        cli_version: meta
            .get("capture")
            .and_then(|capture| capture.get("cli_version"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        adapter_version_verified: meta
            .get("adapter_version_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    Ok(SessionMeta {
        format: FORMAT_TAG.to_string(),
        id,
        agent,
        models: meta
            .get("models")
            .and_then(Value::as_array)
            .map(|models| {
                models
                    .iter()
                    .filter_map(|model| model.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        title: meta
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_string),
        started_at: meta
            .get("started_at")
            .and_then(timestamp_string)
            .ok_or_else(|| format!("error: session {ulid}: missing started_at"))?,
        ended_at: meta.get("ended_at").and_then(timestamp_string),
        repo: RepoInfo {
            remote_urls: Vec::new(),
            branch: meta
                .get("branch")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            head_at_start: meta
                .get("head")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        },
        parent_id: None,
        usage: Usage {
            input: usage_u64("input"),
            output: usage_u64("output"),
            cache_read: usage_u64("cache_read"),
            cache_write: usage_u64("cache_write"),
            reasoning: usage_u64("reasoning"),
        },
        files_touched: files_touched_from_events(events_text),
        redaction: RedactionSummary {
            fingerprint: redaction
                .and_then(|r| r.get("fingerprint"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            counts,
        },
        capture,
    })
}

fn parse_agent_name(name: &str) -> Result<AgentName, String> {
    match name {
        "claude-code" => Ok(AgentName::ClaudeCode),
        "codex" => Ok(AgentName::Codex),
        "pi" => Ok(AgentName::Pi),
        "opencode" => Ok(AgentName::Opencode),
        "gemini" => Ok(AgentName::Gemini),
        other => Err(format!("error: unknown agent '{other}' in bundle")),
    }
}

/// A unix-seconds number (or an already-RFC3339 string) as an RFC3339
/// string; anything else is `None`.
fn timestamp_string(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => time::OffsetDateTime::from_unix_timestamp(number.as_i64()?)
            .ok()?
            .format(&time::format_description::well_known::Rfc3339)
            .ok(),
        Value::String(text) => Some(text.clone()),
        _ => None,
    }
}

/// Distinct file paths from the events, in first-seen order: tool-call
/// `tool.input.file_path` and file-change `path`.
fn files_touched_from_events(events_text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in events_text.lines() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let path = match event.get("kind").and_then(Value::as_str) {
            Some("tool_call") => event
                .get("tool")
                .and_then(|tool| tool.get("input"))
                .and_then(|input| input.get("file_path"))
                .and_then(Value::as_str),
            Some("file_change") => event.get("path").and_then(Value::as_str),
            _ => None,
        };
        if let Some(path) = path
            && seen.insert(path.to_string())
        {
            out.push(path.to_string());
        }
    }
    out
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|err| format!("error: cannot read {}: {err}", path.display()))
}

fn write_file(path: &Path, text: &str) -> Result<(), String> {
    write_bytes(path, text.as_bytes())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes)
        .map_err(|err| format!("error: cannot write {}: {err}", path.display()))
}
