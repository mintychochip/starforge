//! `starforge hook session-end`: Claude Code `SessionEnd` entry point.
//!
//! Claude Code pipes `{"session_id", "transcript_path", "cwd",
//! "hook_event_name": "SessionEnd", "reason"}` on stdin. This handler reads
//! it leniently (missing/invalid input is fine), ingests the repo the `cwd`
//! belongs to (the same ingest `post-commit` runs), marks the spooled
//! session whose native key is `session_id` as ended so a `complete` op is
//! queued exactly as the 24 h idle rule does, then attempts one bounded
//! upload pass. It ALWAYS exits `0`: a hook must never break the agent.
//! Every error becomes a one-line stderr message with no effect on the
//! exit code.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use time::format_description::well_known::Rfc3339;

/// Cap on the stdin payload read from Claude Code (1 MiB).
const STDIN_CAP: usize = 1024 * 1024;

/// Claude Code SessionEnd payload (lenient: every field optional).
#[derive(Debug, Default, serde::Deserialize)]
struct SessionEndPayload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    transcript_path: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
}

/// The repo top level enclosing `dir`, or `None` when it is not in a repo.
fn repo_toplevel(dir: &Path) -> Option<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(PathBuf::from(text))
}

/// Read the stdin payload: only when stdin is not a terminal, capped at
/// [`STDIN_CAP`] bytes; missing or invalid input yields an empty payload.
fn read_payload() -> SessionEndPayload {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return SessionEndPayload::default();
    }
    let mut buf = Vec::with_capacity(4096);
    let _ = std::io::stdin()
        .take(STDIN_CAP as u64)
        .read_to_end(&mut buf);
    if buf.is_empty() {
        return SessionEndPayload::default();
    }
    serde_json::from_slice(&buf).unwrap_or_default()
}

/// The greatest event `ts` across the session's segment blobs, if any.
fn last_event_ts(spool: &crate::spool::Spool, ulid: &str) -> Option<String> {
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    let mut best: Option<String> = None;
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        let path = entry.path();
        if !path.extension().is_some_and(|e| e == "zst") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(raw) = starforge_format::decompress(&bytes) else {
            continue;
        };
        let Ok(text) = String::from_utf8(raw) else {
            continue;
        };
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if let Some(ts) = event.get("ts").and_then(|v| v.as_str())
                && best.as_ref().is_none_or(|m| ts > m.as_str())
            {
                best = Some(ts.to_string());
            }
        }
    }
    best
}

/// Mark the session whose native key is `session_id` as ended and queue a
/// `complete` op the way the 24 h idle rule does (only when not already
/// complete / queued). Best-effort: warnings, never an error to the caller
/// beyond a one-line message.
fn mark_ended(spool: &crate::spool::Spool, session_id: &str, now_rfc3339: &str) {
    let records = match spool.cursor_records() {
        Ok(records) => records,
        Err(err) => {
            eprintln!("warning: starforge session-end: cannot read cursors: {err}");
            return;
        }
    };
    let ulid = records
        .iter()
        .filter_map(|(key, rec)| {
            let stem = key.rsplit('/').next().unwrap_or(key);
            (stem == session_id).then_some(rec.ulid.clone())
        })
        .next();
    let Some(ulid) = ulid else {
        return;
    };
    let mut meta = match spool.read_meta(&ulid) {
        Ok(meta) => meta,
        Err(err) => {
            eprintln!("warning: starforge session-end: cannot read session: {err}");
            return;
        }
    };
    if meta.ended_at.is_none() {
        meta.ended_at =
            Some(last_event_ts(spool, &ulid).unwrap_or_else(|| now_rfc3339.to_string()));
        if let Err(err) = spool.put_session(&meta) {
            eprintln!("warning: starforge session-end: cannot end session: {err}");
            return;
        }
    }
    let complete = spool
        .read_upload(&ulid)
        .map(|state| state.complete)
        .unwrap_or(false);
    if complete {
        return;
    }
    let queued = crate::queue::read_queue(spool).unwrap_or_default();
    if queued
        .iter()
        .any(|e| e.op == crate::queue::QueueOp::Complete && e.ulid == ulid)
    {
        return;
    }
    if let Err(err) = crate::queue::enqueue(
        spool,
        crate::queue::QueueEntry {
            op: crate::queue::QueueOp::Complete,
            ulid,
            repo: String::new(),
            segment: None,
            attempts: 0,
            not_before: now_rfc3339.to_string(),
        },
    ) {
        eprintln!("warning: starforge session-end: cannot queue complete: {err}");
    }
}

/// One best-effort upload pass over the queue (the `pre-push`/`sync` path,
/// bounded by 10 s inside [`sync_best_effort`]). Failures only warn.
async fn best_effort_upload(repo: &Path, paths: &crate::config::CliPaths) {
    let common = match crate::git::common_dir(repo) {
        Ok(common) => common,
        Err(err) => {
            eprintln!("warning: starforge session-end: {err}");
            return;
        }
    };
    let spool = crate::spool::Spool::open(&common);
    let (server, owner_repo, _chosen) =
        match crate::commands::status::resolve_server(repo, paths).await {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("warning: starforge session-end: {err}");
                return;
            }
        };
    let Some(host) = crate::cli::sync_host_key(&server.api_url) else {
        eprintln!("warning: starforge session-end: cannot parse server api_url");
        return;
    };
    let token = match crate::auth::resolve_token(paths, &host, |key| std::env::var(key).ok()) {
        Ok(resolved) => resolved.token().to_string(),
        Err(err) => {
            eprintln!("warning: starforge session-end: {err}");
            return;
        }
    };
    let now = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let sleeper = crate::queue::TokioSleeper;
    crate::commands::sync::sync_best_effort(&spool, &server, &owner_repo, &token, &sleeper, &now)
        .await;
}

/// `starforge hook session-end`: ingest, mark the session ended, attempt one
/// upload pass. Always `0`.
pub async fn hook_session_end(paths: &crate::config::CliPaths) -> u8 {
    if let Err(err) = session_end_inner(paths).await {
        eprintln!("warning: starforge session-end: {err}");
    }
    0
}

async fn session_end_inner(paths: &crate::config::CliPaths) -> Result<(), String> {
    let payload = read_payload();
    let start = payload
        .cwd
        .as_deref()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let Some(repo) = repo_toplevel(&start) else {
        return Ok(());
    };
    let common = crate::git::common_dir(&repo).map_err(|err| err.to_string())?;
    let spool = crate::spool::Spool::open(&common);
    if !spool.root.is_dir() {
        return Ok(());
    }
    // The same ingest the post-commit hook runs for this repo.
    crate::commands::hooks::hook_post_commit(&repo, paths);
    let session_id = payload.session_id.clone().or_else(|| {
        payload.transcript_path.as_deref().and_then(|p| {
            Path::new(p)
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
        })
    });
    if let Some(id) = session_id.as_deref() {
        let now = time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("cannot format time: {err}"))?;
        mark_ended(&spool, id, &now);
    }
    best_effort_upload(&repo, paths).await;
    Ok(())
}
