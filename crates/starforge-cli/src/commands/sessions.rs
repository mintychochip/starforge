//! `sessions` subcommands: read-only views plus explicit link management.
//!
//! `list`/`show` resolve ULID prefixes (unambiguous prefix wins; ambiguous or
//! unknown prefixes are errors listing the candidates). `link` records an
//! explicit (`cli_claim`/`exact`) link for the session plus a `Links` queue
//! entry and advances the session's link watermark; `unlink` removes matching
//! `links.jsonl` lines. `--dry-run` prints what would happen and writes
//! nothing.

use std::path::Path;

use crate::git::{common_dir, head_commit};
use crate::queue::{QueueEntry, QueueOp, enqueue};
use crate::spool::{LinkConfidence, LinkEntry, LinkSource, Spool};

/// Resolve `prefix` to a full spooled ULID: exact match wins, else the single
/// prefix match, else an error naming the candidates (or "unknown session").
pub fn resolve_prefix(spool: &Spool, prefix: &str) -> Result<String, String> {
    let mut ulids = Vec::new();
    match std::fs::read_dir(spool.root.join("sessions")) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if entry.path().is_dir()
                    && let Some(name) = entry.file_name().to_str()
                {
                    ulids.push(name.to_string());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("cannot list sessions: {err}")),
    }
    ulids.sort();
    if ulids.iter().any(|u| u == prefix) {
        return Ok(prefix.to_string());
    }
    let hits: Vec<&str> = ulids
        .iter()
        .map(String::as_str)
        .filter(|u| u.starts_with(prefix))
        .collect();
    match hits.as_slice() {
        [] => Err(format!("unknown session `{prefix}`")),
        [one] => Ok((*one).to_string()),
        many => Err(format!(
            "ambiguous session prefix `{prefix}`: {}",
            many.join(", ")
        )),
    }
}

/// One table row for `list`.
struct SessionRow {
    ulid: String,
    agent: String,
    title: String,
    events: u64,
    segments: u64,
    uploaded: u64,
}

fn agent_name(name: &starforge_format::AgentName) -> &'static str {
    match name {
        starforge_format::AgentName::ClaudeCode => "claude-code",
        starforge_format::AgentName::Codex => "codex",
        starforge_format::AgentName::Pi => "pi",
        starforge_format::AgentName::Opencode => "opencode",
        starforge_format::AgentName::Gemini => "gemini",
    }
}

fn row_for(spool: &Spool, ulid: &str) -> Option<SessionRow> {
    let meta = spool.read_meta(ulid).ok()?;
    let mut events = 0u64;
    let mut segments = 0u64;
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".jsonl.zst") {
                continue;
            }
            segments += 1;
            let bytes = std::fs::read(entry.path()).ok()?;
            let text = starforge_format::decompress(&bytes).ok()?;
            let text = String::from_utf8(text).ok()?;
            events += text.lines().filter(|l| !l.trim().is_empty()).count() as u64;
        }
    }
    let uploaded = spool
        .read_upload(ulid)
        .map(|s| s.uploaded_segments.len() as u64)
        .unwrap_or(0);
    let title: String = meta
        .title
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Some(SessionRow {
        ulid: ulid.to_string(),
        agent: agent_name(&meta.agent.name).to_string(),
        title: title.chars().take(40).collect(),
        events,
        segments,
        uploaded,
    })
}

/// List spooled sessions as a table (`ULID agent title events segments
/// uploaded`), one row per line with a header. Empty spool prints
/// `(no sessions)`.
pub fn list(repo: &Path, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    if dry_run {
        return (
            format!("would list sessions in {}", spool.root.display()),
            0,
        );
    }
    let mut ulids = Vec::new();
    match std::fs::read_dir(spool.root.join("sessions")) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if entry.path().is_dir()
                    && let Some(name) = entry.file_name().to_str()
                {
                    ulids.push(name.to_string());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return (format!("error: cannot read sessions: {err}"), 1),
    }
    ulids.sort();
    if ulids.is_empty() {
        return ("(no sessions)".to_string(), 0);
    }
    let mut out = String::from("ULID AGENT TITLE EVENTS SEGMENTS UPLOADED");
    for ulid in &ulids {
        match row_for(&spool, ulid) {
            Some(row) => out.push_str(&format!(
                "\n{} {} {} {} {} {}",
                row.ulid, row.agent, row.title, row.events, row.segments, row.uploaded
            )),
            None => out.push_str(&format!("\n{ulid} ? ? 0 0 0")),
        }
    }
    (out, 0)
}

/// Print a session's `meta.json` (pretty) plus its `links.jsonl` entries.
pub fn show(repo: &Path, ulid_prefix: &str, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    if dry_run {
        return (
            format!(
                "would show session {ulid_prefix} in {}",
                spool.root.display()
            ),
            0,
        );
    }
    let ulid = match resolve_prefix(&spool, ulid_prefix) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let meta = match spool.read_meta(&ulid) {
        Ok(meta) => meta,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let links: Vec<LinkEntry> = spool
        .links()
        .map(|all| all.into_iter().filter(|l| l.ulid == ulid).collect())
        .unwrap_or_default();
    let mut out = serde_json::to_string_pretty(&meta).expect("SessionMeta serializes");
    out.push_str(&format!(
        "\nlinks: {}",
        serde_json::to_string(&links).expect("links serialize")
    ));
    (out, 0)
}

/// Event `seq` range covered by `ulid`'s segments: `(min, max + 1)`, or
/// `(0, 0)` when the session has no parseable events.
fn session_seq_range(spool: &Spool, ulid: &str) -> (u64, u64) {
    let mut min: Option<u64> = None;
    let mut max: Option<u64> = None;
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return (0, 0),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".jsonl.zst") {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let Ok(raw) = starforge_format::decompress(&bytes) else {
            continue;
        };
        let Ok(text) = String::from_utf8(raw) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(event) = starforge_format::parse_event(line) else {
                continue;
            };
            min = Some(min.map_or(event.seq, |m: u64| m.min(event.seq)));
            max = Some(max.map_or(event.seq, |m: u64| m.max(event.seq)));
        }
    }
    match (min, max) {
        (Some(lo), Some(hi)) => (lo, hi + 1),
        _ => (0, 0),
    }
}

/// Record an explicit link (`cli_claim`/`exact`) for the session, enqueue a
/// `Links` upload, and advance the session's link watermark so heuristic
/// linking does not immediately re-link the same events.
pub fn link(repo: &Path, ulid_prefix: &str, commit: Option<&str>, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    let owned;
    // Resolve the prefix before the dry-run return so a typo'd ULID fails
    // the same way in both modes (still writing nothing here).
    let ulid = match resolve_prefix(&spool, ulid_prefix) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let commit: String = match commit {
        Some(c) => c.to_string(),
        None => {
            owned = match head_commit(repo) {
                Ok(sha) => sha,
                Err(err) => return (format!("error: {err}"), 1),
            };
            owned.trim().to_string()
        }
    };
    if dry_run {
        return (
            format!("would link session {ulid_prefix} to commit {commit}"),
            0,
        );
    }
    let (seq_start, seq_end) = session_seq_range(&spool, &ulid);
    if let Err(err) = spool.record_link(&LinkEntry {
        ulid: ulid.clone(),
        commit: commit.clone(),
        source: LinkSource::CliClaim,
        confidence: LinkConfidence::Exact,
        seq_start,
        seq_end,
    }) {
        return (format!("error: cannot record link: {err}"), 1);
    }
    if let Err(err) = enqueue(
        &spool,
        QueueEntry {
            op: QueueOp::Links,
            ulid: ulid.clone(),
            repo: String::new(),
            segment: None,
            attempts: 0,
            not_before: "1970-01-01T00:00:00Z".to_string(),
        },
    ) {
        return (format!("error: cannot enqueue links upload: {err}"), 1);
    }
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    if let Err(err) = spool.write_link_watermark(
        &ulid,
        &crate::spool::LinkWatermark {
            last_linked_seq: seq_end,
            last_linked_at: now,
        },
    ) {
        return (format!("error: cannot write link watermark: {err}"), 1);
    }
    tracing::debug!("sessions link: {ulid} -> {commit} (seq {seq_start}..{seq_end})");
    (format!("linked {ulid} to {commit}"), 0)
}

/// Remove `links.jsonl` lines matching (`ulid`, `commit`), rewriting the file
/// atomically. Errors when nothing matched.
pub fn unlink(repo: &Path, ulid_prefix: &str, commit: &str, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    // Resolve the prefix before the dry-run return so a typo'd ULID fails
    // the same way in both modes (still writing nothing here).
    let ulid = match resolve_prefix(&spool, ulid_prefix) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if dry_run {
        return (
            format!("would unlink session {ulid_prefix} from commit {commit}"),
            0,
        );
    }
    let all = match spool.links() {
        Ok(all) => all,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let kept: Vec<&LinkEntry> = all
        .iter()
        .filter(|l| !(l.ulid == ulid && l.commit == commit))
        .collect();
    if kept.len() == all.len() {
        return (format!("error: no link from {ulid} to {commit}"), 1);
    }
    let removed = all.len() - kept.len();
    let mut text = String::new();
    for link in kept {
        text.push_str(&serde_json::to_string(link).expect("LinkEntry serializes"));
        text.push('\n');
    }
    if let Err(err) = crate::spool::atomic_write(&spool.root.join("links.jsonl"), text.as_bytes()) {
        return (format!("error: cannot rewrite links: {err}"), 1);
    }
    tracing::debug!("sessions unlink: removed {removed} link(s) for {ulid}");
    (format!("unlinked {ulid} from {commit}"), 0)
}
