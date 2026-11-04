//! `enable`/`disable` + hidden `_hook-*` handlers (C5).
//!
//! `enable` installs the three POSIX `sh` dispatchers (see [`crate::hooks`])
//! and prints every file it changes, one path per line. `disable` removes
//! only marker-bearing dispatchers and restores `.starforge-orig` backups.
//!
//! The `prepare-commit-msg` handler appends one `Starforge-Session: <ULID>`
//! trailer per linked session (never rewriting existing trailers) and
//! records the pending selection for `post-commit`, which turns it into
//! `links.jsonl` entries. `pre-push` enqueues uploads for sessions with
//! unwritten segments (actual upload is C6). Hook handlers never fail the
//! git operation: every error becomes a `warning:` on stderr with exit `0`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::git::{common_dir, head_commit, remotes, staged_files};
use crate::hooks::{
    HOOKS, PendingLink, SessionCandidate, append_trailers, existing_trailer_ulids, install_hook,
    remove_hook, select_links,
};
use crate::queue::{QueueEntry, QueueOp, enqueue, read_queue};
use crate::spool::{LinkConfidence, LinkEntry, LinkSource, Spool};
use time::format_description::well_known::Rfc3339;

/// Sidecar the prepare handler leaves for post-commit:
/// `<spool>/pending-trailer.json`.
fn pending_path(spool: &Spool) -> PathBuf {
    spool.root.join("pending-trailer.json")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingRecord {
    ulid: String,
    confidence: LinkConfidence,
    seq_start: u64,
    seq_end: u64,
}

/// Install all three dispatchers (+ spool layout). Returns the human-readable
/// output (one changed path per line) and the exit code.
pub fn enable(repo: &Path, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if dry_run {
        let mut lines = Vec::new();
        for hook in HOOKS {
            lines.push(format!(
                "would install {}",
                common.join("hooks").join(hook).display()
            ));
        }
        return (lines.join("\n"), 0);
    }
    let spool = Spool::open(&common);
    let mut created = Vec::new();
    for name in ["cursors.json", "links.jsonl", "queue.jsonl"] {
        if !spool.root.join(name).exists() {
            created.push(spool.root.join(name));
        }
    }
    if let Err(err) = spool.ensure_layout() {
        return (format!("error: cannot set up spool: {err}"), 1);
    }
    let mut changed: Vec<String> = created.iter().map(|p| p.display().to_string()).collect();
    for hook in HOOKS {
        let backup = common.join("hooks").join(format!("{hook}.starforge-orig"));
        let had_backup = backup.exists();
        match install_hook(&common, hook) {
            Ok(path) => {
                changed.push(path.display().to_string());
                if !had_backup && backup.exists() {
                    changed.push(backup.display().to_string());
                }
            }
            Err(err) => return (format!("error: cannot install {hook}: {err}"), 1),
        }
    }
    (changed.join("\n"), 0)
}

/// Remove installed dispatchers and restore originals. Returns the
/// human-readable output (one changed path per line; empty when nothing
/// changed) and the exit code (always `0` once the repo resolves).
pub fn disable(repo: &Path, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if dry_run {
        let mut lines = Vec::new();
        for hook in HOOKS {
            lines.push(format!(
                "would remove {}",
                common.join("hooks").join(hook).display()
            ));
        }
        return (lines.join("\n"), 0);
    }
    let mut changed = Vec::new();
    for hook in HOOKS {
        match remove_hook(&common, hook) {
            Ok(paths) => changed.extend(paths.into_iter().map(|p| p.display().to_string())),
            Err(err) => return (format!("error: cannot remove {hook}: {err}"), 1),
        }
    }
    (changed.join("\n"), 0)
}

/// Hidden `_hook-prepare-commit-msg`: append session trailers. Always `0`.
pub fn hook_prepare(repo: &Path, msg_file: &Path) -> u8 {
    if let Err(err) = prepare_inner(repo, msg_file) {
        eprintln!("warning: starforge prepare-commit-msg skipped: {err}");
    }
    0
}

/// Hidden `_hook-post-commit`: record the pending trailers as links. Always `0`.
pub fn hook_post_commit(repo: &Path) -> u8 {
    if let Err(err) = post_commit_inner(repo) {
        eprintln!("warning: starforge post-commit skipped: {err}");
    }
    0
}

/// Hidden `_hook-pre-push`: enqueue uploads for unwritten segments. Always `0`.
pub fn hook_pre_push(repo: &Path) -> u8 {
    if let Err(err) = pre_push_inner(repo) {
        eprintln!("warning: starforge pre-push skipped: {err}");
    }
    0
}

/// One candidate plus the event `seq` range the link will cover.
struct CandidateData {
    candidate: SessionCandidate,
    seq_start: u64,
    seq_end: u64,
}

fn prepare_inner(repo: &Path, msg_file: &Path) -> Result<(), String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    let staged = staged_files(repo).map_err(|err| err.to_string())?;
    let data = collect_candidates(&spool)?;
    let candidates: Vec<SessionCandidate> = data.iter().map(|d| d.candidate.clone()).collect();
    let links = select_links(&staged, &candidates);
    let msg = std::fs::read_to_string(msg_file)
        .map_err(|err| format!("cannot read {}: {err}", msg_file.display()))?;
    let have = existing_trailer_ulids(&msg);
    let fresh: Vec<&PendingLink> = links
        .iter()
        .filter(|link| !have.iter().any(|u| u == &link.ulid))
        .collect();
    if fresh.is_empty() {
        return Ok(());
    }
    let ulids: Vec<String> = fresh.iter().map(|link| link.ulid.clone()).collect();
    std::fs::write(msg_file, append_trailers(&msg, &ulids))
        .map_err(|err| format!("cannot write {}: {err}", msg_file.display()))?;
    let by_ulid: BTreeMap<&str, &CandidateData> = data
        .iter()
        .map(|d| (d.candidate.ulid.as_str(), d))
        .collect();
    let pending: Vec<PendingRecord> = fresh
        .iter()
        .map(|link| {
            let seq = by_ulid.get(link.ulid.as_str());
            PendingRecord {
                ulid: link.ulid.clone(),
                confidence: link.confidence,
                seq_start: seq.map(|d| d.seq_start).unwrap_or(0),
                seq_end: seq.map(|d| d.seq_end).unwrap_or(0),
            }
        })
        .collect();
    let bytes = serde_json::to_vec_pretty(&pending)
        .map_err(|err| format!("cannot encode pending: {err}"))?;
    crate::spool::atomic_write(&pending_path(&spool), &bytes)
        .map_err(|err| format!("cannot write pending links: {err}"))?;
    Ok(())
}

fn post_commit_inner(repo: &Path) -> Result<(), String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    let bytes = match std::fs::read(pending_path(&spool)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("cannot read pending links: {err}")),
    };
    let pending: Vec<PendingRecord> = serde_json::from_slice(&bytes)
        .map_err(|err| format!("cannot parse pending links: {err}"))?;
    if pending.is_empty() {
        std::fs::remove_file(pending_path(&spool)).ok();
        return Ok(());
    }
    let commit = head_commit(repo).map_err(|err| err.to_string())?;
    for record in &pending {
        spool
            .record_link(&LinkEntry {
                ulid: record.ulid.clone(),
                commit: commit.clone(),
                source: LinkSource::Trailer,
                confidence: record.confidence,
                seq_start: record.seq_start,
                seq_end: record.seq_end,
            })
            .map_err(|err| format!("cannot record link: {err}"))?;
    }
    std::fs::remove_file(pending_path(&spool)).ok();
    Ok(())
}

fn pre_push_inner(repo: &Path) -> Result<(), String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    let repo_url = remotes(repo)
        .map(|list| {
            list.into_iter()
                .next()
                .map(|(_, url)| url)
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let now = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| format!("cannot format time: {err}"))?;
    let queued = read_queue(&spool).map_err(|err| err.to_string())?;
    let sessions = spool.root.join("sessions");
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("cannot list sessions: {err}")),
    };
    for entry in entries {
        let entry = entry.map_err(|err| format!("cannot list sessions: {err}"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.parse::<ulid::Ulid>().is_err() {
            continue;
        };
        if !entry.path().is_dir() {
            continue;
        }
        let segments = segment_numbers(&spool, &name);
        if segments.is_empty() {
            continue;
        }
        let uploaded = spool
            .read_upload(&name)
            .map(|state| state.uploaded_segments)
            .unwrap_or_default();
        for n in segments {
            if uploaded.contains_key(&n) {
                continue;
            }
            let dup = queued
                .iter()
                .any(|e| e.op == QueueOp::Segment && e.ulid == name && e.segment == Some(n));
            if dup {
                continue;
            }
            enqueue(
                &spool,
                QueueEntry {
                    op: QueueOp::Segment,
                    ulid: name.clone(),
                    repo: repo_url.clone(),
                    segment: Some(n),
                    attempts: 0,
                    not_before: now.clone(),
                },
            )
            .map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

/// Sorted segment numbers present for `ulid` (`segments/<n>.jsonl.zst`).
fn segment_numbers(spool: &Spool, ulid: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(n) = name
            .strip_suffix(".jsonl.zst")
            .and_then(|s| s.parse::<u64>().ok())
        {
            out.push(n);
        }
    }
    out.sort_unstable();
    out
}

/// Gather one [`SessionCandidate`] per spooled session plus the `seq` range
/// a link would cover.
///
/// Files come from `meta.json`'s `files_touched` plus tool-call (`edit` /
/// `write` / `patch`) input paths and `file_change` event paths scanned out
/// of the session's segment blobs. Only events at or past the stored spool
/// cursor (`cursors.json`, defaulting to `0`) count as new; their `seq`
/// range becomes the link's `[seq_start, seq_end)`. A session is `active`
/// when it has new events or any recorded file touches.
fn collect_candidates(spool: &Spool) -> Result<Vec<CandidateData>, String> {
    let cursors = stored_cursors(spool)?;
    let sessions = spool.root.join("sessions");
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("cannot list sessions: {err}")),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("cannot list sessions: {err}"))?;
        let Some(ulid) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if ulid.parse::<ulid::Ulid>().is_err() || !entry.path().is_dir() {
            continue;
        }
        let meta_path = entry.path().join("meta.json");
        let meta_bytes = match std::fs::read(&meta_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("cannot read {}: {err}", meta_path.display())),
        };
        let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
            .map_err(|err| format!("cannot parse {}: {err}", meta_path.display()))?;
        let mut files: Vec<String> = meta
            .get("files_touched")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let floor = cursors.get(&ulid).copied().unwrap_or(0);
        let mut new_seqs: Vec<u64> = Vec::new();
        let mut all_seqs: Vec<u64> = Vec::new();
        for n in segment_numbers(spool, &ulid) {
            let path = spool
                .root
                .join("sessions")
                .join(&ulid)
                .join("segments")
                .join(format!("{n}.jsonl.zst"));
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let text = match starforge_format::decompress(&bytes) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            let Ok(text) = String::from_utf8(text) else {
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
                all_seqs.push(event.seq);
                if event.seq >= floor {
                    new_seqs.push(event.seq);
                }
                files.extend(event_files(&event));
            }
        }
        files.sort();
        files.dedup();
        let active = !new_seqs.is_empty() || !files.is_empty();
        let (seq_start, seq_end) = match (new_seqs.iter().min(), new_seqs.iter().max()) {
            (Some(&lo), Some(&hi)) => (lo, hi + 1),
            _ => match (all_seqs.iter().min(), all_seqs.iter().max()) {
                (Some(&lo), Some(&hi)) => (lo, hi + 1),
                _ => (0, 0),
            },
        };
        out.push(CandidateData {
            candidate: SessionCandidate {
                ulid,
                files_touched: files,
                active,
            },
            seq_start,
            seq_end,
        });
    }
    Ok(out)
}

/// `ulid -> cursor.events` floor from `cursors.json` (missing file = empty).
fn stored_cursors(spool: &Spool) -> Result<BTreeMap<String, u64>, String> {
    let bytes = match std::fs::read(spool.root.join("cursors.json")) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(format!("cannot read cursors: {err}")),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| format!("cannot parse cursors: {err}"))?;
    let mut out = BTreeMap::new();
    if let Some(sessions) = value.get("sessions").and_then(|v| v.as_object()) {
        for record in sessions.values() {
            let (Some(ulid), Some(events)) = (
                record.get("ulid").and_then(|v| v.as_str()),
                record
                    .get("cursor")
                    .and_then(|c| c.get("events"))
                    .and_then(|v| v.as_u64()),
            ) else {
                continue;
            };
            out.insert(ulid.to_string(), events);
        }
    }
    Ok(out)
}

/// File paths carried by one event: `file_change` paths plus `edit` /
/// `write` / `patch` tool-call input paths.
fn event_files(event: &starforge_format::Event) -> Vec<String> {
    use starforge_format::EventKind;
    match &event.kind {
        EventKind::FileChange(change) => vec![change.path.clone()],
        EventKind::ToolCall(call) => tool_input_paths(&call.tool.name, &call.tool.input),
        _ => Vec::new(),
    }
}

fn tool_input_paths(name: &str, input: &serde_json::Value) -> Vec<String> {
    match name.to_lowercase().as_str() {
        "edit" | "write" | "patch" => {}
        _ => return Vec::new(),
    }
    let Some(obj) = input.as_object() else {
        return Vec::new();
    };
    ["path", "file", "file_path", "filename", "filepath"]
        .into_iter()
        .filter_map(|key| obj.get(key).and_then(|v| v.as_str()).map(str::to_string))
        .collect()
}
