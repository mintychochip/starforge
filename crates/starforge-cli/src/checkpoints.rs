//! Session checkpoints: local snapshot creation, rewind, and resume.
//!
//! A checkpoint is a git commit whose tree is the whole working tree
//! (tracked plus untracked non-ignored files), stored under
//! `refs/starforge/checkpoints/<session-ulid>/<n>`. The spool records its
//! label and upload state. Rewind restores the index and worktree to the
//! checkpoint tree; resume also writes `.starforge/resume.md` with the last
//! turns so an agent can continue from the restored state.

use std::path::Path;

use starforge_format::{EventKind, decompress, parse_event};
use time::OffsetDateTime;

use crate::git;
use crate::spool::{CheckpointEntry, Spool};

/// Creates a checkpoint for `ulid`. A no-op when the tree equals the newest
/// checkpoint's tree (unless `force`). Returns the entry.
pub fn create(
    repo: &Path,
    spool: &Spool,
    ulid: &str,
    label: &str,
    source: &str,
    force: bool,
) -> Result<CheckpointEntry, String> {
    let extra = checkpoint_paths(repo, spool, ulid);
    let tree = git::write_tree(repo, &extra).map_err(|err| err.to_string())?;
    let last = spool.last_checkpoint(ulid).map_err(|err| err.to_string())?;
    if !force && last.as_ref().is_some_and(|entry| entry.tree == tree) {
        return Ok(last.expect("checked above"));
    }
    let parent = match &last {
        Some(entry) => Some(entry.commit.clone()),
        None => git::head_commit(repo).ok(),
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    // No `Starforge-Session` trailer: the session is already in the ref name
    // and the DB row, and a trailer would make the push scan record a
    // synthetic commit link from the session to this checkpoint commit.
    let message = format!("checkpoint: {label}\n");
    let parents: Vec<&str> = parent.iter().map(String::as_str).collect();
    let commit =
        git::commit_tree(repo, &tree, &parents, &message, now).map_err(|err| err.to_string())?;
    let n = last.map(|entry| entry.n + 1).unwrap_or(1);
    let ref_name = format!("refs/starforge/checkpoints/{ulid}/{n}");
    git::update_checkpoint_ref(repo, &ref_name, &commit).map_err(|err| err.to_string())?;
    spool
        .append_checkpoint(
            ulid,
            CheckpointEntry {
                n,
                commit,
                tree,
                parent,
                label: label.to_owned(),
                source: source.to_owned(),
                created_at: now,
                uploaded: false,
            },
        )
        .map_err(|err| err.to_string())
}

/// Session-touched untracked files that are safe to include in a checkpoint.
/// Tracked files are captured by `git add -u`; untracked files are included
/// only when the session touched them, they are inside the repository, they
/// are not under `.starforge/`, they are UTF-8, and the redaction rules find
/// nothing in them. A hit keeps the file out of the snapshot.
fn checkpoint_paths(repo: &Path, spool: &Spool, ulid: &str) -> Vec<String> {
    let Ok(meta) = spool.read_meta(ulid) else {
        return Vec::new();
    };
    let Ok(tracked) = git::tracked_files(repo) else {
        return Vec::new();
    };
    let Ok((_, compiled)) = Spool::load_rules(repo) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for path in &meta.files_touched {
        if !safe_relative_path(path) || tracked.contains(path) {
            continue;
        }
        if is_ignored(repo, path) {
            continue;
        }
        let full = repo.join(path);
        let Ok(metadata) = std::fs::symlink_metadata(&full) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        if metadata.len() > 8 * 1024 * 1024 {
            eprintln!("warning: checkpoint skips large untracked file {path}");
            continue;
        }
        let Ok(bytes) = std::fs::read(&full) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            eprintln!("warning: checkpoint skips binary untracked file {path}");
            continue;
        };
        let (_, counts) = starforge_redact::redact_text(&compiled, &text);
        if !counts.is_empty() {
            eprintln!("warning: checkpoint skips {path}: a redaction rule matched");
            continue;
        }
        out.push(path.clone());
    }
    out
}

/// True when git ignores `path`; an ignored file is never added to a
/// checkpoint (a session can touch build output or a local secret store).
fn is_ignored(repo: &Path, path: &str) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["check-ignore", "-q", "--", path])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// True for a repo-relative path that stays inside the worktree and outside
/// `.starforge/` and `.git/`.
fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path != ".starforge"
        && !path.starts_with(".starforge/")
        && !path.starts_with(".git/")
        && !path.contains('\0')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

/// Restores the worktree and index to checkpoint `n`. Refuses a dirty
/// worktree unless `force`; with `force`, first creates a `pre_rewind`
/// checkpoint so the overwritten state is recoverable.
pub fn rewind(
    repo: &Path,
    spool: &Spool,
    ulid: &str,
    n: u64,
    force: bool,
) -> Result<CheckpointEntry, String> {
    let entry = spool
        .read_checkpoints(ulid)
        .map_err(|err| err.to_string())?
        .into_iter()
        .find(|entry| entry.n == n)
        .ok_or_else(|| format!("unknown checkpoint {n} for session {ulid}"))?;
    if !git::object_exists(repo, &entry.commit).map_err(|err| err.to_string())? {
        return Err(format!(
            "checkpoint {} is not available locally; fetch its ref first",
            entry.commit
        ));
    }
    let dirty = !git::status_porcelain(repo)
        .map_err(|err| err.to_string())?
        .trim()
        .is_empty();
    if dirty && !force {
        return Err("worktree is dirty; commit or stash your changes, or pass --force".to_owned());
    }
    if dirty {
        // A local stash keeps every tracked and untracked file, including
        // files the checkpoint snapshot deliberately leaves out. It never
        // uploads, so it is the safe recovery point for --force.
        git::stash_untracked(
            repo,
            &format!("starforge pre-rewind {ulid} checkpoint {}", entry.n),
        )
        .map_err(|err| err.to_string())?;
    }
    git::read_tree_reset(repo, &entry.commit).map_err(|err| err.to_string())?;
    git::clean_untracked(repo).map_err(|err| err.to_string())?;
    Ok(entry)
}

/// Rewinds to checkpoint `n` and writes `.starforge/resume.md` with the
/// session metadata and the last 20 events. Returns the checkpoint and the
/// context file path.
pub fn resume(
    repo: &Path,
    spool: &Spool,
    ulid: &str,
    n: u64,
    force: bool,
) -> Result<(CheckpointEntry, std::path::PathBuf), String> {
    let entry = rewind(repo, spool, ulid, n, force)?;
    let meta = spool.read_meta(ulid).ok();
    let mut text = String::new();
    text.push_str(&format!("# Resume session {ulid}\n\n"));
    if let Some(meta) = &meta {
        text.push_str(&format!("Title: {}\n", meta.title.as_deref().unwrap_or("")));
        text.push_str(&format!(
            "Agent: {:?} {}\n",
            meta.agent.name, meta.agent.version
        ));
    }
    text.push_str(&format!(
        "Checkpoint: {} ({}, {})\n\n",
        entry.n,
        if entry.label.is_empty() {
            "unlabeled"
        } else {
            entry.label.as_str()
        },
        &entry.commit[..entry.commit.len().min(10)]
    ));
    text.push_str("## Recent turns\n\n");
    let events = last_events(spool, ulid, 20)?;
    if events.is_empty() {
        text.push_str("(no local transcript events)\n");
    } else {
        for event in events {
            text.push_str(&render_event(&event));
            text.push('\n');
        }
    }
    text.push_str(
        "\nContinue from this checkpoint. The working tree is restored; inspect it before acting.\n",
    );
    let dir = repo.join(".starforge");
    std::fs::create_dir_all(&dir).map_err(|err| format!("cannot create .starforge: {err}"))?;
    let path = dir.join("resume.md");
    std::fs::write(&path, text).map_err(|err| format!("cannot write resume context: {err}"))?;
    Ok((entry, path))
}

/// The newest `limit` parsed events across the session's segment files.
fn last_events(
    spool: &Spool,
    ulid: &str,
    limit: usize,
) -> Result<Vec<starforge_format::Event>, String> {
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    let mut files: Vec<(u64, std::path::PathBuf)> = std::fs::read_dir(&dir)
        .map_err(|err| format!("cannot read segments: {err}"))?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let stem = path.file_stem()?.to_str()?;
            let n = stem.split('.').next()?.parse::<u64>().ok()?;
            Some((n, path))
        })
        .collect();
    files.sort_by_key(|(n, _)| *n);
    let mut events = Vec::new();
    for (_, path) in files {
        let bytes = std::fs::read(&path).map_err(|err| format!("cannot read segment: {err}"))?;
        let raw = decompress(&bytes).map_err(|err| format!("cannot decompress segment: {err}"))?;
        let text = String::from_utf8(raw).map_err(|err| format!("segment is not UTF-8: {err}"))?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = parse_event(line) {
                events.push(event);
            }
        }
    }
    let start = events.len().saturating_sub(limit);
    Ok(events.split_off(start))
}

/// One readable line for the resume context.
fn render_event(event: &starforge_format::Event) -> String {
    let text = match &event.kind {
        EventKind::UserMessage(message) => format!("User: {}", truncate(&message.text, 800)),
        EventKind::AssistantMessage(message) => {
            format!("Assistant: {}", truncate(&message.text, 800))
        }
        EventKind::Reasoning(reasoning) => {
            format!("Reasoning: {}", truncate(&reasoning.text, 400))
        }
        EventKind::ToolCall(call) => format!("Tool call: {}", call.tool.name),
        EventKind::ToolResult(result) => {
            format!("Tool result: {}", truncate(&result.result.output, 400))
        }
        EventKind::FileChange(change) => format!("File change: {}", change.path),
        EventKind::Compaction(compaction) => format!(
            "Compaction: {}",
            compaction.summary.as_deref().unwrap_or("(summary omitted)")
        ),
        EventKind::SubagentStart(boundary) => {
            format!("Subagent start: {}", boundary.subagent_id)
        }
        EventKind::SubagentEnd(boundary) => format!("Subagent end: {}", boundary.subagent_id),
        EventKind::System(system) => format!("System: {}", truncate(&system.text, 400)),
        EventKind::Unknown(kind) => format!("Event: {kind}"),
    };
    format!("- {text}")
}

fn truncate(text: &str, max: usize) -> String {
    let mut out: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out
}
