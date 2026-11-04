//! `sessions list` / `sessions show`: read-only views over the local spool.
//!
//! Both resolve the spool from the current repo's git common dir and write
//! nothing; `--dry-run` prints what would be read.

use std::path::Path;

use crate::git::common_dir;
use crate::spool::Spool;

/// List spooled session ULIDs, one per line, sorted.
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
    let sessions = spool.root.join("sessions");
    let mut ulids = Vec::new();
    match std::fs::read_dir(&sessions) {
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
    (ulids.join("\n"), 0)
}

/// Print a session's `meta.json`, pretty-printed.
pub fn show(repo: &Path, ulid: &str, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    if dry_run {
        return (
            format!("would show session {ulid} in {}", spool.root.display()),
            0,
        );
    }
    match spool.read_meta(ulid) {
        Ok(meta) => (
            serde_json::to_string_pretty(&meta).expect("SessionMeta serializes"),
            0,
        ),
        Err(err) => (format!("error: {err}"), 1),
    }
}
