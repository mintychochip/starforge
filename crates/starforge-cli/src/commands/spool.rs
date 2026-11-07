//! `spool prune`: reclaim space from fully uploaded, completed, old sessions.
//!
//! Only sessions whose upload state records the server's `complete`
//! acknowledgement, every segment uploaded, and metadata unchanged since
//! upload (see [`Spool::prune_candidates`]) are touched, and only their
//! `segments/` and `raw/` blobs go away: `meta.json`, `upload.json`, and the
//! cursor record stay, so re-ingest reuses the same ULID. `--dry-run` prints
//! the per-session plan and writes nothing.

use std::path::Path;

use crate::git::common_dir;
use crate::spool::Spool;

/// Prune eligible sessions idle longer than `older_than_days`. Prints one
/// line per pruned (or, when `dry_run`, would-be-pruned) session plus the
/// `sessions:` / `bytes freed:` totals, which print in both modes.
pub fn prune(repo: &Path, older_than_days: u64, dry_run: bool) -> (String, u8) {
    // Reject absurd values before scanning: `prune_candidates` casts to
    // `i64`, so a huge value would wrap negative and prune everything.
    if older_than_days > (i64::MAX / 86_400) as u64 {
        return (
            format!("error: --older-than {older_than_days} is too large"),
            1,
        );
    }
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    let candidates = match spool.prune_candidates(time::OffsetDateTime::now_utc(), older_than_days)
    {
        Ok(candidates) => candidates,
        Err(err) => return (format!("error: cannot scan spool: {err}"), 1),
    };
    let mut out = String::new();
    let mut bytes_freed = 0u64;
    for candidate in &candidates {
        if dry_run {
            out.push_str(&format!(
                "\nwould prune {} ({} bytes, last activity {})",
                candidate.ulid, candidate.bytes, candidate.last_activity
            ));
            bytes_freed += candidate.bytes;
            continue;
        }
        match spool.prune_session(&candidate.ulid) {
            Ok(Some(bytes)) => {
                bytes_freed += bytes;
                out.push_str(&format!(
                    "\npruned {} ({} bytes, last activity {})",
                    candidate.ulid, bytes, candidate.last_activity
                ));
            }
            Ok(None) => {
                out.push_str(&format!(
                    "\nskipped {} (changed since scan)",
                    candidate.ulid
                ));
            }
            Err(err) => return (format!("error: cannot prune {}: {err}", candidate.ulid), 1),
        }
    }
    if candidates.is_empty() {
        out.push_str("\n(no sessions to prune)");
    }
    out.push_str(&format!(
        "\nsessions: {}\nbytes freed: {}",
        candidates.len(),
        bytes_freed
    ));
    (out, 0)
}
