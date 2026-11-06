//! Upload queue entries + injected clock (implemented C4/C6).
//!
//! `queue.jsonl` holds one [`QueueEntry`] object per line. Enqueue appends;
//! dequeue rewrites the file atomically (temp file + rename) after settling
//! each operation. A garbage line (crash-partial write) is skipped with a
//! warning, never a panic, and the next rewrite cleans it out.

use std::io;

use time::format_description::well_known::Rfc3339;

use crate::spool::{Spool, atomic_write};

/// One pending upload operation (`queue.jsonl`: one object per line).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueueEntry {
    pub op: QueueOp,
    pub ulid: String,
    pub repo: String,
    pub segment: Option<u64>,
    pub attempts: u32,
    /// RFC 3339.
    pub not_before: String,
}

/// Upload operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueueOp {
    Meta,
    Segment,
    Complete,
    Links,
}

/// Queue failures.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// Filesystem failure.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// A stored `not_before` timestamp did not parse as RFC 3339.
    #[error("bad timestamp `{0}`: {1}")]
    BadTime(String, String),
}

/// Injected clock for backoff + device-flow polling.
///
/// Plain trait with RPITIT — no async-trait dependency.
pub trait Sleeper {
    fn sleep(&self, dur: std::time::Duration) -> impl Future<Output = ()> + '_;
}

/// Production sleeper backed by `tokio::time::sleep`.
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    async fn sleep(&self, dur: std::time::Duration) {
        tokio::time::sleep(dur).await;
    }
}

fn queue_path(spool: &Spool) -> std::path::PathBuf {
    spool.root.join("queue.jsonl")
}

/// Append one entry to `queue.jsonl`. The file is created `0600` on unix
/// (like every other spool file) and tightened best-effort on open, so a
/// `queue.jsonl` deleted and recreated by an append never lands
/// world-readable.
pub fn enqueue(spool: &Spool, entry: QueueEntry) -> Result<(), QueueError> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(queue_path(spool))?;
    crate::spool::tighten_file(&queue_path(spool));
    writeln!(
        file,
        "{}",
        serde_json::to_string(&entry).expect("QueueEntry serializes")
    )?;
    file.sync_all()?;
    Ok(())
}

/// All queued entries in file order. Blank lines are skipped; a line that is
/// not a `QueueEntry` object (e.g. a crash-partial write) is skipped with a
/// warning, not an error.
pub fn read_queue(spool: &Spool) -> Result<Vec<QueueEntry>, QueueError> {
    let text = match std::fs::read_to_string(queue_path(spool)) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(QueueError::Io(e)),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<QueueEntry>(line) {
            Ok(entry) => out.push(entry),
            Err(e) => tracing::warn!("skipping corrupt queue line: {e}"),
        }
    }
    Ok(out)
}

/// Replace `queue.jsonl` with exactly `entries`, atomically (temp + rename).
pub fn rewrite_queue(spool: &Spool, entries: &[QueueEntry]) -> Result<(), QueueError> {
    let mut text = String::new();
    for entry in entries {
        text.push_str(&serde_json::to_string(entry).expect("QueueEntry serializes"));
        text.push('\n');
    }
    atomic_write(&queue_path(spool), text.as_bytes()).map_err(QueueError::Io)?;
    Ok(())
}

/// True when `entry.not_before <= now`. Both sides are RFC 3339 strings in
/// the same (UTC `Z`) shape, so lexicographic order is chronological order.
/// Pure: no clock, no I/O.
pub fn backoff_due(entry: &QueueEntry, now_rfc3339: &str) -> bool {
    entry.not_before.as_str() <= now_rfc3339
}

/// Remove and return every entry due at `now_rfc3339`, rewriting the file
/// atomically with the remainder (which also drops any garbage lines).
pub fn dequeue_ready(spool: &Spool, now_rfc3339: &str) -> Result<Vec<QueueEntry>, QueueError> {
    let mut remaining = Vec::new();
    let mut due = Vec::new();
    for entry in read_queue(spool)? {
        if backoff_due(&entry, now_rfc3339) {
            due.push(entry);
        } else {
            remaining.push(entry);
        }
    }
    rewrite_queue(spool, &remaining)?;
    Ok(due)
}

/// Deterministic exponential backoff: `min(300, 2^attempts)` seconds.
fn backoff_delay_secs(attempts: u32) -> u64 {
    2u64.checked_pow(attempts).unwrap_or(u64::MAX).min(300)
}

/// Record a failed attempt for the entry matching `(op, ulid, segment)`:
/// `attempts` grows by one and `not_before` moves out by
/// `min(300, 2^attempts)` seconds from the stored `not_before` (no clock
/// read, so retries stay deterministic). Returns `false` when no entry
/// matches. The file is rewritten atomically.
pub fn mark_attempt(
    spool: &Spool,
    op: QueueOp,
    ulid: &str,
    segment: Option<u64>,
) -> Result<bool, QueueError> {
    let mut entries = read_queue(spool)?;
    let Some(entry) = entries
        .iter_mut()
        .find(|e| e.op == op && e.ulid == ulid && e.segment == segment)
    else {
        return Ok(false);
    };
    entry.attempts = entry.attempts.saturating_add(1);
    let delay = backoff_delay_secs(entry.attempts);
    let at = time::OffsetDateTime::parse(&entry.not_before, &Rfc3339)
        .map_err(|e| QueueError::BadTime(entry.not_before.clone(), e.to_string()))?;
    let next = at
        .checked_add(time::Duration::seconds(delay as i64))
        .ok_or_else(|| {
            QueueError::BadTime(
                entry.not_before.clone(),
                "timestamp out of range".to_string(),
            )
        })?;
    entry.not_before = next
        .format(&Rfc3339)
        .map_err(|e| QueueError::BadTime(entry.not_before.clone(), e.to_string()))?;
    rewrite_queue(spool, &entries)?;
    Ok(true)
}
