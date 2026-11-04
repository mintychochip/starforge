//! `sync`: drain due queue entries to the server (C6).
//!
//! Order is the queue file's order (enqueue appends meta → segments →
//! complete → links). After every settled op the queue file is rewritten
//! atomically, so a crash never re-uploads a recorded op:
//!
//! - metadata `PUT` from `meta.json`;
//! - each pending segment `PUT` from the spool's exact compressed bytes
//!   (never re-derived from native transcripts), skipping entries whose hash
//!   is already recorded in `upload.json`;
//! - `POST complete` only when the session's `meta.ended_at` is set —
//!   otherwise the entry stays queued and the session is left uncompleted;
//! - `POST links` for the session's unsent links (no links → drop the entry).
//!
//! Failures: transport errors and `5xx` bump `attempts`, push `not_before`
//! out by `min(300, 2^attempts)` seconds from the injected `now`, sleep the
//! same duration via the injected [`Sleeper`](crate::queue::Sleeper), and
//! retry the entry (at most `MAX_RETRIES` per entry per run). A `409` with a
//! different hash surfaces [`SyncSummary::conflict`] and ends the run with
//! exit 2. `401`/`403` aborts the run with [`UploadError::Auth`]
//! ("run `starforge auth login`"). Every other failure is terminal for its
//! entry: the entry stays queued with bumped attempts and the run continues.

use std::time::Duration;

use time::format_description::well_known::Rfc3339;

use crate::discovery::ServerInfo;
use crate::queue::{QueueEntry, QueueOp, Sleeper, backoff_due, enqueue, read_queue, rewrite_queue};
use crate::spool::Spool;
use crate::upload::{UploadClient, UploadError};

/// Retries per entry per run after the initial attempt (brief §C6).
const MAX_RETRIES: u32 = 4;

/// Overall deadline for the best-effort pre-push wrapper.
const BEST_EFFORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of one `sync` run.
#[derive(Debug, Clone, Default)]
pub struct SyncSummary {
    /// Ops uploaded this run.
    pub uploaded: usize,
    /// Ops dropped without HTTP (already-uploaded segments, empty links).
    pub skipped: usize,
    /// Entries still queued (not due, failed, conflicted, uncompleted).
    pub remaining: usize,
    /// At least one segment conflicted (different content on the server).
    pub conflict: bool,
    /// Human-readable plan; only populated for `dry_run`.
    pub planned: Vec<String>,
}

impl SyncSummary {
    /// Exit code: 0 drained, 2 remainder (conflict counts as remainder).
    /// Auth aborts with `Err`, which the CLI maps to 1.
    pub fn exit_code(&self) -> u8 {
        if self.conflict || self.remaining > 0 {
            2
        } else {
            0
        }
    }
}

/// Drain due queue entries: meta → segments (in n order) → links →
/// complete-when-eligible (adapter reports end OR 24 h without new events —
/// v0.1: complete only when the spool session's meta has ended_at set, else
/// leave uncompleted and succeed). Failures bump attempts + not_before
/// (`2^attempts` s, cap 300) via injected now; exit 0 drained / 2 remainder.
/// Drain due queue entries, deriving missing work from spool state first:
/// every session with no recorded metadata PUT gets `Meta`, every segment on
/// disk whose hash is not in `upload.json` gets `Segment`, `Complete` when
/// `meta.ended_at` is set and `upload.json.complete` is false, and `Links`
/// for links not yet recorded as sent. The queue stays the retry record:
/// reconcile only appends entries no queued entry already covers, failures
/// keep their bumped entries and backoff, and `sync_best_effort` (pre-push)
/// keeps draining whatever is queued without reconciling.
pub async fn sync(
    spool: &Spool,
    server: &ServerInfo,
    owner_repo: &str,
    token: &str,
    sleeper: &impl Sleeper,
    now_rfc3339: &str,
    dry_run: bool,
) -> Result<SyncSummary, UploadError> {
    if dry_run {
        return dry_run_summary(spool, now_rfc3339);
    }
    reconcile_queue(spool, now_rfc3339)?;
    sync_with_retries(
        spool,
        server,
        owner_repo,
        token,
        sleeper,
        now_rfc3339,
        false,
        MAX_RETRIES,
    )
    .await
}

/// Blake3 of the canonical metadata JSON: the identity `upload.json.meta_hash`
/// is compared against.
fn meta_body_hash(meta: &starforge_format::SessionMeta) -> Result<String, UploadError> {
    let bytes = serde_json::to_vec(meta).map_err(crate::spool::SpoolError::Json)?;
    Ok(starforge_format::blake3_hex(&bytes))
}

/// Queue identity for dedupe: op plus `(ulid, segment)`.
fn entry_key(op: QueueOp, ulid: &str, segment: Option<u64>) -> (u8, String, Option<u64>) {
    let disc = match op {
        QueueOp::Meta => 0,
        QueueOp::Segment => 1,
        QueueOp::Complete => 2,
        QueueOp::Links => 3,
    };
    (disc, ulid.to_string(), segment)
}

/// Sorted ULIDs present under `sessions/`.
fn session_ulids(spool: &Spool) -> Vec<String> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(spool.root.join("sessions")) {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && name.parse::<ulid::Ulid>().is_ok()
        {
            out.push(name.to_string());
        }
    }
    out.sort();
    out
}

/// Sorted segment numbers present for `ulid`.
fn present_segments(spool: &Spool, ulid: &str) -> Vec<u64> {
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

/// The full canonical upload list for every spooled session, in upload order
/// (`Meta` → segments → `Complete` → `Links` per session, sessions sorted):
/// entries whose work `upload.json` already records are omitted.
fn desired_entries(spool: &Spool, now_rfc3339: &str) -> Result<Vec<QueueEntry>, UploadError> {
    let mut out = Vec::new();
    for ulid in session_ulids(spool) {
        let meta = match spool.read_meta(&ulid) {
            Ok(meta) => meta,
            Err(err) => {
                tracing::warn!("sync: cannot read meta for `{ulid}`: {err}");
                continue;
            }
        };
        let state = spool.read_upload(&ulid)?;
        let hash = meta_body_hash(&meta)?;
        if state.meta_hash.as_deref() != Some(hash.as_str()) {
            out.push(QueueEntry {
                op: QueueOp::Meta,
                ulid: ulid.clone(),
                repo: String::new(),
                segment: None,
                attempts: 0,
                not_before: now_rfc3339.to_string(),
            });
        }
        for n in present_segments(spool, &ulid) {
            let bytes = match spool.segment_bytes(&ulid, n) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!("sync: cannot read segment {n} for `{ulid}`: {err}");
                    continue;
                }
            };
            let hash = starforge_format::blake3_hex(&bytes);
            if state.uploaded_segments.get(&n) != Some(&hash) {
                out.push(QueueEntry {
                    op: QueueOp::Segment,
                    ulid: ulid.clone(),
                    repo: String::new(),
                    segment: Some(n),
                    attempts: 0,
                    not_before: now_rfc3339.to_string(),
                });
            }
        }
        if meta.ended_at.is_some() && !state.complete {
            out.push(QueueEntry {
                op: QueueOp::Complete,
                ulid: ulid.clone(),
                repo: String::new(),
                segment: None,
                attempts: 0,
                not_before: now_rfc3339.to_string(),
            });
        }
        let pairs = spool.link_line_hashes(&ulid)?;
        if pairs
            .iter()
            .any(|(hash, _)| !state.sent_links.contains(hash))
        {
            out.push(QueueEntry {
                op: QueueOp::Links,
                ulid: ulid.clone(),
                repo: String::new(),
                segment: None,
                attempts: 0,
                not_before: now_rfc3339.to_string(),
            });
        }
    }
    Ok(out)
}

/// Append every [`desired_entries`] row no queued entry already covers.
/// Returns the number of entries added. The queue file is only appended to,
/// never rewritten, so existing attempts/backoff survive a reconcile.
pub fn reconcile_queue(spool: &Spool, now_rfc3339: &str) -> Result<usize, UploadError> {
    use std::collections::HashSet;
    let have: HashSet<(u8, String, Option<u64>)> = read_queue(spool)?
        .iter()
        .map(|e| entry_key(e.op, &e.ulid, e.segment))
        .collect();
    let mut added = 0;
    for entry in desired_entries(spool, now_rfc3339)? {
        if !have.contains(&entry_key(entry.op, &entry.ulid, entry.segment)) {
            enqueue(spool, entry)?;
            added += 1;
        }
    }
    if added > 0 {
        tracing::debug!("sync: reconciled {added} missing queue entries from spool state");
    }
    Ok(added)
}

/// Dry-run plan: due queued entries plus derived-but-unqueued work. Writes nothing.
pub fn dry_run_plan(spool: &Spool, now_rfc3339: &str) -> Result<Vec<String>, UploadError> {
    use std::collections::HashSet;
    let queued = read_queue(spool)?;
    let mut planned = Vec::new();
    for entry in &queued {
        if backoff_due(entry, now_rfc3339) {
            planned.push(describe(entry));
        }
    }
    let have: HashSet<(u8, String, Option<u64>)> = queued
        .iter()
        .map(|e| entry_key(e.op, &e.ulid, e.segment))
        .collect();
    for entry in desired_entries(spool, now_rfc3339)? {
        if !have.contains(&entry_key(entry.op, &entry.ulid, entry.segment)) {
            planned.push(describe(&entry));
        }
    }
    Ok(planned)
}

/// Dry-run summary over queued + derived work. Writes nothing.
fn dry_run_summary(spool: &Spool, now_rfc3339: &str) -> Result<SyncSummary, UploadError> {
    Ok(SyncSummary {
        planned: dry_run_plan(spool, now_rfc3339)?,
        ..SyncSummary::default()
    })
}

/// Best-effort upload for the `pre-push` path: at most one attempt per entry,
/// a 10 s overall deadline, every failure swallowed. Always returns (never
/// fails the push); the queue keeps whatever did not make it.
pub async fn sync_best_effort(
    spool: &Spool,
    server: &ServerInfo,
    owner_repo: &str,
    token: &str,
    sleeper: &impl Sleeper,
    now_rfc3339: &str,
) -> SyncSummary {
    let run = sync_with_retries(
        spool,
        server,
        owner_repo,
        token,
        sleeper,
        now_rfc3339,
        false,
        0,
    );
    match tokio::time::timeout(BEST_EFFORT_TIMEOUT, run).await {
        Ok(Ok(summary)) => summary,
        _ => SyncSummary {
            remaining: read_queue(spool).map(|q| q.len()).unwrap_or(0),
            ..SyncSummary::default()
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn sync_with_retries(
    spool: &Spool,
    server: &ServerInfo,
    owner_repo: &str,
    token: &str,
    sleeper: &impl Sleeper,
    now_rfc3339: &str,
    dry_run: bool,
    max_retries: u32,
) -> Result<SyncSummary, UploadError> {
    let now = time::OffsetDateTime::parse(now_rfc3339, &Rfc3339)
        .map_err(|err| UploadError::Time(now_rfc3339.to_string(), err.to_string()))?;
    let client = UploadClient::new(server.api_url.clone(), token.to_string());
    let mut working = read_queue(spool)?;
    let mut summary = SyncSummary::default();

    let mut i = 0;
    while i < working.len() {
        let entry = working[i].clone();
        if !backoff_due(&entry, now_rfc3339) {
            i += 1;
            continue;
        }
        if dry_run {
            summary.planned.push(describe(&entry));
            i += 1;
            continue;
        }
        match settle_entry(
            &client,
            spool,
            owner_repo,
            &mut working,
            i,
            sleeper,
            now,
            max_retries,
        )
        .await
        {
            Ok(stats) => {
                if stats.uploaded {
                    summary.uploaded += 1;
                }
                if stats.skipped {
                    summary.skipped += 1;
                }
                if stats.conflict {
                    summary.conflict = true;
                }
                if stats.removed {
                    working.remove(i);
                    rewrite_queue(spool, &working)?;
                } else {
                    i += 1;
                }
            }
            // Auth aborts the run; nothing was mutated for this entry.
            Err(err) => return Err(err),
        }
    }
    summary.remaining = working.len();
    Ok(summary)
}

/// Per-entry settle statistics.
#[derive(Debug, Clone, Copy, Default)]
struct EntryStats {
    /// The entry is done: remove it from the queue.
    removed: bool,
    uploaded: bool,
    skipped: bool,
    conflict: bool,
}

impl EntryStats {
    fn uploaded() -> Self {
        Self {
            removed: true,
            uploaded: true,
            ..Self::default()
        }
    }

    fn skipped() -> Self {
        Self {
            removed: true,
            skipped: true,
            ..Self::default()
        }
    }

    fn kept() -> Self {
        Self::default()
    }
}

/// Outcome of the retry driver.
enum Driven {
    /// The op succeeded; the caller records it and removes the entry.
    Done,
    /// Terminal for this entry; the entry was bumped and stays queued.
    Kept { conflict: bool },
}

#[allow(clippy::too_many_arguments)]
async fn settle_entry(
    client: &UploadClient,
    spool: &Spool,
    owner_repo: &str,
    working: &mut [QueueEntry],
    idx: usize,
    sleeper: &impl Sleeper,
    now: time::OffsetDateTime,
    max_retries: u32,
) -> Result<EntryStats, UploadError> {
    let entry = working[idx].clone();
    match entry.op {
        QueueOp::Meta => {
            let meta = match spool.read_meta(&entry.ulid) {
                Ok(meta) => meta,
                Err(err) => {
                    tracing::warn!("sync: cannot read meta for `{}`: {err}", entry.ulid);
                    return Ok(EntryStats::kept());
                }
            };
            match drive(working, idx, spool, sleeper, now, max_retries, || {
                client.put_meta(owner_repo, &meta)
            })
            .await?
            {
                Driven::Done => {
                    let hash = meta_body_hash(&meta)?;
                    spool.mark_meta_uploaded(&entry.ulid, hash)?;
                    Ok(EntryStats::uploaded())
                }
                Driven::Kept { conflict } => Ok(conflict_stats(conflict)),
            }
        }
        QueueOp::Segment => {
            let Some(n) = entry.segment else {
                tracing::warn!("sync: segment op without a number for `{}`", entry.ulid);
                return Ok(EntryStats::kept());
            };
            let bytes = match spool.segment_bytes(&entry.ulid, n) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!("sync: cannot read segment {n} for `{}`: {err}", entry.ulid);
                    return Ok(EntryStats::kept());
                }
            };
            let hash = starforge_format::blake3_hex(&bytes);
            match spool.read_upload(&entry.ulid) {
                Ok(state) if state.uploaded_segments.get(&n) == Some(&hash) => {
                    return Ok(EntryStats::skipped());
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!("sync: cannot read upload.json for `{}`: {err}", entry.ulid);
                    return Ok(EntryStats::kept());
                }
            }
            match drive(working, idx, spool, sleeper, now, max_retries, || {
                client.put_segment(owner_repo, &entry.ulid, n, &bytes)
            })
            .await?
            {
                Driven::Done => {
                    spool.mark_segment_uploaded(&entry.ulid, n)?;
                    Ok(EntryStats::uploaded())
                }
                Driven::Kept { conflict } => Ok(conflict_stats(conflict)),
            }
        }
        QueueOp::Complete => {
            let meta = match spool.read_meta(&entry.ulid) {
                Ok(meta) => meta,
                Err(err) => {
                    tracing::warn!("sync: cannot read meta for `{}`: {err}", entry.ulid);
                    return Ok(EntryStats::kept());
                }
            };
            if meta.ended_at.is_none() {
                // Session still open: leave uncompleted (entry stays queued).
                return Ok(EntryStats::kept());
            }
            match drive(working, idx, spool, sleeper, now, max_retries, || {
                client.post_complete(owner_repo, &entry.ulid)
            })
            .await?
            {
                Driven::Done => {
                    mark_complete(spool, &entry.ulid)?;
                    Ok(EntryStats::uploaded())
                }
                Driven::Kept { conflict } => Ok(conflict_stats(conflict)),
            }
        }
        QueueOp::Links => {
            let pairs = match spool.link_line_hashes(&entry.ulid) {
                Ok(pairs) => pairs,
                Err(err) => {
                    tracing::warn!("sync: cannot read links: {err}");
                    return Ok(EntryStats::kept());
                }
            };
            if pairs.is_empty() {
                return Ok(EntryStats::skipped());
            }
            let ours: Vec<serde_json::Value> = pairs
                .iter()
                .map(|(_, link)| serde_json::to_value(link).expect("LinkEntry serializes"))
                .collect();
            match drive(working, idx, spool, sleeper, now, max_retries, || {
                client.post_links(owner_repo, &entry.ulid, &ours)
            })
            .await?
            {
                Driven::Done => {
                    let hashes: Vec<String> = pairs.iter().map(|(hash, _)| hash.clone()).collect();
                    spool.mark_links_sent(&entry.ulid, &hashes)?;
                    Ok(EntryStats::uploaded())
                }
                Driven::Kept { conflict } => Ok(conflict_stats(conflict)),
            }
        }
    }
}

fn conflict_stats(conflict: bool) -> EntryStats {
    EntryStats {
        conflict,
        ..EntryStats::kept()
    }
}

/// Run `op` with backoff retries. `Ok(Done)` on success; terminal failures
/// (bumped, persisted, kept) as `Ok(Kept)`; only auth aborts with `Err`.
async fn drive<Fut>(
    working: &mut [QueueEntry],
    idx: usize,
    spool: &Spool,
    sleeper: &impl Sleeper,
    now: time::OffsetDateTime,
    max_retries: u32,
    op: impl Fn() -> Fut,
) -> Result<Driven, UploadError>
where
    Fut: Future<Output = Result<(), UploadError>>,
{
    let mut retries = 0u32;
    loop {
        match op().await {
            Ok(()) => return Ok(Driven::Done),
            Err(err) if err.is_retryable() && retries < max_retries => {
                retries += 1;
                let delay = bump_entry(working, idx, now)?;
                rewrite_queue(spool, working)?;
                sleeper.sleep(delay).await;
            }
            Err(err @ UploadError::Auth { .. }) => return Err(err),
            Err(UploadError::Conflict { .. }) => {
                bump_entry(working, idx, now)?;
                rewrite_queue(spool, working)?;
                return Ok(Driven::Kept { conflict: true });
            }
            Err(_) => {
                bump_entry(working, idx, now)?;
                rewrite_queue(spool, working)?;
                return Ok(Driven::Kept { conflict: false });
            }
        }
    }
}

/// Deterministic exponential backoff: `min(300, 2^attempts)` seconds.
fn backoff_delay_secs(attempts: u32) -> u64 {
    2u64.checked_pow(attempts).unwrap_or(u64::MAX).min(300)
}

/// Bump `working[idx]`: `attempts + 1`, `not_before = now + delay`.
/// Returns the sleep duration.
fn bump_entry(
    working: &mut [QueueEntry],
    idx: usize,
    now: time::OffsetDateTime,
) -> Result<Duration, UploadError> {
    let entry = &mut working[idx];
    entry.attempts = entry.attempts.saturating_add(1);
    let delay_secs = backoff_delay_secs(entry.attempts);
    let next = now
        .checked_add(time::Duration::seconds(delay_secs as i64))
        .ok_or_else(|| {
            UploadError::Time(
                entry.not_before.clone(),
                "timestamp out of range".to_string(),
            )
        })?;
    entry.not_before = next
        .format(&Rfc3339)
        .map_err(|err| UploadError::Time(entry.not_before.clone(), err.to_string()))?;
    Ok(Duration::from_secs(delay_secs))
}

/// Record `complete = true` in `sessions/<ulid>/upload.json`, atomically.
fn mark_complete(spool: &Spool, ulid: &str) -> Result<(), UploadError> {
    let mut state = spool.read_upload(ulid)?;
    state.complete = true;
    let bytes = serde_json::to_vec_pretty(&state).expect("UploadState serializes");
    crate::spool::atomic_write(
        &spool.root.join("sessions").join(ulid).join("upload.json"),
        &bytes,
    )?;
    Ok(())
}

/// One-line dry-run plan for an entry.
pub fn describe(entry: &QueueEntry) -> String {
    match entry.op {
        QueueOp::Meta => format!("PUT sessions/{}", entry.ulid),
        QueueOp::Segment => format!(
            "PUT sessions/{}/segments/{}",
            entry.ulid,
            entry
                .segment
                .map_or_else(|| "?".to_string(), |n| n.to_string())
        ),
        QueueOp::Complete => format!("POST sessions/{}/complete", entry.ulid),
        QueueOp::Links => format!("POST sessions/{}/links", entry.ulid),
    }
}
