//! Capture ingest: native transcripts → redacted spool sessions (C7 GAP A).
//!
//! [`ingest`] runs every capture adapter that [`Adapter::detect`]s under
//! `roots`, discovers new or grown sessions, reads the new records, redacts
//! them, and persists them through [`Spool`]: `append_events` for normalized
//! JSONL (split at [`DEFAULT_SEGMENT_CAP`](starforge_format::DEFAULT_SEGMENT_CAP)),
//! [`Spool::write_raw`] for the redacted native slice, `meta.json` updates,
//! cursor updates, and queue entries (`Meta` whenever the session's
//! metadata body hash differs from `upload.json`'s `meta_hash`, `Segment`
//! per new segment, `Complete` when the 24 h idle rule fires; `Links` stays
//! with `post-commit`).
//!
//! Redaction happens BEFORE storage: both the normalized events
//! ([`redact_event`](starforge_redact::redact_event)) and the raw native slice
//! ([`redact_text`](starforge_redact::redact_text)) are scrubbed with the
//! repo's effective rules, and the rule-set fingerprint lands in
//! `meta.redaction`. A session ends when its last event is older than 24 h
//! relative to the caller-supplied `now` (adapters expose no end signal).
//! Because discovery skips transcripts that have not grown, the batch path
//! alone cannot end a session ingested while active once its transcript
//! stops growing; an idle sweep at the end of [`ingest`] therefore ends
//! every spooled session whose cursor `last_event_at` is at least 24 h
//! before `now` (records without `last_event_at`, spooled by older CLIs,
//! are left alone).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use starforge_capture::{Adapter, Roots};
use starforge_format::{AgentName, Event, EventKind, SessionMeta, Usage};
use time::OffsetDateTime;

/// Ingest outcome.
#[derive(Debug, Clone, Default)]
pub struct IngestStats {
    /// Native sessions seen (new or grown).
    pub sessions: usize,
    /// New normalized events appended.
    pub new_events: usize,
    /// New segments written.
    pub new_segments: usize,
    /// Queue entries enqueued.
    pub enqueued: usize,
}

/// Ingest failures.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// Native transcript unreadable.
    #[error("capture error: {0}")]
    Capture(#[from] starforge_capture::CaptureError),
    /// Spool failure.
    #[error(transparent)]
    Spool(#[from] crate::spool::SpoolError),
    /// Queue failure.
    #[error(transparent)]
    Queue(#[from] crate::queue::QueueError),
    /// Filesystem failure outside the spool.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The caller-supplied `now` did not format as RFC 3339.
    #[error("bad timestamp: {0}")]
    Time(String),
}

/// Object-safe slice of [`Adapter`] for the ingest loop (the trait itself is
/// not `dyn`-compatible because of its associated const).
trait IngestAdapter {
    fn id(&self) -> AgentName;
    fn detect(&self, roots: &Roots) -> bool;
    fn discover(
        &self,
        roots: &Roots,
        known: &HashMap<String, starforge_capture::Cursor>,
    ) -> Vec<starforge_capture::Candidate>;
    fn read(
        &self,
        candidate: &starforge_capture::Candidate,
        cursor: &starforge_capture::Cursor,
        fallback_ts: &str,
    ) -> Result<starforge_capture::ReadOutput, starforge_capture::CaptureError>;
}

impl<T: Adapter> IngestAdapter for T {
    fn id(&self) -> AgentName {
        <Self as Adapter>::id(self)
    }
    fn detect(&self, roots: &Roots) -> bool {
        <Self as Adapter>::detect(self, roots)
    }
    fn discover(
        &self,
        roots: &Roots,
        known: &HashMap<String, starforge_capture::Cursor>,
    ) -> Vec<starforge_capture::Candidate> {
        <Self as Adapter>::discover(self, roots, known)
    }
    fn read(
        &self,
        candidate: &starforge_capture::Candidate,
        cursor: &starforge_capture::Cursor,
        fallback_ts: &str,
    ) -> Result<starforge_capture::ReadOutput, starforge_capture::CaptureError> {
        <Self as Adapter>::read(self, candidate, cursor, fallback_ts)
    }
}

/// Kebab-case agent key used in `cursors.json` (`"<agent>/<session_key>"`).
fn agent_key(name: &AgentName) -> &'static str {
    match name {
        AgentName::ClaudeCode => "claude-code",
        AgentName::Codex => "codex",
        AgentName::Pi => "pi",
        AgentName::Opencode => "opencode",
        AgentName::Gemini => "gemini",
    }
}

fn op_present(
    queued: &HashSet<(u8, String, Option<u64>)>,
    op: u8,
    ulid: &str,
    segment: Option<u64>,
) -> bool {
    queued.contains(&(op, ulid.to_string(), segment))
}

/// End `meta` at `last_event_at` when it is idle at least 24 h before
/// `now_rfc3339`. Returns `true` when the session was ended. The single
/// implementation of the rule, shared by the batch path and the idle sweep.
fn end_at_last_if_idle(meta: &mut SessionMeta, last_event_at: &str, now_rfc3339: &str) -> bool {
    if meta.ended_at.is_some() {
        return false;
    }
    let (Some(last_dt), Some(now_dt)) = (parse_ts(last_event_at), parse_ts(now_rfc3339)) else {
        return false;
    };
    if now_dt - last_dt < time::Duration::hours(24) {
        return false;
    }
    meta.ended_at = Some(last_event_at.to_string());
    true
}

/// Enqueue one op unless the queue already holds a matching entry (the
/// `queued` set is seeded from the spool queue at sweep start).
fn enqueue_op(
    spool: &crate::spool::Spool,
    op: crate::queue::QueueOp,
    segment: Option<u64>,
    ulid: &str,
    now_rfc3339: &str,
    queued: &mut HashSet<(u8, String, Option<u64>)>,
    stats: &mut IngestStats,
) -> Result<(), IngestError> {
    let disc = match op {
        crate::queue::QueueOp::Meta => 0,
        crate::queue::QueueOp::Segment => 1,
        crate::queue::QueueOp::Complete => 2,
        crate::queue::QueueOp::Links => 3,
    };
    if !op_present(queued, disc, ulid, segment) {
        crate::queue::enqueue(
            spool,
            crate::queue::QueueEntry {
                op,
                ulid: ulid.to_string(),
                repo: String::new(),
                segment,
                attempts: 0,
                not_before: now_rfc3339.to_string(),
            },
        )?;
        queued.insert((disc, ulid.to_string(), segment));
        stats.enqueued += 1;
    }
    Ok(())
}

/// Queue `Complete` for an ended session unless the upload state already
/// marks it complete, with the same `queued` dedupe as the batch path.
fn queue_complete(
    spool: &crate::spool::Spool,
    ulid: &str,
    now_rfc3339: &str,
    queued: &mut HashSet<(u8, String, Option<u64>)>,
    stats: &mut IngestStats,
) -> Result<(), IngestError> {
    let state = spool.read_upload(ulid)?;
    if !state.complete {
        enqueue_op(
            spool,
            crate::queue::QueueOp::Complete,
            None,
            ulid,
            now_rfc3339,
            queued,
            stats,
        )?;
    }
    Ok(())
}

/// Queue `Meta` whenever the spool meta's body hash differs from
/// `upload.json`'s `meta_hash` (`None` or different), with the same
/// `queued` dedupe as the batch path.
fn queue_meta(
    spool: &crate::spool::Spool,
    ulid: &str,
    meta: &SessionMeta,
    now_rfc3339: &str,
    queued: &mut HashSet<(u8, String, Option<u64>)>,
    stats: &mut IngestStats,
) -> Result<(), IngestError> {
    let state = spool.read_upload(ulid)?;
    let hash = crate::spool::meta_body_hash(meta)?;
    if state.meta_hash.as_deref() != Some(hash.as_str()) {
        enqueue_op(
            spool,
            crate::queue::QueueOp::Meta,
            None,
            ulid,
            now_rfc3339,
            queued,
            stats,
        )?;
    }
    Ok(())
}

/// File paths carried by one normalized event (mirrors the trailer logic).
fn event_files(event: &Event) -> Vec<String> {
    match &event.kind {
        EventKind::FileChange(change) => vec![change.path.clone()],
        EventKind::ToolCall(call) => {
            let name = call.tool.name.to_lowercase();
            if !matches!(name.as_str(), "edit" | "write" | "patch") {
                return Vec::new();
            }
            let Some(obj) = call.tool.input.as_object() else {
                return Vec::new();
            };
            ["path", "file", "file_path", "filename", "filepath"]
                .into_iter()
                .filter_map(|key| obj.get(key).and_then(|v| v.as_str()).map(str::to_string))
                .collect()
        }
        _ => Vec::new(),
    }
}

fn parse_ts(ts: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339).ok()
}

/// Scrub a free-text meta field; counts merge into the caller's map.
fn redact_str(
    compiled: &starforge_redact::Compiled,
    text: &str,
    counts: &mut BTreeMap<String, u64>,
) -> String {
    let (redacted, c) = starforge_redact::redact_text(compiled, text);
    for (k, v) in c {
        *counts.entry(k).or_insert(0) += v;
    }
    redacted
}

/// Whether raw native slices may be captured for `agent`.
///
/// Raw slices are byte ranges `[cursor.offset, next.offset)` into an
/// append-only native file, so they are only meaningful when the cursor
/// offset is a byte offset into a JSONL append-only transcript
/// (claude-code, codex, pi). Gemini rewrites the whole chat JSON document
/// on growth (`offset` is the whole-document length; the slice would be the
/// entire document, not the incremental delta). OpenCode is a SQLite store
/// whose cursor `offset` is the largest consumed message `seq`, not a byte
/// offset; slicing the database file would leak arbitrary SQLite page bytes
/// from every session into one session's spool.
fn raw_slice_eligible(agent: &AgentName) -> bool {
    matches!(
        agent,
        AgentName::ClaudeCode | AgentName::Codex | AgentName::Pi
    )
}

/// Discover → read → redact → spool for every detecting adapter, each with
/// its own [`Roots`] (keyed by agent key: `claude-code`, `codex`, `pi`,
/// `opencode`, `gemini`; adapters without a roots entry are skipped).
///
/// `repo_root` scopes discovery (each roots' `worktree` should equal it)
/// and supplies the redaction rules plus `RepoInfo`. `now` is
/// caller-supplied (production passes `OffsetDateTime::now_utc()`); it
/// stamps `fallback_ts`, queue `not_before`, and the 24 h idle rule.
pub fn ingest(
    spool: &crate::spool::Spool,
    roots: &BTreeMap<String, Roots>,
    repo_root: &Path,
    now: OffsetDateTime,
) -> Result<IngestStats, IngestError> {
    use starforge_capture::agents::{
        ClaudeAdapter, CodexAdapter, GeminiAdapter, OpencodeAdapter, PiAdapter,
    };

    let now_rfc3339 = now
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|err| IngestError::Time(err.to_string()))?;
    let (rules, compiled) = crate::spool::Spool::load_rules(repo_root)?;
    let fingerprint = starforge_redact::fingerprint(&rules);
    let records = spool.cursor_records()?;
    let mut queued: HashSet<(u8, String, Option<u64>)> = crate::queue::read_queue(spool)?
        .iter()
        .map(|e| {
            let disc = match e.op {
                crate::queue::QueueOp::Meta => 0,
                crate::queue::QueueOp::Segment => 1,
                crate::queue::QueueOp::Complete => 2,
                crate::queue::QueueOp::Links => 3,
            };
            (disc, e.ulid.clone(), e.segment)
        })
        .collect();

    let mut stats = IngestStats::default();
    let adapters: Vec<Box<dyn IngestAdapter>> = vec![
        Box::new(ClaudeAdapter),
        Box::new(CodexAdapter),
        Box::new(PiAdapter),
        Box::new(OpencodeAdapter),
        Box::new(GeminiAdapter),
    ];
    for adapter in &adapters {
        let agent = agent_key(&adapter.id()).to_string();
        let Some(roots) = roots.get(&agent) else {
            continue;
        };
        if !adapter.detect(roots) {
            continue;
        }
        let mut known: HashMap<String, starforge_capture::Cursor> = HashMap::new();
        for (key, rec) in &records {
            if let Some(session_key) = key.strip_prefix(&format!("{agent}/")) {
                known.insert(session_key.to_string(), rec.cursor);
            }
        }
        for candidate in adapter.discover(roots, &known) {
            let key = format!("{agent}/{}", candidate.session_key);
            let (ulid, cursor, prev_last) = match spool.read_cursor(&key)? {
                Some(rec) => (rec.ulid, rec.cursor, rec.last_event_at),
                None => (
                    ulid::Ulid::new().to_string(),
                    starforge_capture::Cursor::start(),
                    None,
                ),
            };
            let first_sight = spool.read_meta(&ulid).is_err();
            // Per-candidate failures must not starve later candidates or
            // adapters: warn and move on. Only genuinely global spool/queue
            // failures (below) abort the sweep.
            let out = match adapter.read(&candidate, &cursor, &now_rfc3339) {
                Ok(out) => out,
                Err(err) => {
                    tracing::warn!("ingest: skipping {agent}/{}: {err}", candidate.session_key);
                    continue;
                }
            };
            if out.events.is_empty() {
                if out.next != cursor || first_sight {
                    spool.write_cursor(
                        &key,
                        &ulid,
                        out.next,
                        &candidate.native_path.to_string_lossy(),
                        None,
                    )?;
                }
                continue;
            }
            stats.sessions += 1;
            stats.new_events += out.events.len();

            // `append_events` needs the session dir: create it on first sight.
            // The fold below refreshes the header fields afterwards.
            if first_sight {
                let mut meta_counts: BTreeMap<String, u64> = BTreeMap::new();
                let mut meta = out.header.clone();
                meta.id = ulid.parse().expect("fresh ULID parses");
                // Scrub free-text header fields before they reach the spool:
                // only the redacted copies are ever persisted.
                if let Some(title) = meta.title.clone() {
                    meta.title = if title.trim().is_empty() {
                        None
                    } else {
                        Some(redact_str(&compiled, &title, &mut meta_counts))
                    };
                }
                let version = meta.agent.version.clone();
                meta.agent.version = redact_str(&compiled, &version, &mut meta_counts);
                let remotes = crate::git::remotes(repo_root).unwrap_or_default();
                meta.repo = starforge_format::RepoInfo {
                    // Strip credential userinfo: secrets must never reach the spool.
                    remote_urls: remotes
                        .into_iter()
                        .map(|(_, url)| crate::discovery::sanitize_remote_url(&url))
                        .map(|url| redact_str(&compiled, &url, &mut meta_counts))
                        .collect(),
                    branch: String::new(),
                    head_at_start: crate::git::head_commit(repo_root).unwrap_or_default(),
                };
                meta.files_touched = Vec::new();
                meta.models = Vec::new();
                meta.usage = Usage::default();
                meta.redaction = starforge_format::RedactionSummary {
                    fingerprint: fingerprint.clone(),
                    counts: meta_counts,
                };
                meta.capture.mode = starforge_format::CaptureMode::Discovery;
                meta.capture.cli_version = env!("CARGO_PKG_VERSION").to_string();
                meta.started_at = now_rfc3339.clone();
                meta.ended_at = None;
                spool.put_session(&meta)?;
            }

            let mut counts: BTreeMap<String, u64> = BTreeMap::new();
            let mut lines = Vec::with_capacity(out.events.len());
            let mut redacted_events = Vec::with_capacity(out.events.len());
            for event in &out.events {
                let (redacted, c) = starforge_redact::redact_event(&compiled, event);
                for (k, v) in c {
                    *counts.entry(k).or_insert(0) += v;
                }
                lines.push(serde_json::to_string(&redacted).expect("Event serializes"));
                redacted_events.push(redacted);
            }
            let jsonl = lines.join("\n") + "\n";
            let nums = spool.append_events(
                &ulid,
                &jsonl,
                starforge_format::DEFAULT_SEGMENT_CAP,
                &counts,
            )?;
            stats.new_segments += nums.len();

            // Raw native slice for the newly consumed byte range, redacted as
            // text. Only byte-offset adapters are eligible (see
            // `raw_slice_eligible`): OpenCode/Gemini offsets are not byte
            // offsets into an append-only file. A raw read failure only
            // skips the raw bytes: events are already appended and the meta
            // fold below must still run, otherwise models/usage/counts stay
            // permanently stale for this batch.
            let raw_eligible = raw_slice_eligible(&adapter.id());
            let native = if raw_eligible {
                match std::fs::read(&candidate.native_path) {
                    Ok(native) => Some(native),
                    Err(err) => {
                        tracing::warn!(
                            "ingest: skipping raw slice for {agent}/{}: {err}",
                            candidate.session_key
                        );
                        None
                    }
                }
            } else {
                None
            };
            let mut raw_counts: BTreeMap<String, u64> = BTreeMap::new();
            if let Some(native) = native {
                let start = (cursor.offset as usize).min(native.len());
                let end = (out.next.offset as usize).min(native.len());
                if end > start {
                    let mut raw_lines = Vec::new();
                    for line in String::from_utf8_lossy(&native[start..end]).lines() {
                        let (redacted, c) = starforge_redact::redact_text(&compiled, line);
                        for (k, v) in c {
                            *raw_counts.entry(k).or_insert(0) += v;
                        }
                        raw_lines.push(redacted);
                    }
                    if !raw_lines.is_empty() {
                        let raw = raw_lines.join("\n") + "\n";
                        // One copy per new segment: the raw slice has no per-segment
                        // split, so every new segment carries the full redacted slice.
                        for n in &nums {
                            spool.write_raw(&ulid, *n, raw.as_bytes())?;
                        }
                    }
                }
            }

            // The session dir exists here (created above on first sight), so
            // fold into the stored meta: `append_events` already accumulated
            // the event counts; merge the raw-slice counts too so `meta.json`
            // reports raw hits as well.
            let mut meta = spool.read_meta(&ulid)?;
            meta.capture.mode = starforge_format::CaptureMode::Discovery;
            meta.capture.cli_version = env!("CARGO_PKG_VERSION").to_string();
            meta.redaction.fingerprint = fingerprint.clone();
            for (k, v) in &raw_counts {
                *meta.redaction.counts.entry(k.clone()).or_insert(0) += v;
            }
            let mut models_counts: BTreeMap<String, u64> = BTreeMap::new();
            let mut models = std::collections::HashSet::new();
            for model in &meta.models {
                models.insert(redact_str(&compiled, model, &mut models_counts));
            }
            for model in &out.header.models {
                models.insert(redact_str(&compiled, model, &mut models_counts));
            }
            let mut models: Vec<String> = models.into_iter().collect();
            models.sort();
            meta.models = models;
            let version = if meta.agent.version.is_empty() {
                out.header.agent.version.clone()
            } else {
                meta.agent.version.clone()
            };
            meta.agent.version = redact_str(&compiled, &version, &mut models_counts);
            for (k, v) in &models_counts {
                *meta.redaction.counts.entry(k.clone()).or_insert(0) += v;
            }
            let usage = out.header.usage;
            meta.usage.input = meta.usage.input.max(usage.input);
            meta.usage.output = meta.usage.output.max(usage.output);
            meta.usage.cache_read = meta.usage.cache_read.max(usage.cache_read);
            meta.usage.cache_write = meta.usage.cache_write.max(usage.cache_write);
            meta.usage.reasoning = meta.usage.reasoning.max(usage.reasoning);
            let mut meta_counts: BTreeMap<String, u64> = BTreeMap::new();
            let mut files = std::collections::HashSet::new();
            for f in &meta.files_touched {
                files.insert(redact_str(&compiled, f, &mut meta_counts));
            }
            // Derive from REDACTED events so no unredacted path reaches the spool.
            for event in &redacted_events {
                for f in event_files(event) {
                    files.insert(redact_str(&compiled, &f, &mut meta_counts));
                }
            }
            let mut files: Vec<String> = files.into_iter().collect();
            files.sort();
            meta.files_touched = files;
            // Redact remaining free-text meta fields (branch; remote urls are
            // already sanitized at first sight, redacted defensively here).
            if !meta.repo.branch.is_empty() {
                let branch = meta.repo.branch.clone();
                meta.repo.branch = redact_str(&compiled, &branch, &mut meta_counts);
            }
            let mut urls = Vec::with_capacity(meta.repo.remote_urls.len());
            for url in &meta.repo.remote_urls {
                urls.push(redact_str(&compiled, url, &mut meta_counts));
            }
            meta.repo.remote_urls = urls;
            // Latest non-empty adapter title wins.
            if let Some(title) = &out.header.title
                && !title.trim().is_empty()
            {
                meta.title = Some(redact_str(&compiled, title, &mut meta_counts));
            }
            for (k, v) in &meta_counts {
                *meta.redaction.counts.entry(k.clone()).or_insert(0) += v;
            }
            let mut min_ts = meta.started_at.clone();
            let mut max_ts: Option<String> = None;
            for event in &out.events {
                if event.ts < min_ts {
                    min_ts = event.ts.clone();
                }
                if max_ts.as_deref().is_none_or(|m| event.ts.as_str() > m) {
                    max_ts = Some(event.ts.clone());
                }
            }
            meta.started_at = min_ts;
            let merged_last = match (prev_last, max_ts) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, b) => b,
            };
            if let Some(last) = merged_last.as_deref() {
                end_at_last_if_idle(&mut meta, last, &now_rfc3339);
            }
            spool.put_session(&meta)?;

            queue_meta(spool, &ulid, &meta, &now_rfc3339, &mut queued, &mut stats)?;
            for n in &nums {
                enqueue_op(
                    spool,
                    crate::queue::QueueOp::Segment,
                    Some(*n),
                    &ulid,
                    &now_rfc3339,
                    &mut queued,
                    &mut stats,
                )?;
            }
            if meta.ended_at.is_some() {
                queue_complete(spool, &ulid, &now_rfc3339, &mut queued, &mut stats)?;
            }
            // Cursor advances LAST: every persist above (session dir, segments,
            // raw slices, meta fold, queue entries) succeeded when this runs, so
            // a mid-candidate failure leaves the cursor behind the new records
            // and the next sweep replays them (possible duplicates) instead of
            // skipping them (silent loss). Value is still `out.next`.
            if out.next != cursor || first_sight {
                spool.write_cursor(
                    &key,
                    &ulid,
                    out.next,
                    &candidate.native_path.to_string_lossy(),
                    merged_last.clone(),
                )?;
            }
        }
    }
    // Idle sweep: discovery skips ungrown transcripts, so sessions
    // ingested while active would otherwise stay `receiving` forever once
    // growth stops. End any session whose cursor `last_event_at` is idle
    // at least 24 h before `now`, for every cached record (including
    // agents not detected this run). Records without `last_event_at`
    // (spooled by older CLIs) are left alone.
    for rec in spool.cursor_records()?.values() {
        let Some(last_event_at) = rec.last_event_at.as_deref() else {
            continue;
        };
        let Ok(mut meta) = spool.read_meta(&rec.ulid) else {
            continue;
        };
        if !end_at_last_if_idle(&mut meta, last_event_at, &now_rfc3339) {
            continue;
        }
        spool.put_session(&meta)?;
        queue_meta(
            spool,
            &rec.ulid,
            &meta,
            &now_rfc3339,
            &mut queued,
            &mut stats,
        )?;
        queue_complete(spool, &rec.ulid, &now_rfc3339, &mut queued, &mut stats)?;
    }
    Ok(stats)
}
