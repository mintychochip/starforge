//! Session upload domain logic (spec §6-§7): authorization plus the four ingest
//! operations behind the upload routes. Handlers authenticate (scope check) and
//! delegate here; no route touches `Db` or the blob store directly.
//!
//! D3 lands the auth seam, the storage plumbing, and shape validation. D4 adds
//! hash/size/sequence validation, D5 the quarantine re-scan.

use std::collections::HashSet;

use starforge_format::{FormatError, SessionMeta, blake3_hex, decompress_bounded, parse_event};
use starforged_db::sessions::{self as db_sessions, NewSession, SessionRow};
use ulid::Ulid;

use crate::accounts::User;
use crate::jobs::Job;
use crate::permission::Permission;
use crate::quota;
use crate::repos::RepoAccess;
use crate::tokens::TokenAuth;
use crate::{Core, CoreConfig, CoreError, CoreResult};

/// Proof that an authenticated caller may upload sessions to a repository.
#[derive(Debug, Clone)]
pub struct IngestAuth {
    pub user: User,
    pub access: RepoAccess,
}

/// Outcome of a segment `PUT`: the stored row, or the stored hash when the
/// segment number already holds different bytes (the route answers `409`).
#[derive(Debug, Clone)]
pub enum SegmentPut {
    Stored(SessionRow),
    /// Same bytes already recorded: a re-sync no-op.
    Unchanged(SessionRow),
    Conflict {
        session: SessionRow,
        stored_hash: String,
    },
}

/// One blob recorded by [`Core::store_segment`].
#[derive(Debug, Clone)]
pub struct StoredBlob {
    pub hash: String,
    pub size: u64,
}

impl Core {
    /// Session-write guard: the uploader or a repo admin may mutate the
    /// session (metadata, segments, lifecycle, links). Any other writer who
    /// knows the ULID gets `Forbidden` — without this, a stranger could
    /// append segments to someone else's session, complete it, file commit
    /// links, or squat segment numbers so the uploader's bytes 409 forever.
    /// Takes `&IngestAuth` (not `&TokenAuth`) because the caller's effective
    /// repo permission is already resolved on `access` by `authorize_upload`.
    fn authorize_session_write(session: &SessionRow, auth: &IngestAuth) -> CoreResult<()> {
        if session.uploader_id == auth.user.id || auth.access.permission >= Permission::Admin {
            return Ok(());
        }
        Err(CoreError::Forbidden)
    }

    /// Authorizes a session upload: the caller must have effective `write` or
    /// above on the repository. Unknown repositories and repositories invisible
    /// to the caller answer `NotFound` (so private repositories stay
    /// undiscoverable); visible-but-insufficient repositories answer `Forbidden`.
    ///
    /// NOTE (§6.4 open-change exception): once Trails exist (M2), the author of
    /// an open change may upload without `write`; that exception plugs in here
    /// without a route change. Until then every non-writer gets `403`.
    pub async fn authorize_upload(
        &self,
        auth: &TokenAuth,
        owner: &str,
        name: &str,
    ) -> CoreResult<IngestAuth> {
        let access = self
            .require_repo(Some(&auth.user), owner, name, Permission::Write)
            .await?;
        Ok(IngestAuth {
            user: auth.user.clone(),
            access,
        })
    }

    /// Creates the session row for `ulid`, or refreshes its metadata when the
    /// CLI re-PUTs it. Returns the row and whether it was created. The body
    /// must parse as Trace Format v1 metadata: the path ULID must equal
    /// `meta.id`, and the format tag, agent, ULIDs, and timestamps must be
    /// known shapes. A re-PUT by a different user requires repo-admin
    /// permission; uploader ownership stays pinned to the creator. The
    /// lifecycle and quarantine are preserved on re-PUT (a `complete` session
    /// stays complete).
    pub async fn upsert_session_meta(
        &self,
        auth: &IngestAuth,
        ulid: &str,
        meta: &serde_json::Value,
    ) -> CoreResult<(SessionRow, bool)> {
        let raw = serde_json::to_string(meta)
            .map_err(|_| CoreError::Invalid("session metadata must be a JSON object".into()))?;
        let parsed = SessionMeta::parse(&raw)
            .map_err(|e| CoreError::Invalid(format!("invalid session metadata: {e}")))?;
        let path_ulid = Ulid::from_string(ulid)
            .map_err(|_| CoreError::Invalid("invalid session ULID".into()))?;
        if path_ulid != parsed.id {
            return Err(CoreError::Invalid(
                "session id in body must match the URL".into(),
            ));
        }
        let repo_id = auth.access.repo.id;
        let models = stringify(meta.get("models"));
        let files_touched = stringify(meta.get("files_touched"));
        let redaction_counts = stringify(meta.get("redaction_counts"));
        let new = session_from_meta(
            repo_id,
            auth.user.id,
            ulid,
            meta,
            "receiving",
            &models,
            &files_touched,
            &redaction_counts,
        );
        match db_sessions::session_by_ulid(self.db(), repo_id, ulid).await? {
            None => {
                let id = db_sessions::insert_session(self.db(), &new).await?;
                // Trailers may have arrived before the upload (push first, sync later):
                // point those rows at the session now that it exists.
                db_sessions::backfill_trailer_session_id(self.db(), repo_id, ulid, id).await?;
                let row = db_sessions::session_by_ulid(self.db(), repo_id, ulid)
                    .await?
                    .ok_or_else(|| CoreError::Internal("session vanished after insert".into()))?;
                debug_assert_eq!(row.id, id);
                Ok((row, true))
            }
            Some(existing) => {
                Self::authorize_session_write(&existing, auth)?;
                let mut updated = session_from_meta(
                    repo_id,
                    existing.uploader_id,
                    ulid,
                    meta,
                    &existing.lifecycle,
                    &models,
                    &files_touched,
                    &redaction_counts,
                );
                // Re-PUT never moves quarantine or uploader ownership, and never
                // drops server-merged redaction counts the metadata refresh did
                // not observe.
                updated.quarantine = existing.quarantine.as_str();
                if !existing.redaction_counts.is_empty() {
                    updated.redaction_counts = existing.redaction_counts.as_str();
                }
                db_sessions::update_session_meta(self.db(), existing.id, &updated).await?;
                db_sessions::backfill_trailer_session_id(self.db(), repo_id, ulid, existing.id)
                    .await?;
                let row = db_sessions::session_by_ulid(self.db(), repo_id, ulid)
                    .await?
                    .ok_or_else(|| CoreError::Internal("session vanished after update".into()))?;
                Ok((row, false))
            }
        }
    }

    /// Stores raw segment bytes in the blob store and records the blob row
    /// (refcounted, so identical bytes across sessions share one file).
    /// D4 finishes this with hash/size validation against the request header.
    pub async fn store_segment(&self, bytes: &[u8]) -> CoreResult<StoredBlob> {
        let stored = self
            .config()
            .blob_store
            .put(bytes)
            .await
            .map_err(|e| CoreError::Internal(format!("storing segment bytes: {e}")))?;
        let size = i64::try_from(bytes.len())
            .map_err(|_| CoreError::Invalid("segment body is too large".into()))?;
        db_sessions::blob_incref(self.db(), &stored.hash, size, &stored.hash).await?;
        Ok(StoredBlob {
            hash: stored.hash,
            size: stored.size,
        })
    }

    /// Records segment `n` of `ulid`: checks append-only numbering, quotas, the
    /// claimed BLAKE3, and the event content, then stores the compressed bytes
    /// in the blob store (refcounted) and inserts the segment row with the
    /// event sequence range. An identical re-upload of a stored number is a
    /// no-op success (no quota, blob, or row changes); different bytes at the
    /// same number report the stored hash.
    pub async fn put_segment(
        &self,
        auth: &IngestAuth,
        ulid: &str,
        n: i64,
        bytes: &[u8],
        claimed_hex: Option<String>,
    ) -> CoreResult<SegmentPut> {
        if n < 0 {
            return Err(CoreError::Invalid("segment numbers start at 0".into()));
        }
        let repo_id = auth.access.repo.id;
        let session = db_sessions::session_by_ulid(self.db(), repo_id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        // Before the idempotency branches: the `Conflict` hash is still a
        // stored-secret oracle, and every later path writes.
        Self::authorize_session_write(&session, auth)?;
        let stored_segments = db_sessions::segments_of(self.db(), session.id).await?;
        let expected = stored_segments.len() as i64;
        let actual_hex = blake3_hex(bytes);
        if n < expected {
            // Idempotency territory: identical bytes are a no-op (reads only,
            // so quota pressure never breaks a re-sync); different bytes
            // report the stored hash. This also covers `complete` sessions.
            let existing = db_sessions::segment_by_n(self.db(), session.id, n)
                .await?
                .ok_or_else(|| CoreError::Internal("segment row vanished".into()))?;
            if actual_hex == existing.blob_hash {
                return Ok(SegmentPut::Unchanged(session));
            }
            return Ok(SegmentPut::Conflict {
                session,
                stored_hash: existing.blob_hash,
            });
        }
        if n > expected {
            return Err(CoreError::Invalid(format!(
                "segment {n} is out of order: next expected segment is {expected}"
            )));
        }
        // A finished session only accepts re-syncs of identical bytes (handled
        // above); new content is rejected.
        if session.lifecycle == "complete" {
            return Err(CoreError::Invalid("session is complete".into()));
        }
        quota::check_rate_limit()?;
        quota::check_storage_quotas(self, auth.user.id, repo_id, bytes.len() as u64).await?;
        quota::check_hourly_volume(self, auth.user.id, bytes.len() as u64).await?;
        match claimed_hex {
            Some(claimed) if claimed == actual_hex => {}
            Some(_) => {
                return Err(CoreError::Invalid(
                    "X-Starforge-Blake3 does not match the request body".into(),
                ));
            }
            None => {
                return Err(CoreError::Invalid(
                    "missing X-Starforge-Blake3 header".into(),
                ));
            }
        }
        let text = decompress_segment_text(self.config(), bytes)?;
        let (seq_start, seq_end) = segment_seq_range(&text)?;
        if let Some(prev_end) = stored_segments.iter().map(|s| s.seq_end).max()
            && seq_start <= prev_end
        {
            return Err(CoreError::Invalid(format!(
                "segment sequence range {seq_start}..={seq_end} overlaps stored events ending at {prev_end}"
            )));
        }
        // The re-scan runs on the decompressed, already-validated JSONL before
        // the segment row is committed; a hit quarantines the session below
        // without rejecting the bytes.
        let compiled = self.scan_rules_for(repo_id).await?;
        let scan = crate::rescan::scan_segment_text(&compiled, &text, n);
        let stored = self.store_segment(bytes).await?;
        debug_assert_eq!(stored.hash, actual_hex);
        match db_sessions::insert_segment(
            self.db(),
            session.id,
            n,
            seq_start,
            seq_end,
            &stored.hash,
            i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        )
        .await
        {
            Ok(_) => {
                let accepted = db_sessions::session_by_ulid(self.db(), repo_id, ulid)
                    .await?
                    .ok_or_else(|| CoreError::Internal("session vanished after insert".into()))?;
                self.merge_scan_counts(&accepted, &scan.counts).await?;
                if let Some(hit) = &scan.first_hit {
                    self.apply_quarantine_hit(Some(auth.user.id), &accepted, hit)
                        .await?;
                }
                let done = db_sessions::session_by_ulid(self.db(), repo_id, ulid)
                    .await?
                    .ok_or_else(|| CoreError::Internal("session vanished after insert".into()))?;
                self.enqueue_ingest_jobs(&done).await?;
                Ok(SegmentPut::Stored(done))
            }
            Err(e) if e.is_unique_violation() => {
                // A concurrent upload won the race: drop our extra refcount so
                // exactly one ref is held per accepted segment, then report
                // what is stored now.
                db_sessions::blob_decref(self.db(), &stored.hash).await?;
                let current = db_sessions::segment_by_n(self.db(), session.id, n)
                    .await?
                    .ok_or(CoreError::Internal(
                        "segment vanished after conflict".into(),
                    ))?;
                if current.blob_hash == stored.hash {
                    Ok(SegmentPut::Stored(session))
                } else {
                    Ok(SegmentPut::Conflict {
                        session,
                        stored_hash: current.blob_hash,
                    })
                }
            }
            Err(e) => {
                db_sessions::blob_decref(self.db(), &stored.hash).await?;
                Err(e.into())
            }
        }
    }

    /// Marks the session `complete`. Idempotent: completing twice succeeds.
    pub async fn complete_session(&self, auth: &IngestAuth, ulid: &str) -> CoreResult<SessionRow> {
        let session = db_sessions::session_by_ulid(self.db(), auth.access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        Self::authorize_session_write(&session, auth)?;
        if session.lifecycle != "complete" {
            db_sessions::set_lifecycle(self.db(), session.id, "complete").await?;
        }
        db_sessions::session_by_ulid(self.db(), auth.access.repo.id, ulid)
            .await?
            .ok_or_else(|| CoreError::Internal("session vanished after complete".into()))
    }

    /// Records the CLI's commit claims through D1's `upsert_claim_links`.
    /// Every entry is validated up front (`sha` is 40 hexadecimal characters
    /// under `sha` or the CLI's `commit` key, confidence is known, the
    /// sequence range is sane), so a bad entry rejects the whole batch with
    /// no partial insert; the validated rows then commit in one transaction,
    /// so a mid-batch database failure rolls everything back. Duplicate SHAs
    /// in one payload dedupe to a single row; re-posts merge idempotently.
    /// Returns the accepted count.
    pub async fn claim_links(
        &self,
        auth: &IngestAuth,
        ulid: &str,
        links: &[serde_json::Value],
    ) -> CoreResult<usize> {
        let session = db_sessions::session_by_ulid(self.db(), auth.access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        Self::authorize_session_write(&session, auth)?;
        let mut seen = HashSet::new();
        let mut valid = Vec::with_capacity(links.len());
        for link in links {
            let sha = link
                .get("sha")
                .or_else(|| link.get("commit"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CoreError::Invalid("link entries need a sha".into()))?;
            if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(CoreError::Invalid(
                    "link sha must be 40 hexadecimal characters".into(),
                ));
            }
            let confidence = link
                .get("confidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("heuristic");
            if !matches!(confidence, "exact" | "heuristic") {
                return Err(CoreError::Invalid(format!(
                    "unknown link confidence '{confidence}'"
                )));
            }
            let seq_start = link_seq(link, "seq_start")?;
            let seq_end = link_seq(link, "seq_end")?;
            if let (Some(start), Some(end)) = (seq_start, seq_end)
                && start > end
            {
                return Err(CoreError::Invalid(
                    "link seq_start must not exceed seq_end".into(),
                ));
            }
            if seen.insert(sha.to_owned()) {
                valid.push(ValidatedLink {
                    sha: sha.to_owned(),
                    confidence: confidence.to_owned(),
                    seq_start,
                    seq_end,
                });
            }
        }
        let batch: Vec<db_sessions::ClaimLinkUpsert<'_>> = valid
            .iter()
            .map(|entry| db_sessions::ClaimLinkUpsert {
                sha: &entry.sha,
                confidence: &entry.confidence,
                seq_start: entry.seq_start,
                seq_end: entry.seq_end,
            })
            .collect();
        db_sessions::upsert_claim_links(self.db(), auth.access.repo.id, session.id, ulid, &batch)
            .await?;
        Ok(valid.len())
    }
    /// Records one trailer row per `Starforge-Session: <ULID>` trailer found in
    /// each commit message. `commits` pairs the full commit SHA with the full
    /// message; malformed SHAs and invalid ULIDs are skipped with a warning and
    /// never fail a push. Trailer-first rows carry a `NULL` session id until
    /// the upload arrives, when [`Core::upsert_session_meta`] backfills it.
    /// Idempotent: re-scanning the same commit touches the same rows.
    /// Returns the distinct trailer links recorded.
    pub async fn record_trailer_links(
        &self,
        repo_id: i64,
        commits: &[(String, String)],
    ) -> CoreResult<usize> {
        let mut seen = HashSet::new();
        let mut recorded = 0;
        for (sha, message) in commits {
            if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                tracing::warn!(%sha, "trailer scan: skipping malformed commit sha");
                continue;
            }
            for ulid in trailer_ulids(message) {
                if seen.insert((sha.clone(), ulid.clone())) {
                    db_sessions::upsert_trailer_link(self.db(), repo_id, &ulid, sha).await?;
                    recorded += 1;
                }
            }
        }
        Ok(recorded)
    }

    /// Recomputes the segment-derived counters for `session_id` from its
    /// segment events: one turn per `user_message`, one tool call per
    /// `tool_call`, and the summed `usage` objects of `assistant_message`
    /// events. Unknown sessions (already purged) succeed with zeros; corrupt
    /// blobs fail the job so the queue retries with backoff. Idempotent:
    /// recomputing twice writes the same values.
    pub async fn update_session_stats(&self, session_id: i64) -> CoreResult<SessionStats> {
        if db_sessions::session_by_id(self.db(), session_id)
            .await?
            .is_none()
        {
            return Ok(SessionStats::default());
        }
        let limit = usize::try_from(self.config().max_decompressed_bytes).unwrap_or(usize::MAX);
        let mut stats = SessionStats::default();
        for segment in db_sessions::segments_of(self.db(), session_id).await? {
            let bytes = self
                .config()
                .blob_store
                .get_by_hash(&segment.blob_hash)
                .await
                .map_err(|e| {
                    CoreError::Internal(format!(
                        "stats: reading segment {} blob {}: {e}",
                        segment.n, segment.blob_hash
                    ))
                })?;
            let raw = starforge_format::decompress_bounded(&bytes, limit).map_err(|e| {
                CoreError::Internal(format!("stats: decompressing segment {}: {e}", segment.n))
            })?;
            let text = String::from_utf8(raw).map_err(|e| {
                CoreError::Internal(format!("stats: segment {} is not UTF-8: {e}", segment.n))
            })?;
            for (index, line) in text.split('\n').enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let event = match parse_event(line) {
                    Ok(event) => event,
                    Err(err) => {
                        tracing::warn!(
                            session_id,
                            segment = segment.n,
                            line = index + 1,
                            error = %err,
                            "stats: skipping unparseable event line"
                        );
                        continue;
                    }
                };
                match &event.kind {
                    starforge_format::EventKind::UserMessage(_) => stats.turn_count += 1,
                    starforge_format::EventKind::ToolCall(_) => stats.tool_call_count += 1,
                    starforge_format::EventKind::AssistantMessage(message) => {
                        stats.usage_input = stats
                            .usage_input
                            .saturating_add(as_i64(message.usage.input));
                        stats.usage_output = stats
                            .usage_output
                            .saturating_add(as_i64(message.usage.output));
                        stats.usage_cache_read = stats
                            .usage_cache_read
                            .saturating_add(as_i64(message.usage.cache_read));
                        stats.usage_cache_write = stats
                            .usage_cache_write
                            .saturating_add(as_i64(message.usage.cache_write));
                        stats.usage_reasoning = stats
                            .usage_reasoning
                            .saturating_add(as_i64(message.usage.reasoning));
                    }
                    _ => {}
                }
            }
        }
        db_sessions::set_session_stats(
            self.db(),
            session_id,
            stats.usage_input,
            stats.usage_output,
            stats.usage_cache_read,
            stats.usage_cache_write,
            stats.usage_reasoning,
            stats.turn_count,
            stats.tool_call_count,
        )
        .await?;
        Ok(stats)
    }

    /// Queues the per-segment ingest jobs after a new segment is stored. Queue
    /// failures propagate (the segment write already committed; the jobs rerun
    /// idempotently on the next store or a manual enqueue).
    async fn enqueue_ingest_jobs(&self, session: &SessionRow) -> CoreResult<()> {
        let ulid = session.ulid.clone();
        self.enqueue(&Job::IndexSessionEvents {
            session_id: session.id,
        })
        .await?;
        self.enqueue(&Job::ResolveCommitLinks {
            repo_id: session.repo_id,
            session_ulid: ulid,
        })
        .await?;
        self.enqueue(&Job::UpdateSessionStats {
            session_id: session.id,
        })
        .await?;
        self.enqueue(&Job::SessionWebhookOutbox {
            session_id: session.id,
            event: "segment.stored".to_owned(),
        })
        .await
    }
}

fn number_as_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_u64()
        .and_then(|n| i64::try_from(n).ok())
        .or_else(|| value.as_i64())
}

/// Segment-derived counters recomputed by [`Core::update_session_stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub turn_count: i64,
    pub tool_call_count: i64,
    pub usage_input: i64,
    pub usage_output: i64,
    pub usage_cache_read: i64,
    pub usage_cache_write: i64,
    pub usage_reasoning: i64,
}

/// ULIDs claimed by `Starforge-Session: <ULID>` trailer lines in `message`, in
/// order. Binding with the CLI's `trailer_line`: the value must be exactly 26
/// Crockford characters and parse as a ULID, or the line is ignored.
fn trailer_ulids(message: &str) -> Vec<String> {
    message
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("Starforge-Session: ")?;
            if rest.len() != 26
                || !rest.bytes().all(|b| {
                    matches!(
                        b,
                        b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'
                    )
                })
            {
                return None;
            }
            Ulid::from_string(rest).ok()?;
            Some(rest.to_owned())
        })
        .collect()
}

/// Saturating `u64` → `i64` for usage sums that must fit the sessions columns.
fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// One link entry that passed whole-batch validation, ready to upsert.
struct ValidatedLink {
    sha: String,
    confidence: String,
    seq_start: Option<i64>,
    seq_end: Option<i64>,
}

/// Reads one optional link sequence bound: absent or null means unbounded;
/// anything present must be a non-negative integer.
fn link_seq(link: &serde_json::Value, key: &str) -> CoreResult<Option<i64>> {
    match link.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => match number_as_i64(value).filter(|bound| *bound >= 0) {
            Some(bound) => Ok(Some(bound)),
            None => Err(CoreError::Invalid(format!(
                "link {key} must be a non-negative integer"
            ))),
        },
    }
}

/// Decompresses one segment body with the configured cap. Validation and the
/// D5 re-scan both go through this helper, so an over-cap body answers
/// `Invalid` (422) before anything is stored and the server never
/// materializes more than `limit + 1` bytes per segment.
pub(crate) fn decompress_segment_text(config: &CoreConfig, bytes: &[u8]) -> CoreResult<String> {
    let limit = usize::try_from(config.max_decompressed_bytes).unwrap_or(usize::MAX);
    let raw = decompress_bounded(bytes, limit).map_err(|e| match e {
        FormatError::TooLarge { limit } => {
            CoreError::Invalid(format!("segment decompresses past the {limit}-byte limit"))
        }
        other => CoreError::Invalid(format!("invalid segment body: {other}")),
    })?;
    String::from_utf8(raw)
        .map_err(|_| CoreError::Invalid("segment payload is not valid UTF-8".into()))
}

/// Validates that `text` is a JSONL transcript of `v:1` events and returns
/// the `(min, max)` event sequence numbers. Validation only: the stored form
/// stays the compressed bytes.
fn segment_seq_range(text: &str) -> CoreResult<(i64, i64)> {
    let mut seqs: Vec<u64> = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = parse_event(line).map_err(|e| {
            CoreError::Invalid(format!("invalid event on segment line {}: {e}", index + 1))
        })?;
        seqs.push(event.seq);
    }
    let (Some(min), Some(max)) = (seqs.iter().min(), seqs.iter().max()) else {
        return Err(CoreError::Invalid("segment has no events".into()));
    };
    let start = i64::try_from(*min)
        .map_err(|_| CoreError::Invalid(format!("event seq {min} is out of range")))?;
    let end = i64::try_from(*max)
        .map_err(|_| CoreError::Invalid(format!("event seq {max} is out of range")))?;
    Ok((start, end))
}

/// Builds a [`NewSession`] from the CLI's `SessionMeta` JSON. D3 extracts what
/// the schema needs and defaults the rest; D4 validates the document.
/// Structured values arrive pre-serialized from the caller so every borrow in
/// the row outlives the call.
#[allow(clippy::too_many_arguments)]
fn session_from_meta<'a>(
    repo_id: i64,
    uploader_id: i64,
    ulid: &'a str,
    meta: &'a serde_json::Value,
    lifecycle: &'a str,
    models: &'a str,
    files_touched: &'a str,
    redaction_counts: &'a str,
) -> NewSession<'a> {
    NewSession {
        repo_id,
        ulid,
        uploader_id,
        agent_name: meta_str(meta, &["agent", "name"]),
        agent_version: meta_str(meta, &["agent", "version"]),
        models,
        title: meta_str(meta, &["title"]),
        branch: meta_str(meta, &["branch"]),
        head_sha: meta_str(meta, &["head_sha"]),
        started_at: 0,
        ended_at: None,
        parent_ulid: meta_str_opt(meta, &["parent_id"]),
        usage_input: 0,
        usage_output: 0,
        usage_cache_read: 0,
        usage_cache_write: 0,
        usage_reasoning: 0,
        files_touched,
        turn_count: 0,
        tool_call_count: 0,
        lifecycle,
        quarantine: "none",
        quarantine_reason: "",
        quarantine_detail: "",
        visibility: "inherit",
        raw_enabled: 0,
        redaction_fingerprint: meta_str(meta, &["redaction", "fingerprint"]),
        redaction_counts,
        capture_mode: meta_str(meta, &["capture", "mode"]),
        cli_version: meta_str(meta, &["cli_version"]),
        adapter_verified: 0,
    }
}

fn meta_lookup<'a>(meta: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut value = meta;
    for key in path {
        value = value.get(*key)?;
    }
    Some(value)
}

fn meta_str<'a>(meta: &'a serde_json::Value, path: &[&str]) -> &'a str {
    meta_lookup(meta, path)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

fn meta_str_opt<'a>(meta: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    meta_lookup(meta, path).and_then(serde_json::Value::as_str)
}

/// Re-serializes the sub-document at `key` (`""` when absent or null).
fn stringify(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::{Fixture, test_core, user};
    use crate::tokens::Scope;

    const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
    const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";

    fn meta(ulid: &str) -> serde_json::Value {
        serde_json::json!({
            "format": "starforge.session/v1",
            "id": ulid,
            "agent": {"name": "claude-code", "version": "1.0"},
            "models": ["opus"],
            "title": "test session",
            "started_at": "2026-11-04T00:00:00Z",
            "ended_at": null,
            "repo": {},
            "parent_id": null,
            "usage": {},
            "files_touched": [],
            "redaction": {},
            "capture": {"mode": "discovery"},
        })
    }

    async fn ingest_ctx() -> (Core, Fixture, IngestAuth) {
        let (core, f) = test_core().await;
        let alice = user(&core, "alice").await;
        core.create_repo(
            &alice,
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
        let created = core
            .create_token(&alice, "t", &[Scope::SessionUpload], 30)
            .await
            .unwrap();
        let token = core.authenticate_token(&created.secret).await.unwrap();
        let auth = core
            .authorize_upload(&token, "alice", "proj")
            .await
            .unwrap();
        (core, f, auth)
    }

    /// `(sha, confidence, trailer_seen, claim_seen, session_id)` for every link filed under `ulid`.
    async fn link_rows(
        core: &Core,
        repo_id: i64,
        ulid: &str,
    ) -> Vec<(String, String, i64, i64, Option<i64>)> {
        sqlx::query_as::<_, (String, String, i64, i64, Option<i64>)>(
            "SELECT sha, confidence, trailer_seen, claim_seen, session_id FROM commit_links \
             WHERE repo_id = $1 AND session_ulid = $2 ORDER BY sha",
        )
        .bind(repo_id)
        .bind(ulid)
        .fetch_all(core.db().pool())
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn trailer_scan_records_rows_and_claim_merges() {
        let (core, _f, auth) = ingest_ctx().await;
        let repo_id = auth.access.repo.id;
        core.upsert_session_meta(&auth, ULID_A, &meta(ULID_A))
            .await
            .unwrap();
        let sha_a = "ab".repeat(20);
        let sha_b = "cd".repeat(20);
        let message = format!(
            "implement feature\n\nStarforge-Session: {ULID_A}\nStarforge-Session: nope\nStarforge-Session: {ULID_B}\n"
        );
        let n = core
            .record_trailer_links(
                repo_id,
                &[
                    (sha_a.clone(), message.clone()),
                    (sha_b.clone(), "no trailers here\n".to_owned()),
                ],
            )
            .await
            .unwrap();
        assert_eq!(n, 2);
        // The garbage `nope` line is skipped; the trailer-less commit creates nothing.
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM commit_links")
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(total, 2);
        let rows_a = link_rows(&core, repo_id, ULID_A).await;
        assert_eq!(rows_a.len(), 1);
        assert_eq!(
            rows_a[0],
            (sha_a.clone(), "heuristic".to_owned(), 1, 0, None)
        );
        // Re-scanning the same commit is a no-op (no duplicate rows).
        core.record_trailer_links(repo_id, &[(sha_a.clone(), message)])
            .await
            .unwrap();
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM commit_links")
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(total, 2);
        // A later CLI claim merges into the trailer row; the other row is untouched.
        core.claim_links(
            &auth,
            ULID_A,
            &[serde_json::json!({"sha": sha_a, "confidence": "exact", "seq_start": 0, "seq_end": 5})],
        )
        .await
        .unwrap();
        let session_id = db_sessions::session_by_ulid(core.db(), repo_id, ULID_A)
            .await
            .unwrap()
            .unwrap()
            .id;
        assert_eq!(
            link_rows(&core, repo_id, ULID_A).await,
            vec![(sha_a, "exact".to_owned(), 1, 1, Some(session_id))]
        );
        let rows_b = link_rows(&core, repo_id, ULID_B).await;
        assert_eq!(rows_b.len(), 1);
        assert_eq!(rows_b[0].1, "heuristic".to_owned());
        assert_eq!((rows_b[0].2, rows_b[0].3), (1, 0));
    }

    #[tokio::test]
    async fn trailer_first_row_is_backfilled_on_upload() {
        let (core, _f, auth) = ingest_ctx().await;
        let repo_id = auth.access.repo.id;
        // Trailer arrives before any session upload: the row stores with a NULL session id.
        let sha = "ef".repeat(20);
        core.record_trailer_links(
            repo_id,
            &[(
                sha.clone(),
                format!("work\n\nStarforge-Session: {ULID_B}\n"),
            )],
        )
        .await
        .unwrap();
        assert_eq!(
            link_rows(&core, repo_id, ULID_B).await,
            vec![(sha.clone(), "heuristic".to_owned(), 1, 0, None)]
        );
        // The later upload backfills the session id; the later claim merges into the same row.
        let (row, created) = core
            .upsert_session_meta(&auth, ULID_B, &meta(ULID_B))
            .await
            .unwrap();
        assert!(created);
        assert_eq!(
            link_rows(&core, repo_id, ULID_B).await,
            vec![(sha.clone(), "heuristic".to_owned(), 1, 0, Some(row.id))]
        );
        core.claim_links(
            &auth,
            ULID_B,
            &[serde_json::json!({"sha": sha, "confidence": "exact"})],
        )
        .await
        .unwrap();
        assert_eq!(
            link_rows(&core, repo_id, ULID_B).await,
            vec![(sha, "exact".to_owned(), 1, 1, Some(row.id))]
        );
    }

    #[tokio::test]
    async fn claim_before_trailer_still_merges() {
        let (core, _f, auth) = ingest_ctx().await;
        let repo_id = auth.access.repo.id;
        core.upsert_session_meta(&auth, ULID_A, &meta(ULID_A))
            .await
            .unwrap();
        let sha = "ab".repeat(20);
        core.claim_links(
            &auth,
            ULID_A,
            &[serde_json::json!({"sha": sha, "confidence": "exact"})],
        )
        .await
        .unwrap();
        let session_id = db_sessions::session_by_ulid(core.db(), repo_id, ULID_A)
            .await
            .unwrap()
            .unwrap()
            .id;
        assert_eq!(
            link_rows(&core, repo_id, ULID_A).await,
            vec![(sha.clone(), "exact".to_owned(), 0, 1, Some(session_id))]
        );
        // The trailer arriving second flips `trailer_seen` without touching the claim.
        core.record_trailer_links(
            repo_id,
            &[(
                sha.clone(),
                format!("work\n\nStarforge-Session: {ULID_A}\n"),
            )],
        )
        .await
        .unwrap();
        assert_eq!(
            link_rows(&core, repo_id, ULID_A).await,
            vec![(sha, "exact".to_owned(), 1, 1, Some(session_id))]
        );
    }
}
