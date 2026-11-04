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
}

fn number_as_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_u64()
        .and_then(|n| i64::try_from(n).ok())
        .or_else(|| value.as_i64())
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
