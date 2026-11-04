//! Session upload domain logic (spec §6-§7): authorization plus the four ingest
//! operations behind the upload routes. Handlers authenticate (scope check) and
//! delegate here; no route touches `Db` or the blob store directly.
//!
//! D3 lands the auth seam, the storage plumbing, and shape validation. D4 adds
//! hash/size/sequence validation, D5 the quarantine re-scan.

use starforged_db::sessions::{self as db_sessions, NewSession, SessionRow};

use crate::accounts::User;
use crate::permission::Permission;
use crate::quota;
use crate::repos::RepoAccess;
use crate::tokens::TokenAuth;
use crate::{Core, CoreError, CoreResult};

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
    /// CLI re-PUTs it. Returns the row and whether it was created. The
    /// lifecycle is preserved on re-PUT (a `complete` session stays complete).
    /// Hash/size/sequence validation lands in D4; D3 stores the provided meta.
    pub async fn upsert_session_meta(
        &self,
        auth: &IngestAuth,
        ulid: &str,
        meta: &serde_json::Value,
    ) -> CoreResult<(SessionRow, bool)> {
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
                // D3 never moves quarantine or uploader ownership on re-PUT.
                updated.quarantine = existing.quarantine.as_str();
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

    /// Records segment `n` of `ulid`: stores the bytes, enforces quotas, and
    /// inserts the segment row. An identical re-upload is a no-op success;
    /// different bytes at the same number report the stored hash.
    pub async fn put_segment(
        &self,
        auth: &IngestAuth,
        ulid: &str,
        n: i64,
        bytes: &[u8],
    ) -> CoreResult<SegmentPut> {
        if n < 0 {
            return Err(CoreError::Invalid("segment numbers start at 0".into()));
        }
        let repo_id = auth.access.repo.id;
        let session = db_sessions::session_by_ulid(self.db(), repo_id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        quota::check_rate_limit()?;
        quota::check_storage_quotas(self, auth.user.id, repo_id, bytes.len() as u64).await?;
        quota::check_hourly_volume(self, auth.user.id, bytes.len() as u64).await?;
        // A finished session only accepts re-syncs of identical bytes (spec §6.3).
        if session.lifecycle == "complete" {
            if let Some(existing) = db_sessions::segment_by_n(self.db(), session.id, n).await? {
                if existing.byte_size == bytes.len() as i64 {
                    let stored = self.store_segment_no_ref(bytes).await?;
                    if stored == existing.blob_hash {
                        return Ok(SegmentPut::Unchanged(session));
                    }
                }
                return Ok(SegmentPut::Conflict {
                    session,
                    stored_hash: existing.blob_hash,
                });
            }
            return Err(CoreError::Invalid("session is complete".into()));
        }
        if let Some(existing) = db_sessions::segment_by_n(self.db(), session.id, n).await? {
            if existing.byte_size == bytes.len() as i64 {
                let hash = self.store_segment_no_ref(bytes).await?;
                if hash == existing.blob_hash {
                    return Ok(SegmentPut::Unchanged(session));
                }
            }
            return Ok(SegmentPut::Conflict {
                session,
                stored_hash: existing.blob_hash,
            });
        }
        let stored = self.store_segment(bytes).await?;
        match db_sessions::insert_segment(
            self.db(),
            session.id,
            n,
            0,
            0,
            &stored.hash,
            i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        )
        .await
        {
            Ok(_) => Ok(SegmentPut::Stored(session)),
            Err(e) if e.is_unique_violation() => {
                // A concurrent upload won the race; report what is stored now.
                let current = db_sessions::segment_by_n(self.db(), session.id, n)
                    .await?
                    .ok_or(CoreError::Internal(
                        "segment vanished after conflict".into(),
                    ))?;
                if current.blob_hash == stored.hash {
                    Ok(SegmentPut::Stored(session))
                } else {
                    self.unstore_segment(&stored.hash).await;
                    Ok(SegmentPut::Conflict {
                        session,
                        stored_hash: current.blob_hash,
                    })
                }
            }
            Err(e) => {
                self.unstore_segment(&stored.hash).await;
                Err(e.into())
            }
        }
    }

    /// Marks the session `complete`. Idempotent: completing twice succeeds.
    pub async fn complete_session(&self, auth: &IngestAuth, ulid: &str) -> CoreResult<SessionRow> {
        let session = db_sessions::session_by_ulid(self.db(), auth.access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        if session.lifecycle != "complete" {
            db_sessions::set_lifecycle(self.db(), session.id, "complete").await?;
        }
        db_sessions::session_by_ulid(self.db(), auth.access.repo.id, ulid)
            .await?
            .ok_or_else(|| CoreError::Internal("session vanished after complete".into()))
    }

    /// Records the CLI's commit claims through D1's `upsert_claim_link`.
    /// Entries carry `sha` (the CLI's `LinkEntry.commit` arrives under the same
    /// key); confidence defaults to `heuristic`. Returns accepted count.
    pub async fn claim_links(
        &self,
        auth: &IngestAuth,
        ulid: &str,
        links: &[serde_json::Value],
    ) -> CoreResult<usize> {
        let session = db_sessions::session_by_ulid(self.db(), auth.access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        let mut accepted = 0;
        for link in links {
            let sha = link
                .get("sha")
                .or_else(|| link.get("commit"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CoreError::Invalid("link entries need a sha".into()))?;
            if sha.trim().is_empty() {
                return Err(CoreError::Invalid("link entries need a sha".into()));
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
            let seq_start = link.get("seq_start").and_then(number_as_i64);
            let seq_end = link.get("seq_end").and_then(number_as_i64);
            db_sessions::upsert_claim_link(
                self.db(),
                auth.access.repo.id,
                session.id,
                ulid,
                sha,
                confidence,
                seq_start,
                seq_end,
            )
            .await?;
            accepted += 1;
        }
        Ok(accepted)
    }

    /// Hashes bytes through the blob store without recording a blob row
    /// (idempotent re-upload compare). D4 replaces this with header validation.
    async fn store_segment_no_ref(&self, bytes: &[u8]) -> CoreResult<String> {
        let stored = self
            .config()
            .blob_store
            .put(bytes)
            .await
            .map_err(|e| CoreError::Internal(format!("hashing segment bytes: {e}")))?;
        Ok(stored.hash)
    }

    /// Best-effort cleanup of bytes stored for a losing racer. The blob row was
    /// never increfed, so only the file needs removing; failures are ignored
    /// (the GC sweep reaps unreferenced files).
    async fn unstore_segment(&self, hash: &str) {
        let blob = starforged_blob::BlobRef {
            hash: hash.to_owned(),
            size: 0,
            key: hash.to_owned(),
        };
        let _ = self.config().blob_store.delete(&blob).await;
    }
}

fn number_as_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_u64()
        .and_then(|n| i64::try_from(n).ok())
        .or_else(|| value.as_i64())
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
