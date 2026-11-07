//! `sessions`: ingested CLI sessions, their segments, commit links, and content blobs.
//!
//! The data-access layer stays thin: no validation, quota, or quarantine verdicts here
//! (those live in `starforged-core`, tasks D3+). `raw_blob_hash` on segments is always
//! `NULL` in M1d (Ruling R1); the M1f raw wire fills it with no migration rewrite.

use sqlx::Row;
use sqlx::any::{Any, AnyRow};

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub id: i64,
    pub repo_id: i64,
    pub ulid: String,
    pub uploader_id: i64,
    pub agent_name: String,
    pub agent_version: String,
    pub models: String,
    pub title: String,
    pub branch: String,
    pub head_sha: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub parent_ulid: Option<String>,
    pub usage_input: i64,
    pub usage_output: i64,
    pub usage_cache_read: i64,
    pub usage_cache_write: i64,
    pub usage_reasoning: i64,
    pub files_touched: String,
    pub turn_count: i64,
    pub tool_call_count: i64,
    pub lifecycle: String,
    pub quarantine: String,
    pub quarantine_reason: String,
    pub quarantine_detail: String,
    pub visibility: String,
    pub raw_enabled: i64,
    pub redaction_fingerprint: String,
    pub redaction_counts: String,
    pub capture_mode: String,
    pub cli_version: String,
    pub adapter_verified: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRow {
    pub id: i64,
    pub session_id: i64,
    pub n: i64,
    pub seq_start: i64,
    pub seq_end: i64,
    pub blob_hash: String,
    pub byte_size: i64,
    pub raw_blob_hash: Option<String>,
    pub uploaded_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitLinkRow {
    pub id: i64,
    pub repo_id: i64,
    pub session_ulid: String,
    pub session_id: Option<i64>,
    pub sha: String,
    pub source: String,
    pub confidence: String,
    pub seq_start: Option<i64>,
    pub seq_end: Option<i64>,
    pub trailer_seen: i64,
    pub claim_seen: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRow {
    pub hash: String,
    pub size: i64,
    pub refcount: i64,
    pub backend_key: String,
}

pub struct NewSession<'a> {
    pub repo_id: i64,
    pub ulid: &'a str,
    pub uploader_id: i64,
    pub agent_name: &'a str,
    pub agent_version: &'a str,
    pub models: &'a str,
    pub title: &'a str,
    pub branch: &'a str,
    pub head_sha: &'a str,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub parent_ulid: Option<&'a str>,
    pub usage_input: i64,
    pub usage_output: i64,
    pub usage_cache_read: i64,
    pub usage_cache_write: i64,
    pub usage_reasoning: i64,
    pub files_touched: &'a str,
    pub turn_count: i64,
    pub tool_call_count: i64,
    pub lifecycle: &'a str,
    pub quarantine: &'a str,
    pub quarantine_reason: &'a str,
    pub quarantine_detail: &'a str,
    pub visibility: &'a str,
    pub raw_enabled: i64,
    pub redaction_fingerprint: &'a str,
    pub redaction_counts: &'a str,
    pub capture_mode: &'a str,
    pub cli_version: &'a str,
    pub adapter_verified: i64,
}

macro_rules! select_session {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, ulid, uploader_id, agent_name, agent_version, models, title, branch, head_sha, ",
            "started_at, ended_at, parent_ulid, usage_input, usage_output, usage_cache_read, usage_cache_write, ",
            "usage_reasoning, files_touched, turn_count, tool_call_count, lifecycle, quarantine, quarantine_reason, ",
            "quarantine_detail, visibility, raw_enabled, redaction_fingerprint, redaction_counts, capture_mode, ",
            "cli_version, adapter_verified, created_at, updated_at FROM sessions ",
            $tail
        )
    };
}

macro_rules! select_segment {
    ($tail:literal) => {
        concat!(
            "SELECT id, session_id, n, seq_start, seq_end, blob_hash, byte_size, raw_blob_hash, uploaded_at ",
            "FROM segments ",
            $tail
        )
    };
}

macro_rules! select_link {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, session_ulid, session_id, sha, source, confidence, seq_start, seq_end, ",
            "trailer_seen, claim_seen FROM commit_links ",
            $tail
        )
    };
}

fn session_from_row(row: &AnyRow) -> DbResult<SessionRow> {
    Ok(SessionRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        ulid: row.try_get("ulid")?,
        uploader_id: row.try_get("uploader_id")?,
        agent_name: row.try_get("agent_name")?,
        agent_version: row.try_get("agent_version")?,
        models: row.try_get("models")?,
        title: row.try_get("title")?,
        branch: row.try_get("branch")?,
        head_sha: row.try_get("head_sha")?,
        started_at: row.try_get("started_at")?,
        ended_at: row.try_get("ended_at")?,
        parent_ulid: row.try_get("parent_ulid")?,
        usage_input: row.try_get("usage_input")?,
        usage_output: row.try_get("usage_output")?,
        usage_cache_read: row.try_get("usage_cache_read")?,
        usage_cache_write: row.try_get("usage_cache_write")?,
        usage_reasoning: row.try_get("usage_reasoning")?,
        files_touched: row.try_get("files_touched")?,
        turn_count: row.try_get("turn_count")?,
        tool_call_count: row.try_get("tool_call_count")?,
        lifecycle: row.try_get("lifecycle")?,
        quarantine: row.try_get("quarantine")?,
        quarantine_reason: row.try_get("quarantine_reason")?,
        quarantine_detail: row.try_get("quarantine_detail")?,
        visibility: row.try_get("visibility")?,
        raw_enabled: row.try_get("raw_enabled")?,
        redaction_fingerprint: row.try_get("redaction_fingerprint")?,
        redaction_counts: row.try_get("redaction_counts")?,
        capture_mode: row.try_get("capture_mode")?,
        cli_version: row.try_get("cli_version")?,
        adapter_verified: row.try_get("adapter_verified")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn segment_from_row(row: &AnyRow) -> DbResult<SegmentRow> {
    Ok(SegmentRow {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        n: row.try_get("n")?,
        seq_start: row.try_get("seq_start")?,
        seq_end: row.try_get("seq_end")?,
        blob_hash: row.try_get("blob_hash")?,
        byte_size: row.try_get("byte_size")?,
        raw_blob_hash: row.try_get("raw_blob_hash")?,
        uploaded_at: row.try_get("uploaded_at")?,
    })
}

fn link_from_row(row: &AnyRow) -> DbResult<CommitLinkRow> {
    Ok(CommitLinkRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        session_ulid: row.try_get("session_ulid")?,
        session_id: row.try_get("session_id")?,
        sha: row.try_get("sha")?,
        source: row.try_get("source")?,
        confidence: row.try_get("confidence")?,
        seq_start: row.try_get("seq_start")?,
        seq_end: row.try_get("seq_end")?,
        trailer_seen: row.try_get("trailer_seen")?,
        claim_seen: row.try_get("claim_seen")?,
    })
}

fn blob_from_row(row: &AnyRow) -> DbResult<BlobRow> {
    Ok(BlobRow {
        hash: row.try_get("hash")?,
        size: row.try_get("size")?,
        refcount: row.try_get("refcount")?,
        backend_key: row.try_get("backend_key")?,
    })
}

pub async fn insert_session(db: &Db, s: &NewSession<'_>) -> DbResult<i64> {
    let ts = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO sessions (repo_id, ulid, uploader_id, agent_name, agent_version, models, title, branch, head_sha, \
         started_at, ended_at, parent_ulid, usage_input, usage_output, usage_cache_read, usage_cache_write, \
         usage_reasoning, files_touched, turn_count, tool_call_count, lifecycle, quarantine, quarantine_reason, \
         quarantine_detail, visibility, raw_enabled, redaction_fingerprint, redaction_counts, capture_mode, \
         cli_version, adapter_verified, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, \
         $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33) RETURNING id",
    )
    .bind(s.repo_id)
    .bind(s.ulid)
    .bind(s.uploader_id)
    .bind(s.agent_name)
    .bind(s.agent_version)
    .bind(s.models)
    .bind(s.title)
    .bind(s.branch)
    .bind(s.head_sha)
    .bind(s.started_at)
    .bind(s.ended_at)
    .bind(s.parent_ulid)
    .bind(s.usage_input)
    .bind(s.usage_output)
    .bind(s.usage_cache_read)
    .bind(s.usage_cache_write)
    .bind(s.usage_reasoning)
    .bind(s.files_touched)
    .bind(s.turn_count)
    .bind(s.tool_call_count)
    .bind(s.lifecycle)
    .bind(s.quarantine)
    .bind(s.quarantine_reason)
    .bind(s.quarantine_detail)
    .bind(s.visibility)
    .bind(s.raw_enabled)
    .bind(s.redaction_fingerprint)
    .bind(s.redaction_counts)
    .bind(s.capture_mode)
    .bind(s.cli_version)
    .bind(s.adapter_verified)
    .bind(ts)
    .bind(ts)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

pub async fn session_by_ulid(db: &Db, repo_id: i64, ulid: &str) -> DbResult<Option<SessionRow>> {
    let row = sqlx::query(select_session!("WHERE repo_id = $1 AND ulid = $2"))
        .bind(repo_id)
        .bind(ulid)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(session_from_row).transpose()
}

pub async fn update_session_meta(db: &Db, id: i64, s: &NewSession<'_>) -> DbResult<()> {
    sqlx::query(
        "UPDATE sessions SET repo_id = $1, ulid = $2, uploader_id = $3, agent_name = $4, agent_version = $5, \
         models = $6, title = $7, branch = $8, head_sha = $9, started_at = $10, ended_at = $11, parent_ulid = $12, \
         usage_input = $13, usage_output = $14, usage_cache_read = $15, usage_cache_write = $16, \
         usage_reasoning = $17, files_touched = $18, turn_count = $19, tool_call_count = $20, lifecycle = $21, \
         quarantine = $22, quarantine_reason = $23, quarantine_detail = $24, visibility = $25, raw_enabled = $26, \
         redaction_fingerprint = $27, redaction_counts = $28, capture_mode = $29, cli_version = $30, \
         adapter_verified = $31, updated_at = $32 WHERE id = $33",
    )
    .bind(s.repo_id)
    .bind(s.ulid)
    .bind(s.uploader_id)
    .bind(s.agent_name)
    .bind(s.agent_version)
    .bind(s.models)
    .bind(s.title)
    .bind(s.branch)
    .bind(s.head_sha)
    .bind(s.started_at)
    .bind(s.ended_at)
    .bind(s.parent_ulid)
    .bind(s.usage_input)
    .bind(s.usage_output)
    .bind(s.usage_cache_read)
    .bind(s.usage_cache_write)
    .bind(s.usage_reasoning)
    .bind(s.files_touched)
    .bind(s.turn_count)
    .bind(s.tool_call_count)
    .bind(s.lifecycle)
    .bind(s.quarantine)
    .bind(s.quarantine_reason)
    .bind(s.quarantine_detail)
    .bind(s.visibility)
    .bind(s.raw_enabled)
    .bind(s.redaction_fingerprint)
    .bind(s.redaction_counts)
    .bind(s.capture_mode)
    .bind(s.cli_version)
    .bind(s.adapter_verified)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn set_lifecycle(db: &Db, id: i64, lifecycle: &str) -> DbResult<()> {
    sqlx::query("UPDATE sessions SET lifecycle = $1, updated_at = $2 WHERE id = $3")
        .bind(lifecycle)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_quarantine(
    db: &Db,
    id: i64,
    quarantine: &str,
    reason: &str,
    detail: &str,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE sessions SET quarantine = $1, quarantine_reason = $2, quarantine_detail = $3, updated_at = $4 \
         WHERE id = $5",
    )
    .bind(quarantine)
    .bind(reason)
    .bind(detail)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn session_by_id(db: &Db, id: i64) -> DbResult<Option<SessionRow>> {
    let row = sqlx::query(select_session!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(session_from_row).transpose()
}

/// Overwrites the merged server/client redaction counts (`redaction_counts`
/// accumulates server-found hits on top of the client's fingerprint counts).
pub async fn set_redaction_counts(db: &Db, id: i64, counts: &str) -> DbResult<()> {
    sqlx::query("UPDATE sessions SET redaction_counts = $1, updated_at = $2 WHERE id = $3")
        .bind(counts)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn segment_by_n(db: &Db, session_id: i64, n: i64) -> DbResult<Option<SegmentRow>> {
    let row = sqlx::query(select_segment!("WHERE session_id = $1 AND n = $2"))
        .bind(session_id)
        .bind(n)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(segment_from_row).transpose()
}

/// Overwrites the segment-derived counters (recomputed by the stats job from
/// segment events, since uploads only ever append).
#[allow(clippy::too_many_arguments)]
pub async fn set_session_stats(
    db: &Db,
    id: i64,
    usage_input: i64,
    usage_output: i64,
    usage_cache_read: i64,
    usage_cache_write: i64,
    usage_reasoning: i64,
    turn_count: i64,
    tool_call_count: i64,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE sessions SET usage_input = $1, usage_output = $2, usage_cache_read = $3, \
         usage_cache_write = $4, usage_reasoning = $5, turn_count = $6, tool_call_count = $7, \
         updated_at = $8 WHERE id = $9",
    )
    .bind(usage_input)
    .bind(usage_output)
    .bind(usage_cache_read)
    .bind(usage_cache_write)
    .bind(usage_reasoning)
    .bind(turn_count)
    .bind(tool_call_count)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn segment_count(db: &Db, session_id: i64) -> DbResult<i64> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM segments WHERE session_id = $1")
        .bind(session_id)
        .fetch_one(db.read_pool())
        .await?;
    Ok(count)
}

pub async fn insert_segment(
    db: &Db,
    session_id: i64,
    n: i64,
    seq_start: i64,
    seq_end: i64,
    blob_hash: &str,
    byte_size: i64,
) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO segments (session_id, n, seq_start, seq_end, blob_hash, byte_size, uploaded_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(session_id)
    .bind(n)
    .bind(seq_start)
    .bind(seq_end)
    .bind(blob_hash)
    .bind(byte_size)
    .bind(now())
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

pub async fn segments_of(db: &Db, session_id: i64) -> DbResult<Vec<SegmentRow>> {
    let rows = sqlx::query(select_segment!("WHERE session_id = $1 ORDER BY n ASC"))
        .bind(session_id)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(segment_from_row).collect()
}

/// Deletes the session; segments and commit links follow via `ON DELETE CASCADE`.
/// Returns the segments the session had, so callers can drop blob refcounts.
pub async fn delete_session(db: &Db, id: i64) -> DbResult<Vec<SegmentRow>> {
    let removed = segments_of(db, id).await?;
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(removed)
}
/// Deletes every commit link filed under `ulid`: trailer-first rows carry a
/// `NULL` `session_id` and would survive the session row's `ON DELETE CASCADE`.
pub async fn delete_session_links(db: &Db, repo_id: i64, ulid: &str) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM commit_links WHERE repo_id = $1 AND session_ulid = $2")
        .bind(repo_id)
        .bind(ulid)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}

/// Records a `Starforge-Session` push trailer. Trailer-first arrivals have no session row
/// yet, so `session_id` stays `NULL` until the CLI claim fills it in.
pub async fn upsert_trailer_link(db: &Db, repo_id: i64, ulid: &str, sha: &str) -> DbResult<i64> {
    sqlx::query(
        "INSERT INTO commit_links (repo_id, session_ulid, sha, source, confidence, trailer_seen, claim_seen) \
         VALUES ($1, $2, $3, 'trailer', 'heuristic', 1, 0) ON CONFLICT DO NOTHING",
    )
    .bind(repo_id)
    .bind(ulid)
    .bind(sha)
    .execute(db.pool())
    .await?;
    sqlx::query(
        "UPDATE commit_links SET trailer_seen = 1 \
         WHERE repo_id = $1 AND session_ulid = $2 AND sha = $3",
    )
    .bind(repo_id)
    .bind(ulid)
    .bind(sha)
    .execute(db.pool())
    .await?;
    link_id_by_key(db, repo_id, ulid, sha).await
}

/// Points trailer-first rows filed under `ulid` (which arrived with a `NULL`
/// `session_id`) at the now-existing session. Returns the rows updated.
pub async fn backfill_trailer_session_id(
    db: &Db,
    repo_id: i64,
    ulid: &str,
    session_id: i64,
) -> DbResult<u64> {
    let result = sqlx::query(
        "UPDATE commit_links SET session_id = $3 \
         WHERE repo_id = $1 AND session_ulid = $2 AND session_id IS NULL",
    )
    .bind(repo_id)
    .bind(ulid)
    .bind(session_id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected())
}

/// Records the CLI's commit claim, merging into the trailer row when one arrived first.
/// A claim overwrites confidence and the sequence range.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_claim_link(
    db: &Db,
    repo_id: i64,
    session_id: i64,
    ulid: &str,
    sha: &str,
    confidence: &str,
    seq_start: Option<i64>,
    seq_end: Option<i64>,
) -> DbResult<i64> {
    let mut tx = db.pool().begin().await?;
    let id = upsert_claim_link_tx(
        &mut tx, repo_id, session_id, ulid, sha, confidence, seq_start, seq_end,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// One validated commit claim, ready for [`upsert_claim_links`].
pub struct ClaimLinkUpsert<'a> {
    pub sha: &'a str,
    pub confidence: &'a str,
    pub seq_start: Option<i64>,
    pub seq_end: Option<i64>,
}

/// Records a whole validated batch in one transaction: any row failing rolls
/// back every row, so callers never leave a partial batch behind.
pub async fn upsert_claim_links(
    db: &Db,
    repo_id: i64,
    session_id: i64,
    ulid: &str,
    entries: &[ClaimLinkUpsert<'_>],
) -> DbResult<()> {
    let mut tx = db.pool().begin().await?;
    for entry in entries {
        upsert_claim_link_tx(
            &mut tx,
            repo_id,
            session_id,
            ulid,
            entry.sha,
            entry.confidence,
            entry.seq_start,
            entry.seq_end,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// [`upsert_claim_link`] inside the caller's transaction.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_claim_link_tx(
    tx: &mut sqlx::Transaction<'_, Any>,
    repo_id: i64,
    session_id: i64,
    ulid: &str,
    sha: &str,
    confidence: &str,
    seq_start: Option<i64>,
    seq_end: Option<i64>,
) -> DbResult<i64> {
    sqlx::query(
        "INSERT INTO commit_links (repo_id, session_ulid, session_id, sha, source, confidence, seq_start, seq_end, \
         trailer_seen, claim_seen) \
         VALUES ($1, $2, $3, $4, 'cli_claim', $5, $6, $7, 0, 1) ON CONFLICT DO NOTHING",
    )
    .bind(repo_id)
    .bind(ulid)
    .bind(session_id)
    .bind(sha)
    .bind(confidence)
    .bind(seq_start)
    .bind(seq_end)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE commit_links SET session_id = $4, source = 'cli_claim', confidence = $5, seq_start = $6, \
         seq_end = $7, claim_seen = 1 WHERE repo_id = $1 AND session_ulid = $2 AND sha = $3",
    )
    .bind(repo_id)
    .bind(ulid)
    .bind(sha)
    .bind(session_id)
    .bind(confidence)
    .bind(seq_start)
    .bind(seq_end)
    .execute(&mut **tx)
    .await?;
    link_id_by_key_tx(tx, repo_id, ulid, sha).await
}

async fn link_id_by_key(db: &Db, repo_id: i64, ulid: &str, sha: &str) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "SELECT id FROM commit_links WHERE repo_id = $1 AND session_ulid = $2 AND sha = $3",
    )
    .bind(repo_id)
    .bind(ulid)
    .bind(sha)
    .fetch_one(db.read_pool())
    .await?;
    Ok(id)
}

async fn link_id_by_key_tx(
    tx: &mut sqlx::Transaction<'_, Any>,
    repo_id: i64,
    ulid: &str,
    sha: &str,
) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "SELECT id FROM commit_links WHERE repo_id = $1 AND session_ulid = $2 AND sha = $3",
    )
    .bind(repo_id)
    .bind(ulid)
    .bind(sha)
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

pub async fn links_of_session(db: &Db, session_id: i64) -> DbResult<Vec<CommitLinkRow>> {
    let rows = sqlx::query(select_link!("WHERE session_id = $1 ORDER BY id ASC"))
        .bind(session_id)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(link_from_row).collect()
}

pub async fn blob_by_hash(db: &Db, hash: &str) -> DbResult<Option<BlobRow>> {
    let row = sqlx::query("SELECT hash, size, refcount, backend_key FROM blobs WHERE hash = $1")
        .bind(hash)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(blob_from_row).transpose()
}

/// Inserts the blob row when absent, then increments the refcount. Returns the refcount.
pub async fn blob_incref(db: &Db, hash: &str, size: i64, backend_key: &str) -> DbResult<i64> {
    sqlx::query(
        "INSERT INTO blobs (hash, size, backend_key, refcount, created_at) \
         VALUES ($1, $2, $3, 0, $4) ON CONFLICT DO NOTHING",
    )
    .bind(hash)
    .bind(size)
    .bind(backend_key)
    .bind(now())
    .execute(db.pool())
    .await?;
    sqlx::query("UPDATE blobs SET refcount = refcount + 1 WHERE hash = $1")
        .bind(hash)
        .execute(db.pool())
        .await?;
    let refcount: i64 = sqlx::query_scalar("SELECT refcount FROM blobs WHERE hash = $1")
        .bind(hash)
        .fetch_one(db.pool())
        .await?;
    Ok(refcount)
}

/// Decrements the refcount, floored at zero. Returns the refcount (zero when no row).
pub async fn blob_decref(db: &Db, hash: &str) -> DbResult<i64> {
    sqlx::query("UPDATE blobs SET refcount = refcount - 1 WHERE hash = $1 AND refcount > 0")
        .bind(hash)
        .execute(db.pool())
        .await?;
    let refcount: Option<i64> = sqlx::query_scalar("SELECT refcount FROM blobs WHERE hash = $1")
        .bind(hash)
        .fetch_optional(db.pool())
        .await?;
    Ok(refcount.unwrap_or(0))
}

/// Zero-ref blobs, oldest first, at most `limit` rows — the GC sweep's work list.
pub async fn zero_ref_blobs(db: &Db, limit: i64) -> DbResult<Vec<BlobRow>> {
    let rows = sqlx::query(
        "SELECT hash, size, refcount, backend_key FROM blobs \
         WHERE refcount <= 0 ORDER BY created_at ASC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(blob_from_row).collect()
}

pub async fn delete_blob(db: &Db, hash: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM blobs WHERE hash = $1")
        .bind(hash)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Deletes the blob row only when nothing references it. Returns whether the row
/// was deleted. Row-first GC ordering: callers delete the file only after this
/// claims the row, so a concurrent `blob_incref` between selection and deletion
/// keeps its bytes instead of losing them to a stale sweep.
pub async fn delete_blob_if_unreferenced(db: &Db, hash: &str) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM blobs WHERE hash = $1 AND refcount <= 0")
        .bind(hash)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Total segment bytes stored for the repository.
pub async fn repo_storage_bytes(db: &Db, repo_id: i64) -> DbResult<i64> {
    let bytes: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(g.byte_size), 0) AS BIGINT) FROM segments g \
         JOIN sessions s ON s.id = g.session_id WHERE s.repo_id = $1",
    )
    .bind(repo_id)
    .fetch_one(db.read_pool())
    .await?;
    Ok(bytes)
}

/// Total segment bytes stored for sessions uploaded by the user.
pub async fn user_storage_bytes(db: &Db, user_id: i64) -> DbResult<i64> {
    let bytes: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(g.byte_size), 0) AS BIGINT) FROM segments g \
         JOIN sessions s ON s.id = g.session_id WHERE s.uploader_id = $1",
    )
    .bind(user_id)
    .fetch_one(db.read_pool())
    .await?;
    Ok(bytes)
}

/// Segment bytes uploaded by the user at or after `since_unix`.
pub async fn user_volume_since(db: &Db, user_id: i64, since_unix: i64) -> DbResult<i64> {
    let bytes: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(g.byte_size), 0) AS BIGINT) FROM segments g \
         JOIN sessions s ON s.id = g.session_id WHERE s.uploader_id = $1 AND g.uploaded_at >= $2",
    )
    .bind(user_id)
    .bind(since_unix)
    .fetch_one(db.read_pool())
    .await?;
    Ok(bytes)
}

/// Sessions of the repository awaiting quarantine review, oldest first.
pub async fn quarantined_of_repo(db: &Db, repo_id: i64) -> DbResult<Vec<SessionRow>> {
    let rows = sqlx::query(select_session!(
        "WHERE repo_id = $1 AND quarantine = 'quarantined' ORDER BY id ASC"
    ))
    .bind(repo_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(session_from_row).collect()
}
/// Every quarantined session across all repositories, oldest first, with the
/// repository label (`owner/name`) and the uploader handle for the site-admin
/// quarantine queue. The sweep is capped; callers pass a sane `limit`.
pub async fn quarantined_all(db: &Db, limit: i64) -> DbResult<Vec<(SessionRow, String, String)>> {
    let rows = sqlx::query(
        "SELECT s.id, s.repo_id, s.ulid, s.uploader_id, s.agent_name, s.agent_version, s.models, s.title, s.branch, s.head_sha, \
         s.started_at, s.ended_at, s.parent_ulid, s.usage_input, s.usage_output, s.usage_cache_read, s.usage_cache_write, \
         s.usage_reasoning, s.files_touched, s.turn_count, s.tool_call_count, s.lifecycle, s.quarantine, s.quarantine_reason, \
         s.quarantine_detail, s.visibility, s.raw_enabled, s.redaction_fingerprint, s.redaction_counts, s.capture_mode, \
         s.cli_version, s.adapter_verified, s.created_at, s.updated_at, o.handle AS repo_owner, r.name AS repo_name, \
         uo.handle AS uploader_handle \
         FROM sessions s \
         JOIN repos r ON r.id = s.repo_id \
         JOIN owners o ON o.id = r.owner_id \
         JOIN owners uo ON uo.id = s.uploader_id \
         WHERE s.quarantine = 'quarantined' ORDER BY s.id ASC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        let owner: String = row.try_get("repo_owner")?;
        let name: String = row.try_get("repo_name")?;
        let uploader: String = row.try_get("uploader_handle")?;
        out.push((session_from_row(row)?, format!("{owner}/{name}"), uploader));
    }
    Ok(out)
}

/// Every commit-link row filed under `sha` for the repository, oldest first — both trailer-first rows
/// (with a `NULL` `session_id`) and claimed rows. Used by the commit panel (M1e); callers filter by
/// read rule before displaying.
pub async fn links_for_sha(db: &Db, repo_id: i64, sha: &str) -> DbResult<Vec<CommitLinkRow>> {
    let rows = sqlx::query(select_link!(
        "WHERE repo_id = $1 AND sha = $2 ORDER BY session_ulid ASC"
    ))
    .bind(repo_id)
    .bind(sha)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(link_from_row).collect()
}

/// Every commit-link row filed under any of `shas`, oldest first — the
/// batched variant of [`links_for_sha`] for the commits list page (one query
/// per page, never one per commit). Callers filter by read rule before displaying.
pub async fn links_for_shas(
    db: &Db,
    repo_id: i64,
    shas: &[String],
) -> DbResult<Vec<CommitLinkRow>> {
    if shas.is_empty() {
        return Ok(Vec::new());
    }
    let mut sql = String::from(
        "SELECT id, repo_id, session_ulid, session_id, sha, source, confidence, seq_start, seq_end, \
         trailer_seen, claim_seen FROM commit_links WHERE repo_id = $1 AND sha IN (",
    );
    for (index, _) in shas.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push_str(&format!("${}", index + 2));
    }
    sql.push_str(") ORDER BY sha ASC, session_ulid ASC");
    // Safe: only `$N` placeholders are interpolated; every sha is a bound parameter.
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(repo_id);
    for sha in shas {
        query = query.bind(sha);
    }
    let rows = query.fetch_all(db.read_pool()).await?;
    rows.iter().map(link_from_row).collect()
}

/// Sessions uploaded by `uploader_id` across all repositories, newest
/// first, at most `limit` rows. Callers pass every row through the §6.4
/// read check for the viewer and truncate to the display cap.
pub async fn sessions_uploaded_by(
    db: &Db,
    uploader_id: i64,
    limit: i64,
) -> DbResult<Vec<SessionRow>> {
    let rows = sqlx::query(select_session!(
        "WHERE uploader_id = $1 ORDER BY id DESC LIMIT $2"
    ))
    .bind(uploader_id)
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(session_from_row).collect()
}

/// Sessions of the repository, oldest first, at most `limit` rows.
pub async fn sessions_of_repo(db: &Db, repo_id: i64, limit: i64) -> DbResult<Vec<SessionRow>> {
    let rows = sqlx::query(select_session!(
        "WHERE repo_id = $1 ORDER BY id ASC LIMIT $2"
    ))
    .bind(repo_id)
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(session_from_row).collect()
}
/// Sessions of the repository, newest first, at most `limit` rows.
pub async fn sessions_of_repo_newest(
    db: &Db,
    repo_id: i64,
    limit: i64,
) -> DbResult<Vec<SessionRow>> {
    let rows = sqlx::query(select_session!(
        "WHERE repo_id = $1 ORDER BY started_at DESC, id DESC LIMIT $2"
    ))
    .bind(repo_id)
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(session_from_row).collect()
}

/// Direct subagent sessions of one parent in the repository, oldest first.
pub async fn sessions_by_parent(
    db: &Db,
    repo_id: i64,
    parent_ulid: &str,
) -> DbResult<Vec<SessionRow>> {
    let rows = sqlx::query(select_session!(
        "WHERE repo_id = $1 AND parent_ulid = $2 ORDER BY started_at ASC, id ASC"
    ))
    .bind(repo_id)
    .bind(parent_ulid)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(session_from_row).collect()
}

/// Overwrites the session visibility (`inherit` or `published`). Callers validate the value.
pub async fn set_visibility(db: &Db, id: i64, visibility: &str) -> DbResult<()> {
    sqlx::query("UPDATE sessions SET visibility = $1, updated_at = $2 WHERE id = $3")
        .bind(visibility)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    fn user(handle: &str) -> NewUser<'_> {
        NewUser {
            handle,
            display_name: "",
            email: None,
            email_verified: false,
            password_hash: None,
            is_admin: false,
        }
    }

    fn repo(owner_id: i64, name: &str) -> NewRepo<'_> {
        NewRepo {
            owner_id,
            name,
            description: "",
            visibility: "private",
            default_branch: "main",
        }
    }

    fn session<'a>(repo_id: i64, uploader_id: i64, ulid: &'a str) -> NewSession<'a> {
        NewSession {
            repo_id,
            ulid,
            uploader_id,
            agent_name: "pi",
            agent_version: "0.1.0",
            models: r#"{"main":"spark"}"#,
            title: "fix login",
            branch: "work",
            head_sha: "abc123",
            started_at: 1_700_000_000,
            ended_at: Some(1_700_000_600),
            parent_ulid: Some("01PARENT"),
            usage_input: 100,
            usage_output: 200,
            usage_cache_read: 300,
            usage_cache_write: 400,
            usage_reasoning: 500,
            files_touched: r#"["a.rs"]"#,
            turn_count: 7,
            tool_call_count: 11,
            lifecycle: "receiving",
            quarantine: "none",
            quarantine_reason: "",
            quarantine_detail: "",
            visibility: "inherit",
            raw_enabled: 0,
            redaction_fingerprint: "fp1",
            redaction_counts: "{}",
            capture_mode: "full",
            cli_version: "9.9.9",
            adapter_verified: 1,
        }
    }

    async fn setup() -> (TestDb, i64, i64) {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("alice")).await.unwrap();
        let repo_id = repos::insert(&t.db, &repo(alice, "demo")).await.unwrap();
        (t, alice, repo_id)
    }

    #[tokio::test]
    async fn insert_round_trips_every_column() {
        let (t, alice, repo_id) = setup().await;
        let id = insert_session(&t.db, &session(repo_id, alice, "01ROUNDTRIP"))
            .await
            .unwrap();
        let got = session_by_ulid(&t.db, repo_id, "01ROUNDTRIP")
            .await
            .unwrap()
            .expect("session present");
        assert_eq!(got.id, id);
        assert_eq!(got.repo_id, repo_id);
        assert_eq!(got.ulid, "01ROUNDTRIP");
        assert_eq!(got.uploader_id, alice);
        assert_eq!(got.agent_name, "pi");
        assert_eq!(got.agent_version, "0.1.0");
        assert_eq!(got.models, r#"{"main":"spark"}"#);
        assert_eq!(got.title, "fix login");
        assert_eq!(got.branch, "work");
        assert_eq!(got.head_sha, "abc123");
        assert_eq!(got.started_at, 1_700_000_000);
        assert_eq!(got.ended_at, Some(1_700_000_600));
        assert_eq!(got.parent_ulid.as_deref(), Some("01PARENT"));
        assert_eq!(got.usage_input, 100);
        assert_eq!(got.usage_output, 200);
        assert_eq!(got.usage_cache_read, 300);
        assert_eq!(got.usage_cache_write, 400);
        assert_eq!(got.usage_reasoning, 500);
        assert_eq!(got.files_touched, r#"["a.rs"]"#);
        assert_eq!(got.turn_count, 7);
        assert_eq!(got.tool_call_count, 11);
        assert_eq!(got.lifecycle, "receiving");
        assert_eq!(got.quarantine, "none");
        assert_eq!(got.quarantine_reason, "");
        assert_eq!(got.quarantine_detail, "");
        assert_eq!(got.visibility, "inherit");
        assert_eq!(got.raw_enabled, 0);
        assert_eq!(got.redaction_fingerprint, "fp1");
        assert_eq!(got.redaction_counts, "{}");
        assert_eq!(got.capture_mode, "full");
        assert_eq!(got.cli_version, "9.9.9");
        assert_eq!(got.adapter_verified, 1);
        assert!(got.created_at > 0);
        assert!(got.updated_at > 0);
        assert_eq!(
            session_by_ulid(&t.db, repo_id, "01MISSING").await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn duplicate_ulid_in_same_repo_is_a_unique_violation() {
        let (t, alice, repo_id) = setup().await;
        insert_session(&t.db, &session(repo_id, alice, "01DUP"))
            .await
            .unwrap();
        let err = insert_session(&t.db, &session(repo_id, alice, "01DUP"))
            .await
            .unwrap_err();
        assert!(err.is_unique_violation(), "{err}");
        // The same ULID in another repo is fine.
        let bob = users::insert(&t.db, &user("bob")).await.unwrap();
        let other = repos::insert(&t.db, &repo(bob, "other")).await.unwrap();
        insert_session(&t.db, &session(other, bob, "01DUP"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lifecycle_and_quarantine_transitions() {
        let (t, alice, repo_id) = setup().await;
        let id = insert_session(&t.db, &session(repo_id, alice, "01STATE"))
            .await
            .unwrap();
        set_lifecycle(&t.db, id, "complete").await.unwrap();
        let got = session_by_ulid(&t.db, repo_id, "01STATE")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.lifecycle, "complete");
        set_quarantine(&t.db, id, "quarantined", "secret", "rule xyz")
            .await
            .unwrap();
        let got = session_by_ulid(&t.db, repo_id, "01STATE")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.quarantine, "quarantined");
        assert_eq!(got.quarantine_reason, "secret");
        assert_eq!(got.quarantine_detail, "rule xyz");
        let queued = quarantined_of_repo(&t.db, repo_id).await.unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].id, id);
        set_quarantine(&t.db, id, "released", "", "").await.unwrap();
        let got = session_by_ulid(&t.db, repo_id, "01STATE")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.quarantine, "released");
        assert!(
            quarantined_of_repo(&t.db, repo_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn update_session_meta_rewrites_columns() {
        let (t, alice, repo_id) = setup().await;
        let id = insert_session(&t.db, &session(repo_id, alice, "01META"))
            .await
            .unwrap();
        let mut changed = session(repo_id, alice, "01META");
        changed.title = "new title";
        changed.turn_count = 42;
        changed.lifecycle = "complete";
        update_session_meta(&t.db, id, &changed).await.unwrap();
        let got = session_by_ulid(&t.db, repo_id, "01META")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.title, "new title");
        assert_eq!(got.turn_count, 42);
        assert_eq!(got.lifecycle, "complete");
    }

    #[tokio::test]
    async fn segments_insert_list_get_and_count_in_order() {
        let (t, alice, repo_id) = setup().await;
        let sid = insert_session(&t.db, &session(repo_id, alice, "01SEGS"))
            .await
            .unwrap();
        insert_segment(&t.db, sid, 2, 200, 299, "hash2", 20)
            .await
            .unwrap();
        insert_segment(&t.db, sid, 0, 0, 99, "hash0", 10)
            .await
            .unwrap();
        insert_segment(&t.db, sid, 1, 100, 199, "hash1", 15)
            .await
            .unwrap();
        let all = segments_of(&t.db, sid).await.unwrap();
        assert_eq!(
            all.iter().map(|s| s.n).collect::<Vec<_>>(),
            vec![0, 1, 2],
            "segments_of orders by n"
        );
        assert_eq!(all[0].blob_hash, "hash0");
        assert_eq!(all[0].byte_size, 10);
        assert_eq!(all[0].raw_blob_hash, None);
        let one = segment_by_n(&t.db, sid, 1).await.unwrap().unwrap();
        assert_eq!((one.seq_start, one.seq_end), (100, 199));
        assert_eq!(segment_by_n(&t.db, sid, 9).await.unwrap(), None);
        assert_eq!(segment_count(&t.db, sid).await.unwrap(), 3);
        let err = insert_segment(&t.db, sid, 1, 100, 199, "hash1", 15)
            .await
            .unwrap_err();
        assert!(err.is_unique_violation(), "{err}");
    }

    #[tokio::test]
    async fn blobs_incref_decref_and_gc() {
        let (t, _, _) = setup().await;
        assert_eq!(blob_by_hash(&t.db, "h1").await.unwrap(), None);
        assert_eq!(blob_incref(&t.db, "h1", 100, "blobs/h1").await.unwrap(), 1);
        assert_eq!(blob_incref(&t.db, "h1", 100, "blobs/h1").await.unwrap(), 2);
        let row = blob_by_hash(&t.db, "h1").await.unwrap().unwrap();
        assert_eq!(
            row,
            BlobRow {
                hash: "h1".to_owned(),
                size: 100,
                refcount: 2,
                backend_key: "blobs/h1".to_owned(),
            }
        );
        assert_eq!(blob_decref(&t.db, "h1").await.unwrap(), 1);
        assert_eq!(blob_decref(&t.db, "h1").await.unwrap(), 0);
        assert_eq!(
            blob_decref(&t.db, "h1").await.unwrap(),
            0,
            "floored at zero"
        );
        assert_eq!(blob_decref(&t.db, "missing").await.unwrap(), 0);
        let zeros = zero_ref_blobs(&t.db, 100).await.unwrap();
        assert_eq!(zeros.len(), 1);
        assert_eq!(zeros[0].hash, "h1");
        delete_blob(&t.db, "h1").await.unwrap();
        assert_eq!(blob_by_hash(&t.db, "h1").await.unwrap(), None);
        assert!(zero_ref_blobs(&t.db, 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn conditional_blob_delete_spares_newly_referenced_blobs() {
        let (t, _, _) = setup().await;
        let hash = "ab".repeat(32);
        // A purge leaves a zero-ref row behind for the sweep.
        blob_incref(&t.db, &hash, 4, &hash).await.unwrap();
        blob_decref(&t.db, &hash).await.unwrap();
        // A concurrent upload references the bytes again after the sweep's
        // selection but before its delete: the conditional delete claims nothing.
        blob_incref(&t.db, &hash, 4, &hash).await.unwrap();
        assert!(!delete_blob_if_unreferenced(&t.db, &hash).await.unwrap());
        let row = blob_by_hash(&t.db, &hash).await.unwrap().unwrap();
        assert_eq!(row.refcount, 1);
        // Once truly unreferenced, the delete claims exactly one row.
        blob_decref(&t.db, &hash).await.unwrap();
        assert!(delete_blob_if_unreferenced(&t.db, &hash).await.unwrap());
        assert_eq!(blob_by_hash(&t.db, &hash).await.unwrap(), None);
        // Deleting again claims nothing.
        assert!(!delete_blob_if_unreferenced(&t.db, &hash).await.unwrap());
    }

    #[tokio::test]
    async fn trailer_then_claim_merges_into_one_row() {
        let (t, alice, repo_id) = setup().await;
        let sid = insert_session(&t.db, &session(repo_id, alice, "01LINK"))
            .await
            .unwrap();
        let first = upsert_trailer_link(&t.db, repo_id, "01LINK", "deadbeef")
            .await
            .unwrap();
        let second = upsert_claim_link(
            &t.db,
            repo_id,
            sid,
            "01LINK",
            "deadbeef",
            "exact",
            Some(0),
            Some(99),
        )
        .await
        .unwrap();
        assert_eq!(first, second);
        let links = links_of_session(&t.db, sid).await.unwrap();
        assert_eq!(links.len(), 1);
        let link = &links[0];
        assert_eq!(link.repo_id, repo_id);
        assert_eq!(link.session_ulid, "01LINK");
        assert_eq!(link.session_id, Some(sid));
        assert_eq!(link.sha, "deadbeef");
        assert_eq!(link.trailer_seen, 1);
        assert_eq!(link.claim_seen, 1);
        assert_eq!(link.confidence, "exact");
        assert_eq!((link.seq_start, link.seq_end), (Some(0), Some(99)));
    }

    #[tokio::test]
    async fn claim_then_trailer_merges_into_one_row() {
        let (t, alice, repo_id) = setup().await;
        let sid = insert_session(&t.db, &session(repo_id, alice, "01LINK2"))
            .await
            .unwrap();
        let first = upsert_claim_link(
            &t.db,
            repo_id,
            sid,
            "01LINK2",
            "cafef00d",
            "heuristic",
            None,
            None,
        )
        .await
        .unwrap();
        let second = upsert_trailer_link(&t.db, repo_id, "01LINK2", "cafef00d")
            .await
            .unwrap();
        assert_eq!(first, second, "either arrival order yields one row");
        let links = links_of_session(&t.db, sid).await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!((links[0].trailer_seen, links[0].claim_seen), (1, 1));
    }

    #[tokio::test]
    async fn delete_session_removes_children_and_returns_segments() {
        let (t, alice, repo_id) = setup().await;
        let sid = insert_session(&t.db, &session(repo_id, alice, "01DEL"))
            .await
            .unwrap();
        insert_segment(&t.db, sid, 0, 0, 9, "hh", 10).await.unwrap();
        upsert_trailer_link(&t.db, repo_id, "01DEL", "aaa")
            .await
            .unwrap();
        upsert_claim_link(
            &t.db,
            repo_id,
            sid,
            "01DEL",
            "aaa",
            "exact",
            Some(0),
            Some(9),
        )
        .await
        .unwrap();
        let removed = delete_session(&t.db, sid).await.unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].n, 0);
        assert_eq!(
            session_by_ulid(&t.db, repo_id, "01DEL").await.unwrap(),
            None
        );
        assert!(segments_of(&t.db, sid).await.unwrap().is_empty());
        assert!(links_of_session(&t.db, sid).await.unwrap().is_empty());
        assert_eq!(segment_count(&t.db, sid).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn storage_accounting_and_repo_delete_cascade() {
        let (t, alice, repo_id) = setup().await;
        let before = now();
        let s1 = insert_session(&t.db, &session(repo_id, alice, "01Q1"))
            .await
            .unwrap();
        let s2 = insert_session(&t.db, &session(repo_id, alice, "01Q2"))
            .await
            .unwrap();
        insert_segment(&t.db, s1, 0, 0, 9, "qa", 100).await.unwrap();
        insert_segment(&t.db, s2, 0, 0, 9, "qb", 50).await.unwrap();
        upsert_claim_link(&t.db, repo_id, s1, "01Q1", "sha1", "exact", None, None)
            .await
            .unwrap();
        assert_eq!(repo_storage_bytes(&t.db, repo_id).await.unwrap(), 150);
        assert_eq!(user_storage_bytes(&t.db, alice).await.unwrap(), 150);
        assert_eq!(user_volume_since(&t.db, alice, 0).await.unwrap(), 150);
        assert_eq!(
            user_volume_since(&t.db, alice, before + 10_000)
                .await
                .unwrap(),
            0
        );
        assert_eq!(repo_storage_bytes(&t.db, 9999).await.unwrap(), 0);

        // Hard repo delete leaves no orphan session/segment/link rows; blobs are global.
        blob_incref(&t.db, "qa", 100, "blobs/qa").await.unwrap();
        repos::delete(&t.db, repo_id).await.unwrap();
        assert_eq!(session_by_ulid(&t.db, repo_id, "01Q1").await.unwrap(), None);
        assert!(segments_of(&t.db, s1).await.unwrap().is_empty());
        assert!(links_of_session(&t.db, s1).await.unwrap().is_empty());
        let dangling_segments: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM segments WHERE session_id = $1")
                .bind(s1)
                .fetch_one(t.db.pool())
                .await
                .unwrap();
        assert_eq!(dangling_segments, 0);
        let dangling_links: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM commit_links WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(t.db.pool())
                .await
                .unwrap();
        assert_eq!(dangling_links, 0);
        assert!(blob_by_hash(&t.db, "qa").await.unwrap().is_some());
    }
    #[tokio::test]
    async fn claim_batch_rolls_back_on_mid_batch_db_failure() {
        let (t, alice, repo_id) = setup().await;
        let sid = insert_session(&t.db, &session(repo_id, alice, "01TX"))
            .await
            .unwrap();
        // One good row, then a row violating the confidence CHECK: dropping
        // the transaction must leave zero rows behind.
        let mut tx = t.db.pool().begin().await.unwrap();
        upsert_claim_link_tx(
            &mut tx,
            repo_id,
            sid,
            "01TX",
            &"a".repeat(40),
            "exact",
            None,
            None,
        )
        .await
        .unwrap();
        let bad = upsert_claim_link_tx(
            &mut tx,
            repo_id,
            sid,
            "01TX",
            &"b".repeat(40),
            "bogus",
            None,
            None,
        )
        .await;
        assert!(bad.is_err(), "confidence CHECK must reject 'bogus'");
        drop(tx);
        assert!(links_of_session(&t.db, sid).await.unwrap().is_empty());

        // The batch entry point commits the same shape all-or-nothing.
        upsert_claim_links(
            &t.db,
            repo_id,
            sid,
            "01TX",
            &[
                ClaimLinkUpsert {
                    sha: &"a".repeat(40),
                    confidence: "exact",
                    seq_start: Some(0),
                    seq_end: Some(9),
                },
                ClaimLinkUpsert {
                    sha: &"b".repeat(40),
                    confidence: "heuristic",
                    seq_start: None,
                    seq_end: None,
                },
            ],
        )
        .await
        .unwrap();
        assert_eq!(links_of_session(&t.db, sid).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn links_for_sha_returns_trailer_and_claimed_rows() {
        let (t, alice, repo_id) = setup().await;
        let sha = "a".repeat(40);
        // Trailer-first arrival with no session yet: NULL session_id.
        upsert_trailer_link(&t.db, repo_id, "01SHAA", &sha)
            .await
            .unwrap();
        // A claimed row for the same SHA under another ULID.
        let sid = insert_session(&t.db, &session(repo_id, alice, "01SHAB"))
            .await
            .unwrap();
        upsert_claim_link(
            &t.db,
            repo_id,
            sid,
            "01SHAB",
            &sha,
            "exact",
            Some(0),
            Some(9),
        )
        .await
        .unwrap();
        // A row on another SHA must not match.
        upsert_claim_link(
            &t.db,
            repo_id,
            sid,
            "01SHAB",
            &"b".repeat(40),
            "heuristic",
            None,
            None,
        )
        .await
        .unwrap();
        let rows = links_for_sha(&t.db, repo_id, &sha).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].session_ulid, "01SHAA");
        assert_eq!(rows[0].session_id, None);
        assert_eq!(rows[1].session_ulid, "01SHAB");
        assert_eq!(rows[1].session_id, Some(sid));
        assert!(
            links_for_sha(&t.db, repo_id, &"c".repeat(40))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn set_visibility_round_trips() {
        let (t, alice, repo_id) = setup().await;
        let sid = insert_session(&t.db, &session(repo_id, alice, "01VIS"))
            .await
            .unwrap();
        assert_eq!(
            session_by_id(&t.db, sid).await.unwrap().unwrap().visibility,
            "inherit"
        );
        set_visibility(&t.db, sid, "published").await.unwrap();
        assert_eq!(
            session_by_id(&t.db, sid).await.unwrap().unwrap().visibility,
            "published"
        );
        set_visibility(&t.db, sid, "inherit").await.unwrap();
        assert_eq!(
            session_by_id(&t.db, sid).await.unwrap().unwrap().visibility,
            "inherit"
        );
    }

    #[tokio::test]
    async fn sessions_of_repo_is_scoped_and_capped() {
        let (t, alice, repo_id) = setup().await;
        let other = repos::insert(&t.db, &repo(alice, "other")).await.unwrap();
        insert_session(&t.db, &session(repo_id, alice, "01LISTA"))
            .await
            .unwrap();
        insert_session(&t.db, &session(repo_id, alice, "01LISTB"))
            .await
            .unwrap();
        insert_session(&t.db, &session(other, alice, "01LISTC"))
            .await
            .unwrap();
        let all = sessions_of_repo(&t.db, repo_id, 10).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].ulid, "01LISTA");
        assert_eq!(all[1].ulid, "01LISTB");
        let capped = sessions_of_repo(&t.db, repo_id, 1).await.unwrap();
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].ulid, "01LISTA");
    }
}
