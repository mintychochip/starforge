//! `sandboxes` and `sandbox_usage`: the M6b sandbox control plane's
//! records (spec M6, migration 0037).
//!
//! The data-access layer stays thin — no validation or permission checks
//! here (those live in `starforged-core`). The public sandbox handle is
//! the provider's `external_id`, not the row id. `metadata` is TEXT
//! holding JSON (no JSON operators — both engines). `cpu` decodes as
//! `f64` on both engines (`REAL` / `DOUBLE PRECISION`).

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult};

#[derive(Debug, Clone, PartialEq)]
pub struct SandboxRow {
    pub id: i64,
    pub provider: String,
    pub runtime: String,
    pub external_id: String,
    pub job_id: Option<i64>,
    pub owner_id: i64,
    pub repo_id: i64,
    pub state: String,
    pub template: String,
    pub cpu: f64,
    pub mem_mb: i64,
    pub disk_gb: i64,
    pub idempotency_key: Option<String>,
    pub ca_fingerprint: Option<String>,
    pub metadata: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewSandbox<'a> {
    pub provider: &'a str,
    pub runtime: &'a str,
    pub external_id: &'a str,
    pub job_id: Option<i64>,
    pub owner_id: i64,
    pub repo_id: i64,
    pub state: &'a str,
    pub template: &'a str,
    pub cpu: f64,
    pub mem_mb: i64,
    pub disk_gb: i64,
    pub idempotency_key: Option<&'a str>,
    pub ca_fingerprint: Option<&'a str>,
    pub metadata: &'a str,
    pub created_at: i64,
    pub expires_at: i64,
}

macro_rules! select_sandbox {
    ($tail:literal) => {
        concat!(
            "SELECT id, provider, runtime, external_id, job_id, owner_id, repo_id, state, ",
            "template, cpu, mem_mb, disk_gb, idempotency_key, ca_fingerprint, metadata, ",
            "created_at, expires_at, last_seen_at FROM sandboxes ",
            $tail
        )
    };
}

fn sandbox_from_row(row: &AnyRow) -> DbResult<SandboxRow> {
    Ok(SandboxRow {
        id: row.try_get("id")?,
        provider: row.try_get("provider")?,
        runtime: row.try_get("runtime")?,
        external_id: row.try_get("external_id")?,
        job_id: row.try_get("job_id")?,
        owner_id: row.try_get("owner_id")?,
        repo_id: row.try_get("repo_id")?,
        state: row.try_get("state")?,
        template: row.try_get("template")?,
        cpu: row.try_get("cpu")?,
        mem_mb: row.try_get("mem_mb")?,
        disk_gb: row.try_get("disk_gb")?,
        idempotency_key: row.try_get("idempotency_key")?,
        ca_fingerprint: row.try_get("ca_fingerprint")?,
        metadata: row.try_get("metadata")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}

/// Inserts a sandbox row and returns it. A colliding
/// `(owner_id, idempotency_key)` pair violates the partial unique index
/// (callers read the existing row first, after a unique-violation race).
pub async fn insert_sandbox(db: &Db, n: &NewSandbox<'_>) -> DbResult<SandboxRow> {
    let row = sqlx::query(
        "INSERT INTO sandboxes (provider, runtime, external_id, job_id, owner_id, repo_id, state, template, cpu, mem_mb, disk_gb, idempotency_key, ca_fingerprint, metadata, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
         RETURNING id, provider, runtime, external_id, job_id, owner_id, repo_id, state, template, cpu, mem_mb, disk_gb, idempotency_key, ca_fingerprint, metadata, created_at, expires_at, last_seen_at",
    )
    .bind(n.provider)
    .bind(n.runtime)
    .bind(n.external_id)
    .bind(n.job_id)
    .bind(n.owner_id)
    .bind(n.repo_id)
    .bind(n.state)
    .bind(n.template)
    .bind(n.cpu)
    .bind(n.mem_mb)
    .bind(n.disk_gb)
    .bind(n.idempotency_key)
    .bind(n.ca_fingerprint)
    .bind(n.metadata)
    .bind(n.created_at)
    .bind(n.expires_at)
    .fetch_one(db.pool())
    .await?;
    sandbox_from_row(&row)
}

/// One sandbox by provider handle (`external_id`), if it still exists.
pub async fn sandbox_by_external_id(db: &Db, external_id: &str) -> DbResult<Option<SandboxRow>> {
    let row = sqlx::query(select_sandbox!("WHERE external_id = $1"))
        .bind(external_id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(sandbox_from_row).transpose()
}

/// The sandbox an idempotent create already produced, if any.
pub async fn sandbox_by_idempotency(
    db: &Db,
    owner_id: i64,
    idempotency_key: &str,
) -> DbResult<Option<SandboxRow>> {
    let row = sqlx::query(select_sandbox!(
        "WHERE owner_id = $1 AND idempotency_key = $2"
    ))
    .bind(owner_id)
    .bind(idempotency_key)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(sandbox_from_row).transpose()
}

/// Sandboxes of one owner, newest first (capped at `limit`).
pub async fn sandboxes_for_owner(db: &Db, owner_id: i64, limit: i64) -> DbResult<Vec<SandboxRow>> {
    let rows = sqlx::query(select_sandbox!(
        "WHERE owner_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
    ))
    .bind(owner_id)
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(sandbox_from_row).collect()
}

/// Every sandbox, newest first (capped at `limit`), with the repository
/// owner's handle and name for the site-admin page. Sandboxes of a
/// repository that was purged are omitted (no names to show).
pub async fn list_all_sandboxes(
    db: &Db,
    limit: i64,
) -> DbResult<Vec<(SandboxRow, String, String)>> {
    let rows = sqlx::query(
        "SELECT sandboxes.id, sandboxes.provider, sandboxes.runtime, \
         sandboxes.external_id, sandboxes.job_id, sandboxes.owner_id, sandboxes.repo_id, \
         sandboxes.state, sandboxes.template, sandboxes.cpu, sandboxes.mem_mb, \
         sandboxes.disk_gb, sandboxes.idempotency_key, sandboxes.ca_fingerprint, \
         sandboxes.metadata, sandboxes.created_at, sandboxes.expires_at, sandboxes.last_seen_at, \
         owners.handle AS owner_handle, repos.name AS repo_name \
         FROM sandboxes \
         JOIN repos ON repos.id = sandboxes.repo_id \
         JOIN owners ON owners.id = repos.owner_id \
         ORDER BY sandboxes.created_at DESC, sandboxes.id DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok((
                sandbox_from_row(row)?,
                row.try_get("owner_handle")?,
                row.try_get("repo_name")?,
            ))
        })
        .collect()
}

/// Updates a sandbox's state (and `last_seen_at` heartbeat); false when
/// the row is gone. `state` must be a valid lifecycle state.
pub async fn update_sandbox_state(
    db: &Db,
    external_id: &str,
    state: &str,
    last_seen_at: i64,
) -> DbResult<bool> {
    let affected =
        sqlx::query("UPDATE sandboxes SET state = $1, last_seen_at = $2 WHERE external_id = $3")
            .bind(state)
            .bind(last_seen_at)
            .bind(external_id)
            .execute(db.pool())
            .await?
            .rows_affected();
    Ok(affected == 1)
}

/// Updates a sandbox's expiry (the `timeout` call); false when the row is
/// gone.
pub async fn update_sandbox_expires_at(
    db: &Db,
    external_id: &str,
    expires_at: i64,
) -> DbResult<bool> {
    let affected = sqlx::query("UPDATE sandboxes SET expires_at = $1 WHERE external_id = $2")
        .bind(expires_at)
        .bind(external_id)
        .execute(db.pool())
        .await?
        .rows_affected();
    Ok(affected == 1)
}

/// Live sandboxes (not killed/error) of one owner: the concurrent quota.
pub async fn count_active_by_owner(db: &Db, owner_id: i64) -> DbResult<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sandboxes WHERE owner_id = $1 AND state IN ('creating', 'running', 'paused')",
    )
    .bind(owner_id)
    .fetch_one(db.read_pool())
    .await?;
    Ok(n)
}

/// Live sandboxes (not killed/error) of one repo: the concurrent quota.
pub async fn count_active_by_repo(db: &Db, repo_id: i64) -> DbResult<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sandboxes WHERE repo_id = $1 AND state IN ('creating', 'running', 'paused')",
    )
    .bind(repo_id)
    .fetch_one(db.read_pool())
    .await?;
    Ok(n)
}

/// Provider handles of sandboxes past their expiry (GC input).
pub async fn expired_sandbox_ids(db: &Db, now_ts: i64, limit: i64) -> DbResult<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT external_id FROM sandboxes WHERE expires_at <= $1 AND state IN ('creating', 'running', 'paused') ORDER BY expires_at ASC LIMIT $2",
    )
    .bind(now_ts)
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    Ok(rows)
}

/// Records consumed sandbox-seconds in one hourly window.
pub async fn record_usage(
    db: &Db,
    owner_id: i64,
    repo_id: i64,
    window_start: i64,
    seconds: i64,
    now_ts: i64,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO sandbox_usage (owner_id, repo_id, window_start, seconds, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(owner_id)
    .bind(repo_id)
    .bind(window_start)
    .bind(seconds)
    .bind(now_ts)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Sandbox-seconds metered for one owner since `since` (unix seconds).
pub async fn usage_seconds_since(db: &Db, owner_id: i64, since: i64) -> DbResult<i64> {
    let total: Option<i64> = sqlx::query_scalar(
        "SELECT SUM(seconds) FROM sandbox_usage WHERE owner_id = $1 AND window_start >= $2",
    )
    .bind(owner_id)
    .bind(since)
    .fetch_one(db.read_pool())
    .await?;
    Ok(total.unwrap_or(0))
}

/// Sandbox-seconds metered for one repo since `since` (unix seconds).
pub async fn repo_usage_seconds_since(db: &Db, repo_id: i64, since: i64) -> DbResult<i64> {
    let total: Option<i64> = sqlx::query_scalar(
        "SELECT SUM(seconds) FROM sandbox_usage WHERE repo_id = $1 AND window_start >= $2",
    )
    .bind(repo_id)
    .bind(since)
    .fetch_one(db.read_pool())
    .await?;
    Ok(total.unwrap_or(0))
}
