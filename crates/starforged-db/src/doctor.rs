//! Read-only queries behind `starforged doctor` (plan M5b, task O3).
//!
//! Every statement here runs unchanged on SQLite and Postgres (`$N`
//! placeholders, `i64` integers), so the binary crate (`starforged`)
//! never needs an SQL dependency of its own.

use sqlx::Row;

use crate::{Db, DbResult};

/// Every `repo_remotes.url`, for doctor's SSH-client check.
pub async fn remote_urls(db: &Db) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT url FROM repo_remotes")
        .fetch_all(db.pool())
        .await?;
    let urls = rows
        .iter()
        .map(|row| row.try_get::<String, _>("url"))
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(urls)
}

/// Every `repos.id`, including soft-deleted rows, for doctor's stray
/// repository-directory check.
pub async fn repo_ids(db: &Db) -> DbResult<Vec<i64>> {
    let rows = sqlx::query("SELECT id FROM repos")
        .fetch_all(db.pool())
        .await?;
    let ids = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("id"))
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(ids)
}

/// Every `blobs.hash`, for doctor's orphaned-blob-file check.
pub async fn blob_hashes(db: &Db) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT hash FROM blobs")
        .fetch_all(db.pool())
        .await?;
    let hashes = rows
        .iter()
        .map(|row| row.try_get::<String, _>("hash"))
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(hashes)
}

/// Zero-ref blob rows created before `cutoff` (unix seconds), for
/// doctor's stale-row check.
pub async fn stale_zero_ref_blobs(db: &Db, cutoff: i64) -> DbResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE refcount <= 0 AND created_at < $1")
            .bind(cutoff)
            .fetch_one(db.pool())
            .await?,
    )
}

/// Trails in live repositories: the database side of doctor's search
/// index count comparison.
pub async fn live_trail_count(db: &Db) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM trails t JOIN repos r ON r.id = t.repo_id WHERE r.deleted_at IS NULL",
    )
    .fetch_one(db.pool())
    .await?)
}
