//! `collaborators`: direct per-repository grants to users (spec §6.1).

use sqlx::Row;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollaboratorRow {
    pub user_id: i64,
    pub handle: String,
    pub permission: String,
}

/// Grants `permission`, replacing any existing grant.
pub async fn upsert(db: &Db, repo_id: i64, user_id: i64, permission: &str) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO collaborators (repo_id, user_id, permission, created_at) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (repo_id, user_id) DO UPDATE SET permission = excluded.permission",
    )
    .bind(repo_id)
    .bind(user_id)
    .bind(permission)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn remove(db: &Db, repo_id: i64, user_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM collaborators WHERE repo_id = $1 AND user_id = $2")
        .bind(repo_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn permission(db: &Db, repo_id: i64, user_id: i64) -> DbResult<Option<String>> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT permission FROM collaborators WHERE repo_id = $1 AND user_id = $2",
    )
    .bind(repo_id)
    .bind(user_id)
    .fetch_optional(db.read_pool())
    .await?;
    Ok(value)
}

pub async fn list(db: &Db, repo_id: i64) -> DbResult<Vec<CollaboratorRow>> {
    let rows = sqlx::query(
        "SELECT c.user_id, o.handle, c.permission FROM collaborators c JOIN owners o ON o.id = c.user_id \
         WHERE c.repo_id = $1 ORDER BY o.handle",
    )
    .bind(repo_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(CollaboratorRow {
                user_id: row.try_get("user_id")?,
                handle: row.try_get("handle")?,
                permission: row.try_get("permission")?,
            })
        })
        .collect()
}
