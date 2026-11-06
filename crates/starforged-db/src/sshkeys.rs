//! `ssh_keys` and `deploy_keys`: OpenSSH public keys (spec §6.1, D3).

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyRow {
    pub id: i64,
    pub user_id: i64,
    pub title: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployKeyRow {
    pub id: i64,
    pub repo_id: i64,
    pub title: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub read_write: bool,
    pub created_by: Option<i64>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub struct NewSshKey<'a> {
    pub user_id: i64,
    pub title: &'a str,
    pub algorithm: &'a str,
    pub fingerprint: &'a str,
    pub public_key: &'a str,
}

pub struct NewDeployKey<'a> {
    pub repo_id: i64,
    pub title: &'a str,
    pub algorithm: &'a str,
    pub fingerprint: &'a str,
    pub public_key: &'a str,
    pub read_write: bool,
    pub created_by: i64,
}

/// Why a transactional key insert did not add a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddKeyError {
    /// The fingerprint is already registered (user key or deploy key).
    Duplicate,
    /// The parent (user / repository) already holds the maximum keys.
    TooMany,
}

fn ssh_from_row(row: &AnyRow) -> DbResult<SshKeyRow> {
    Ok(SshKeyRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        title: row.try_get("title")?,
        algorithm: row.try_get("algorithm")?,
        fingerprint: row.try_get("fingerprint")?,
        public_key: row.try_get("public_key")?,
        created_at: row.try_get("created_at")?,
        last_used_at: row.try_get("last_used_at")?,
    })
}

fn deploy_from_row(row: &AnyRow) -> DbResult<DeployKeyRow> {
    let read_write: i64 = row.try_get("read_write")?;
    Ok(DeployKeyRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        title: row.try_get("title")?,
        algorithm: row.try_get("algorithm")?,
        fingerprint: row.try_get("fingerprint")?,
        public_key: row.try_get("public_key")?,
        read_write: read_write != 0,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        last_used_at: row.try_get("last_used_at")?,
    })
}

/// Inserts a user key in one transaction: locks the user row, counts
/// existing keys, inserts the key and its `ssh_fingerprints` registry row.
/// The per-parent lock (users row) serializes concurrent adds for one
/// user so the cap holds on Postgres READ COMMITTED; the registry primary
/// key serializes cross-table fingerprint claims. A unique violation from
/// either the key table or the registry maps to `Duplicate`.
pub async fn insert_ssh_key(
    db: &Db,
    key: &NewSshKey<'_>,
    max_per_user: i64,
) -> DbResult<Result<i64, AddKeyError>> {
    let mut tx = db.pool().begin().await?;
    // `users` has no `updated_at`; `display_name = display_name` is a
    // no-op update that takes the row lock (and the write lock on SQLite).
    sqlx::query("UPDATE users SET display_name = display_name WHERE id = $1")
        .bind(key.user_id)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ssh_keys WHERE user_id = $1")
        .bind(key.user_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= max_per_user {
        return Ok(Err(AddKeyError::TooMany));
    }
    let inserted: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO ssh_keys (user_id, title, algorithm, fingerprint, public_key, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(key.user_id)
    .bind(key.title)
    .bind(key.algorithm)
    .bind(key.fingerprint)
    .bind(key.public_key)
    .bind(now())
    .fetch_one(&mut *tx)
    .await;
    let id = match inserted {
        Ok(id) => id,
        Err(e)
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation()) =>
        {
            return Ok(Err(AddKeyError::Duplicate));
        }
        Err(e) => return Err(e.into()),
    };
    let registered =
        sqlx::query("INSERT INTO ssh_fingerprints (fingerprint, ssh_key_id, deploy_key_id) VALUES ($1, $2, NULL)")
            .bind(key.fingerprint)
            .bind(id)
            .execute(&mut *tx)
            .await;
    if let Err(e) = registered {
        if e.as_database_error()
            .is_some_and(|d| d.is_unique_violation())
        {
            return Ok(Err(AddKeyError::Duplicate));
        }
        return Err(e.into());
    }
    tx.commit().await?;
    Ok(Ok(id))
}

/// Inserts a deploy key in one transaction; see [`insert_ssh_key`]. The
/// per-parent lock is the `repos` row (`updated_at = updated_at`).
pub async fn insert_deploy_key(
    db: &Db,
    key: &NewDeployKey<'_>,
    max_per_repo: i64,
) -> DbResult<Result<i64, AddKeyError>> {
    let mut tx = db.pool().begin().await?;
    sqlx::query("UPDATE repos SET updated_at = updated_at WHERE id = $1")
        .bind(key.repo_id)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deploy_keys WHERE repo_id = $1")
        .bind(key.repo_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= max_per_repo {
        return Ok(Err(AddKeyError::TooMany));
    }
    let inserted: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO deploy_keys (repo_id, title, algorithm, fingerprint, public_key, read_write, created_by, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(key.repo_id)
    .bind(key.title)
    .bind(key.algorithm)
    .bind(key.fingerprint)
    .bind(key.public_key)
    .bind(i64::from(key.read_write))
    .bind(key.created_by)
    .bind(now())
    .fetch_one(&mut *tx)
    .await;
    let id = match inserted {
        Ok(id) => id,
        Err(e)
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation()) =>
        {
            return Ok(Err(AddKeyError::Duplicate));
        }
        Err(e) => return Err(e.into()),
    };
    let registered =
        sqlx::query("INSERT INTO ssh_fingerprints (fingerprint, ssh_key_id, deploy_key_id) VALUES ($1, NULL, $2)")
            .bind(key.fingerprint)
            .bind(id)
            .execute(&mut *tx)
            .await;
    if let Err(e) = registered {
        if e.as_database_error()
            .is_some_and(|d| d.is_unique_violation())
        {
            return Ok(Err(AddKeyError::Duplicate));
        }
        return Err(e.into());
    }
    tx.commit().await?;
    Ok(Ok(id))
}

pub async fn ssh_key_by_fingerprint(db: &Db, fingerprint: &str) -> DbResult<Option<SshKeyRow>> {
    let row = sqlx::query(concat!(
        "SELECT id, user_id, title, algorithm, fingerprint, public_key, created_at, last_used_at ",
        "FROM ssh_keys WHERE fingerprint = $1"
    ))
    .bind(fingerprint)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(ssh_from_row).transpose()
}

pub async fn deploy_key_by_fingerprint(
    db: &Db,
    fingerprint: &str,
) -> DbResult<Option<DeployKeyRow>> {
    let row = sqlx::query(concat!(
        "SELECT id, repo_id, title, algorithm, fingerprint, public_key, read_write, created_by, created_at, last_used_at ",
        "FROM deploy_keys WHERE fingerprint = $1"
    ))
    .bind(fingerprint)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(deploy_from_row).transpose()
}

pub async fn list_ssh_keys(db: &Db, user_id: i64) -> DbResult<Vec<SshKeyRow>> {
    let rows = sqlx::query(concat!(
        "SELECT id, user_id, title, algorithm, fingerprint, public_key, created_at, last_used_at ",
        "FROM ssh_keys WHERE user_id = $1 ORDER BY id"
    ))
    .bind(user_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(ssh_from_row).collect()
}

pub async fn list_deploy_keys(db: &Db, repo_id: i64) -> DbResult<Vec<DeployKeyRow>> {
    let rows = sqlx::query(concat!(
        "SELECT id, repo_id, title, algorithm, fingerprint, public_key, read_write, created_by, created_at, last_used_at ",
        "FROM deploy_keys WHERE repo_id = $1 ORDER BY id"
    ))
    .bind(repo_id)
        .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(deploy_from_row).collect()
}

pub async fn count_ssh_keys(db: &Db, user_id: i64) -> DbResult<i64> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ssh_keys WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db.read_pool())
        .await?;
    Ok(count)
}

pub async fn count_deploy_keys(db: &Db, repo_id: i64) -> DbResult<i64> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deploy_keys WHERE repo_id = $1")
        .bind(repo_id)
        .fetch_one(db.read_pool())
        .await?;
    Ok(count)
}

/// Deletes the user's key; the `ssh_fingerprints` claim row cascades.
/// `false` when it does not exist or belongs to someone else.
pub async fn remove_ssh_key(db: &Db, user_id: i64, id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM ssh_keys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes a deploy key; the `ssh_fingerprints` claim row cascades.
/// `false` when absent or in another repository.
pub async fn remove_deploy_key(db: &Db, repo_id: i64, id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM deploy_keys WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Whether the row's `last_used_at` is at least 60 seconds old (or unset).
pub fn touch_due(last_used_at: Option<i64>) -> bool {
    match last_used_at {
        None => true,
        Some(ts) => now() - ts >= 60,
    }
}

pub async fn touch_ssh_key(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("UPDATE ssh_keys SET last_used_at = $1 WHERE id = $2")
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn touch_deploy_key(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("UPDATE deploy_keys SET last_used_at = $1 WHERE id = $2")
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
