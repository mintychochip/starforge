//! `repo_remotes`: configured git remotes for import and mirrors (spec §8.6,
//! M4b D2). Credentials are stored only sealed (`sealed_secret`); this crate
//! never interprets them.

use sqlx::Row;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRow {
    pub id: i64,
    pub repo_id: i64,
    pub role: String,
    pub url: String,
    pub auth: String,
    pub username: String,
    pub sealed_secret: Option<String>,
    pub ssh_public_key: Option<String>,
    pub interval_secs: i64,
    pub enabled: i64,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: String,
    pub created_by: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct NewRemote<'a> {
    pub repo_id: i64,
    pub role: &'a str,
    pub url: &'a str,
    pub auth: &'a str,
    pub username: &'a str,
    pub sealed_secret: Option<&'a str>,
    pub ssh_public_key: Option<&'a str>,
    pub created_by: i64,
}

macro_rules! select_remote {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, role, url, auth, username, sealed_secret, ssh_public_key, ",
            "interval_secs, enabled, last_attempt_at, last_success_at, last_error, ",
            "created_by, created_at, updated_at FROM repo_remotes ",
            $tail
        )
    };
}

fn from_row(row: &sqlx::any::AnyRow) -> DbResult<RemoteRow> {
    Ok(RemoteRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        role: row.try_get("role")?,
        url: row.try_get("url")?,
        auth: row.try_get("auth")?,
        username: row.try_get("username")?,
        sealed_secret: row.try_get("sealed_secret")?,
        ssh_public_key: row.try_get("ssh_public_key")?,
        interval_secs: row.try_get("interval_secs")?,
        enabled: row.try_get("enabled")?,
        last_attempt_at: row.try_get("last_attempt_at")?,
        last_success_at: row.try_get("last_success_at")?,
        last_error: row.try_get("last_error")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// Inserts the remote. The unique indexes refuse a second import or pull row
/// per repository; callers translate that into a validation error.
pub async fn insert(db: &Db, remote: &NewRemote<'_>) -> DbResult<i64> {
    let ts = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO repo_remotes (repo_id, role, url, auth, username, sealed_secret, \
         ssh_public_key, created_by, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(remote.repo_id)
    .bind(remote.role)
    .bind(remote.url)
    .bind(remote.auth)
    .bind(remote.username)
    .bind(remote.sealed_secret)
    .bind(remote.ssh_public_key)
    .bind(remote.created_by)
    .bind(ts)
    .bind(ts)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

/// Any remote with this id.
pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<RemoteRow>> {
    let row = sqlx::query(select_remote!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// The `import` or `pull` remote of a repository (`role` is a fixed caller
/// string, never user input).
pub async fn by_repo_role(db: &Db, repo_id: i64, role: &str) -> DbResult<Option<RemoteRow>> {
    let row = sqlx::query(select_remote!("WHERE repo_id = $1 AND role = $2"))
        .bind(repo_id)
        .bind(role)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// Every remote of a repository, by id.
pub async fn list_by_repo(db: &Db, repo_id: i64) -> DbResult<Vec<RemoteRow>> {
    let rows = sqlx::query(select_remote!("WHERE repo_id = $1 ORDER BY id"))
        .bind(repo_id)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(from_row).collect()
}

/// Deletes the remote; `false` when it does not exist.
pub async fn delete(db: &Db, id: i64) -> DbResult<bool> {
    let done = sqlx::query("DELETE FROM repo_remotes WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Replaces the stored credentials (re-entered on retry/rotation). The URL
/// stays the one the row was created with.
pub async fn update_credentials(
    db: &Db,
    id: i64,
    auth: &str,
    username: &str,
    sealed_secret: Option<&str>,
    ssh_public_key: Option<&str>,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE repo_remotes SET auth = $1, username = $2, sealed_secret = $3, \
         ssh_public_key = $4, updated_at = $5 WHERE id = $6",
    )
    .bind(auth)
    .bind(username)
    .bind(sealed_secret)
    .bind(ssh_public_key)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Records one fetch/push attempt: `error = ''` means success.
pub async fn record_attempt(db: &Db, id: i64, success: bool, error: &str) -> DbResult<()> {
    if success {
        sqlx::query(
            "UPDATE repo_remotes SET last_attempt_at = $1, last_success_at = $1, \
             last_error = '', updated_at = $1 WHERE id = $2",
        )
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    } else {
        sqlx::query(
            "UPDATE repo_remotes SET last_attempt_at = $1, last_error = $2, \
             updated_at = $1 WHERE id = $3",
        )
        .bind(now())
        .bind(error)
        .bind(id)
        .execute(db.pool())
        .await?;
    }
    Ok(())
}

/// Sets `import_state` only while the repository's import remote row
/// still exists; `false` when it was deleted mid-flight (the caller
/// must then skip every further state write). Safe on both engines.
pub async fn set_import_state_if_remote(db: &Db, repo_id: i64, state: &str) -> DbResult<bool> {
    let result = sqlx::query(
        "UPDATE repos SET import_state = $1 WHERE id = $2 \
         AND EXISTS (SELECT 1 FROM repo_remotes WHERE repo_id = $2 AND role = 'import')",
    )
    .bind(state)
    .bind(repo_id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Rewrites a pull mirror's configuration (URL, credentials, interval) and
/// enables it. Used by the pull-mirror PUT; the push-mirror PUT reuses the
/// same shape with its own caller.
#[allow(clippy::too_many_arguments)]
pub async fn update_pull_config(
    db: &Db,
    id: i64,
    url: &str,
    auth: &str,
    username: &str,
    sealed_secret: Option<&str>,
    ssh_public_key: Option<&str>,
    interval_secs: i64,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE repo_remotes SET url = $1, auth = $2, username = $3, sealed_secret = $4, \
         ssh_public_key = $5, interval_secs = $6, enabled = 1, updated_at = $7 WHERE id = $8",
    )
    .bind(url)
    .bind(auth)
    .bind(username)
    .bind(sealed_secret)
    .bind(ssh_public_key)
    .bind(interval_secs)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Enables or disables a remote. Disabling restores pushes on a pull mirror
/// without forgetting its configuration.
pub async fn set_enabled(db: &Db, id: i64, enabled: bool) -> DbResult<()> {
    sqlx::query("UPDATE repo_remotes SET enabled = $1, updated_at = $2 WHERE id = $3")
        .bind(i64::from(enabled))
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Repositories with an enabled pull mirror, for the schedule reconciler.
pub async fn enabled_pull_repo_ids(db: &Db) -> DbResult<Vec<i64>> {
    let rows: Vec<i64> =
        sqlx::query_scalar("SELECT repo_id FROM repo_remotes WHERE role = 'pull' AND enabled = 1")
            .fetch_all(db.read_pool())
            .await?;
    Ok(rows)
}

/// Enabled push-mirror remote ids, for the schedule reconciler (M4b D5).
pub async fn enabled_push_remote_ids(db: &Db) -> DbResult<Vec<i64>> {
    let rows: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM repo_remotes WHERE role = 'push' AND enabled = 1")
            .fetch_all(db.read_pool())
            .await?;
    Ok(rows)
}

/// Inserts one push remote, refusing when the repository already has
/// `max` push mirrors (`None` in that case). The count and the insert run
/// in one transaction after a parent-row lock on the repository, so
/// concurrent adds serialize and the cap holds on both engines (under
/// Postgres READ COMMITTED a bare count-then-insert could let two
/// transactions both pass the count).
pub async fn insert_push_remote_capped(
    db: &Db,
    remote: &NewRemote<'_>,
    max: i64,
) -> DbResult<Option<i64>> {
    let ts = now();
    let mut tx = db.pool().begin().await?;
    sqlx::query("UPDATE repos SET updated_at = updated_at WHERE id = $1")
        .bind(remote.repo_id)
        .execute(tx.as_mut())
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM repo_remotes WHERE repo_id = $1 AND role = 'push'",
    )
    .bind(remote.repo_id)
    .fetch_one(tx.as_mut())
    .await?;
    if count >= max {
        return Ok(None);
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO repo_remotes (repo_id, role, url, auth, username, sealed_secret, \
         ssh_public_key, created_by, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(remote.repo_id)
    .bind(remote.role)
    .bind(remote.url)
    .bind(remote.auth)
    .bind(remote.username)
    .bind(remote.sealed_secret)
    .bind(remote.ssh_public_key)
    .bind(remote.created_by)
    .bind(ts)
    .bind(ts)
    .fetch_one(tx.as_mut())
    .await?;
    tx.commit().await?;
    Ok(Some(id))
}
