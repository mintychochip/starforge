//! `web_sessions`: browser sessions, keyed by SHA-256 of the cookie value.

use sqlx::Row;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSessionRow {
    pub id: i64,
    pub user_id: i64,
    pub csrf_token: String,
    pub expires_at: i64,
    pub last_seen_at: i64,
}

pub struct NewWebSession<'a> {
    pub session_hash: &'a str,
    pub user_id: i64,
    pub csrf_token: &'a str,
    pub expires_at: i64,
    pub user_agent: &'a str,
    pub ip: &'a str,
}

pub async fn insert(db: &Db, session: &NewWebSession<'_>) -> DbResult<i64> {
    let ts = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO web_sessions (session_hash, user_id, csrf_token, created_at, expires_at, last_seen_at, user_agent, ip) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(session.session_hash)
    .bind(session.user_id)
    .bind(session.csrf_token)
    .bind(ts)
    .bind(session.expires_at)
    .bind(ts)
    .bind(session.user_agent)
    .bind(session.ip)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

/// The session whose cookie hashes to `session_hash`, if it expires after `now_ts`.
pub async fn active_by_hash(
    db: &Db,
    session_hash: &str,
    now_ts: i64,
) -> DbResult<Option<WebSessionRow>> {
    let row = sqlx::query("SELECT id, user_id, csrf_token, expires_at, last_seen_at FROM web_sessions WHERE session_hash = $1 AND expires_at > $2")
        .bind(session_hash)
        .bind(now_ts)
        .fetch_optional(db.pool())
        .await?;
    row.map(|row| {
        Ok(WebSessionRow {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            csrf_token: row.try_get("csrf_token")?,
            expires_at: row.try_get("expires_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
        })
    })
    .transpose()
}

pub async fn delete_by_hash(db: &Db, session_hash: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM web_sessions WHERE session_hash = $1")
        .bind(session_hash)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Deletes sessions whose expiry is at or before `now_ts`; returns how many.
pub async fn delete_expired(db: &Db, now_ts: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE expires_at <= $1")
        .bind(now_ts)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}

/// Signs a user out everywhere; returns how many sessions ended.
pub async fn delete_for_user(db: &Db, user_id: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListRow {
    pub id: i64,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub user_agent: String,
    pub ip: String,
}

/// The user's unexpired sessions, most recently active first.
pub async fn list_for_user(db: &Db, user_id: i64, now_ts: i64) -> DbResult<Vec<SessionListRow>> {
    let rows = sqlx::query(
        "SELECT id, created_at, last_seen_at, user_agent, ip FROM web_sessions \
         WHERE user_id = $1 AND expires_at > $2 ORDER BY last_seen_at DESC, id DESC",
    )
    .bind(user_id)
    .bind(now_ts)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(SessionListRow {
                id: row.try_get("id")?,
                created_at: row.try_get("created_at")?,
                last_seen_at: row.try_get("last_seen_at")?,
                user_agent: row.try_get("user_agent")?,
                ip: row.try_get("ip")?,
            })
        })
        .collect()
}

pub async fn touch(db: &Db, id: i64, now_ts: i64) -> DbResult<()> {
    sqlx::query("UPDATE web_sessions SET last_seen_at = $1 WHERE id = $2")
        .bind(now_ts)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Ends one of the user's sessions; `false` when the user has no session with that id.
pub async fn delete_by_id_for_user(db: &Db, id: i64, user_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Ends every session of the user except `keep_id`; returns how many ended.
pub async fn delete_for_user_except(db: &Db, user_id: i64, keep_id: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE user_id = $1 AND id <> $2")
        .bind(user_id)
        .bind(keep_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}
