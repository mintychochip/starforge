//! `web_sessions`: browser sessions, keyed by SHA-256 of the cookie value.

use sqlx::Row;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSessionRow {
    pub id: i64,
    pub user_id: i64,
    pub csrf_token: String,
    pub expires_at: i64,
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
    let row = sqlx::query("SELECT id, user_id, csrf_token, expires_at FROM web_sessions WHERE session_hash = $1 AND expires_at > $2")
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
