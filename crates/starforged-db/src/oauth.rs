//! OAuth device-flow one-time codes (RFC 8628): only the SHA-256 hash of the
//! `device_code` is stored. `user_code` is stored uppercased so lookups are
//! case-insensitive.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCodeRow {
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub status: String,
    pub user_id: Option<i64>,
    pub interval_secs: i64,
    pub expires_at: i64,
    pub last_poll_at: Option<i64>,
    pub created_at: i64,
}

pub struct NewDeviceCode<'a> {
    pub device_code_hash: &'a str,
    pub user_code: &'a str,
    pub client_id: &'a str,
    pub scope: &'a str,
    pub interval_secs: i64,
    pub expires_at: i64,
}

macro_rules! select_device_code {
    ($tail:literal) => {
        concat!(
            "SELECT device_code_hash, user_code, client_id, scope, status, user_id, ",
            "interval_secs, expires_at, last_poll_at, created_at FROM device_codes ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<DeviceCodeRow> {
    Ok(DeviceCodeRow {
        device_code_hash: row.try_get("device_code_hash")?,
        user_code: row.try_get("user_code")?,
        client_id: row.try_get("client_id")?,
        scope: row.try_get("scope")?,
        status: row.try_get("status")?,
        user_id: row.try_get("user_id")?,
        interval_secs: row.try_get("interval_secs")?,
        expires_at: row.try_get("expires_at")?,
        last_poll_at: row.try_get("last_poll_at")?,
        created_at: row.try_get("created_at")?,
    })
}

pub async fn insert_device_code(db: &Db, code: &NewDeviceCode<'_>) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, status, interval_secs, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)",
    )
    .bind(code.device_code_hash)
    .bind(code.user_code)
    .bind(code.client_id)
    .bind(code.scope)
    .bind(code.interval_secs)
    .bind(code.expires_at)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn device_code_by_hash(
    db: &Db,
    device_code_hash: &str,
) -> DbResult<Option<DeviceCodeRow>> {
    let row = sqlx::query(select_device_code!("WHERE device_code_hash = $1"))
        .bind(device_code_hash)
        .fetch_optional(db.pool())
        .await?;
    row.map(|row| from_row(&row)).transpose()
}

/// `user_code` must already be normalized (uppercased); codes are stored that way.
pub async fn device_code_by_user_code(db: &Db, user_code: &str) -> DbResult<Option<DeviceCodeRow>> {
    let row = sqlx::query(select_device_code!("WHERE user_code = $1"))
        .bind(user_code)
        .fetch_optional(db.pool())
        .await?;
    row.map(|row| from_row(&row)).transpose()
}

/// Binds the approver and flips `pending` to `approved` or `denied`.
/// Returns `false` when the row is gone or no longer pending.
pub async fn approve_device_code(
    db: &Db,
    device_code_hash: &str,
    user_id: i64,
    approved: bool,
) -> DbResult<bool> {
    let status = if approved { "approved" } else { "denied" };
    let result = sqlx::query(
        "UPDATE device_codes SET status = $1, user_id = $2 WHERE device_code_hash = $3 AND status = 'pending'",
    )
    .bind(status)
    .bind(user_id)
    .bind(device_code_hash)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Records a poll: refreshes `last_poll_at` and persists the (possibly grown) interval.
pub async fn record_poll(
    db: &Db,
    device_code_hash: &str,
    now: i64,
    interval_secs: i64,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE device_codes SET last_poll_at = $1, interval_secs = $2 WHERE device_code_hash = $3",
    )
    .bind(now)
    .bind(interval_secs)
    .bind(device_code_hash)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn mark_consumed(db: &Db, device_code_hash: &str) -> DbResult<()> {
    sqlx::query("UPDATE device_codes SET status = 'consumed' WHERE device_code_hash = $1")
        .bind(device_code_hash)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn delete_device_code(db: &Db, device_code_hash: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM device_codes WHERE device_code_hash = $1")
        .bind(device_code_hash)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Sweeps rows past `now` (pending codes nobody approved, stale denials, spent grants).
pub async fn delete_expired(db: &Db, now: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM device_codes WHERE expires_at <= $1")
        .bind(now)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}
