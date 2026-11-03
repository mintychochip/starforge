//! `audit_log`: append-only record of security-relevant events (spec §6.5). Never stores transcript content.

use sqlx::Row;

use crate::{Db, DbResult, now};

pub struct AuditEntry<'a> {
    pub actor_id: Option<i64>,
    pub action: &'a str,
    pub target: &'a str,
    pub detail: &'a str,
    pub ip: &'a str,
    pub user_agent: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: i64,
    pub actor_id: Option<i64>,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub created_at: i64,
}

pub async fn record(db: &Db, entry: &AuditEntry<'_>) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, target, detail, ip, user_agent, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(entry.actor_id)
    .bind(entry.action)
    .bind(entry.target)
    .bind(entry.detail)
    .bind(entry.ip)
    .bind(entry.user_agent)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Newest first.
pub async fn recent(db: &Db, limit: i64) -> DbResult<Vec<AuditRow>> {
    let rows = sqlx::query("SELECT id, actor_id, action, target, detail, created_at FROM audit_log ORDER BY id DESC LIMIT $1")
        .bind(limit)
        .fetch_all(db.pool())
        .await?;
    rows.iter()
        .map(|row| {
            Ok(AuditRow {
                id: row.try_get("id")?,
                actor_id: row.try_get("actor_id")?,
                action: row.try_get("action")?,
                target: row.try_get("target")?,
                detail: row.try_get("detail")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}
