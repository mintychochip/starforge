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
    /// The actor's handle at read time, or `None` for system rows and deleted accounts.
    pub actor_handle: Option<String>,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub ip: String,
    pub user_agent: String,
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

const SELECT_ROWS: &str = "SELECT a.id, a.actor_id, o.handle AS actor_handle, a.action, a.target, a.detail, a.ip, a.user_agent, a.created_at \
     FROM audit_log a LEFT JOIN owners o ON o.id = a.actor_id";

fn from_row(row: &sqlx::any::AnyRow) -> DbResult<AuditRow> {
    Ok(AuditRow {
        id: row.try_get("id")?,
        actor_id: row.try_get("actor_id")?,
        actor_handle: row.try_get("actor_handle")?,
        action: row.try_get("action")?,
        target: row.try_get("target")?,
        detail: row.try_get("detail")?,
        ip: row.try_get("ip")?,
        user_agent: row.try_get("user_agent")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Newest first.
pub async fn recent(db: &Db, limit: i64) -> DbResult<Vec<AuditRow>> {
    // Safe: the query is a fixed literal; `limit` is bound, never interpolated.
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT_ROWS} ORDER BY a.id DESC LIMIT $1"
    )))
    .bind(limit)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Filters for [`search`]; every `None` leaves that dimension unconstrained.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Exact actor handle (case-insensitive); rows without an actor never match.
    pub actor: Option<String>,
    /// Exact action, or a prefix when it ends with `.` (e.g. `session.`).
    pub action: Option<String>,
    /// Case-insensitive substring of the stored target.
    pub target: Option<String>,
    /// Inclusive lower bound on `created_at` (unix seconds).
    pub from: Option<i64>,
    /// Exclusive upper bound on `created_at` (unix seconds).
    pub to: Option<i64>,
    /// Keyset cursor: only rows older than this id.
    pub after: Option<i64>,
    /// Maximum rows to return.
    pub limit: i64,
}

/// Escapes the `LIKE` wildcards in `value` so it matches literally under `ESCAPE '\'`.
fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

enum Bind {
    Text(String),
    Int(i64),
}

/// Newest first, with optional filters and keyset pagination on the id.
pub async fn search(db: &Db, filter: &AuditFilter) -> DbResult<Vec<AuditRow>> {
    let mut sql = String::from(SELECT_ROWS);
    sql.push_str(" WHERE 1 = 1");
    let mut binds: Vec<Bind> = Vec::new();
    let mut next = 1usize;
    let mut placeholder = || {
        let p = format!("${next}");
        next += 1;
        p
    };
    if let Some(actor) = &filter.actor {
        sql.push_str(&format!(" AND LOWER(o.handle) = LOWER({})", placeholder()));
        binds.push(Bind::Text(actor.clone()));
    }
    if let Some(action) = &filter.action {
        if let Some(prefix) = action.strip_suffix('.') {
            sql.push_str(&format!(
                " AND LOWER(a.action) LIKE LOWER({}) ESCAPE '\\'",
                placeholder()
            ));
            binds.push(Bind::Text(format!("{}%", escape_like(prefix))));
        } else {
            sql.push_str(&format!(" AND a.action = {}", placeholder()));
            binds.push(Bind::Text(action.clone()));
        }
    }
    if let Some(target) = &filter.target {
        sql.push_str(&format!(
            " AND LOWER(a.target) LIKE LOWER({}) ESCAPE '\\'",
            placeholder()
        ));
        binds.push(Bind::Text(format!("%{}%", escape_like(target))));
    }
    if let Some(from) = filter.from {
        sql.push_str(&format!(" AND a.created_at >= {}", placeholder()));
        binds.push(Bind::Int(from));
    }
    if let Some(to) = filter.to {
        sql.push_str(&format!(" AND a.created_at < {}", placeholder()));
        binds.push(Bind::Int(to));
    }
    if let Some(after) = filter.after {
        sql.push_str(&format!(" AND a.id < {}", placeholder()));
        binds.push(Bind::Int(after));
    }
    sql.push_str(&format!(" ORDER BY a.id DESC LIMIT {}", placeholder()));
    binds.push(Bind::Int(filter.limit));

    // Safe: only `$N` placeholders and fixed SQL fragments are interpolated;
    // every filter value is bound, never interpolated.
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
    for bind in binds {
        query = match bind {
            Bind::Text(value) => query.bind(value),
            Bind::Int(value) => query.bind(value),
        };
    }
    let rows = query.fetch_all(db.pool()).await?;
    rows.iter().map(from_row).collect()
}
