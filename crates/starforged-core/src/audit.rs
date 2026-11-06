use starforged_db::audit::{self, AuditEntry};

use crate::{Core, CoreError, CoreResult};

impl Core {
    /// Appends to the audit log. `target` names the object, e.g. `token:12` or `repo:alice/proj`.
    pub async fn audit(
        &self,
        actor_id: Option<i64>,
        action: &str,
        target: &str,
        detail: &str,
    ) -> CoreResult<()> {
        self.audit_client(actor_id, action, target, detail, "", "")
            .await
    }

    /// Like [`Core::audit`], recording the client's IP address and user agent.
    pub async fn audit_client(
        &self,
        actor_id: Option<i64>,
        action: &str,
        target: &str,
        detail: &str,
        ip: &str,
        user_agent: &str,
    ) -> CoreResult<()> {
        audit::record(
            self.db(),
            &AuditEntry {
                actor_id,
                action,
                target,
                detail,
                ip,
                user_agent,
            },
        )
        .await?;
        Ok(())
    }
}

/// Audit-log query as raw inputs: dates are `YYYY-MM-DD` days, `after` the keyset cursor.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub after: Option<i64>,
    pub limit: i64,
}

/// One audit entry for the admin page and API: the actor's current handle (or `None` for system rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntryView {
    pub id: i64,
    pub actor: Option<String>,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub ip: String,
    pub user_agent: String,
    pub created_at: i64,
}

/// `YYYY-MM-DD` → unix seconds at 00:00 UTC, for date filters.
pub(crate) fn day_start(date: &str) -> CoreResult<i64> {
    let parsed = time::Date::parse(
        date,
        &time::macros::format_description!("[year]-[month]-[day]"),
    )
    .map_err(|_| CoreError::Invalid(format!("invalid date '{date}'; expected YYYY-MM-DD")))?;
    Ok(parsed.midnight().assume_utc().unix_timestamp())
}
