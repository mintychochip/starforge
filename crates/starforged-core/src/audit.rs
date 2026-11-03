use starforged_db::audit::{self, AuditEntry};

use crate::{Core, CoreResult};

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
