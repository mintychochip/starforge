//! Invites (forge-basics design §4.1, §7): site admins issue single-use sign-up links.

use starforged_db::invites::{self, InviteRow, NewInvite};
use starforged_db::now;

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, crypto, mail, validate};

/// Invites expire 7 days after they are issued.
pub const INVITE_TTL_SECS: i64 = 7 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteStatus {
    Pending,
    Used,
    Expired,
    Revoked,
}

impl InviteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            InviteStatus::Pending => "pending",
            InviteStatus::Used => "used",
            InviteStatus::Expired => "expired",
            InviteStatus::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInfo {
    pub id: i64,
    pub email: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: InviteStatus,
}

#[derive(Debug, Clone)]
pub struct CreatedInvite {
    pub id: i64,
    /// Shown once; only the code's hash is stored.
    pub link: String,
    /// The link was also emailed to the invite's address.
    pub emailed: bool,
}

fn status(row: &InviteRow, now_ts: i64) -> InviteStatus {
    if row.revoked_at.is_some() {
        InviteStatus::Revoked
    } else if row.used_at.is_some() {
        InviteStatus::Used
    } else if row.expires_at <= now_ts {
        InviteStatus::Expired
    } else {
        InviteStatus::Pending
    }
}

impl Core {
    /// Site admins only. When `email` is set, only that address can use the invite, and the link is emailed
    /// if mail is configured.
    pub async fn create_invite(
        &self,
        admin: &User,
        email: Option<&str>,
    ) -> CoreResult<CreatedInvite> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let email = email
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(validate::email)
            .transpose()?;
        let code = crypto::random_hex(32);
        let id = invites::insert(
            self.db(),
            &NewInvite {
                code_hash: &crypto::sha256_hex(&code),
                email: email.as_deref(),
                created_by: admin.id,
                expires_at: now() + INVITE_TTL_SECS,
            },
        )
        .await?;
        let link = format!("{}/join?invite={code}", self.config().base_url);
        let emailed = match &email {
            Some(to) if self.mail_enabled() => {
                self.queue_email(mail::invite_email(to, &admin.handle, &link)?)
                    .await?;
                true
            }
            _ => false,
        };
        self.audit(
            Some(admin.id),
            "invite.create",
            &format!("invite:{id}"),
            email.as_deref().unwrap_or(""),
        )
        .await?;
        Ok(CreatedInvite { id, link, emailed })
    }

    /// Site admins only; newest first.
    pub async fn list_invites(&self, admin: &User) -> CoreResult<Vec<InviteInfo>> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let ts = now();
        Ok(invites::list(self.db(), 500)
            .await?
            .into_iter()
            .map(|row| InviteInfo {
                id: row.id,
                status: status(&row, ts),
                email: row.email,
                created_at: row.created_at,
                expires_at: row.expires_at,
            })
            .collect())
    }

    /// Site admins only. `NotFound` when the invite is unknown, used, or already revoked.
    pub async fn revoke_invite(&self, admin: &User, id: i64) -> CoreResult<()> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        if !invites::revoke(self.db(), id, now()).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(Some(admin.id), "invite.revoke", &format!("invite:{id}"), "")
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, user};

    #[tokio::test]
    async fn only_site_admins_manage_invites() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        assert!(matches!(
            core.create_invite(&alice, None).await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.list_invites(&alice).await,
            Err(CoreError::Forbidden)
        ));
        let root = core
            .create_user(CreateUser {
                handle: "root".into(),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let first = core.create_invite(&root, None).await.unwrap();
        assert!(matches!(
            core.revoke_invite(&alice, first.id).await,
            Err(CoreError::Forbidden)
        ));
        core.revoke_invite(&root, first.id).await.unwrap();
        assert!(matches!(
            core.revoke_invite(&root, first.id).await,
            Err(CoreError::NotFound)
        ));
        let first_code = first.link.split("invite=").nth(1).unwrap();
        assert!(
            core.invite_email(first_code).await.is_err(),
            "revoked invites are unusable"
        );

        let second = core
            .create_invite(&root, Some("x@example.com"))
            .await
            .unwrap();
        assert!(!second.emailed, "no mail configured");
        sqlx::query("UPDATE invites SET expires_at = $1 WHERE id = $2")
            .bind(1_i64)
            .bind(second.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        let listed: Vec<(i64, InviteStatus)> = core
            .list_invites(&root)
            .await
            .unwrap()
            .into_iter()
            .map(|i| (i.id, i.status))
            .collect();
        assert_eq!(
            listed,
            vec![
                (second.id, InviteStatus::Expired),
                (first.id, InviteStatus::Revoked)
            ]
        );
    }
}
