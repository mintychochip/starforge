//! Account settings (forge-basics design §4.6): profile, email address, password, and web sessions.

use starforged_db::{now, users, web_sessions};

use crate::accounts::{User, hash_password};
use crate::email_tokens::{Purpose, VERIFY_TTL_SECS};
use crate::{Core, CoreError, CoreResult, mail, validate};

/// One signed-in browser, for the sessions page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: i64,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub user_agent: String,
    pub ip: String,
}

/// What a request to change the email address did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailChange {
    /// Mail is off: the new address is in use now, unverified.
    Changed,
    /// A confirmation link went to the new address; the change happens when it is used.
    ConfirmationSent,
    /// A confirmation link went out less than 5 minutes ago, so nothing was sent.
    Throttled,
}

pub(crate) fn email_taken() -> CoreError {
    CoreError::Conflict("That email address is already in use.".into())
}

impl Core {
    pub async fn update_profile(&self, user: &User, display_name: &str) -> CoreResult<User> {
        let display_name = validate::display_name(display_name)?;
        users::set_display_name(self.db(), user.id, &display_name).await?;
        self.audit(
            Some(user.id),
            "account.profile",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        self.user_by_id(user.id).await?.ok_or(CoreError::NotFound)
    }

    /// Changes the password after checking the current one; every session except `current_session` ends.
    pub async fn change_password(
        &self,
        user: &User,
        current_session: i64,
        current: &str,
        new: &str,
    ) -> CoreResult<()> {
        if self
            .authenticate_password(&user.handle, current)
            .await
            .is_err()
        {
            return Err(CoreError::Invalid(
                "The current password is incorrect.".into(),
            ));
        }
        validate::password(new)?;
        let hash = hash_password(new.to_owned()).await?;
        users::set_password_hash(self.db(), user.id, &hash).await?;
        web_sessions::delete_for_user_except(self.db(), user.id, current_session).await?;
        self.audit(
            Some(user.id),
            "account.password_change",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(())
    }

    /// With mail, a confirmation link goes to the new address and the change waits for it; without mail,
    /// the new address applies at once, unverified.
    pub async fn change_email(&self, user: &User, new_email: &str) -> CoreResult<EmailChange> {
        let email = validate::email(new_email)?;
        if user.email.as_deref() == Some(email.as_str()) {
            return Err(CoreError::Invalid(
                "That is already your email address.".into(),
            ));
        }
        if users::by_email(self.db(), &email).await?.is_some() {
            return Err(email_taken());
        }
        if !self.mail_enabled() {
            users::set_email(self.db(), user.id, Some(&email), false)
                .await
                .map_err(|e| {
                    if e.is_unique_violation() {
                        email_taken()
                    } else {
                        e.into()
                    }
                })?;
            self.audit(
                Some(user.id),
                "account.email_change",
                &format!("user:{}", user.handle),
                "",
            )
            .await?;
            return Ok(EmailChange::Changed);
        }
        let Some(secret) = self
            .issue_email_token(user.id, Purpose::ChangeEmail, &email, VERIFY_TTL_SECS, true)
            .await?
        else {
            return Ok(EmailChange::Throttled);
        };
        let link = format!("{}/verify/{secret}", self.config().base_url);
        self.queue_email(mail::confirm_email(&email, &user.handle, &link)?)
            .await?;
        Ok(EmailChange::ConfirmationSent)
    }

    pub async fn list_sessions(&self, user: &User) -> CoreResult<Vec<SessionInfo>> {
        Ok(web_sessions::list_for_user(self.db(), user.id, now())
            .await?
            .into_iter()
            .map(|row| SessionInfo {
                id: row.id,
                created_at: row.created_at,
                last_seen_at: row.last_seen_at,
                user_agent: row.user_agent,
                ip: row.ip,
            })
            .collect())
    }

    /// Ends one of the user's sessions; `NotFound` for a session that is not theirs.
    pub async fn revoke_session(&self, user: &User, session_id: i64) -> CoreResult<()> {
        if !web_sessions::delete_by_id_for_user(self.db(), session_id, user.id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "account.session_revoke",
            &format!("user:{}", user.handle),
            &format!("session:{session_id}"),
        )
        .await
    }

    /// Ends every session of the user except `keep`; returns how many ended.
    pub async fn revoke_other_sessions(&self, user: &User, keep: i64) -> CoreResult<u64> {
        let ended = web_sessions::delete_for_user_except(self.db(), user.id, keep).await?;
        self.audit(
            Some(user.id),
            "account.session_revoke",
            &format!("user:{}", user.handle),
            "others",
        )
        .await?;
        Ok(ended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, test_core_with, user, with_file_mail};

    const PASSWORD: &str = "correct horse battery";
    const NEW_PASSWORD: &str = "a brand new password";

    async fn alice(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn changing_the_password_ends_other_sessions() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        let (_, first) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        let (_, second) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        let current = core
            .web_session(&first.cookie_value)
            .await
            .unwrap()
            .unwrap()
            .session_id;
        let wrong = core
            .change_password(&alice, current, "not my password", NEW_PASSWORD)
            .await
            .unwrap_err();
        assert!(
            matches!(&wrong, CoreError::Invalid(m) if m.contains("current password")),
            "{wrong}"
        );
        core.change_password(&alice, current, PASSWORD, NEW_PASSWORD)
            .await
            .unwrap();
        assert!(
            core.web_session(&first.cookie_value)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            core.web_session(&second.cookie_value)
                .await
                .unwrap()
                .is_none()
        );
        core.login("alice", NEW_PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sessions_are_listed_and_revoked_by_their_owner() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        let bob = user(&core, "bob").await;
        core.login("alice", PASSWORD, "firefox", "10.0.0.1")
            .await
            .unwrap();
        core.login("alice", PASSWORD, "curl", "10.0.0.2")
            .await
            .unwrap();
        let listed = core.list_sessions(&alice).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|s| s.user_agent == "firefox" && s.ip == "10.0.0.1")
        );
        assert!(matches!(
            core.revoke_session(&bob, listed[0].id).await,
            Err(CoreError::NotFound)
        ));
        core.revoke_session(&alice, listed[0].id).await.unwrap();
        assert_eq!(core.list_sessions(&alice).await.unwrap().len(), 1);
        assert_eq!(
            core.revoke_other_sessions(&alice, listed[1].id)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn activity_is_recorded_at_most_every_five_minutes() {
        let (core, _f) = test_core().await;
        alice(&core).await;
        let (_, session) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        let last_seen = || async {
            let ts: i64 = sqlx::query_scalar("SELECT last_seen_at FROM web_sessions")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
            ts
        };
        sqlx::query("UPDATE web_sessions SET last_seen_at = $1")
            .bind(100_i64)
            .execute(core.db().pool())
            .await
            .unwrap();
        core.web_session(&session.cookie_value)
            .await
            .unwrap()
            .unwrap();
        assert!(last_seen().await >= starforged_db::now() - 5);
        let recent = starforged_db::now() - 60;
        sqlx::query("UPDATE web_sessions SET last_seen_at = $1")
            .bind(recent)
            .execute(core.db().pool())
            .await
            .unwrap();
        core.web_session(&session.cookie_value)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            last_seen().await,
            recent,
            "recent activity is not rewritten"
        );
    }

    #[tokio::test]
    async fn email_changes_need_confirmation_when_mail_is_on() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = alice(&core).await;
        core.create_user(CreateUser {
            handle: "bob".into(),
            email: Some("bob@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(matches!(
            core.change_email(&alice, "bob@example.com").await,
            Err(CoreError::Conflict(_))
        ));
        assert!(matches!(
            core.change_email(&alice, "alice@example.com").await,
            Err(CoreError::Invalid(_))
        ));
        assert_eq!(
            core.change_email(&alice, "alice@new.example")
                .await
                .unwrap(),
            EmailChange::ConfirmationSent
        );
        assert_eq!(
            core.change_email(&alice, "alice@other.example")
                .await
                .unwrap(),
            EmailChange::Throttled
        );
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(mail[0].contains("To: alice@new.example"), "{}", mail[0]);
        assert_eq!(
            core.user_by_id(alice.id)
                .await
                .unwrap()
                .unwrap()
                .email
                .as_deref(),
            Some("alice@example.com"),
            "the old address stays until the link is used"
        );
        let link = crate::mail::testing::find_link(&mail[0], "/verify/").unwrap();
        let secret = link.rsplit('/').next().unwrap();
        assert!(core.email_link_valid(secret).await.unwrap());
        let user = core.verify_email(secret).await.unwrap();
        assert_eq!(
            (user.email.as_deref(), user.email_verified),
            (Some("alice@new.example"), true)
        );
    }

    #[tokio::test]
    async fn without_mail_email_changes_apply_unverified() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert_eq!(
            core.change_email(&alice, "Alice@New.example")
                .await
                .unwrap(),
            EmailChange::Changed
        );
        let user = core.user_by_id(alice.id).await.unwrap().unwrap();
        assert_eq!(
            (user.email.as_deref(), user.email_verified),
            (Some("alice@new.example"), false)
        );
    }

    #[tokio::test]
    async fn display_names_are_validated() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert_eq!(
            core.update_profile(&alice, "  Alice L.  ")
                .await
                .unwrap()
                .display_name,
            "Alice L."
        );
        assert!(matches!(
            core.update_profile(&alice, &"x".repeat(101)).await,
            Err(CoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn change_email_links_survive_an_address_conflict() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = alice(&core).await;
        assert_eq!(
            core.change_email(&alice, "shared@example.com")
                .await
                .unwrap(),
            EmailChange::ConfirmationSent
        );
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        let link = crate::mail::testing::find_link(&mail[0], "/verify/").unwrap();
        let secret = link.rsplit('/').next().unwrap().to_owned();
        core.create_user(CreateUser {
            handle: "bob".into(),
            email: Some("shared@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(matches!(
            core.verify_email(&secret).await,
            Err(CoreError::Conflict(_))
        ));
        assert!(
            core.email_link_valid(&secret).await.unwrap(),
            "the link is still usable"
        );
        assert_eq!(
            core.user_by_id(alice.id)
                .await
                .unwrap()
                .unwrap()
                .email
                .as_deref(),
            Some("alice@example.com")
        );
    }
}
