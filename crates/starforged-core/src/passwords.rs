//! Password recovery (forge-basics design §4.5, §7): emailed reset links, and links issued by site admins.

use starforged_db::{users, web_sessions};

use crate::accounts::{User, hash_password};
use crate::email_tokens::{ADMIN_RESET_TTL_SECS, Purpose, RESET_TTL_SECS};
use crate::{Core, CoreError, CoreResult, mail, validate};

/// How an admin-issued password reset reaches the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminReset {
    /// A link valid for 1 hour went to the account's address.
    Emailed,
    /// Mail is off or the account has no address: the admin passes this link on. It is valid for 24 hours.
    Link(String),
}

fn unusable_link() -> CoreError {
    CoreError::Invalid("This reset link is invalid, already used, or expired.".into())
}

impl Core {
    /// The "Forgot password?" form, which exists only with mail. The same outcome whether or not an active
    /// account uses `email`; at most one email per 5 minutes.
    pub async fn request_password_reset(&self, email: &str) -> CoreResult<()> {
        if !self.mail_enabled() {
            return Err(CoreError::NotFound);
        }
        let Ok(email) = validate::email(email) else {
            return Ok(());
        };
        let Some(user) = users::by_email(self.db(), &email)
            .await?
            .map(User::from)
            .filter(|u| u.active)
        else {
            return Ok(());
        };
        if let Some(secret) = self
            .issue_email_token(
                user.id,
                Purpose::ResetPassword,
                &email,
                RESET_TTL_SECS,
                true,
            )
            .await?
        {
            let link = self.reset_link(&secret);
            self.queue_email(mail::reset_email(&email, &user.handle, &link)?)
                .await?;
        }
        Ok(())
    }

    /// Site admins reset another account's password: by email when mail is on and the account has an address,
    /// otherwise as a link for the admin to pass on.
    pub async fn admin_password_reset(
        &self,
        admin: &User,
        target: &User,
    ) -> CoreResult<AdminReset> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let emailed_to = target.email.as_deref().filter(|_| self.mail_enabled());
        let ttl_secs = if emailed_to.is_some() {
            RESET_TTL_SECS
        } else {
            ADMIN_RESET_TTL_SECS
        };
        let secret = self
            .issue_email_token(
                target.id,
                Purpose::ResetPassword,
                target.email.as_deref().unwrap_or(""),
                ttl_secs,
                false,
            )
            .await?
            .ok_or_else(|| {
                CoreError::Internal("an unthrottled reset link was not issued".into())
            })?;
        let link = self.reset_link(&secret);
        let outcome = match emailed_to {
            Some(email) => {
                self.queue_email(mail::reset_email(email, &target.handle, &link)?)
                    .await?;
                AdminReset::Emailed
            }
            None => AdminReset::Link(link),
        };
        self.audit(
            Some(admin.id),
            "user.password_reset_issued",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        Ok(outcome)
    }

    /// Whether a reset link can still be used; the reset form is shown only for these.
    pub async fn password_reset_valid(&self, secret: &str) -> CoreResult<bool> {
        Ok(self
            .peek_email_token(secret, Purpose::ResetPassword)
            .await?
            .is_some())
    }

    /// Uses a reset link: sets `new_password` and ends every web session of the account. A password that
    /// fails validation leaves the link usable.
    pub async fn reset_password(&self, secret: &str, new_password: &str) -> CoreResult<User> {
        validate::password(new_password)?;
        let token = self
            .consume_email_token(secret, Purpose::ResetPassword)
            .await?
            .ok_or_else(unusable_link)?;
        let user = self
            .user_by_id(token.user_id)
            .await?
            .ok_or_else(unusable_link)?;
        let hash = hash_password(new_password.to_owned()).await?;
        users::set_password_hash(self.db(), user.id, &hash).await?;
        web_sessions::delete_for_user(self.db(), user.id).await?;
        self.audit(
            Some(user.id),
            "account.password_reset",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(user)
    }

    fn reset_link(&self, secret: &str) -> String {
        format!("{}/reset/{secret}", self.config().base_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, test_core_with, user, with_file_mail};

    const PASSWORD: &str = "correct horse battery";
    const NEW_PASSWORD: &str = "a brand new password";

    async fn member(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            email: Some(format!("{handle}@example.com")),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn site_admin(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    fn secret_in(message: &str) -> String {
        let link = crate::mail::testing::find_link(message, "/reset/").unwrap();
        link.rsplit('/').next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn reset_links_change_the_password_and_end_sessions() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = member(&core, "alice").await;
        let (_, session) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        core.request_password_reset("alice@example.com")
            .await
            .unwrap();
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert!(
            mail[0].contains("Subject: Reset your Starforge password"),
            "{}",
            mail[0]
        );
        let secret = secret_in(&mail[0]);

        assert!(core.password_reset_valid(&secret).await.unwrap());
        assert!(matches!(
            core.reset_password(&secret, "short").await,
            Err(CoreError::Invalid(_))
        ));
        assert!(
            core.password_reset_valid(&secret).await.unwrap(),
            "a rejected password keeps the link usable"
        );
        let user = core.reset_password(&secret, NEW_PASSWORD).await.unwrap();
        assert_eq!(user.id, alice.id);
        assert!(
            core.web_session(&session.cookie_value)
                .await
                .unwrap()
                .is_none(),
            "the reset ended existing sessions"
        );
        core.login("alice", NEW_PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        assert!(matches!(
            core.reset_password(&secret, "another new password").await,
            Err(CoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn forgot_password_needs_mail_and_reveals_nothing() {
        let (core, _f) = test_core().await;
        assert!(matches!(
            core.request_password_reset("a@example.com").await,
            Err(CoreError::NotFound)
        ));

        let (core, fixture) = test_core_with(with_file_mail).await;
        member(&core, "alice").await;
        core.request_password_reset("nobody@example.com")
            .await
            .unwrap();
        core.request_password_reset("alice@example.com")
            .await
            .unwrap();
        core.request_password_reset("alice@example.com")
            .await
            .unwrap();
        core.run_due_jobs().await.unwrap();
        assert_eq!(fixture.mail().len(), 1, "the repeat request was throttled");
    }

    #[tokio::test]
    async fn admins_reset_by_email_or_by_link() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let admin = site_admin(&core).await;
        let alice = member(&core, "alice").await;
        assert!(matches!(
            core.admin_password_reset(&alice, &admin).await,
            Err(CoreError::Forbidden)
        ));
        assert_eq!(
            core.admin_password_reset(&admin, &alice).await.unwrap(),
            AdminReset::Emailed
        );
        core.run_due_jobs().await.unwrap();
        assert!(fixture.mail()[0].contains("To: alice@example.com"));
        let no_address = user(&core, "bob").await;
        match core
            .admin_password_reset(&admin, &no_address)
            .await
            .unwrap()
        {
            AdminReset::Link(link) => {
                assert!(link.starts_with("http://forge.test/reset/"), "{link}")
            }
            other => panic!("{other:?}"),
        }

        let (core, _f) = test_core().await;
        let admin = site_admin(&core).await;
        let carol = member(&core, "carol").await;
        let AdminReset::Link(link) = core.admin_password_reset(&admin, &carol).await.unwrap()
        else {
            panic!("without mail the admin gets a link");
        };
        assert!(link.contains("/reset/"));
        let expires_at: i64 = sqlx::query_scalar(
            "SELECT expires_at FROM email_tokens WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(carol.id)
        .fetch_one(core.db().pool())
        .await
        .unwrap();
        assert!(
            expires_at >= starforged_db::now() + ADMIN_RESET_TTL_SECS - 5,
            "links an admin passes on last 24 hours"
        );
    }
}
