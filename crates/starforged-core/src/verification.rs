//! Email verification (forge-basics design §4.2).

use starforged_db::users;

use crate::accounts::User;
use crate::email_tokens::{Purpose, VERIFY_TTL_SECS};
use crate::{Core, CoreError, CoreResult, mail, validate};

impl Core {
    /// Emails `user` a verification link. `Ok(false)` when nothing was sent: mail is off, the address is
    /// already verified or missing, or a link went out within the throttle window.
    pub async fn send_verification(&self, user: &User) -> CoreResult<bool> {
        if !self.mail_enabled() || user.email_verified {
            return Ok(false);
        }
        let Some(email) = user.email.as_deref() else {
            return Ok(false);
        };
        let Some(secret) = self
            .issue_email_token(user.id, Purpose::VerifyEmail, email, VERIFY_TTL_SECS, true)
            .await?
        else {
            return Ok(false);
        };
        let link = format!("{}/verify/{secret}", self.config().base_url);
        self.queue_email(mail::verify_email(email, &user.handle, &link)?)
            .await?;
        Ok(true)
    }

    /// The resend form: the same outcome whether or not an unverified account uses `email`.
    pub async fn resend_verification(&self, email: &str) -> CoreResult<()> {
        let Ok(email) = validate::email(email) else {
            return Ok(());
        };
        if let Some(row) = users::by_email(self.db(), &email).await? {
            let user = User::from(row);
            if user.active {
                self.send_verification(&user).await?;
            }
        }
        Ok(())
    }

    /// Whether a confirmation link can still be used; the confirm page is shown only for these.
    pub async fn email_link_valid(&self, secret: &str) -> CoreResult<bool> {
        Ok(self
            .peek_email_token(secret, Purpose::VerifyEmail)
            .await?
            .is_some()
            || self
                .peek_email_token(secret, Purpose::ChangeEmail)
                .await?
                .is_some())
    }

    /// Uses a link from a verification or confirm-new-email email; returns the now verified user.
    /// `NotFound` for unknown, used, or expired links, and for links sent to an address the account
    /// no longer uses.
    pub async fn verify_email(&self, secret: &str) -> CoreResult<User> {
        if let Some(token) = self
            .consume_email_token(secret, Purpose::ChangeEmail)
            .await?
        {
            let user = self
                .user_by_id(token.user_id)
                .await?
                .ok_or(CoreError::NotFound)?;
            users::set_email(self.db(), user.id, Some(&token.email), true)
                .await
                .map_err(|e| {
                    if e.is_unique_violation() {
                        crate::account::email_taken()
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
            return self.user_by_id(user.id).await?.ok_or(CoreError::NotFound);
        }
        let token = self
            .consume_email_token(secret, Purpose::VerifyEmail)
            .await?
            .ok_or(CoreError::NotFound)?;
        let user = self
            .user_by_id(token.user_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if user.email.as_deref() != Some(token.email.as_str()) {
            return Err(CoreError::NotFound);
        }
        users::set_email_verified(self.db(), user.id, true).await?;
        self.audit(
            Some(user.id),
            "account.email_verified",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        self.user_by_id(user.id).await?.ok_or(CoreError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, test_core_with, with_file_mail};

    const PASSWORD: &str = "correct horse battery";

    async fn unverified(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            email: Some(format!("{handle}@example.com")),
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    fn secret_in(message: &str) -> String {
        let link = crate::mail::testing::find_link(message, "/verify/").unwrap();
        link.rsplit('/').next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn verification_links_work_once() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = unverified(&core, "alice").await;
        assert!(!alice.email_verified);
        assert!(core.send_verification(&alice).await.unwrap());
        assert!(
            !core.send_verification(&alice).await.unwrap(),
            "throttled for five minutes"
        );
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(
            mail[0].contains("Subject: Verify your email address"),
            "{}",
            mail[0]
        );
        let secret = secret_in(&mail[0]);

        assert!(core.email_link_valid(&secret).await.unwrap());
        assert!(matches!(
            core.login("alice", PASSWORD, "ua", "127.0.0.1").await,
            Err(CoreError::EmailUnverified)
        ));
        let verified = core.verify_email(&secret).await.unwrap();
        assert!(verified.email_verified);
        assert!(!core.email_link_valid(&secret).await.unwrap());
        assert!(matches!(
            core.verify_email(&secret).await,
            Err(CoreError::NotFound)
        ));
        core.login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        assert!(
            !core.send_verification(&verified).await.unwrap(),
            "nothing left to verify"
        );
    }

    #[tokio::test]
    async fn links_for_an_old_address_do_not_verify_a_new_one() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = unverified(&core, "alice").await;
        core.send_verification(&alice).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let secret = secret_in(&fixture.mail()[0]);
        sqlx::query("UPDATE users SET email = $1 WHERE id = $2")
            .bind("new@example.com")
            .bind(alice.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        assert!(matches!(
            core.verify_email(&secret).await,
            Err(CoreError::NotFound)
        ));
        assert!(
            !core
                .user_by_id(alice.id)
                .await
                .unwrap()
                .unwrap()
                .email_verified
        );
    }

    #[tokio::test]
    async fn sign_in_needs_verification_only_when_mail_is_on() {
        let (core, _f) = test_core().await;
        unverified(&core, "alice").await;
        core.login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();

        let (core, _f) = test_core_with(with_file_mail).await;
        core.create_user(CreateUser {
            handle: "bob".into(),
            email: Some("bob@example.com".into()),
            password: Some(PASSWORD.into()),
            email_verified: true,
            ..Default::default()
        })
        .await
        .unwrap();
        core.login("bob", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn resending_is_silent_for_unknown_addresses() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        unverified(&core, "alice").await;
        core.resend_verification("nobody@example.com")
            .await
            .unwrap();
        core.resend_verification("not an address").await.unwrap();
        core.resend_verification("ALICE@example.com").await.unwrap();
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(mail[0].contains("To: alice@example.com"), "{}", mail[0]);
    }
}
