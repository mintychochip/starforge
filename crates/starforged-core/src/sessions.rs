//! Browser sessions (spec §9): random cookie value stored as SHA-256, 30-day lifetime, per-session CSRF token.

use starforged_db::web_sessions::{self, NewWebSession};

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, crypto};

pub const WEB_SESSION_TTL_SECS: i64 = 30 * 86_400;

#[derive(Debug, Clone)]
pub struct WebSession {
    pub user: User,
    pub csrf_token: String,
}

/// A session opened by [`Core::login`]. `cookie_value` goes to the browser and is never stored.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub cookie_value: String,
    pub csrf_token: String,
    pub max_age_secs: i64,
}

impl Core {
    /// Checks the password and opens a session. Successes and failures are audited with the client address.
    pub async fn login(
        &self,
        login: &str,
        password: &str,
        user_agent: &str,
        ip: &str,
    ) -> CoreResult<(User, NewSession)> {
        let user_agent: String = user_agent.chars().take(256).collect();
        let user = match self.authenticate_password(login, password).await {
            Ok(user) => user,
            Err(CoreError::Unauthenticated) => {
                let target = format!("login:{}", login.trim().to_ascii_lowercase());
                self.audit_client(None, "auth.login_failed", &target, "", ip, &user_agent)
                    .await?;
                return Err(CoreError::Unauthenticated);
            }
            Err(other) => return Err(other),
        };
        if self.mail_enabled() && user.email.is_some() && !user.email_verified {
            self.audit_client(
                Some(user.id),
                "auth.login_unverified",
                &format!("user:{}", user.handle),
                "",
                ip,
                &user_agent,
            )
            .await?;
            return Err(CoreError::EmailUnverified);
        }
        let cookie_value = crypto::random_hex(32);
        let csrf_token = crypto::random_hex(32);
        web_sessions::insert(
            self.db(),
            &NewWebSession {
                session_hash: &crypto::sha256_hex(&cookie_value),
                user_id: user.id,
                csrf_token: &csrf_token,
                expires_at: starforged_db::now() + WEB_SESSION_TTL_SECS,
                user_agent: &user_agent,
                ip,
            },
        )
        .await?;
        self.audit_client(
            Some(user.id),
            "auth.login",
            &format!("user:{}", user.handle),
            "",
            ip,
            &user_agent,
        )
        .await?;
        Ok((
            user,
            NewSession {
                cookie_value,
                csrf_token,
                max_age_secs: WEB_SESSION_TTL_SECS,
            },
        ))
    }

    /// The user behind a session cookie, if the session is unexpired and the user is active.
    pub async fn web_session(&self, cookie_value: &str) -> CoreResult<Option<WebSession>> {
        let hash = crypto::sha256_hex(cookie_value);
        let Some(row) =
            web_sessions::active_by_hash(self.db(), &hash, starforged_db::now()).await?
        else {
            return Ok(None);
        };
        let user = self.user_by_id(row.user_id).await?.filter(|u| u.active);
        Ok(user.map(|user| WebSession {
            user,
            csrf_token: row.csrf_token,
        }))
    }

    pub async fn logout(&self, cookie_value: &str) -> CoreResult<()> {
        web_sessions::delete_by_hash(self.db(), &crypto::sha256_hex(cookie_value)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::test_core;

    const PASSWORD: &str = "correct horse battery";

    async fn alice(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "alice".into(),
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn login_lookup_and_logout() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert!(matches!(
            core.login("alice", "wrong password!", "ua", "127.0.0.1")
                .await,
            Err(CoreError::Unauthenticated)
        ));
        let (user, session) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(user.id, alice.id);
        assert_eq!(session.max_age_secs, WEB_SESSION_TTL_SECS);
        let found = core
            .web_session(&session.cookie_value)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (found.user.id, found.csrf_token.as_str()),
            (alice.id, session.csrf_token.as_str())
        );
        assert!(core.web_session("not-a-session").await.unwrap().is_none());

        starforged_db::users::set_state(core.db(), alice.id, "suspended")
            .await
            .unwrap();
        assert!(
            core.web_session(&session.cookie_value)
                .await
                .unwrap()
                .is_none(),
            "suspended users lose their sessions"
        );
        starforged_db::users::set_state(core.db(), alice.id, "active")
            .await
            .unwrap();

        core.logout(&session.cookie_value).await.unwrap();
        assert!(
            core.web_session(&session.cookie_value)
                .await
                .unwrap()
                .is_none()
        );
        let actions: Vec<String> = starforged_db::audit::recent(core.db(), 5)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, vec!["auth.login", "auth.login_failed"]);
    }

    #[tokio::test]
    async fn expired_sessions_are_ignored() {
        let (core, _f) = test_core().await;
        alice(&core).await;
        let (_, session) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        sqlx::query("UPDATE web_sessions SET expires_at = $1")
            .bind(0_i64)
            .execute(core.db().pool())
            .await
            .unwrap();
        assert!(
            core.web_session(&session.cookie_value)
                .await
                .unwrap()
                .is_none()
        );
    }
}
