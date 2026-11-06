//! Browser sessions (spec §9): random cookie value stored as SHA-256, 30-day lifetime, per-session CSRF token.

use starforged_db::auth_factors;
use starforged_db::web_sessions::{self, NewWebSession};

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, crypto};

pub const WEB_SESSION_TTL_SECS: i64 = 30 * 86_400;

/// How long a `totp` login challenge stays usable (spec §9 D2).
pub const SECOND_FACTOR_TTL_SECS: i64 = 5 * 60;
/// Failed codes after which a challenge is voided.
pub const MAX_SECOND_FACTOR_ATTEMPTS: i64 = 5;

/// A session's last-activity time is written at most this often.
const TOUCH_INTERVAL_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct WebSession {
    pub user: User,
    pub csrf_token: String,
    /// The `web_sessions` row, for the sessions page.
    pub session_id: i64,
}

/// A session opened by [`Core::login`]. `cookie_value` goes to the browser and is never stored.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub cookie_value: String,
    pub csrf_token: String,
    pub max_age_secs: i64,
}

/// What a password check produced. A user with TOTP enabled gets no web
/// session until the second factor passes: the browser carries the
/// challenge token (in an `HttpOnly` cookie) to complete the login.
#[derive(Debug, Clone)]
pub enum LoginOutcome {
    /// The web session was opened.
    Session(User, NewSession),
    /// The password was right; the second factor must complete the login.
    /// The inner string is the random challenge token for the browser cookie.
    NeedsSecondFactor(String),
}

impl LoginOutcome {
    /// The session, for callers (mostly tests) whose user has no 2FA.
    /// Panics when the login instead needs a second factor.
    pub fn into_session(self) -> (User, NewSession) {
        match self {
            LoginOutcome::Session(user, session) => (user, session),
            LoginOutcome::NeedsSecondFactor(_) => {
                panic!("login needs a second factor; complete the challenge first")
            }
        }
    }
}

impl Core {
    /// Checks the password. Without 2FA it opens a session at once; with
    /// TOTP enabled it starts a login challenge (5-minute expiry) and
    /// returns [`LoginOutcome::NeedsSecondFactor`] instead. Successes and
    /// failures are audited with the client address.
    pub async fn login(
        &self,
        login: &str,
        password: &str,
        user_agent: &str,
        ip: &str,
    ) -> CoreResult<LoginOutcome> {
        let user_agent: String = user_agent.chars().take(256).collect();
        let normalized = login.trim().to_ascii_lowercase();
        self.check_login_limits(&normalized, ip, &user_agent)
            .await?;
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
        if self.totp_enabled(user.id).await? {
            let token = crypto::random_hex(32);
            auth_factors::insert_challenge(
                self.db(),
                "totp",
                Some(user.id),
                &crypto::sha256_hex(&token),
                starforged_db::now() + SECOND_FACTOR_TTL_SECS,
            )
            .await?;
            return Ok(LoginOutcome::NeedsSecondFactor(token));
        }
        let session = self.open_session(&user, &user_agent, ip).await?;
        self.audit_client(
            Some(user.id),
            "auth.login",
            &format!("user:{}", user.handle),
            "",
            ip,
            &user_agent,
        )
        .await?;
        Ok(LoginOutcome::Session(user, session))
    }

    /// Opens a web session for an already-authenticated user.
    pub(crate) async fn open_session(
        &self,
        user: &User,
        user_agent: &str,
        ip: &str,
    ) -> CoreResult<NewSession> {
        let cookie_value = crypto::random_hex(32);
        let csrf_token = crypto::random_hex(32);
        web_sessions::insert(
            self.db(),
            &NewWebSession {
                session_hash: &crypto::sha256_hex(&cookie_value),
                user_id: user.id,
                csrf_token: &csrf_token,
                expires_at: starforged_db::now() + WEB_SESSION_TTL_SECS,
                user_agent,
                ip,
            },
        )
        .await?;
        Ok(NewSession {
            cookie_value,
            csrf_token,
            max_age_secs: WEB_SESSION_TTL_SECS,
        })
    }

    /// Completes a `totp` login challenge with a TOTP code or a recovery
    /// code. Every failed code writes `login.2fa_failure`; five failures
    /// void the challenge. Success opens the web session and writes
    /// `auth.login`. An unknown or expired challenge is `Unauthenticated`
    /// (start again); a wrong code on a live challenge is `Invalid`.
    ///
    /// Single-use is enforced by claiming the challenge atomically
    /// ([`auth_factors::claim_challenge`]) before verifying the code: the
    /// first claimer owns it, and a concurrent duplicate submission loses
    /// the claim and gets `Unauthenticated`. A failed code does not consume
    /// the challenge: it is restored with its attempt count incremented,
    /// unless that count voids it. The TOTP step and recovery-code claims
    /// are themselves atomic, so two challenges racing one code still mint
    /// exactly one session.
    pub async fn complete_second_factor(
        &self,
        challenge_token: &str,
        code: &str,
        user_agent: &str,
        ip: &str,
    ) -> CoreResult<(User, NewSession)> {
        let user_agent: String = user_agent.chars().take(256).collect();
        let hash = crypto::sha256_hex(challenge_token.trim());
        let challenge = auth_factors::challenge_by_token_hash(self.db(), &hash)
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        let user_id = challenge.user_id.ok_or(CoreError::Unauthenticated)?;
        let user = self
            .user_by_id(user_id)
            .await?
            .filter(|u| u.active)
            .ok_or(CoreError::Unauthenticated)?;
        if starforged_db::now() > challenge.expires_at {
            auth_factors::delete_challenge(self.db(), challenge.id).await?;
            self.audit_client(
                Some(user.id),
                "login.2fa_failure",
                &format!("user:{}", user.handle),
                "challenge expired",
                ip,
                &user_agent,
            )
            .await?;
            return Err(CoreError::Unauthenticated);
        }
        // Claim before verifying: exactly one concurrent submission owns
        // the challenge; the loser is refused here and mints nothing.
        let claimed = auth_factors::claim_challenge(self.db(), "totp", &hash, starforged_db::now())
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        let code = code.trim();
        let totp_ok = self.check_totp_code(&user, code).await.is_ok();
        let recovery_ok = !totp_ok
            && auth_factors::consume_recovery_code(
                self.db(),
                user.id,
                &crypto::sha256_hex(&crate::totp::normalize_recovery_code(code)),
            )
            .await?;
        if !totp_ok && !recovery_ok {
            let attempts = claimed.attempts + 1;
            self.audit_client(
                Some(user.id),
                "login.2fa_failure",
                &format!("user:{}", user.handle),
                "bad code",
                ip,
                &user_agent,
            )
            .await?;
            // A wrong code must not burn a challenge that still has
            // attempts: put it back with the count incremented. At the
            // maximum the claim stands and the challenge is void.
            if attempts < MAX_SECOND_FACTOR_ATTEMPTS {
                auth_factors::restore_challenge(self.db(), &claimed, attempts).await?;
            }
            return Err(CoreError::Invalid("That code is not valid.".into()));
        }
        // The challenge was already claimed above; the session is the only
        // remaining step, so exactly one submission can reach it.
        let session = self.open_session(&user, &user_agent, ip).await?;
        self.audit_client(
            Some(user.id),
            "auth.login",
            &format!("user:{}", user.handle),
            "",
            ip,
            &user_agent,
        )
        .await?;
        Ok((user, session))
    }

    /// The user behind a session cookie, if the session is unexpired and the user is active.
    pub async fn web_session(&self, cookie_value: &str) -> CoreResult<Option<WebSession>> {
        let hash = crypto::sha256_hex(cookie_value);
        let ts = starforged_db::now();
        let Some(row) = web_sessions::active_by_hash(self.db(), &hash, ts).await? else {
            return Ok(None);
        };
        let Some(user) = self.user_by_id(row.user_id).await?.filter(|u| u.active) else {
            return Ok(None);
        };
        if ts - row.last_seen_at >= TOUCH_INTERVAL_SECS {
            web_sessions::touch(self.db(), row.id, ts).await?;
        }
        Ok(Some(WebSession {
            user,
            csrf_token: row.csrf_token,
            session_id: row.id,
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
            .unwrap()
            .into_session();
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
            .unwrap()
            .into_session();
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

    /// Enrolls TOTP for alice and returns her secret. The step+1 code is
    /// used for login so it clears the enrollment step's replay guard.
    async fn totp_alice(core: &Core) -> Vec<u8> {
        let user = alice(core).await;
        let enrollment = core.begin_totp_enrollment(&user).await.unwrap();
        let secret = crate::totp::base32::decode(&enrollment.secret_base32).unwrap();
        let code = code_for(&secret, 0);
        core.confirm_totp_enrollment(&user, &code).await.unwrap();
        secret
    }

    fn code_for(secret: &[u8], step_offset: i64) -> String {
        let step = ((starforged_db::now() / 30) + step_offset) as u64;
        format!("{:06}", crate::totp::code_at(secret, step))
    }

    async fn challenge_token(core: &Core) -> String {
        match core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap()
        {
            LoginOutcome::NeedsSecondFactor(token) => token,
            LoginOutcome::Session(..) => panic!("login should need a second factor"),
        }
    }

    #[tokio::test]
    async fn concurrent_same_challenge_mints_one_session() {
        let (core, _f) = test_core().await;
        let secret = totp_alice(&core).await;
        let token = challenge_token(&core).await;
        let code = code_for(&secret, 1);
        let (a, b) = tokio::join!(
            core.complete_second_factor(&token, &code, "ua", "127.0.0.1"),
            core.complete_second_factor(&token, &code, "ua", "127.0.0.1"),
        );
        assert_eq!(
            [a, b].iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one submission may mint a session"
        );
    }

    #[tokio::test]
    async fn concurrent_two_challenges_mints_one_session() {
        let (core, _f) = test_core().await;
        let secret = totp_alice(&core).await;
        let first = challenge_token(&core).await;
        let second = challenge_token(&core).await;
        let code = code_for(&secret, 1);
        let (a, b) = tokio::join!(
            core.complete_second_factor(&first, &code, "ua", "127.0.0.1"),
            core.complete_second_factor(&second, &code, "ua", "127.0.0.1"),
        );
        assert_eq!(
            [a, b].iter().filter(|r| r.is_ok()).count(),
            1,
            "one code may mint only one session, across challenges"
        );
    }

    #[tokio::test]
    async fn wrong_code_does_not_consume_challenge() {
        let (core, _f) = test_core().await;
        let secret = totp_alice(&core).await;
        let token = challenge_token(&core).await;
        let wrong = code_for(&secret, 5);
        assert!(matches!(
            core.complete_second_factor(&token, &wrong, "ua", "127.0.0.1")
                .await,
            Err(CoreError::Invalid(_))
        ));
        let code = code_for(&secret, 1);
        core.complete_second_factor(&token, &code, "ua", "127.0.0.1")
            .await
            .unwrap();
    }
}
