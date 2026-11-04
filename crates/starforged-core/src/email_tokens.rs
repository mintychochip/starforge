//! One-time links sent by email (forge-basics design §4.3–§4.4). Secrets are 32 random bytes in hex; only
//! their SHA-256 is stored.

use starforged_db::email_tokens::{self, EmailTokenRow, NewEmailToken};
use starforged_db::now;

use crate::{Core, CoreResult, crypto};

/// Lifetime of verify-email and confirm-new-email links.
pub const VERIFY_TTL_SECS: i64 = 24 * 3_600;
/// Lifetime of emailed password-reset links.
pub const RESET_TTL_SECS: i64 = 3_600;
/// Lifetime of password-reset links an admin passes on by hand when mail is off.
pub const ADMIN_RESET_TTL_SECS: i64 = 24 * 3_600;
/// At most one email per address and purpose within this window.
pub const EMAIL_THROTTLE_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    VerifyEmail,
    ChangeEmail,
    ResetPassword,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::VerifyEmail => "verify_email",
            Purpose::ChangeEmail => "change_email",
            Purpose::ResetPassword => "reset_password",
        }
    }
}

/// Whether `secret` has the shape of an issued secret: 64 lowercase hex characters.
fn well_formed(secret: &str) -> bool {
    secret.len() == 64
        && secret
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Core {
    /// Issues a link secret for `user_id` and `purpose`, sent to `email` and valid for `ttl_secs`; the user's
    /// earlier unused links for the same purpose stop working. With `throttle`, returns `None` instead when a
    /// link for the same purpose was issued within [`EMAIL_THROTTLE_SECS`].
    pub(crate) async fn issue_email_token(
        &self,
        user_id: i64,
        purpose: Purpose,
        email: &str,
        ttl_secs: i64,
        throttle: bool,
    ) -> CoreResult<Option<String>> {
        let ts = now();
        if throttle
            && let Some(last) =
                email_tokens::newest_created_at(self.db(), user_id, purpose.as_str()).await?
            && ts - last < EMAIL_THROTTLE_SECS
        {
            return Ok(None);
        }
        let secret = crypto::random_hex(32);
        email_tokens::replace(
            self.db(),
            &NewEmailToken {
                user_id,
                purpose: purpose.as_str(),
                token_hash: &crypto::sha256_hex(&secret),
                email,
                expires_at: ts + ttl_secs,
            },
        )
        .await?;
        Ok(Some(secret))
    }

    /// Uses a link once: its token when `secret` is unused, unexpired, and for `purpose`.
    pub(crate) async fn consume_email_token(
        &self,
        secret: &str,
        purpose: Purpose,
    ) -> CoreResult<Option<EmailTokenRow>> {
        if !well_formed(secret) {
            return Ok(None);
        }
        Ok(email_tokens::consume(
            self.db(),
            &crypto::sha256_hex(secret),
            purpose.as_str(),
            now(),
        )
        .await?)
    }

    /// Like [`Core::consume_email_token`], without using the link.
    pub(crate) async fn peek_email_token(
        &self,
        secret: &str,
        purpose: Purpose,
    ) -> CoreResult<Option<EmailTokenRow>> {
        if !well_formed(secret) {
            return Ok(None);
        }
        Ok(email_tokens::peek(
            self.db(),
            &crypto::sha256_hex(secret),
            purpose.as_str(),
            now(),
        )
        .await?)
    }
}
