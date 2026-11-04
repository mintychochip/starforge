//! OAuth device authorization grant (RFC 8628) for CLI login.
//!
//! The CLI (anonymous) requests a `device_code` + human-typable `user_code`,
//! polls `poll_device_code` honoring the interval, and the user approves the
//! code on the web approval page. Only the SHA-256 hash of the `device_code`
//! is stored; the `user_code` is short and looked up case-insensitively.

use starforged_db::oauth::{self as db_oauth, NewDeviceCode};
use starforged_db::tokens::{self as db_tokens, NewToken};

use crate::accounts::User;
use crate::tokens::parse_scopes;
use crate::{Core, CoreError, CoreResult, crypto};

/// The only OAuth client in M1d: the `starforge-cli` device flow.
pub const DEVICE_CLIENT_ID: &str = "starforge-cli";
/// Device codes live 15 minutes (RFC 8628 §3.2 recommendation).
pub const DEVICE_EXPIRES_IN: i64 = 900;
/// The CLI waits this long between polls; polling faster is a `slow_down`.
pub const DEVICE_INTERVAL_SECS: i64 = 5;
/// Access tokens minted by the device flow live 1 hour …
pub const DEVICE_ACCESS_TTL: i64 = 3_600;
/// … and their refresh tokens live 90 days (rotation lands in M3).
pub const DEVICE_REFRESH_TTL: i64 = 90 * 86_400;

/// Crockford base32 without ambiguous characters (no `I`, `L`, `O`, `U`).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone)]
pub struct DeviceAuthRequest {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    Pending,
    SlowDown,
    Expired,
    Denied,
    Granted {
        access_token: String,
        refresh_token: String,
        expires_in: i64,
        scope: String,
    },
}

/// `XXXX-XXXX` from 40 random bits (Crockford base32), already normalized.
fn generate_user_code() -> String {
    let mut bits = [0_u8; 5];
    getrandom::fill(&mut bits).expect("the OS random number generator is available");
    let mut acc: u64 = 0;
    for byte in bits {
        acc = (acc << 8) | u64::from(byte);
    }
    let code: String = (0..8)
        .map(|i| CROCKFORD[((acc >> (35 - 5 * i)) & 31) as usize] as char)
        .collect();
    format!("{}-{}", &code[..4], &code[4..])
}

/// Trims and uppercases typed input so lookups are case-insensitive.
pub fn normalize_user_code(input: &str) -> String {
    input.trim().to_ascii_uppercase()
}

fn verification_uri(base_url: &str, user_code: &str) -> String {
    format!(
        "{}/oauth/device?user_code={user_code}",
        base_url.trim_end_matches('/')
    )
}

impl Core {
    /// Starts a device flow: validates the client and scope, then stores a
    /// one-time code pair. Anonymous, like `.well-known` (no authentication).
    pub async fn create_device_code(
        &self,
        client_id: &str,
        scope: &str,
    ) -> CoreResult<DeviceAuthRequest> {
        if client_id != DEVICE_CLIENT_ID {
            return Err(CoreError::Invalid("unknown client_id".into()));
        }
        let scopes = parse_scopes(scope)?;
        let scope = crate::tokens::format_scopes(&scopes);
        let now = starforged_db::now();
        let row = loop {
            let device_code = crypto::random_hex(32);
            let user_code = generate_user_code();
            let inserted = db_oauth::insert_device_code(
                self.db(),
                &NewDeviceCode {
                    device_code_hash: &crypto::sha256_hex(&device_code),
                    user_code: &user_code,
                    client_id: DEVICE_CLIENT_ID,
                    scope: &scope,
                    interval_secs: DEVICE_INTERVAL_SECS,
                    expires_at: now + DEVICE_EXPIRES_IN,
                },
            )
            .await;
            match inserted {
                Ok(()) => {
                    break (device_code, user_code);
                }
                Err(e) if e.is_unique_violation() => continue,
                Err(e) => return Err(e.into()),
            }
        };
        let uri = verification_uri(&self.config().base_url, &row.1);
        Ok(DeviceAuthRequest {
            device_code: row.0,
            user_code: row.1,
            verification_uri_complete: uri.clone(),
            verification_uri: uri,
            expires_in: DEVICE_EXPIRES_IN,
            interval: DEVICE_INTERVAL_SECS,
        })
    }

    /// Binds the signed-in web user to a pending code (approve) or marks it
    /// denied. Wrong codes are `NotFound`; spent or expired codes are `Invalid`.
    pub async fn approve_device_code(
        &self,
        user: &User,
        user_code: &str,
        approve: bool,
    ) -> CoreResult<()> {
        let normalized = normalize_user_code(user_code);
        let row = db_oauth::device_code_by_user_code(self.db(), &normalized)
            .await?
            .ok_or(CoreError::NotFound)?;
        if row.expires_at <= starforged_db::now() {
            db_oauth::delete_device_code(self.db(), &row.device_code_hash).await?;
            return Err(CoreError::Invalid("device code expired".into()));
        }
        if row.status != "pending" {
            return Err(CoreError::Invalid(
                "device code is no longer pending".into(),
            ));
        }
        if !db_oauth::approve_device_code(self.db(), &row.device_code_hash, user.id, approve)
            .await?
        {
            return Err(CoreError::Invalid(
                "device code is no longer pending".into(),
            ));
        }
        let action = if approve {
            "oauth.device.approve"
        } else {
            "oauth.device.deny"
        };
        self.audit(Some(user.id), action, "oauth:device-code", "")
            .await?;
        Ok(())
    }

    /// The RFC 8628 §3.5 polling state machine.
    pub async fn poll_device_code(
        &self,
        device_code: &str,
        client_id: &str,
    ) -> CoreResult<PollOutcome> {
        let hash = crypto::sha256_hex(device_code);
        let row = db_oauth::device_code_by_hash(self.db(), &hash)
            .await?
            .ok_or_else(|| CoreError::Invalid("invalid_grant".into()))?;
        if row.client_id != client_id {
            return Err(CoreError::Invalid("invalid_grant".into()));
        }
        let now = starforged_db::now();
        if now >= row.expires_at {
            db_oauth::delete_device_code(self.db(), &hash).await?;
            return Ok(PollOutcome::Expired);
        }
        match row.status.as_str() {
            "denied" => Ok(PollOutcome::Denied),
            "consumed" => Ok(PollOutcome::Expired),
            "approved" => self.grant_device_tokens(&row, now).await,
            _ => {
                if let Some(last) = row.last_poll_at
                    && now < last + row.interval_secs
                {
                    let interval = row.interval_secs + DEVICE_INTERVAL_SECS;
                    db_oauth::record_poll(self.db(), &hash, now, interval).await?;
                    return Ok(PollOutcome::SlowDown);
                }
                db_oauth::record_poll(self.db(), &hash, now, row.interval_secs).await?;
                Ok(PollOutcome::Pending)
            }
        }
    }

    /// Mints the access (1 h) + refresh (90 d) pair for an approved code and
    /// consumes the code so it can never grant twice.
    async fn grant_device_tokens(
        &self,
        row: &db_oauth::DeviceCodeRow,
        now: i64,
    ) -> CoreResult<PollOutcome> {
        let user_id = row
            .user_id
            .ok_or_else(|| CoreError::Internal("approved device code has no user".into()))?;
        let user = self
            .user_by_id(user_id)
            .await?
            .filter(|u| u.active)
            .ok_or(CoreError::Unauthenticated)?;
        let access_secret = format!("sfp_{}", crypto::random_hex(32));
        let refresh_secret = format!("sfp_{}", crypto::random_hex(32));
        for (secret, name, expires_at) in [
            (&access_secret, "device flow", now + DEVICE_ACCESS_TTL),
            (
                &refresh_secret,
                "device flow refresh",
                now + DEVICE_REFRESH_TTL,
            ),
        ] {
            let hint = &secret[secret.len() - 4..];
            let id = db_tokens::insert(
                self.db(),
                &NewToken {
                    user_id: user.id,
                    name,
                    token_hash: &crypto::sha256_hex(secret),
                    token_hint: hint,
                    scopes: &row.scope,
                    expires_at,
                },
            )
            .await?;
            self.audit(Some(user.id), "token.create", &format!("token:{id}"), name)
                .await?;
        }
        db_oauth::mark_consumed(self.db(), &row.device_code_hash).await?;
        Ok(PollOutcome::Granted {
            access_token: access_secret,
            refresh_token: refresh_secret,
            expires_in: DEVICE_ACCESS_TTL,
            scope: row.scope.clone(),
        })
    }
}
