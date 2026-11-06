//! TOTP two-factor authentication (spec §9, M3d D1–D3): RFC 6238 with
//! HMAC-SHA1 from `ring` (6 digits, 30 s step, ±1 step window), a
//! hand-written base32 codec, and the enrollment / recovery-code /
//! second-factor logic on [`Core`].
//!
//! The secret is 20 bytes, sealed with the server-key seal helper (the
//! webhook `seal_secret`/`open_secret`) and never stored in clear or
//! logged. Recovery codes are `xxxxx-xxxxx` over base32, shown once at
//! issue time, and stored only as SHA-256 hashes of their normalized
//! form. A used TOTP step is recorded (`totp_last_step`) and replay of
//! the same or an older step is refused.

use starforged_db::{auth_factors, users};
use subtle::ConstantTimeEq;

use crate::accounts::{User, verify_password};
use crate::webhooks::{open_secret, seal_secret};
use crate::{Core, CoreError, CoreResult, crypto};

/// The TOTP time step in seconds (RFC 6238 default).
pub const STEP_SECS: u64 = 30;
/// How many recovery codes one issue produces.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Recovery-code bytes per code (base32 encodes them to 16 characters).
const RECOVERY_CODE_BYTES: usize = 10;
/// The issuer shown in the `otpauth://` URI: there is no configurable site
/// name yet, so the product name stands in (plan D1).
pub const TOTP_ISSUER: &str = "Starforge";

/// Base32 (RFC 4648, alphabet `A-Z2-7`) without padding.
pub mod base32 {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// Encodes bytes as uppercase base32 without `=` padding.
    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
        for chunk in data.chunks(5) {
            let mut buf = [0u8; 5];
            buf[..chunk.len()].copy_from_slice(chunk);
            let n = u64::from_be_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], 0, 0, 0]);
            let chars = match chunk.len() {
                1 => 2,
                2 => 4,
                3 => 5,
                4 => 7,
                _ => 8,
            };
            for i in 0..chars {
                let shift = 59 - 5 * i as u32;
                out.push(ALPHABET[((n >> shift) & 0x1f) as usize] as char);
            }
        }
        out
    }

    /// Decodes base32 without padding. Lowercase and whitespace are
    /// accepted; `None` on any character outside the alphabet or a
    /// length the encoding cannot produce.
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let mut bits: u32 = 0;
        let mut nbits: u32 = 0;
        let mut out = Vec::new();
        let mut count = 0usize;
        for c in text.chars() {
            if c.is_whitespace() {
                continue;
            }
            let value = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32,
                '2'..='7' => c as u32 - '2' as u32 + 26,
                _ => return None,
            };
            bits = (bits << 5) | value;
            nbits += 5;
            count += 1;
            if nbits >= 8 {
                nbits -= 8;
                out.push(((bits >> nbits) & 0xff) as u8);
            }
        }
        // Encoded lengths mod 8 must be 0, 2, 4, 5, or 7 (never 1, 3, 6).
        if !matches!(count % 8, 0 | 2 | 4 | 5 | 7) {
            return None;
        }
        Some(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips() {
            for len in 0..=20usize {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                    .collect();
                assert_eq!(decode(&encode(&data)).as_deref(), Some(data.as_slice()));
            }
        }

        #[test]
        fn rfc4648_vectors() {
            // RFC 4648 §10 vectors, padding stripped.
            for (plain, encoded) in [
                (b"" as &[u8], ""),
                (b"f", "MY"),
                (b"fo", "MZXQ"),
                (b"foo", "MZXW6"),
                (b"foob", "MZXW6YQ"),
                (b"fooba", "MZXW6YTB"),
                (b"foobar", "MZXW6YTBOI"),
            ] {
                assert_eq!(encode(plain), encoded);
                assert_eq!(decode(encoded).as_deref(), Some(plain));
            }
        }

        #[test]
        fn rejects_garbage() {
            assert_eq!(
                decode("JBSWY3DPEHPK3PXP"),
                Some(b"Hello!\xde\xad\xbe\xef".to_vec())
            );
            assert_eq!(
                decode("jbswy3dpehpk3pxp"),
                Some(b"Hello!\xde\xad\xbe\xef".to_vec())
            );
            assert!(decode("JBSWY3DP!").is_none());
            assert!(decode("ABC").is_none(), "length 3 is impossible");
            assert_eq!(decode(""), Some(Vec::new()));
        }
    }
}

/// The 6-digit code for `secret` at `unix_step` (RFC 6238, `step = T / 30`).
pub fn code_at(secret: &[u8], unix_step: u64) -> u32 {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let digest = ring::hmac::sign(&key, &unix_step.to_be_bytes());
    let bytes = digest.as_ref();
    let offset = (bytes[bytes.len() - 1] & 0x0f) as usize;
    let truncated = u64::from_be_bytes([
        0,
        0,
        0,
        0,
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]) & 0x7fff_ffff;
    (truncated % 1_000_000) as u32
}

/// Verifies `code` (6 digits) at `now_secs`, accepting the current step
/// ± 1. Returns the matched step, compared in constant time.
pub fn verify(secret: &[u8], code: &str, now_secs: i64) -> Option<u64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = (now_secs.max(0) as u64) / STEP_SECS;
    for step in current.saturating_sub(1)..=current.saturating_add(1) {
        let expected = format!("{:06}", code_at(secret, step));
        if expected.len() == code.len() && bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return Some(step);
        }
    }
    None
}

/// Normalizes a typed recovery code for hashing: uppercase, no dashes/spaces.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// `xxxxx-xxxxx` plaintext recovery codes, generated fresh (shown once).
fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut raw = [0u8; RECOVERY_CODE_BYTES];
            getrandom::fill(&mut raw).expect("the OS random number generator is available");
            let encoded = base32::encode(&raw).to_ascii_lowercase();
            format!("{}-{}", &encoded[..5], &encoded[5..10])
        })
        .collect()
}

fn hash_recovery_code(code: &str) -> String {
    crypto::sha256_hex(&normalize_recovery_code(code))
}

/// The enrollment data a settings page shows once per (re-)enrollment.
#[derive(Debug, Clone)]
pub struct TotpEnrollment {
    /// The base32 secret to enter or scan.
    pub secret_base32: String,
    /// The `otpauth://` URI for authenticator apps.
    pub otpauth_uri: String,
}

/// What the settings page needs to render two-factor state.
#[derive(Debug, Clone)]
pub struct TwoFactorStatus {
    pub enabled: bool,
    /// The pending enrollment, while a user mid-enrollment revisits the page.
    pub pending: Option<TotpEnrollment>,
}

fn otpauth_uri(handle: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{TOTP_ISSUER}:{handle}?secret={secret_base32}&issuer={TOTP_ISSUER}&algorithm=SHA1&digits=6&period=30"
    )
}

fn random_secret() -> Vec<u8> {
    let mut secret = [0u8; 20];
    getrandom::fill(&mut secret).expect("the OS random number generator is available");
    secret.to_vec()
}

impl Core {
    fn totp_key(&self) -> [u8; 32] {
        self.config().webhook_key.0
    }

    fn open_totp(&self, sealed: &str) -> CoreResult<Vec<u8>> {
        let plain = open_secret(&self.totp_key(), sealed)?;
        base32::decode(&plain).ok_or_else(|| CoreError::Internal("corrupt TOTP secret".into()))
    }

    /// Whether the user has two-factor authentication active.
    pub async fn totp_enabled(&self, user_id: i64) -> CoreResult<bool> {
        Ok(auth_factors::totp_state(self.db(), user_id)
            .await?
            .is_some_and(|s| s.enabled))
    }

    /// The settings-page view of two-factor state: active, or mid-enrollment
    /// with the pending secret to display.
    pub async fn two_factor_status(&self, user: &User) -> CoreResult<TwoFactorStatus> {
        let state = auth_factors::totp_state(self.db(), user.id)
            .await?
            .ok_or_else(|| CoreError::Internal("user missing".into()))?;
        let pending = if !state.enabled {
            state
                .secret
                .as_deref()
                .map(|sealed| self.open_totp(sealed))
                .transpose()?
                .map(|secret| {
                    let secret_base32 = base32::encode(&secret);
                    TotpEnrollment {
                        otpauth_uri: otpauth_uri(&user.handle, &secret_base32),
                        secret_base32,
                    }
                })
        } else {
            None
        };
        Ok(TwoFactorStatus {
            enabled: state.enabled,
            pending,
        })
    }

    /// Starts enrollment: stores a fresh sealed secret (still disabled) and
    /// returns the base32 secret and `otpauth://` URI. Refused while 2FA is
    /// already active or an enrollment is pending.
    pub async fn begin_totp_enrollment(&self, user: &User) -> CoreResult<TotpEnrollment> {
        let state = auth_factors::totp_state(self.db(), user.id)
            .await?
            .ok_or_else(|| CoreError::Internal("user missing".into()))?;
        if state.enabled {
            return Err(CoreError::Invalid(
                "Two-factor authentication is already enabled.".into(),
            ));
        }
        if state.secret.is_some() {
            return Err(CoreError::Invalid(
                "An enrollment is already in progress; finish it or disable it first.".into(),
            ));
        }
        let secret = random_secret();
        let sealed = seal_secret(&self.totp_key(), &base32::encode(&secret))?;
        auth_factors::set_totp(self.db(), user.id, Some(&sealed), false, None).await?;
        let secret_base32 = base32::encode(&secret);
        Ok(TotpEnrollment {
            otpauth_uri: otpauth_uri(&user.handle, &secret_base32),
            secret_base32,
        })
    }

    /// Checks a code against the user's opened secret and records the
    /// matched step, refusing replays of the same or an older step.
    pub(crate) async fn check_totp_code(&self, user: &User, code: &str) -> CoreResult<()> {
        let matched = self.matched_totp_step(user, code).await?;
        // The CAS claim is the replay guard: a concurrent request that
        // already recorded this step (or a newer one) makes it fail here,
        // so exactly one caller ever passes for a given step.
        if !auth_factors::claim_totp_step(self.db(), user.id, matched).await? {
            return Err(CoreError::Invalid(
                "That code has already been used. Wait for the next code.".into(),
            ));
        }
        Ok(())
    }

    /// The step a code matches, verified against the user's opened secret
    /// WITHOUT recording it. Callers that must record the step together
    /// with another state change (enrollment) claim it themselves.
    async fn matched_totp_step(&self, user: &User, code: &str) -> CoreResult<i64> {
        let state = auth_factors::totp_state(self.db(), user.id)
            .await?
            .ok_or_else(|| CoreError::Internal("user missing".into()))?;
        let sealed = state.secret.as_deref().ok_or_else(|| {
            CoreError::Invalid("Two-factor authentication is not enabled.".into())
        })?;
        let secret = self.open_totp(sealed)?;
        let now = starforged_db::now();
        let matched = verify(&secret, code, now)
            .ok_or_else(|| CoreError::Invalid("That code is not valid.".into()))?;
        i64::try_from(matched).map_err(|_| CoreError::Internal("step out of range".into()))
    }

    /// Confirms a pending enrollment with a valid code: enables 2FA, records
    /// the step, issues recovery codes, and audits `account.2fa_enabled`.
    /// The codes are returned once and never stored in plaintext.
    pub async fn confirm_totp_enrollment(
        &self,
        user: &User,
        code: &str,
    ) -> CoreResult<Vec<String>> {
        let state = auth_factors::totp_state(self.db(), user.id)
            .await?
            .ok_or_else(|| CoreError::Internal("user missing".into()))?;
        if state.enabled {
            return Err(CoreError::Invalid(
                "Two-factor authentication is already enabled.".into(),
            ));
        }
        if state.secret.is_none() {
            return Err(CoreError::Invalid("Start enrollment first.".into()));
        }
        let matched = self.matched_totp_step(user, code).await?;
        // Record the step and enable 2FA in one statement: no window in
        // which password login sees TOTP disabled with the step consumed.
        if !auth_factors::claim_totp_step_and_enable(self.db(), user.id, matched).await? {
            return Err(CoreError::Invalid(
                "That code has already been used. Wait for the next code.".into(),
            ));
        }
        let codes = new_recovery_codes();
        let hashes: Vec<String> = codes.iter().map(|c| hash_recovery_code(c)).collect();
        auth_factors::insert_recovery_codes(self.db(), user.id, &hashes).await?;
        self.audit(
            Some(user.id),
            "account.2fa_enabled",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(codes)
    }

    /// Disables 2FA after the password (or, for password-less accounts, the
    /// code alone) plus a current code. Clears the secret, codes, and any
    /// pending login challenges, and audits `account.2fa_disabled`.
    pub async fn disable_totp(&self, user: &User, password: &str, code: &str) -> CoreResult<()> {
        let row = users::by_id(self.db(), user.id)
            .await?
            .ok_or_else(|| CoreError::NotFound)?;
        let state = auth_factors::totp_state(self.db(), user.id)
            .await?
            .ok_or_else(|| CoreError::Internal("user missing".into()))?;
        if !state.enabled {
            return Err(CoreError::Invalid(
                "Two-factor authentication is not enabled.".into(),
            ));
        }
        let has_password = row.password_hash.is_some();
        let password_ok =
            !has_password || verify_password(row.password_hash, password.to_owned()).await?;
        if !password_ok {
            return Err(CoreError::Invalid("The password is not correct.".into()));
        }
        self.check_totp_code(user, code).await?;
        auth_factors::set_totp(self.db(), user.id, None, false, None).await?;
        auth_factors::delete_recovery_codes(self.db(), user.id).await?;
        auth_factors::delete_challenges_for_user(self.db(), user.id).await?;
        self.audit(
            Some(user.id),
            "account.2fa_disabled",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(())
    }

    /// Replaces the recovery codes after a current code; the old ones stop
    /// working at once. Audits `account.recovery_codes_regenerated` and
    /// returns the fresh codes once.
    pub async fn regenerate_recovery_codes(
        &self,
        user: &User,
        code: &str,
    ) -> CoreResult<Vec<String>> {
        let state = auth_factors::totp_state(self.db(), user.id)
            .await?
            .ok_or_else(|| CoreError::Internal("user missing".into()))?;
        if !state.enabled {
            return Err(CoreError::Invalid(
                "Two-factor authentication is not enabled.".into(),
            ));
        }
        self.check_totp_code(user, code).await?;
        auth_factors::delete_recovery_codes(self.db(), user.id).await?;
        let codes = new_recovery_codes();
        let hashes: Vec<String> = codes.iter().map(|c| hash_recovery_code(c)).collect();
        auth_factors::insert_recovery_codes(self.db(), user.id, &hashes).await?;
        self.audit(
            Some(user.id),
            "account.recovery_codes_regenerated",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(codes)
    }

    /// A site admin disables a user's 2FA: the secret, recovery codes, and
    /// pending challenges go, and `user.2fa_reset` is audited with the
    /// admin as actor. Anything but a site admin gets `Forbidden`.
    pub async fn admin_reset_2fa(&self, admin: &User, target_id: i64) -> CoreResult<()> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let target = self
            .user_by_id(target_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        auth_factors::set_totp(self.db(), target.id, None, false, None).await?;
        auth_factors::delete_recovery_codes(self.db(), target.id).await?;
        auth_factors::delete_challenges_for_user(self.db(), target.id).await?;
        self.audit(
            Some(admin.id),
            "user.2fa_reset",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::test_core;

    const PASSWORD: &str = "correct horse battery";

    /// RFC 6238 Appendix B, SHA-1 rows, truncated to 6 digits.
    #[test]
    fn rfc_6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        let cases = [
            (59_i64, 287082_u32),
            (1_111_111_109, 81804),
            (1_111_111_111, 50471),
            (1_234_567_890, 5924),
            (2_000_000_000, 279037),
            (20_000_000_000, 353130),
        ];
        for (t, expected) in cases {
            let step = (t / 30) as u64;
            assert_eq!(code_at(secret, step), expected, "T={t}");
            assert_eq!(
                verify(secret, &format!("{expected:06}"), t),
                Some(step),
                "T={t}"
            );
        }
    }

    #[test]
    fn verify_accepts_a_step_either_side_and_rejects_the_rest() {
        let secret = b"12345678901234567890";
        let t = 1_234_567_890_i64;
        let step = (t / 30) as u64;
        let code = |s: u64| format!("{:06}", code_at(secret, s));
        assert_eq!(verify(secret, &code(step - 1), t), Some(step - 1));
        assert_eq!(verify(secret, &code(step), t), Some(step));
        assert_eq!(verify(secret, &code(step + 1), t), Some(step + 1));
        assert_eq!(verify(secret, &code(step + 2), t), None);
        let wrong = format!("{:06}", (code_at(secret, step) + 1) % 1_000_000);
        assert_eq!(verify(secret, &wrong, t), None);
        assert_eq!(verify(secret, "12345", t), None);
        assert_eq!(verify(secret, "abcdef", t), None);
    }

    #[test]
    fn recovery_codes_normalize_before_hashing() {
        assert_eq!(
            hash_recovery_code("abcde-fghij"),
            hash_recovery_code("ABCDE FGHIJ")
        );
        assert_ne!(
            hash_recovery_code("abcde-fghij"),
            hash_recovery_code("abcde-fghik")
        );
    }

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
    async fn enrollment_then_disable_round_trip() {
        let (core, _f) = test_core().await;
        let user = alice(&core).await;
        let enrollment = core.begin_totp_enrollment(&user).await.unwrap();
        let secret = base32::decode(&enrollment.secret_base32).unwrap();
        assert_eq!(secret.len(), 20);
        assert!(
            enrollment
                .otpauth_uri
                .contains(&format!("secret={}", enrollment.secret_base32))
        );
        let code = format!(
            "{:06}",
            code_at(&secret, (starforged_db::now() / 30) as u64)
        );
        let codes = core.confirm_totp_enrollment(&user, &code).await.unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        for code in &codes {
            assert_eq!(code.len(), 11, "{code}");
            assert_eq!(code.as_bytes()[5], b'-');
        }
        assert!(core.totp_enabled(user.id).await.unwrap());
        // The stored value is sealed, never the base32 secret.
        let row = auth_factors::totp_state(core.db(), user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(row.secret.as_deref().unwrap().starts_with("v1:"));
        assert!(
            !row.secret
                .as_deref()
                .unwrap()
                .contains(&enrollment.secret_base32)
        );

        assert!(
            core.disable_totp(&user, "wrong password", &code)
                .await
                .is_err()
        );
        let fresh = format!(
            "{:06}",
            code_at(&secret, ((starforged_db::now() + 30) / 30) as u64)
        );
        core.disable_totp(&user, PASSWORD, &fresh).await.unwrap();
        assert!(!core.totp_enabled(user.id).await.unwrap());
    }
}
