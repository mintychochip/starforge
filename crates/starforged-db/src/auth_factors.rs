//! Auth factors (spec §9, M3d): TOTP state on `users`, recovery-code hashes,
//! OIDC identity links, and in-progress login challenges.
//!
//! TOTP secrets are stored only as the sealed string (`users.totp_secret`);
//! recovery codes only as SHA-256 hashes of their normalized form; login
//! challenge tokens only as SHA-256 hashes of the random token the browser
//! carries in its cookie.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

/// One user's TOTP state. `secret` is the sealed secret, pending or active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpRow {
    pub secret: Option<String>,
    pub enabled: bool,
    pub last_step: Option<i64>,
}

/// The TOTP state for `user_id`, or `None` when the user does not exist.
pub async fn totp_state(db: &Db, user_id: i64) -> DbResult<Option<TotpRow>> {
    let row =
        sqlx::query("SELECT totp_secret, totp_enabled, totp_last_step FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db.pool())
            .await?;
    row.as_ref().map(totp_from_row).transpose()
}

fn totp_from_row(row: &AnyRow) -> DbResult<TotpRow> {
    Ok(TotpRow {
        secret: row.try_get("totp_secret")?,
        enabled: row.try_get::<i64, _>("totp_enabled")? != 0,
        last_step: row.try_get("totp_last_step")?,
    })
}

/// Stores (or clears) the sealed secret and the enabled flag. Callers always
/// pass `last_step` explicitly: `None` on enrollment/reset, the accepted step
/// once a code has been consumed.
pub async fn set_totp(
    db: &Db,
    user_id: i64,
    secret: Option<&str>,
    enabled: bool,
    last_step: Option<i64>,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE users SET totp_secret = $1, totp_enabled = $2, totp_last_step = $3 WHERE id = $4",
    )
    .bind(secret.map(str::to_owned))
    .bind(i64::from(enabled))
    .bind(last_step)
    .bind(user_id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Records the highest TOTP step accepted so far (replay guard).
pub async fn set_totp_last_step(db: &Db, user_id: i64, step: i64) -> DbResult<()> {
    sqlx::query("UPDATE users SET totp_last_step = $1 WHERE id = $2")
        .bind(step)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Stores fresh recovery-code hashes for `user_id` (callers delete the old ones first).
pub async fn insert_recovery_codes(db: &Db, user_id: i64, hashes: &[String]) -> DbResult<()> {
    for hash in hashes {
        sqlx::query(
            "INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(hash)
        .bind(now())
        .execute(db.pool())
        .await?;
    }
    Ok(())
}

/// Deletes every recovery code of the user (used, unused, or live).
pub async fn delete_recovery_codes(db: &Db, user_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Consumes one unused recovery code; `true` when the hash matched an unused row.
pub async fn consume_recovery_code(db: &Db, user_id: i64, code_hash: &str) -> DbResult<bool> {
    let affected = sqlx::query(
        "UPDATE recovery_codes SET used_at = $1 WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL",
    )
    .bind(now())
    .bind(user_id)
    .bind(code_hash)
    .execute(db.pool())
    .await?;
    Ok(affected.rows_affected() > 0)
}

/// One linked OIDC identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRow {
    pub id: i64,
    pub user_id: i64,
    pub issuer: String,
    pub subject: String,
}

fn identity_from_row(row: &AnyRow) -> DbResult<IdentityRow> {
    Ok(IdentityRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        issuer: row.try_get("issuer")?,
        subject: row.try_get("subject")?,
    })
}

/// Links `(issuer, subject)` to the user; the unique constraint refuses a second link.
pub async fn insert_identity(db: &Db, user_id: i64, issuer: &str, subject: &str) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO user_identities (user_id, issuer, subject, created_at) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(user_id)
    .bind(issuer)
    .bind(subject)
    .bind(now())
    .fetch_one(db.pool())
    .await?)
}

/// The identity for an OIDC `(issuer, subject)`, if it is linked.
pub async fn identity_by_issuer_subject(
    db: &Db,
    issuer: &str,
    subject: &str,
) -> DbResult<Option<IdentityRow>> {
    let row = sqlx::query(
        "SELECT id, user_id, issuer, subject FROM user_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(issuer)
    .bind(subject)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(identity_from_row).transpose()
}

/// Every identity linked to the user, by id.
pub async fn identities_for_user(db: &Db, user_id: i64) -> DbResult<Vec<IdentityRow>> {
    let rows = sqlx::query(
        "SELECT id, user_id, issuer, subject FROM user_identities WHERE user_id = $1 ORDER BY id ASC",
    )
    .bind(user_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(identity_from_row).collect()
}

/// Removes one identity link; `false` when it belongs to someone else or is missing.
pub async fn delete_identity(db: &Db, id: i64, user_id: i64) -> DbResult<bool> {
    let affected = sqlx::query("DELETE FROM user_identities WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(affected.rows_affected() > 0)
}

/// One in-progress login: a TOTP second step (kind `totp`) or, from the later
/// OIDC tasks, an authorization-code flow (kind `oidc`) whose `state`, `nonce`,
/// and PKCE verifier live here. The browser carries only the random token;
/// `token_hash` is its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginChallengeRow {
    pub id: i64,
    pub kind: String,
    pub user_id: Option<i64>,
    pub token_hash: String,
    pub attempts: i64,
    pub expires_at: i64,
}

fn challenge_from_row(row: &AnyRow) -> DbResult<LoginChallengeRow> {
    Ok(LoginChallengeRow {
        id: row.try_get("id")?,
        kind: row.try_get("kind")?,
        user_id: row.try_get("user_id")?,
        token_hash: row.try_get("token_hash")?,
        attempts: row.try_get("attempts")?,
        expires_at: row.try_get("expires_at")?,
    })
}

/// Starts a login challenge and returns its row id.
pub async fn insert_challenge(
    db: &Db,
    kind: &str,
    user_id: Option<i64>,
    token_hash: &str,
    expires_at: i64,
) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO login_challenges (kind, user_id, token_hash, attempts, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(kind)
    .bind(user_id)
    .bind(token_hash)
    .bind(0_i64)
    .bind(expires_at)
    .bind(now())
    .fetch_one(db.pool())
    .await?)
}

/// The challenge whose token hashes to `token_hash`, if it exists.
pub async fn challenge_by_token_hash(
    db: &Db,
    token_hash: &str,
) -> DbResult<Option<LoginChallengeRow>> {
    let row = sqlx::query(
        "SELECT id, kind, user_id, token_hash, attempts, expires_at FROM login_challenges WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(challenge_from_row).transpose()
}

/// Ends a challenge (completed, voided, or expired).
pub async fn delete_challenge(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM login_challenges WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Ends every challenge of the user (e.g. after an admin 2FA reset).
pub async fn delete_challenges_for_user(db: &Db, user_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM login_challenges WHERE user_id = $1")
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Counts one failed second-factor attempt; returns the new attempt count.
pub async fn bump_challenge_attempts(db: &Db, id: i64) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "UPDATE login_challenges SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await?)
}
