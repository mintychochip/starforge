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
            .fetch_optional(db.read_pool())
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

/// Atomically records `step` as the highest TOTP step accepted so far
/// (replay guard). Returns `false` when the step was already recorded or a
/// newer step won the race: the caller lost and must refuse the code.
pub async fn claim_totp_step(db: &Db, user_id: i64, step: i64) -> DbResult<bool> {
    let affected = sqlx::query(
        "UPDATE users SET totp_last_step = $1 \
         WHERE id = $2 AND (totp_last_step IS NULL OR totp_last_step < $1)",
    )
    .bind(step)
    .bind(user_id)
    .execute(db.pool())
    .await?;
    Ok(affected.rows_affected() > 0)
}

/// Atomically records `step` as the highest TOTP step accepted so far
/// AND enables two-factor authentication, in one statement. Enrollment
/// confirmation uses this so no window exists where the step is recorded
/// but password login still sees TOTP disabled. Returns `false` when the
/// step was already recorded or a newer step won the race.
pub async fn claim_totp_step_and_enable(db: &Db, user_id: i64, step: i64) -> DbResult<bool> {
    let affected = sqlx::query(
        "UPDATE users SET totp_last_step = $1, totp_enabled = 1 \
         WHERE id = $2 AND (totp_last_step IS NULL OR totp_last_step < $1)",
    )
    .bind(step)
    .bind(user_id)
    .execute(db.pool())
    .await?;
    Ok(affected.rows_affected() > 0)
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
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(identity_from_row).transpose()
}

/// Every identity linked to the user, by id.
pub async fn identities_for_user(db: &Db, user_id: i64) -> DbResult<Vec<IdentityRow>> {
    let rows = sqlx::query(
        "SELECT id, user_id, issuer, subject FROM user_identities WHERE user_id = $1 ORDER BY id ASC",
    )
    .bind(user_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(identity_from_row).collect()
}

/// Why an identity unlink was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkIdentityError {
    /// The identity belongs to someone else or is missing (or the user is gone).
    NotFound,
    /// The account has no password and this is its only identity: unlinking
    /// would leave it with no way to sign in.
    LastMeansOfLogin,
}

/// Removes one identity link unless it is the account's last means of
/// sign-in (no password and no other identity). The check and the delete
/// run in one transaction behind a parent-row lock on `users`
/// (`display_name = display_name` is a no-op update that takes the row
/// lock; `users` has no `updated_at`), so two concurrent unlinks cannot
/// strand a password-less account under Postgres READ COMMITTED.
pub async fn delete_identity_unless_last(
    db: &Db,
    id: i64,
    user_id: i64,
) -> DbResult<Result<(), UnlinkIdentityError>> {
    let mut tx = db.pool().begin().await?;
    sqlx::query("UPDATE users SET display_name = display_name WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let password_hash: Option<Option<String>> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(password_hash) = password_hash else {
        return Ok(Err(UnlinkIdentityError::NotFound));
    };
    let exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if exists == 0 {
        return Ok(Err(UnlinkIdentityError::NotFound));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if password_hash.is_none() && count <= 1 {
        return Ok(Err(UnlinkIdentityError::LastMeansOfLogin));
    }
    sqlx::query("DELETE FROM user_identities WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Ok(()))
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
    /// OIDC flow state (kind `oidc` only): the provider `state`, the
    /// `nonce` the ID token must echo, and the PKCE verifier.
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    pub attempts: i64,
    pub expires_at: i64,
}

fn challenge_from_row(row: &AnyRow) -> DbResult<LoginChallengeRow> {
    Ok(LoginChallengeRow {
        id: row.try_get("id")?,
        state: row.try_get("state")?,
        nonce: row.try_get("nonce")?,
        code_verifier: row.try_get("code_verifier")?,
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
        "SELECT id, kind, user_id, token_hash, state, nonce, code_verifier, attempts, expires_at FROM login_challenges WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(challenge_from_row).transpose()
}

/// Starts an OIDC authorization-code flow and returns its row id. The
/// `state`, `nonce`, and PKCE verifier live on the row; the browser
/// carries only the random token whose SHA-256 is `token_hash`.
pub async fn insert_oidc_challenge(
    db: &Db,
    token_hash: &str,
    user_id: Option<i64>,
    state: &str,
    nonce: &str,
    code_verifier: &str,
    expires_at: i64,
) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO login_challenges (kind, user_id, token_hash, state, nonce, code_verifier, attempts, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind("oidc")
    .bind(user_id)
    .bind(token_hash)
    .bind(state)
    .bind(nonce)
    .bind(code_verifier)
    .bind(0_i64)
    .bind(expires_at)
    .bind(now())
    .fetch_one(db.pool())
    .await?)
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

/// Atomically claims a live challenge of `kind` by deleting it; returns
/// the claimed row, or `None` when the token is unknown, expired at
/// `now_ts`, of a different kind, or a concurrent request already claimed
/// it. The first claimer owns the challenge: single-use consumption,
/// like `grant_device_tokens`. The kind rides in the WHERE clause so one
/// flow can never claim another flow's challenge.
pub async fn claim_challenge(
    db: &Db,
    kind: &str,
    token_hash: &str,
    now_ts: i64,
) -> DbResult<Option<LoginChallengeRow>> {
    let row = sqlx::query(
        "DELETE FROM login_challenges WHERE kind = $1 AND token_hash = $2 AND expires_at > $3 \
         RETURNING id, kind, user_id, token_hash, state, nonce, code_verifier, attempts, expires_at",
    )
    .bind(kind)
    .bind(token_hash)
    .bind(now_ts)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(challenge_from_row).transpose()
}

/// Restores a challenge claimed with [`claim_challenge`] whose code failed,
/// carrying the incremented attempt count. With fewer than the configured
/// maximum attempts the challenge stays usable; at the maximum it is void
/// by not being restored. Returns the restored row id.
pub async fn restore_challenge(
    db: &Db,
    challenge: &LoginChallengeRow,
    attempts: i64,
) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO login_challenges (kind, user_id, token_hash, state, nonce, code_verifier, attempts, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(&challenge.kind)
    .bind(challenge.user_id)
    .bind(&challenge.token_hash)
    .bind(challenge.state.as_deref())
    .bind(challenge.nonce.as_deref())
    .bind(challenge.code_verifier.as_deref())
    .bind(attempts)
    .bind(challenge.expires_at)
    .bind(now())
    .fetch_one(db.pool())
    .await?)
}
