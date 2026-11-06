//! `email_tokens`: one-time links sent by email (forge-basics design §4.3), stored as SHA-256 of the secret.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailTokenRow {
    pub id: i64,
    pub user_id: i64,
    pub purpose: String,
    /// The address the link was sent to (for `change_email`, the new address).
    pub email: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
}

pub struct NewEmailToken<'a> {
    pub user_id: i64,
    /// `verify_email`, `change_email`, or `reset_password`.
    pub purpose: &'a str,
    pub token_hash: &'a str,
    pub email: &'a str,
    pub expires_at: i64,
}

macro_rules! select_token {
    ($tail:literal) => {
        concat!(
            "SELECT id, user_id, purpose, email, created_at, expires_at, used_at FROM email_tokens ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<EmailTokenRow> {
    Ok(EmailTokenRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        purpose: row.try_get("purpose")?,
        email: row.try_get("email")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        used_at: row.try_get("used_at")?,
    })
}

/// When the newest token for `user_id` and `purpose` was issued; the email throttle reads it.
pub async fn newest_created_at(db: &Db, user_id: i64, purpose: &str) -> DbResult<Option<i64>> {
    let newest: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(created_at) FROM email_tokens WHERE user_id = $1 AND purpose = $2",
    )
    .bind(user_id)
    .bind(purpose)
    .fetch_one(db.read_pool())
    .await?;
    Ok(newest)
}

/// Inserts a token after retiring the user's unused tokens for the same purpose: only the newest link works.
pub async fn replace(db: &Db, token: &NewEmailToken<'_>) -> DbResult<i64> {
    let ts = now();
    let mut tx = db.pool().begin().await?;
    sqlx::query(
        "UPDATE email_tokens SET used_at = $1 WHERE user_id = $2 AND purpose = $3 AND used_at IS NULL",
    )
    .bind(ts)
    .bind(token.user_id)
    .bind(token.purpose)
    .execute(&mut *tx)
    .await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO email_tokens (user_id, purpose, token_hash, email, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(token.user_id)
    .bind(token.purpose)
    .bind(token.token_hash)
    .bind(token.email)
    .bind(ts)
    .bind(token.expires_at)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// The unused token with this hash and purpose that expires after `now_ts`, without using it.
pub async fn peek(
    db: &Db,
    token_hash: &str,
    purpose: &str,
    now_ts: i64,
) -> DbResult<Option<EmailTokenRow>> {
    let row = sqlx::query(select_token!(
        "WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3"
    ))
    .bind(token_hash)
    .bind(purpose)
    .bind(now_ts)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(from_row).transpose()
}

/// Uses a token once: returns it when it was unused, unexpired, and for `purpose`, and marks it used.
pub async fn consume(
    db: &Db,
    token_hash: &str,
    purpose: &str,
    now_ts: i64,
) -> DbResult<Option<EmailTokenRow>> {
    let Some(row) = peek(db, token_hash, purpose, now_ts).await? else {
        return Ok(None);
    };
    let used =
        sqlx::query("UPDATE email_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL")
            .bind(now_ts)
            .bind(row.id)
            .execute(db.pool())
            .await?
            .rows_affected();
    Ok((used == 1).then_some(row))
}

/// Deletes tokens whose expiry is at or before `now_ts`; returns how many.
pub async fn delete_expired(db: &Db, now_ts: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM email_tokens WHERE expires_at <= $1")
        .bind(now_ts)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    #[tokio::test]
    async fn tokens_work_once_until_they_expire_and_newer_ones_retire_older() {
        let t = TestDb::new().await;
        let user = users::insert(
            &t.db,
            &NewUser {
                handle: "alice",
                display_name: "",
                email: Some("a@example.com"),
                email_verified: false,
                password_hash: None,
                is_admin: false,
            },
        )
        .await
        .unwrap();
        let token = |token_hash: &'static str, expires_at: i64| NewEmailToken {
            user_id: user,
            purpose: "verify_email",
            token_hash,
            email: "a@example.com",
            expires_at,
        };
        assert_eq!(
            newest_created_at(&t.db, user, "verify_email")
                .await
                .unwrap(),
            None
        );
        replace(&t.db, &token("h1", i64::MAX)).await.unwrap();
        replace(&t.db, &token("h2", i64::MAX)).await.unwrap();
        assert!(
            newest_created_at(&t.db, user, "verify_email")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            consume(&t.db, "h1", "verify_email", 10)
                .await
                .unwrap()
                .is_none(),
            "the newer token retired h1"
        );
        assert!(
            consume(&t.db, "h2", "reset_password", 10)
                .await
                .unwrap()
                .is_none(),
            "wrong purpose"
        );
        let row = consume(&t.db, "h2", "verify_email", 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((row.user_id, row.email.as_str()), (user, "a@example.com"));
        assert!(
            consume(&t.db, "h2", "verify_email", 10)
                .await
                .unwrap()
                .is_none(),
            "tokens work once"
        );
        replace(&t.db, &token("h3", 100)).await.unwrap();
        assert!(
            peek(&t.db, "h3", "verify_email", 99)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            peek(&t.db, "h3", "verify_email", 99)
                .await
                .unwrap()
                .is_some(),
            "peeking does not use the token"
        );
        assert!(
            consume(&t.db, "h3", "verify_email", 100)
                .await
                .unwrap()
                .is_none(),
            "expired"
        );
        assert_eq!(delete_expired(&t.db, 101).await.unwrap(), 1);
    }
}
