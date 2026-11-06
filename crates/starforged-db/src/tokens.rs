//! `access_tokens`: personal access tokens, stored as SHA-256 hex of the secret.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRow {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub token_hint: String,
    pub scopes: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub struct NewToken<'a> {
    pub user_id: i64,
    pub name: &'a str,
    pub token_hash: &'a str,
    pub token_hint: &'a str,
    pub scopes: &'a str,
    pub expires_at: i64,
}

macro_rules! select_token {
    ($tail:literal) => {
        concat!(
            "SELECT id, user_id, name, token_hint, scopes, created_at, expires_at, last_used_at, revoked_at ",
            "FROM access_tokens ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<TokenRow> {
    Ok(TokenRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        name: row.try_get("name")?,
        token_hint: row.try_get("token_hint")?,
        scopes: row.try_get("scopes")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub async fn insert(db: &Db, token: &NewToken<'_>) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO access_tokens (user_id, name, token_hash, token_hint, scopes, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(token.user_id)
    .bind(token.name)
    .bind(token.token_hash)
    .bind(token.token_hint)
    .bind(token.scopes)
    .bind(now())
    .bind(token.expires_at)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

pub async fn by_hash(db: &Db, token_hash: &str) -> DbResult<Option<TokenRow>> {
    let row = sqlx::query(select_token!("WHERE token_hash = $1"))
        .bind(token_hash)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn list_for_user(db: &Db, user_id: i64) -> DbResult<Vec<TokenRow>> {
    let rows = sqlx::query(select_token!("WHERE user_id = $1 ORDER BY id DESC"))
        .bind(user_id)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(from_row).collect()
}

/// Revokes the user's token; `false` when it does not exist, belongs to someone else, or is already revoked.
pub async fn revoke(db: &Db, user_id: i64, token_id: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "UPDATE access_tokens SET revoked_at = $1 WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(token_id)
    .bind(user_id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn touch(db: &Db, token_id: i64) -> DbResult<()> {
    sqlx::query("UPDATE access_tokens SET last_used_at = $1 WHERE id = $2")
        .bind(now())
        .bind(token_id)
        .execute(db.pool())
        .await?;
    Ok(())
}
