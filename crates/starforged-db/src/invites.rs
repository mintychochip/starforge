//! `invites`: single-use sign-up links issued by site admins (forge-basics design §4.1), stored as SHA-256 of
//! the code.
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    pub id: i64,
    /// When set, only this address can sign up with the invite.
    pub email: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub struct NewInvite<'a> {
    pub code_hash: &'a str,
    pub email: Option<&'a str>,
    pub created_by: i64,
    pub expires_at: i64,
}

macro_rules! select_invite {
    ($tail:literal) => {
        concat!(
            "SELECT id, email, created_by, created_at, expires_at, used_at, used_by, revoked_at FROM invites ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<InviteRow> {
    Ok(InviteRow {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        used_at: row.try_get("used_at")?,
        used_by: row.try_get("used_by")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub async fn insert(db: &Db, invite: &NewInvite<'_>) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO invites (code_hash, email, created_by, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(invite.code_hash)
    .bind(invite.email.map(str::to_owned))
    .bind(invite.created_by)
    .bind(now())
    .bind(invite.expires_at)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

pub async fn by_code_hash(db: &Db, code_hash: &str) -> DbResult<Option<InviteRow>> {
    let row = sqlx::query(select_invite!("WHERE code_hash = $1"))
        .bind(code_hash)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// Marks the invite used if it is unused, unrevoked, and unexpired at `now_ts`; `false` otherwise.
pub async fn claim(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "UPDATE invites SET used_at = $1 \
         WHERE id = $2 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $3",
    )
    .bind(now_ts)
    .bind(id)
    .bind(now_ts)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Undoes [`claim`] after the sign-up that claimed the invite failed.
pub async fn release(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("UPDATE invites SET used_at = NULL WHERE id = $1 AND used_by IS NULL")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_used_by(db: &Db, id: i64, user_id: i64) -> DbResult<()> {
    sqlx::query("UPDATE invites SET used_by = $1 WHERE id = $2")
        .bind(user_id)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Newest first.
pub async fn list(db: &Db, limit: i64) -> DbResult<Vec<InviteRow>> {
    let rows = sqlx::query(select_invite!("ORDER BY id DESC LIMIT $1"))
        .bind(limit)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(from_row).collect()
}

/// Revokes an unused, unrevoked invite; `false` when there is no such invite.
pub async fn revoke(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "UPDATE invites SET revoked_at = $1 WHERE id = $2 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(now_ts)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes invites that expired before `before`; returns how many.
pub async fn delete_expired_before(db: &Db, before: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM invites WHERE expires_at < $1")
        .bind(before)
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
    async fn invites_are_claimed_once_and_can_be_released_or_revoked() {
        let t = TestDb::new().await;
        let admin = users::insert(
            &t.db,
            &NewUser {
                handle: "root",
                display_name: "",
                email: None,
                email_verified: false,
                password_hash: None,
                is_admin: true,
            },
        )
        .await
        .unwrap();
        let id = insert(
            &t.db,
            &NewInvite {
                code_hash: "c1",
                email: Some("a@example.com"),
                created_by: admin,
                expires_at: 1_000,
            },
        )
        .await
        .unwrap();
        let row = by_code_hash(&t.db, "c1").await.unwrap().unwrap();
        assert_eq!(
            (row.id, row.email.as_deref(), row.created_by),
            (id, Some("a@example.com"), Some(admin))
        );
        assert!(
            !claim(&t.db, id, 1_000).await.unwrap(),
            "an invite has expired at its expiry time"
        );
        assert!(claim(&t.db, id, 10).await.unwrap());
        assert!(!claim(&t.db, id, 10).await.unwrap(), "single use");
        release(&t.db, id).await.unwrap();
        assert!(
            claim(&t.db, id, 10).await.unwrap(),
            "a released invite works again"
        );
        set_used_by(&t.db, id, admin).await.unwrap();
        release(&t.db, id).await.unwrap();
        assert!(
            !claim(&t.db, id, 10).await.unwrap(),
            "a completed sign-up keeps its invite"
        );

        let other = insert(
            &t.db,
            &NewInvite {
                code_hash: "c2",
                email: None,
                created_by: admin,
                expires_at: 1_000,
            },
        )
        .await
        .unwrap();
        assert!(revoke(&t.db, other, 20).await.unwrap());
        assert!(!revoke(&t.db, other, 20).await.unwrap());
        assert!(!claim(&t.db, other, 30).await.unwrap(), "revoked");
        assert_eq!(
            list(&t.db, 10)
                .await
                .unwrap()
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![other, id]
        );
        assert_eq!(delete_expired_before(&t.db, 1_001).await.unwrap(), 2);
    }
}
