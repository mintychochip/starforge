//! `owners` + `users`: accounts and the handle namespace shared with orgs (spec §6.1).

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub id: i64,
    pub handle: String,
    pub display_name: String,
    pub email: Option<String>,
    /// The owner of `email` confirmed it, or an administrator vouched for it.
    pub email_verified: bool,
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub state: String,
    pub created_at: i64,
}

pub struct NewUser<'a> {
    pub handle: &'a str,
    pub display_name: &'a str,
    pub email: Option<&'a str>,
    /// The owner of `email` confirmed it, or an administrator vouched for it.
    pub email_verified: bool,
    pub password_hash: Option<&'a str>,
    pub is_admin: bool,
}

macro_rules! select_user {
    ($tail:literal) => {
        concat!(
            "SELECT u.id, o.handle, u.display_name, u.email, u.email_verified, u.password_hash, u.is_admin, u.state, u.created_at ",
            "FROM users u JOIN owners o ON o.id = u.id ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<UserRow> {
    Ok(UserRow {
        id: row.try_get("id")?,
        handle: row.try_get("handle")?,
        display_name: row.try_get("display_name")?,
        email: row.try_get("email")?,
        email_verified: row.try_get::<i64, _>("email_verified")? != 0,
        password_hash: row.try_get("password_hash")?,
        is_admin: row.try_get::<i64, _>("is_admin")? != 0,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Inserts the owner row and the user row in one transaction and returns the shared id.
pub async fn insert(db: &Db, new: &NewUser<'_>) -> DbResult<i64> {
    let created_at = now();
    let mut tx = db.pool().begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO owners (kind, handle, created_at) VALUES ('user', $1, $2) RETURNING id",
    )
    .bind(new.handle)
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO users (id, display_name, email, email_verified, password_hash, is_admin, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(new.display_name)
    .bind(new.email.map(str::to_owned))
    .bind(i64::from(new.email_verified))
    .bind(new.password_hash.map(str::to_owned))
    .bind(i64::from(new.is_admin))
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<UserRow>> {
    let row = sqlx::query(select_user!("WHERE u.id = $1"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// `handle` must already be lowercase.
pub async fn by_handle(db: &Db, handle: &str) -> DbResult<Option<UserRow>> {
    let row = sqlx::query(select_user!("WHERE o.handle = $1"))
        .bind(handle)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// `email` must already be lowercase.
pub async fn by_email(db: &Db, email: &str) -> DbResult<Option<UserRow>> {
    let row = sqlx::query(select_user!("WHERE u.email = $1"))
        .bind(email)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn set_state(db: &Db, id: i64, state: &str) -> DbResult<()> {
    sqlx::query("UPDATE users SET state = $1 WHERE id = $2")
        .bind(state)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// All users whose handle or email contains `query` (already lowercased; empty matches all),
/// by handle, at most `limit` rows.
pub async fn list_users(db: &Db, query: &str, limit: i64) -> DbResult<Vec<UserRow>> {
    let rows = sqlx::query(select_user!(
        "WHERE LOWER(o.handle) LIKE '%' || LOWER($1) || '%' OR LOWER(u.email) LIKE '%' || LOWER($1) || '%' ORDER BY o.handle ASC LIMIT $2"
    ))
    .bind(query)
    .bind(limit)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Sets or clears the site-admin flag (`0`/`1` on both engines).
pub async fn set_is_admin(db: &Db, id: i64, is_admin: bool) -> DbResult<()> {
    sqlx::query("UPDATE users SET is_admin = $1 WHERE id = $2")
        .bind(i64::from(is_admin))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Total user count, for the admin overview.
pub async fn count(db: &Db) -> DbResult<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db.read_pool())
        .await?)
}
pub async fn set_email_verified(db: &Db, id: i64, verified: bool) -> DbResult<()> {
    sqlx::query("UPDATE users SET email_verified = $1 WHERE id = $2")
        .bind(i64::from(verified))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
pub async fn set_password_hash(db: &Db, id: i64, password_hash: &str) -> DbResult<()> {
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(password_hash)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_display_name(db: &Db, id: i64, display_name: &str) -> DbResult<()> {
    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(display_name)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Sets the (lowercase) address and whether it is verified.
pub async fn set_email(db: &Db, id: i64, email: Option<&str>, verified: bool) -> DbResult<()> {
    sqlx::query("UPDATE users SET email = $1, email_verified = $2 WHERE id = $3")
        .bind(email.map(str::to_owned))
        .bind(i64::from(verified))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Active site admins other than `id`.
pub async fn count_active_admins_except(db: &Db, id: i64) -> DbResult<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND state = 'active' AND id <> $1",
    )
    .bind(id)
    .fetch_one(db.read_pool())
    .await?;
    Ok(count)
}

/// Deletes the account's owner row. The user row, web sessions, access tokens, email links, collaborator
/// grants, repository redirects, and any repository rows cascade; invites and audit entries keep their rows
/// with the user cleared.
pub async fn delete(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM owners WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDb;

    fn alice() -> NewUser<'static> {
        NewUser {
            handle: "alice",
            display_name: "Alice",
            email: Some("alice@example.com"),
            email_verified: false,
            password_hash: Some("hash"),
            is_admin: false,
        }
    }

    #[tokio::test]
    async fn insert_and_look_up() {
        let t = TestDb::new().await;
        let id = insert(&t.db, &alice()).await.unwrap();
        let row = by_handle(&t.db, "alice").await.unwrap().unwrap();
        assert_eq!(row.id, id);
        assert_eq!(row.display_name, "Alice");
        assert_eq!(row.email.as_deref(), Some("alice@example.com"));
        assert_eq!(row.password_hash.as_deref(), Some("hash"));
        assert!(!row.is_admin);
        assert_eq!(row.state, "active");
        assert_eq!(
            by_email(&t.db, "alice@example.com")
                .await
                .unwrap()
                .unwrap()
                .id,
            id
        );
        assert_eq!(by_id(&t.db, id).await.unwrap().unwrap().handle, "alice");
        assert!(by_handle(&t.db, "bob").await.unwrap().is_none());
        set_state(&t.db, id, "suspended").await.unwrap();
        assert_eq!(by_id(&t.db, id).await.unwrap().unwrap().state, "suspended");
    }

    #[tokio::test]
    async fn duplicate_handle_or_email_is_a_unique_violation() {
        let t = TestDb::new().await;
        insert(&t.db, &alice()).await.unwrap();
        let same_handle = insert(
            &t.db,
            &NewUser {
                email: Some("other@example.com"),
                ..alice()
            },
        )
        .await
        .unwrap_err();
        assert!(same_handle.is_unique_violation());
        let same_email = insert(
            &t.db,
            &NewUser {
                handle: "alice2",
                ..alice()
            },
        )
        .await
        .unwrap_err();
        assert!(same_email.is_unique_violation());
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM owners WHERE handle = $1")
            .bind("alice2")
            .fetch_one(t.db.pool())
            .await
            .unwrap();
        assert_eq!(owners, 0, "a failed insert must roll back its owner row");
    }
    #[tokio::test]
    async fn email_verification_is_stored() {
        let t = TestDb::new().await;
        let id = insert(
            &t.db,
            &NewUser {
                email_verified: true,
                ..alice()
            },
        )
        .await
        .unwrap();
        assert!(by_id(&t.db, id).await.unwrap().unwrap().email_verified);
        set_email_verified(&t.db, id, false).await.unwrap();
        assert!(!by_id(&t.db, id).await.unwrap().unwrap().email_verified);
    }
    #[tokio::test]
    async fn list_users_searches_handle_and_email() {
        let db = TestDb::new().await;
        insert(
            &db.db,
            &NewUser {
                handle: "alice",
                display_name: "A",
                email: Some("alice@example.com"),
                email_verified: true,
                password_hash: None,
                is_admin: true,
            },
        )
        .await
        .unwrap();
        insert(
            &db.db,
            &NewUser {
                handle: "bob",
                display_name: "B",
                email: Some("bob@example.com"),
                email_verified: false,
                password_hash: None,
                is_admin: false,
            },
        )
        .await
        .unwrap();
        let handles = |rows: Vec<UserRow>| rows.into_iter().map(|r| r.handle).collect::<Vec<_>>();
        assert_eq!(
            handles(list_users(&db.db, "", 200).await.unwrap()),
            vec!["alice", "bob"]
        );
        assert_eq!(
            handles(list_users(&db.db, "ali", 200).await.unwrap()),
            vec!["alice"]
        );
        assert_eq!(
            handles(list_users(&db.db, "BOB@EXAMPLE", 200).await.unwrap()),
            vec!["bob"]
        );
        assert_eq!(count(&db.db).await.unwrap(), 2);
    }
}
