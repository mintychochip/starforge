//! `orgs` + `org_members`: organizations and their membership (spec §6.1, D1-D2).
//! Team tables live in the same migration; team queries arrive in A2.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgRow {
    pub id: i64,
    pub handle: String,
    pub display_name: String,
    pub description: String,
    pub base_permission: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRow {
    pub id: i64,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    pub user_id: i64,
    pub handle: String,
    pub display_name: String,
    pub role: String,
}

fn from_org(row: &AnyRow) -> DbResult<OrgRow> {
    Ok(OrgRow {
        id: row.try_get("id")?,
        handle: row.try_get("handle")?,
        display_name: row.try_get("display_name")?,
        description: row.try_get("description")?,
        base_permission: row.try_get("base_permission")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// Any owner row (user or org) by handle. `handle` must already be lowercase.
pub async fn owner_by_handle(db: &Db, handle: &str) -> DbResult<Option<OwnerRow>> {
    let row = sqlx::query("SELECT id, kind FROM owners WHERE handle = $1")
        .bind(handle)
        .fetch_optional(db.pool())
        .await?;
    row.map(|row| {
        Ok(OwnerRow {
            id: row.try_get("id")?,
            kind: row.try_get("kind")?,
        })
    })
    .transpose()
}

/// Inserts the owner row (`kind = 'org'`), the org row, and the creator's owner
/// membership in one transaction, returning the shared id.
pub async fn create(
    db: &Db,
    handle: &str,
    display_name: &str,
    description: &str,
    creator_id: i64,
) -> DbResult<i64> {
    let ts = now();
    let mut tx = db.pool().begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO owners (kind, handle, created_at) VALUES ('org', $1, $2) RETURNING id",
    )
    .bind(handle)
    .bind(ts)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO orgs (id, display_name, description, base_permission, created_at, updated_at) \
         VALUES ($1, $2, $3, 'none', $4, $5)",
    )
    .bind(id)
    .bind(display_name)
    .bind(description)
    .bind(ts)
    .bind(ts)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO org_members (org_id, user_id, role, created_at) VALUES ($1, $2, 'owner', $3)",
    )
    .bind(id)
    .bind(creator_id)
    .bind(ts)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// `handle` must already be lowercase.
pub async fn by_handle(db: &Db, handle: &str) -> DbResult<Option<OrgRow>> {
    let row = sqlx::query(
        "SELECT o.id, o.handle, g.display_name, g.description, g.base_permission, g.created_at, g.updated_at \
         FROM orgs g JOIN owners o ON o.id = g.id WHERE o.handle = $1",
    )
    .bind(handle)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(from_org).transpose()
}

pub async fn set(
    db: &Db,
    id: i64,
    display_name: &str,
    description: &str,
    base_permission: &str,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE orgs SET display_name = $1, description = $2, base_permission = $3, updated_at = $4 \
         WHERE id = $5",
    )
    .bind(display_name)
    .bind(description)
    .bind(base_permission)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Deletes the owner row; the org row, memberships, and teams cascade. Frees the handle.
pub async fn delete(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM owners WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// The base permission and the viewer's membership role for an org-owned
/// repository, in one query. `None` when `org_id` is not an org.
pub async fn grant_for_repo_owner(
    db: &Db,
    org_id: i64,
    user_id: i64,
) -> DbResult<Option<(String, Option<String>)>> {
    let row = sqlx::query(
        "SELECT g.base_permission, m.role FROM orgs g \
         LEFT JOIN org_members m ON m.org_id = g.id AND m.user_id = $2 WHERE g.id = $1",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(db.pool())
    .await?;
    row.map(|row| {
        Ok((
            row.try_get::<String, _>("base_permission")?,
            row.try_get::<Option<String>, _>("role")?,
        ))
    })
    .transpose()
}

/// The user's role in the org, if any.
pub async fn role(db: &Db, org_id: i64, user_id: i64) -> DbResult<Option<String>> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(db.pool())
            .await?
            .flatten();
    Ok(role)
}

pub async fn owner_count(db: &Db, org_id: i64) -> DbResult<i64> {
    let count: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner'")
            .bind(org_id)
            .fetch_optional(db.pool())
            .await?
            .flatten();
    Ok(count.unwrap_or(0))
}

pub async fn member_count(db: &Db, org_id: i64) -> DbResult<i64> {
    let count: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM org_members WHERE org_id = $1")
            .bind(org_id)
            .fetch_optional(db.pool())
            .await?
            .flatten();
    Ok(count.unwrap_or(0))
}

/// Memberships with handles, ordered by handle.
pub async fn list_members(db: &Db, org_id: i64) -> DbResult<Vec<MemberRow>> {
    let rows = sqlx::query(
        "SELECT m.user_id, o.handle, u.display_name, m.role FROM org_members m \
         JOIN users u ON u.id = m.user_id JOIN owners o ON o.id = m.user_id \
         WHERE m.org_id = $1 ORDER BY o.handle",
    )
    .bind(org_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(MemberRow {
                user_id: row.try_get("user_id")?,
                handle: row.try_get("handle")?,
                display_name: row.try_get("display_name")?,
                role: row.try_get("role")?,
            })
        })
        .collect()
}

pub async fn add_member(db: &Db, org_id: i64, user_id: i64, role: &str) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO org_members (org_id, user_id, role, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(role)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn set_role(db: &Db, org_id: i64, user_id: i64, role: &str) -> DbResult<()> {
    sqlx::query("UPDATE org_members SET role = $1 WHERE org_id = $2 AND user_id = $3")
        .bind(role)
        .bind(org_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn remove_member(db: &Db, org_id: i64, user_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}
