//! `repos`: repository metadata. Git data lives on disk under `<data_dir>/repos` (spec §5.3).

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRow {
    pub id: i64,
    pub owner_id: i64,
    pub owner_handle: String,
    pub name: String,
    pub description: String,
    pub visibility: String,
    pub default_branch: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct NewRepo<'a> {
    pub owner_id: i64,
    pub name: &'a str,
    pub description: &'a str,
    pub visibility: &'a str,
    pub default_branch: &'a str,
}

macro_rules! select_repo {
    ($tail:literal) => {
        concat!(
            "SELECT r.id, r.owner_id, o.handle AS owner_handle, r.name, r.description, r.visibility, ",
            "r.default_branch, r.created_at, r.updated_at FROM repos r JOIN owners o ON o.id = r.owner_id ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<RepoRow> {
    Ok(RepoRow {
        id: row.try_get("id")?,
        owner_id: row.try_get("owner_id")?,
        owner_handle: row.try_get("owner_handle")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        visibility: row.try_get("visibility")?,
        default_branch: row.try_get("default_branch")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub async fn insert(db: &Db, repo: &NewRepo<'_>) -> DbResult<i64> {
    let ts = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO repos (owner_id, name, lower_name, description, visibility, default_branch, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(repo.owner_id)
    .bind(repo.name)
    .bind(repo.name.to_ascii_lowercase())
    .bind(repo.description)
    .bind(repo.visibility)
    .bind(repo.default_branch)
    .bind(ts)
    .bind(ts)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

/// Case-insensitive lookup by owner handle and repository name.
pub async fn by_owner_and_name(
    db: &Db,
    owner_handle: &str,
    name: &str,
) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!("WHERE o.handle = $1 AND r.lower_name = $2"))
        .bind(owner_handle.to_ascii_lowercase())
        .bind(name.to_ascii_lowercase())
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!("WHERE r.id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn list_by_owner(db: &Db, owner_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!("WHERE r.owner_id = $1 ORDER BY r.lower_name"))
        .bind(owner_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(from_row).collect()
}

/// Repositories where `user_id` is a collaborator, by owner then name.
pub async fn list_collaborating(db: &Db, user_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "JOIN collaborators c ON c.repo_id = r.id WHERE c.user_id = $1 ORDER BY o.handle, r.lower_name"
    ))
    .bind(user_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

pub async fn delete(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM repos WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
