//! Branch-protection push allow-lists (spec §8.2, M3b B1): who may push
//! directly to a protected branch despite a rule's `block_direct_push`.
//!
//! The data-access layer stays thin — validation (users exist, teams belong
//! to the owning org of an org-owned repository) lives in
//! `starforged-core`. Rows carry exactly one of `user_id`/`team_id` (the
//! table CHECK enforces it); deleting a rule cascades, deleting a user or
//! team drops its entries.

use sqlx::Row;

use crate::{Db, DbResult};

/// One allow-list entry of a gate rule: exactly one of `user_id`/`team_id`
/// is `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushAllowlistRow {
    pub rule_id: i64,
    pub user_id: Option<i64>,
    pub team_id: Option<i64>,
}

/// The rule's entries in insert order.
pub async fn push_allowlist_for_rule(db: &Db, rule_id: i64) -> DbResult<Vec<PushAllowlistRow>> {
    let rows = sqlx::query(
        "SELECT rule_id, user_id, team_id FROM gate_rule_push_allowlist \
         WHERE rule_id = $1 ORDER BY id ASC",
    )
    .bind(rule_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(PushAllowlistRow {
                rule_id: row.try_get("rule_id")?,
                user_id: row.try_get("user_id")?,
                team_id: row.try_get("team_id")?,
            })
        })
        .collect()
}

/// Replaces the rule's entries with `entries` (`(user_id, team_id)` pairs,
///
/// The delete and the inserts run in one transaction, so a concurrent
/// reader never sees a half-replaced list.
pub async fn replace_push_allowlist(
    db: &Db,
    rule_id: i64,
    entries: &[(Option<i64>, Option<i64>)],
    now: i64,
) -> DbResult<()> {
    let mut tx = db.pool().begin().await?;
    sqlx::query("DELETE FROM gate_rule_push_allowlist WHERE rule_id = $1")
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;
    for (user_id, team_id) in entries {
        sqlx::query(
            "INSERT INTO gate_rule_push_allowlist (rule_id, user_id, team_id, created_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(rule_id)
        .bind(*user_id)
        .bind(*team_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// True when `user_id` belongs to `team_id`.
pub async fn is_team_member(db: &Db, team_id: i64, user_id: i64) -> DbResult<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team_id)
            .bind(user_id)
            .fetch_one(db.read_pool())
            .await?;
    Ok(count > 0)
}

/// One tag-protection row: a glob; any tag it matches needs `maintain` or
/// above to create, move, or delete (spec §8.2, M3b D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagProtectionRow {
    pub id: i64,
    pub repo_id: i64,
    pub pattern: String,
    pub created_at: i64,
}

fn tag_protection_from_row(row: &sqlx::any::AnyRow) -> DbResult<TagProtectionRow> {
    Ok(TagProtectionRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        pattern: row.try_get("pattern")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Tag protections of the repo in insert order.
pub async fn tag_protections_for_repo(db: &Db, repo_id: i64) -> DbResult<Vec<TagProtectionRow>> {
    let rows = sqlx::query(
        "SELECT id, repo_id, pattern, created_at FROM tag_protections \
         WHERE repo_id = $1 ORDER BY id ASC",
    )
    .bind(repo_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(tag_protection_from_row).collect()
}

/// One tag protection by id, scoped to the repo (`None` for a missing id or
/// another repo's id).
pub async fn tag_protection_by_id(
    db: &Db,
    id: i64,
    repo_id: i64,
) -> DbResult<Option<TagProtectionRow>> {
    let row = sqlx::query(
        "SELECT id, repo_id, pattern, created_at FROM tag_protections \
         WHERE id = $1 AND repo_id = $2",
    )
    .bind(id)
    .bind(repo_id)
    .fetch_optional(db.read_pool())
    .await?;
    row.map(|row| tag_protection_from_row(&row)).transpose()
}

/// Inserts a tag-protection row; a duplicate `(repo_id, pattern)` violates
/// the unique index (callers in `starforged-core` pre-check and report
/// `Conflict`).
pub async fn insert_tag_protection(
    db: &Db,
    repo_id: i64,
    pattern: &str,
    now: i64,
) -> DbResult<TagProtectionRow> {
    let row = sqlx::query(
        "INSERT INTO tag_protections (repo_id, pattern, created_at) \
         VALUES ($1, $2, $3) RETURNING id, repo_id, pattern, created_at",
    )
    .bind(repo_id)
    .bind(pattern)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    tag_protection_from_row(&row)
}

/// Deletes the tag protection `id` scoped to the repo.
pub async fn delete_tag_protection(db: &Db, id: i64, repo_id: i64) -> DbResult<bool> {
    let done = sqlx::query("DELETE FROM tag_protections WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .execute(db.pool())
        .await?;
    Ok(done.rows_affected() > 0)
}
