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
    pub archived_at: Option<i64>,
    pub deleted_at: Option<i64>,
    pub created_at: i64,
    pub mirror: i64,
    pub import_state: String,
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
            "r.default_branch, r.archived_at, r.deleted_at, r.mirror, r.import_state, r.created_at, r.updated_at FROM repos r JOIN owners o ON o.id = r.owner_id ",
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
        archived_at: row.try_get("archived_at")?,
        deleted_at: row.try_get("deleted_at")?,
        mirror: row.try_get("mirror")?,
        import_state: row.try_get("import_state")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// Inserts the repository. A redirect that held its name stops (forge-basics design §5.3).
pub async fn insert(db: &Db, repo: &NewRepo<'_>) -> DbResult<i64> {
    let mut tx = db.pool().begin().await?;
    let id = insert_in(&mut tx, repo).await?;
    tx.commit().await?;
    Ok(id)
}

/// Inserts a repository owned by an org behind the per-org lock, so a racing
/// org deletion cannot slip it into a namespace being removed. When the org
/// row is gone (a deletion committed first, or while blocked on the lock),
/// returns `None` instead of hitting the `owner_id` foreign key as a 500.
pub async fn insert_org_repo(db: &Db, org_id: i64, repo: &NewRepo<'_>) -> DbResult<Option<i64>> {
    let mut tx = db.pool().begin().await?;
    crate::orgs::lock_org(&mut tx, org_id).await?;
    let kept: Option<i64> = sqlx::query_scalar("SELECT id FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_optional(tx.as_mut())
        .await?;
    if kept.is_none() {
        return Ok(None);
    }
    let id = insert_in(&mut tx, repo).await?;
    tx.commit().await?;
    Ok(Some(id))
}

async fn insert_in(tx: &mut sqlx::Transaction<'_, sqlx::Any>, repo: &NewRepo<'_>) -> DbResult<i64> {
    let ts = now();
    let lower_name = repo.name.to_ascii_lowercase();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO repos (owner_id, name, lower_name, description, visibility, default_branch, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(repo.owner_id)
    .bind(repo.name)
    .bind(lower_name.as_str())
    .bind(repo.description)
    .bind(repo.visibility)
    .bind(repo.default_branch)
    .bind(ts)
    .bind(ts)
    .fetch_one(tx.as_mut())
    .await?;
    sqlx::query("DELETE FROM repo_redirects WHERE owner_id = $1 AND lower_name = $2")
        .bind(repo.owner_id)
        .bind(lower_name.as_str())
        .execute(tx.as_mut())
        .await?;
    Ok(id)
}

/// Case-insensitive lookup by owner handle and repository name, among repositories that are not deleted.
pub async fn by_owner_and_name(
    db: &Db,
    owner_handle: &str,
    name: &str,
) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!(
        "WHERE o.handle = $1 AND r.lower_name = $2 AND r.deleted_at IS NULL"
    ))
    .bind(owner_handle.to_ascii_lowercase())
    .bind(name.to_ascii_lowercase())
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(from_row).transpose()
}

/// Any repository with this id, deleted or not.
pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!("WHERE r.id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}
/// The repo's `.starforge/redact.toml` content (`''` when none is configured).
/// Read as a scalar so session ingest does not need the full row.
pub async fn redact_rules(db: &Db, id: i64) -> DbResult<String> {
    let rules: Option<String> = sqlx::query_scalar("SELECT redact_rules FROM repos WHERE id = $1")
        .bind(id)
        .fetch_optional(db.pool())
        .await?
        .flatten();
    Ok(rules.unwrap_or_default())
}

/// The owner's repositories that are not deleted, by name.
pub async fn list_by_owner(db: &Db, owner_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.owner_id = $1 AND r.deleted_at IS NULL ORDER BY r.lower_name"
    ))
    .bind(owner_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Repositories that are not deleted where `user_id` is a collaborator, by owner then name.
pub async fn list_collaborating(db: &Db, user_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "JOIN collaborators c ON c.repo_id = r.id WHERE c.user_id = $1 AND r.deleted_at IS NULL \
         ORDER BY o.handle, r.lower_name"
    ))
    .bind(user_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Live repositories where `user_id` is a member through an org: every
/// repository of an org the user owns or belongs to with a non-`none` base
/// permission, plus every repository covered by one of the user's teams
/// (an `all_repos` team covers the whole org, otherwise the link must name
/// the repository). (Owned and collaborator repositories come from
/// [`list_by_owner`] and [`list_collaborating`].)
pub async fn list_org_member_repos(db: &Db, user_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(
        "SELECT r.id, r.owner_id, o.handle AS owner_handle, r.name, r.description, r.visibility, \
         r.default_branch, r.archived_at, r.deleted_at, r.mirror, r.import_state, r.created_at, r.updated_at \
         FROM repos r JOIN owners o ON o.id = r.owner_id \
         JOIN orgs g ON g.id = r.owner_id JOIN org_members m ON m.org_id = g.id \
         WHERE m.user_id = $1 AND (m.role = 'owner' OR g.base_permission <> 'none') AND r.deleted_at IS NULL \
         UNION \
         SELECT r.id, r.owner_id, o.handle AS owner_handle, r.name, r.description, r.visibility, \
         r.default_branch, r.archived_at, r.deleted_at, r.mirror, r.import_state, r.created_at, r.updated_at \
         FROM repos r JOIN owners o ON o.id = r.owner_id \
         JOIN teams t ON t.org_id = r.owner_id JOIN team_members tm ON tm.team_id = t.id \
         LEFT JOIN team_repos tr ON tr.team_id = t.id AND tr.repo_id = r.id \
         WHERE tm.user_id = $1 AND (t.all_repos <> 0 OR tr.repo_id IS NOT NULL) AND r.deleted_at IS NULL \
         ORDER BY owner_handle, name",
    )
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

pub async fn set_description(db: &Db, id: i64, description: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET description = $1, updated_at = $2 WHERE id = $3")
        .bind(description)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_default_branch(db: &Db, id: i64, branch: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET default_branch = $1, updated_at = $2 WHERE id = $3")
        .bind(branch)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_visibility(db: &Db, id: i64, visibility: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET visibility = $1, updated_at = $2 WHERE id = $3")
        .bind(visibility)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Renames repository `id` in one transaction. The old name then redirects to it (unless only the case
/// changed), and a redirect that held the new name is dropped. A taken name is a unique violation and changes
/// nothing.
pub async fn rename(db: &Db, id: i64, new_name: &str) -> DbResult<()> {
    let ts = now();
    let new_lower = new_name.to_ascii_lowercase();
    let mut tx = db.pool().begin().await?;
    let (owner_id, old_lower): (i64, String) =
        sqlx::query_as("SELECT owner_id, lower_name FROM repos WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("UPDATE repos SET name = $1, lower_name = $2, updated_at = $3 WHERE id = $4")
        .bind(new_name)
        .bind(new_lower.as_str())
        .bind(ts)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM repo_redirects WHERE owner_id = $1 AND lower_name = $2")
        .bind(owner_id)
        .bind(new_lower.as_str())
        .execute(&mut *tx)
        .await?;
    if old_lower != new_lower {
        sqlx::query(
            "INSERT INTO repo_redirects (owner_id, lower_name, repo_id, created_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (owner_id, lower_name) DO UPDATE SET repo_id = excluded.repo_id, created_at = excluded.created_at",
        )
        .bind(owner_id)
        .bind(old_lower.as_str())
        .bind(id)
        .bind(ts)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The outcome of a repository transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOutcome {
    Done {
        old_owner_id: i64,
    },
    /// The new owner already has a live repository with this name.
    Clash,
    /// The repository is gone — or the new owner vanished mid-transaction.
    Gone,
}

/// Moves repository `id` to `new_owner_id` in one transaction: the repo row
/// and both org rows (in id order, a no-op for users) are locked first, so
/// racing transfers and org deletions serialize. The old `<owner>/<name>`
/// path is recorded in `repo_redirects` (reusing the rename redirect), a
/// redirect holding the new path stops, the old org's team links drop, and
/// collaborators are kept. A deleted name at the target stays a unique
/// violation for the caller to report.
pub async fn transfer(db: &Db, id: i64, new_owner_id: i64) -> DbResult<TransferOutcome> {
    let ts = now();
    let mut tx = db.pool().begin().await?;
    let held = sqlx::query("UPDATE repos SET updated_at = updated_at WHERE id = $1")
        .bind(id)
        .execute(tx.as_mut())
        .await?
        .rows_affected();
    if held == 0 {
        return Ok(TransferOutcome::Gone);
    }
    let (old_owner_id, lower_name): (i64, String) =
        sqlx::query_as("SELECT owner_id, lower_name FROM repos WHERE id = $1")
            .bind(id)
            .fetch_one(tx.as_mut())
            .await?;
    if old_owner_id == new_owner_id {
        return Ok(TransferOutcome::Done { old_owner_id });
    }
    for org_id in [
        old_owner_id.min(new_owner_id),
        old_owner_id.max(new_owner_id),
    ] {
        crate::orgs::lock_org(&mut tx, org_id).await?;
    }
    // A deletion that committed first (or while blocked on the lock) turns
    // the lock into a no-op: re-check the new owner instead of hitting the
    // `owner_id` foreign key as a 500.
    let kept: Option<i64> = sqlx::query_scalar("SELECT id FROM owners WHERE id = $1")
        .bind(new_owner_id)
        .fetch_optional(tx.as_mut())
        .await?;
    if kept.is_none() {
        return Ok(TransferOutcome::Gone);
    }
    let clash: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM repos WHERE owner_id = $1 AND lower_name = $2 AND deleted_at IS NULL AND id <> $3",
    )
    .bind(new_owner_id)
    .bind(lower_name.as_str())
    .bind(id)
    .fetch_optional(tx.as_mut())
    .await?;
    if clash.is_some() {
        return Ok(TransferOutcome::Clash);
    }
    sqlx::query("UPDATE repos SET owner_id = $1, updated_at = $2 WHERE id = $3")
        .bind(new_owner_id)
        .bind(ts)
        .bind(id)
        .execute(tx.as_mut())
        .await?;
    sqlx::query("DELETE FROM repo_redirects WHERE owner_id = $1 AND lower_name = $2")
        .bind(new_owner_id)
        .bind(lower_name.as_str())
        .execute(tx.as_mut())
        .await?;
    sqlx::query(
        "INSERT INTO repo_redirects (owner_id, lower_name, repo_id, created_at) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (owner_id, lower_name) DO UPDATE SET repo_id = excluded.repo_id, created_at = excluded.created_at",
    )
    .bind(old_owner_id)
    .bind(lower_name.as_str())
    .bind(id)
    .bind(ts)
    .execute(tx.as_mut())
    .await?;
    sqlx::query(
        "DELETE FROM team_repos WHERE repo_id = $1 AND team_id IN (SELECT id FROM teams WHERE org_id = $2)",
    )
    .bind(id)
    .bind(old_owner_id)
    .execute(tx.as_mut())
    .await?;
    tx.commit().await?;
    Ok(TransferOutcome::Done { old_owner_id })
}

/// Archives the repository (`Some(time)`) or lifts the archive (`None`).
pub async fn set_archived(db: &Db, id: i64, archived_at: Option<i64>) -> DbResult<()> {
    sqlx::query("UPDATE repos SET archived_at = $1, updated_at = $2 WHERE id = $3")
        .bind(archived_at)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// The owner's deleted repositories, the most recently deleted first.
pub async fn list_deleted_by_owner(db: &Db, owner_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.owner_id = $1 AND r.deleted_at IS NOT NULL ORDER BY r.deleted_at DESC"
    ))
    .bind(owner_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Every soft-deleted repository, the most recently deleted first, at most `limit`.
pub async fn list_all_deleted(db: &Db, limit: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.deleted_at IS NOT NULL ORDER BY r.deleted_at DESC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}
/// Every live repository of every owner, ordered by owner then name, at most `limit`.
pub async fn list_all_live(db: &Db, limit: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.deleted_at IS NULL ORDER BY o.handle, r.lower_name LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Live plus deleted repositories, for the admin overview.
pub async fn count_all(db: &Db) -> DbResult<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM repos")
        .fetch_one(db.pool())
        .await?)
}

/// Repositories deleted at or before `cutoff`, the oldest deletion first.
pub async fn deleted_before(db: &Db, cutoff: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.deleted_at IS NOT NULL AND r.deleted_at <= $1 ORDER BY r.deleted_at"
    ))
    .bind(cutoff)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Deletes the repository softly (`Some(time)`) or restores it (`None`).
pub async fn set_deleted(db: &Db, id: i64, deleted_at: Option<i64>) -> DbResult<()> {
    sqlx::query("UPDATE repos SET deleted_at = $1, updated_at = $2 WHERE id = $3")
        .bind(deleted_at)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Whether a deleted repository of `owner_id` holds `name` (case-insensitive).
pub async fn deleted_name_exists(db: &Db, owner_id: i64, name: &str) -> DbResult<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM repos WHERE owner_id = $1 AND lower_name = $2 AND deleted_at IS NOT NULL",
    )
    .bind(owner_id)
    .bind(name.to_ascii_lowercase())
    .fetch_one(db.pool())
    .await?;
    Ok(count > 0)
}

/// Who may use `refs/for` pushes on the repository: `'anyone_with_read'`
/// (the default on insert) or `'members'`. The allowed set is enforced by a
/// `CHECK` on the column (added by migration 0012 on both engines); anything
/// outside it fails here as a database error.
pub async fn refs_for_access(db: &Db, id: i64) -> DbResult<String> {
    let value: Option<String> =
        sqlx::query_scalar("SELECT refs_for_access FROM repos WHERE id = $1")
            .bind(id)
            .fetch_optional(db.pool())
            .await?
            .flatten();
    Ok(value.unwrap_or_else(|| "anyone_with_read".to_owned()))
}

pub async fn set_refs_for_access(db: &Db, id: i64, value: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET refs_for_access = $1 WHERE id = $2")
        .bind(value)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// The one-time import state (`none|pending|running|done|failed`) of the
/// repository, for the hook's push-refusal snapshot (M4b D3).
pub async fn import_state(db: &Db, id: i64) -> DbResult<String> {
    let value: Option<String> = sqlx::query_scalar("SELECT import_state FROM repos WHERE id = $1")
        .bind(id)
        .fetch_optional(db.pool())
        .await?
        .flatten();
    Ok(value.unwrap_or_else(|| "none".to_owned()))
}

/// Sets the one-time import state (M4b D3); the `CHECK` constraint refuses
/// anything outside the enum.
pub async fn set_import_state(db: &Db, id: i64, state: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET import_state = $1 WHERE id = $2")
        .bind(state)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Whether the repository is a pull mirror (M4b D4; I3 owns writing it).
pub async fn set_mirror(db: &Db, id: i64, mirror: bool) -> DbResult<()> {
    sqlx::query("UPDATE repos SET mirror = $1 WHERE id = $2")
        .bind(i64::from(mirror))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    fn user(handle: &str) -> NewUser<'_> {
        NewUser {
            handle,
            display_name: "",
            email: None,
            email_verified: false,
            password_hash: None,
            is_admin: false,
        }
    }

    fn repo(owner_id: i64, name: &str) -> NewRepo<'_> {
        NewRepo {
            owner_id,
            name,
            description: "",
            visibility: "public",
            default_branch: "main",
        }
    }

    #[tokio::test]
    async fn all_deleted_lists_every_owner() {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("alice")).await.unwrap();
        let bob = users::insert(&t.db, &user("bob")).await.unwrap();
        insert(&t.db, &repo(alice, "live")).await.unwrap();
        let alice_deleted = insert(&t.db, &repo(alice, "gone")).await.unwrap();
        let bob_deleted = insert(&t.db, &repo(bob, "vanished")).await.unwrap();
        let base = now();
        set_deleted(&t.db, alice_deleted, Some(base - 10))
            .await
            .unwrap();
        set_deleted(&t.db, bob_deleted, Some(base)).await.unwrap();
        let all = list_all_deleted(&t.db, 200).await.unwrap();
        assert_eq!(
            all.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![bob_deleted, alice_deleted],
            "every owner's deleted repos, most recently deleted first"
        );
        assert_eq!(all[0].owner_handle, "bob");
        assert_eq!(all[0].name, "vanished");
        assert_eq!(all[1].owner_handle, "alice");
        assert_eq!(all[1].name, "gone");
        assert_eq!(
            count_all(&t.db).await.unwrap(),
            3,
            "count_all counts live plus deleted"
        );
    }
}
