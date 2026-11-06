//! `orgs` + `org_members`: organizations and their membership (spec §6.1, D1-D3).
//! Teams, team membership, and team repository links live here too.

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

/// The handle of any owner row (user or org) by id.
pub async fn owner_handle_by_id(db: &Db, id: i64) -> DbResult<Option<String>> {
    let handle: Option<String> = sqlx::query_scalar("SELECT handle FROM owners WHERE id = $1")
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    Ok(handle)
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

/// Deletes the org only when it owns no live repositories and no deleted
/// ones newer than `deleted_cutoff` (the grace window): the count check and
/// the delete run in one transaction behind the per-org lock, so a racing
/// repository creation or transfer cannot slip a repository in between.
/// Returns the blocking repository count; nonzero rolls back and deletes
/// nothing.
pub async fn delete_serialized(db: &Db, org_id: i64, deleted_cutoff: i64) -> DbResult<i64> {
    let mut tx = db.pool().begin().await?;
    lock_org(&mut tx, org_id).await?;
    let live: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM repos WHERE owner_id = $1 AND deleted_at IS NULL")
            .bind(org_id)
            .fetch_one(tx.as_mut())
            .await?;
    let grace: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM repos WHERE owner_id = $1 AND deleted_at IS NOT NULL AND deleted_at > $2",
    )
    .bind(org_id)
    .bind(deleted_cutoff)
    .fetch_one(tx.as_mut())
    .await?;
    if live + grace > 0 {
        return Ok(live + grace);
    }
    sqlx::query("DELETE FROM owners WHERE id = $1")
        .bind(org_id)
        .execute(tx.as_mut())
        .await?;
    tx.commit().await?;
    Ok(0)
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

pub async fn set_role(db: &Db, org_id: i64, user_id: i64, role: &str) -> DbResult<bool> {
    let result = sqlx::query("UPDATE org_members SET role = $1 WHERE org_id = $2 AND user_id = $3")
        .bind(role)
        .bind(org_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Takes the per-org serialization lock. Must be the first statement of an
/// owner-changing transaction: it is the row lock on Postgres and the write
/// lock on SQLite. Conditional single statements are NOT enough — under
/// READ COMMITTED two of them can each count 2 owners and change different
/// rows (write skew), orphaning the org.
pub(crate) async fn lock_org(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: i64,
) -> DbResult<()> {
    sqlx::query("UPDATE orgs SET updated_at = updated_at WHERE id = $1")
        .bind(org_id)
        .execute(tx.as_mut())
        .await?;
    Ok(())
}

async fn role_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: i64,
    user_id: i64,
) -> DbResult<Option<String>> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(tx.as_mut())
            .await?;
    Ok(role)
}

async fn owner_count_in(tx: &mut sqlx::Transaction<'_, sqlx::Any>, org_id: i64) -> DbResult<i64> {
    let count: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner'")
            .bind(org_id)
            .fetch_optional(tx.as_mut())
            .await?
            .flatten();
    Ok(count.unwrap_or(0))
}

/// The outcome of a serialized owner change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerChange {
    /// The change committed.
    Done,
    /// Refused: the target is an owner and the last one.
    LastOwner,
    /// The target membership is gone.
    Gone,
    /// The actor may not do this (lost or never had owner rights).
    Forbidden,
    /// Already in the target state; nothing to do and nothing to audit.
    NoChange,
}

/// Demotes an owner to member, serialized per org: locks the org row, then
/// re-checks the actor, the target, and the owner count inside one
/// transaction. The last owner cannot be demoted.
pub async fn demote_owner_serialized(
    db: &Db,
    org_id: i64,
    actor_id: i64,
    user_id: i64,
) -> DbResult<OwnerChange> {
    let mut tx = db.pool().begin().await?;
    lock_org(&mut tx, org_id).await?;
    if role_in(&mut tx, org_id, actor_id).await?.as_deref() != Some("owner") {
        return Ok(OwnerChange::Forbidden);
    }
    match role_in(&mut tx, org_id, user_id).await?.as_deref() {
        None => Ok(OwnerChange::Gone),
        Some("member") => Ok(OwnerChange::NoChange),
        Some(_) => {
            if owner_count_in(&mut tx, org_id).await? <= 1 {
                return Ok(OwnerChange::LastOwner);
            }
            sqlx::query(
                "UPDATE org_members SET role = 'member' WHERE org_id = $1 AND user_id = $2",
            )
            .bind(org_id)
            .bind(user_id)
            .execute(tx.as_mut())
            .await?;
            tx.commit().await?;
            Ok(OwnerChange::Done)
        }
    }
}

/// Removes a membership, serialized per org like [`demote_owner_serialized`].
/// Owners go only while another owner remains; the member leaves the org's
/// teams in the same transaction. Owners may remove anyone, a member may
/// leave, and strangers learn nothing beyond `Gone`.
pub async fn remove_member_serialized(
    db: &Db,
    org_id: i64,
    actor_id: i64,
    user_id: i64,
) -> DbResult<OwnerChange> {
    let mut tx = db.pool().begin().await?;
    lock_org(&mut tx, org_id).await?;
    let actor_role = role_in(&mut tx, org_id, actor_id).await?;
    if actor_id != user_id && actor_role.as_deref() != Some("owner") {
        return Ok(if actor_role.is_none() {
            OwnerChange::Gone
        } else {
            OwnerChange::Forbidden
        });
    }
    match role_in(&mut tx, org_id, user_id).await?.as_deref() {
        None => Ok(OwnerChange::Gone),
        Some("owner") => {
            if owner_count_in(&mut tx, org_id).await? <= 1 {
                return Ok(OwnerChange::LastOwner);
            }
            delete_member_in(&mut tx, org_id, user_id).await?;
            tx.commit().await?;
            Ok(OwnerChange::Done)
        }
        Some(_) => {
            delete_member_in(&mut tx, org_id, user_id).await?;
            tx.commit().await?;
            Ok(OwnerChange::Done)
        }
    }
}

/// Deletes the membership and the org-team memberships in one transaction.
async fn delete_member_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: i64,
    user_id: i64,
) -> DbResult<()> {
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .execute(tx.as_mut())
        .await?;
    sqlx::query(
        "DELETE FROM team_members WHERE user_id = $1 \
         AND team_id IN (SELECT id FROM teams WHERE org_id = $2)",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(tx.as_mut())
    .await?;
    Ok(())
}

// --- Teams (A2, D3). ---------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamRow {
    pub id: i64,
    pub org_id: i64,
    pub name: String,
    pub lower_name: String,
    pub description: String,
    pub permission: String,
    pub all_repos: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamMemberRow {
    pub user_id: i64,
    pub handle: String,
    pub display_name: String,
}

fn from_team(row: &AnyRow) -> DbResult<TeamRow> {
    Ok(TeamRow {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        name: row.try_get("name")?,
        lower_name: row.try_get("lower_name")?,
        description: row.try_get("description")?,
        permission: row.try_get("permission")?,
        all_repos: row.try_get::<i64, _>("all_repos")? != 0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// The outcome of a serialized team creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamCreate {
    Created(i64),
    Clash,
}

/// Creates the team behind the per-org lock: the clash check (lower name or
/// slug, so `a-b` and `a b` cannot share one URL) and the insert run in one
/// transaction, since the UNIQUE constraint covers only `lower_name`.
pub async fn create_team(
    db: &Db,
    org_id: i64,
    name: &str,
    lower_name: &str,
    description: &str,
    permission: &str,
    all_repos: bool,
) -> DbResult<TeamCreate> {
    let mut tx = db.pool().begin().await?;
    lock_org(&mut tx, org_id).await?;
    if clash_in(&mut tx, org_id, None, lower_name).await?.is_some() {
        return Ok(TeamCreate::Clash);
    }
    let ts = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO teams (org_id, name, lower_name, description, permission, all_repos, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(org_id)
    .bind(name)
    .bind(lower_name)
    .bind(description)
    .bind(permission)
    .bind(i64::from(all_repos))
    .bind(ts)
    .bind(ts)
    .fetch_one(tx.as_mut())
    .await?;
    tx.commit().await?;
    Ok(TeamCreate::Created(id))
}

/// The id of a team whose lower name or slug collides with `lower_name`,
/// ignoring `ignore_id` (a rename keeps its own name). `None` when free.
async fn clash_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: i64,
    ignore_id: Option<i64>,
    lower_name: &str,
) -> DbResult<Option<i64>> {
    let slug = lower_name.replace(' ', "-");
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM teams WHERE org_id = $1 AND (id <> $2 OR $2 IS NULL) \
         AND (lower_name = $3 OR REPLACE(lower_name, ' ', '-') = $4) ORDER BY id LIMIT 1",
    )
    .bind(org_id)
    .bind(ignore_id)
    .bind(lower_name)
    .bind(slug.as_str())
    .fetch_optional(tx.as_mut())
    .await?;
    Ok(id)
}

/// The team's URL slug is its lower name with spaces as `-` (D3); matching
/// happens in SQL so callers never reimplement it.
pub async fn team_by_slug(db: &Db, org_id: i64, slug: &str) -> DbResult<Option<TeamRow>> {
    let row = sqlx::query(
        "SELECT id, org_id, name, lower_name, description, permission, all_repos, created_at, updated_at \
         FROM teams WHERE org_id = $1 AND REPLACE(lower_name, ' ', '-') = $2 ORDER BY id LIMIT 1",
    )
    .bind(org_id)
    .bind(slug)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(from_team).transpose()
}

/// One team by id, if it still exists.
pub async fn team_by_id(db: &Db, id: i64) -> DbResult<Option<TeamRow>> {
    let row = sqlx::query(
        "SELECT id, org_id, name, lower_name, description, permission, all_repos, created_at, updated_at \
         FROM teams WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(from_team).transpose()
}

pub async fn list_teams(db: &Db, org_id: i64) -> DbResult<Vec<TeamRow>> {
    let rows = sqlx::query(
        "SELECT id, org_id, name, lower_name, description, permission, all_repos, created_at, updated_at \
         FROM teams WHERE org_id = $1 ORDER BY lower_name",
    )
    .bind(org_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_team).collect()
}

/// The mutable team fields for [`set_team`].
pub struct TeamFields<'a> {
    pub name: &'a str,
    pub lower_name: &'a str,
    pub description: &'a str,
    pub permission: &'a str,
    pub all_repos: bool,
}

/// The outcome of a serialized team update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamUpdate {
    Done,
    Clash,
    Gone,
}

/// Renames (slugs follow), re-describes, re-permissions, or flips
/// `all_repos` behind the per-org lock: the clash check and the update run
/// in one transaction, so racing conflicting renames cannot both commit.
pub async fn set_team(
    db: &Db,
    org_id: i64,
    id: i64,
    fields: &TeamFields<'_>,
) -> DbResult<TeamUpdate> {
    let mut tx = db.pool().begin().await?;
    lock_org(&mut tx, org_id).await?;
    let kept: Option<i64> =
        sqlx::query_scalar("SELECT id FROM teams WHERE id = $1 AND org_id = $2")
            .bind(id)
            .bind(org_id)
            .fetch_optional(tx.as_mut())
            .await?;
    if kept.is_none() {
        return Ok(TeamUpdate::Gone);
    }
    if clash_in(&mut tx, org_id, Some(id), fields.lower_name)
        .await?
        .is_some()
    {
        return Ok(TeamUpdate::Clash);
    }
    sqlx::query(
        "UPDATE teams SET name = $1, lower_name = $2, description = $3, permission = $4, all_repos = $5, \
         updated_at = $6 WHERE id = $7",
    )
    .bind(fields.name)
    .bind(fields.lower_name)
    .bind(fields.description)
    .bind(fields.permission)
    .bind(i64::from(fields.all_repos))
    .bind(now())
    .bind(id)
    .execute(tx.as_mut())
    .await?;
    tx.commit().await?;
    Ok(TeamUpdate::Done)
}

/// Deletes the team; memberships and repo links cascade.
pub async fn delete_team(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM teams WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Adds the member, or does nothing when already present (for idempotent
/// retries). Returns whether the row was inserted.
pub async fn team_member_add(db: &Db, team_id: i64, user_id: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "INSERT INTO team_members (team_id, user_id, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT (team_id, user_id) DO NOTHING",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn team_member_remove(db: &Db, team_id: i64, user_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Memberships with handles, ordered by handle.
pub async fn list_team_members(db: &Db, team_id: i64) -> DbResult<Vec<TeamMemberRow>> {
    let rows = sqlx::query(
        "SELECT m.user_id, o.handle, u.display_name FROM team_members m \
         JOIN users u ON u.id = m.user_id JOIN owners o ON o.id = m.user_id \
         WHERE m.team_id = $1 ORDER BY o.handle",
    )
    .bind(team_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(TeamMemberRow {
                user_id: row.try_get("user_id")?,
                handle: row.try_get("handle")?,
                display_name: row.try_get("display_name")?,
            })
        })
        .collect()
}

/// Links the repository, or does nothing when already linked. Returns whether
/// the row was inserted.
pub async fn team_repo_add(db: &Db, team_id: i64, repo_id: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "INSERT INTO team_repos (team_id, repo_id, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT (team_id, repo_id) DO NOTHING",
    )
    .bind(team_id)
    .bind(repo_id)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn team_repo_remove(db: &Db, team_id: i64, repo_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM team_repos WHERE team_id = $1 AND repo_id = $2")
        .bind(team_id)
        .bind(repo_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// The team's repository ids, ordered by repository name.
pub async fn list_team_repo_ids(db: &Db, team_id: i64) -> DbResult<Vec<i64>> {
    let rows: Vec<i64> = sqlx::query_scalar(
        "SELECT r.id FROM team_repos t JOIN repos r ON r.id = t.repo_id \
         WHERE t.team_id = $1 ORDER BY r.lower_name",
    )
    .bind(team_id)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Every team permission covering `(org, user, repo)` in one query (D4): the
/// user is a team member and the team grants all repos or names this one.
pub async fn covering_team_grants(
    db: &Db,
    org_id: i64,
    user_id: i64,
    repo_id: i64,
) -> DbResult<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT t.permission FROM teams t JOIN team_members m ON m.team_id = t.id AND m.user_id = $2 \
         WHERE t.org_id = $1 AND (t.all_repos = 1 \
         OR EXISTS (SELECT 1 FROM team_repos r WHERE r.team_id = t.id AND r.repo_id = $3))",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(repo_id)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// Whether a live repository with this lower name exists outside the org (to
/// tell "another owner's repo" 422 apart from "no such repo" 404).
pub async fn repo_name_taken_by_other(db: &Db, org_id: i64, lower_name: &str) -> DbResult<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM repos WHERE lower_name = $1 AND owner_id <> $2 AND deleted_at IS NULL",
    )
    .bind(lower_name)
    .bind(org_id)
    .fetch_one(db.pool())
    .await?;
    Ok(count > 0)
}

/// Handles of orgs where `user_id` is an owner, ordered by handle: the
/// new-repository owner selector.
pub async fn owned_by(db: &Db, user_id: i64) -> DbResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT o.handle FROM org_members m JOIN owners o ON o.id = m.org_id \
         WHERE m.user_id = $1 AND m.role = 'owner' ORDER BY o.handle",
    )
    .bind(user_id)
    .fetch_all(db.pool())
    .await?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgSummaryRow {
    pub handle: String,
    pub display_name: String,
    pub member_count: i64,
    pub repo_count: i64,
}

/// Every org with its member and live-repository counts, ordered by handle,
/// for the site-admin org list.
pub async fn summaries(db: &Db) -> DbResult<Vec<OrgSummaryRow>> {
    let rows = sqlx::query(
        "SELECT o.handle, g.display_name, \
         (SELECT COUNT(*) FROM org_members m WHERE m.org_id = o.id) AS member_count, \
         (SELECT COUNT(*) FROM repos r WHERE r.owner_id = o.id AND r.deleted_at IS NULL) AS repo_count \
         FROM orgs g JOIN owners o ON o.id = g.id ORDER BY o.handle",
    )
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(OrgSummaryRow {
                handle: row.try_get("handle")?,
                display_name: row.try_get("display_name")?,
                member_count: row.try_get("member_count")?,
                repo_count: row.try_get("repo_count")?,
            })
        })
        .collect()
}
