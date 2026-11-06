//! `trails`: issue-like discussion objects scoped to a repository.
//!
//! Numbering is per repository (`UNIQUE (repo_id, number)`): `insert_trail`
//! allocates the next number from `trail_sequences` inside the same transaction
//! that inserts the row, so concurrent creates never collide and a rolled-back
//! insert returns its number. The data-access layer stays
//! thin — no validation or permission checks here (those live in `starforged-core`).
//! `merged` is admitted by the state `CHECK` but never written in M2a; the merge
//! path owns it.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailRow {
    pub id: i64,
    pub repo_id: i64,
    pub number: i64,
    pub title: String,
    pub intent: String,
    pub state: String,
    pub ready: i64,
    pub author_id: Option<i64>,
    /// The original GitHub login when the author matched no local user (D1);
    /// `author_id` is then NULL. `github_id` is the GitHub issue/PR id.
    pub imported_author: Option<String>,
    pub github_id: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub closed_at: Option<i64>,
    pub merged_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailLabelRow {
    pub trail_id: i64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailAssigneeRow {
    pub trail_id: i64,
    pub user_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailCommentRow {
    pub id: i64,
    pub trail_id: i64,
    pub author_id: Option<i64>,
    /// The original GitHub login when the author matched no local user (D1);
    /// `author_id` is then NULL. `github_id` is the GitHub comment id.
    pub imported_author: Option<String>,
    pub github_id: Option<i64>,
    pub body: String,
    pub created_at: i64,
    pub edited_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEventRow {
    pub id: i64,
    pub repo_id: i64,
    pub trail_id: Option<i64>,
    pub kind: String,
    pub actor_id: Option<i64>,
    pub payload: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewTrail<'a> {
    pub repo_id: i64,
    pub title: &'a str,
    pub intent: &'a str,
    pub author_id: i64,
}

#[derive(Debug, Clone)]
pub struct TrailFilter {
    pub state: Option<String>,
    pub label: Option<String>,
    pub assignee_id: Option<i64>,
    pub author_id: Option<i64>,
    /// `Some(true)` matches Trails with at least one change in any state;
    /// `Some(false)` matches Trails with none.
    pub has_changes: Option<bool>,
    /// `Some(true)` keeps Trails with at least one session the viewer may
    /// read (§6.4, through commits or explicit links); `Some(false)` keeps
    /// the rest. The viewer facts travel alongside for the SQL predicate.
    pub has_sessions: Option<bool>,
    pub session_facts: SessionViewerFacts,
    /// Matches Trails with a pending review request for this user.
    pub review_requested_id: Option<i64>,
    pub after: Option<i64>,
    pub limit: i64,
}

/// Bound facts about the viewer for the `has_sessions` SQL predicate (the
/// same three rules as `core::read::can_read_session`): zeros and `false`
/// for anonymous viewers on non-public repos. Defaults to that anonymous
/// shape; only used when `has_sessions` is `Some`.
#[derive(Debug, Clone, Default)]
pub struct SessionViewerFacts {
    /// 0 when anonymous (user ids start at 1).
    pub viewer_id: i64,
    pub signed_in: bool,
    pub site_admin: bool,
    /// Explicit grant only (ownership or collaborator row).
    pub member: bool,
    /// Effective repo permission is Admin or higher (owners count).
    pub repo_admin: bool,
    pub repo_public: bool,
    pub repo_internal: bool,
}

impl Default for TrailFilter {
    fn default() -> Self {
        TrailFilter {
            state: None,
            label: None,
            assignee_id: None,
            author_id: None,
            has_changes: None,
            has_sessions: None,
            session_facts: SessionViewerFacts::default(),
            review_requested_id: None,
            after: None,
            limit: 30,
        }
    }
}

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult};

macro_rules! select_trail {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, number, title, intent, state, ready, author_id, imported_author, github_id, created_at, updated_at, closed_at, ",
            "merged_at FROM trails ",
            $tail
        )
    };
}

macro_rules! select_comment {
    ($tail:literal) => {
        concat!(
            "SELECT id, trail_id, author_id, imported_author, github_id, body, created_at, edited_at FROM trail_comments ",
            $tail
        )
    };
}

macro_rules! select_timeline {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, trail_id, kind, actor_id, payload, created_at FROM timeline_events ",
            $tail
        )
    };
}

fn trail_from_row(row: &AnyRow) -> DbResult<TrailRow> {
    Ok(TrailRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        number: row.try_get("number")?,
        title: row.try_get("title")?,
        intent: row.try_get("intent")?,
        state: row.try_get("state")?,
        ready: row.try_get("ready")?,
        author_id: row.try_get("author_id")?,
        imported_author: row.try_get("imported_author")?,
        github_id: row.try_get("github_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        closed_at: row.try_get("closed_at")?,
        merged_at: row.try_get("merged_at")?,
    })
}

fn comment_from_row(row: &AnyRow) -> DbResult<TrailCommentRow> {
    Ok(TrailCommentRow {
        id: row.try_get("id")?,
        trail_id: row.try_get("trail_id")?,
        author_id: row.try_get("author_id")?,
        imported_author: row.try_get("imported_author")?,
        github_id: row.try_get("github_id")?,
        body: row.try_get("body")?,
        created_at: row.try_get("created_at")?,
        edited_at: row.try_get("edited_at")?,
    })
}

fn timeline_from_row(row: &AnyRow) -> DbResult<TimelineEventRow> {
    Ok(TimelineEventRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        trail_id: row.try_get("trail_id")?,
        kind: row.try_get("kind")?,
        actor_id: row.try_get("actor_id")?,
        payload: row.try_get("payload")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Inserts the trail, allocating the next per-repo number from `trail_sequences`
/// inside the same transaction that inserts the row: the upsert takes the sequence
/// row lock, so concurrent creates serialize and never collide; rolling back
/// returns the allocated number. A `UNIQUE (repo_id, number)` violation is still
/// possible if rows were inserted behind the sequence's back — callers map it to
/// `Conflict` as a defensive fallback and never retry it in a loop.
pub async fn insert_trail(db: &Db, t: &NewTrail<'_>, now: i64) -> DbResult<TrailRow> {
    let mut tx = db.pool().begin().await?;
    let number: i64 = sqlx::query_scalar(
        "INSERT INTO trail_sequences (repo_id, next_number) VALUES ($1, 2) \
         ON CONFLICT (repo_id) DO UPDATE SET next_number = trail_sequences.next_number + 1 \
         RETURNING next_number - 1",
    )
    .bind(t.repo_id)
    .fetch_one(&mut *tx)
    .await?;
    let row = sqlx::query(
        "INSERT INTO trails (repo_id, number, title, intent, state, ready, author_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'open', 0, $5, $6, $6) \
         RETURNING id, repo_id, number, title, intent, state, ready, author_id, imported_author, github_id, created_at, updated_at, closed_at, merged_at",
    )
    .bind(t.repo_id)
    .bind(number)
    .bind(t.title)
    .bind(t.intent)
    .bind(t.author_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let trail = trail_from_row(&row)?;
    tx.commit().await?;
    Ok(trail)
}
/// Inserts a Trail with an explicit GitHub number (M4c D2), instead of
/// allocating one: `number` is the GitHub issue/PR number and
/// `trail_sequences` is advanced past it in the same transaction, so the
/// next locally created Trail continues after the highest imported number.
/// `author_id` is `None` exactly when `imported_author` carries the GitHub
/// login (D1). Re-importing the same `github_id` fails on the unique index;
/// callers check [`trail_by_github_id`] first so a resume never duplicates.
#[allow(clippy::too_many_arguments)]
pub async fn insert_imported_trail(
    db: &Db,
    repo_id: i64,
    number: i64,
    title: &str,
    intent: &str,
    state: &str,
    author_id: Option<i64>,
    imported_author: Option<&str>,
    github_id: i64,
    now: i64,
) -> DbResult<TrailRow> {
    let mut tx = db.pool().begin().await?;
    sqlx::query(
        "INSERT INTO trail_sequences (repo_id, next_number) VALUES ($1, $2) \
         ON CONFLICT (repo_id) DO UPDATE SET next_number = CASE WHEN trail_sequences.next_number < $2 THEN $2 ELSE trail_sequences.next_number END",
    )
    .bind(repo_id)
    .bind(number + 1)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(
        "INSERT INTO trails (repo_id, number, title, intent, state, ready, author_id, imported_author, github_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9, $9) \
         RETURNING id, repo_id, number, title, intent, state, ready, author_id, imported_author, github_id, created_at, updated_at, closed_at, merged_at",
    )
    .bind(repo_id)
    .bind(number)
    .bind(title)
    .bind(intent)
    .bind(state)
    .bind(author_id)
    .bind(imported_author)
    .bind(github_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let trail = trail_from_row(&row)?;
    tx.commit().await?;
    Ok(trail)
}

/// The imported Trail with this GitHub id, if any (idempotent resumption).
pub async fn trail_by_github_id(db: &Db, github_id: i64) -> DbResult<Option<TrailRow>> {
    let row = sqlx::query(select_trail!("WHERE github_id = $1"))
        .bind(github_id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(trail_from_row).transpose()
}

/// Inserts a Trail comment from an import (M4c): `author_id` is `None`
/// exactly when `imported_author` carries the GitHub login (D1).
pub async fn insert_imported_comment(
    db: &Db,
    trail_id: i64,
    author_id: Option<i64>,
    imported_author: Option<&str>,
    github_id: i64,
    body: &str,
    now: i64,
) -> DbResult<TrailCommentRow> {
    let row = sqlx::query(
        "INSERT INTO trail_comments (trail_id, author_id, imported_author, github_id, body, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, trail_id, author_id, imported_author, github_id, body, created_at, edited_at",
    )
    .bind(trail_id)
    .bind(author_id)
    .bind(imported_author)
    .bind(github_id)
    .bind(body)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    comment_from_row(&row)
}

/// The imported Trail comment with this GitHub id, if any.
pub async fn comment_by_github_id(db: &Db, github_id: i64) -> DbResult<Option<TrailCommentRow>> {
    let row = sqlx::query(select_comment!("WHERE github_id = $1"))
        .bind(github_id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(comment_from_row).transpose()
}

pub async fn trail_by_number(db: &Db, repo_id: i64, number: i64) -> DbResult<Option<TrailRow>> {
    let row = sqlx::query(select_trail!("WHERE repo_id = $1 AND number = $2"))
        .bind(repo_id)
        .bind(number)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(trail_from_row).transpose()
}

pub async fn trail_by_id(db: &Db, id: i64) -> DbResult<Option<TrailRow>> {
    let row = sqlx::query(select_trail!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(trail_from_row).transpose()
}

/// Trails of the repository in ascending number order, at most `f.limit` rows.
/// Every filter is optional: `after` is the keyset cursor (rows above it only),
/// label/assignee/review-request match through `EXISTS` subqueries, state/author
/// directly, `has_changes` through an existence check on `changes`, and
/// `has_sessions` through readable-session existence checks (commit links with
/// a non-null `session_id` plus explicit links).
///
/// The readable-session predicate mirrors `starforged_core::read::can_read_session`
/// arm for arm with bound viewer facts (`$11`-`$17`; anonymous viewers bind
/// zero/false): site admins read everything; quarantined sessions admit only
/// the uploader, the repo owner, or repo admins; otherwise owners read all,
/// published sessions need repo read, and unpublished sessions need repo read
/// on non-public repos but explicit membership on public ones. A bare session
/// existence check would leak unreadable (unpublished or quarantined)
/// sessions, so the two must stay in sync — the `trail_sessions` §6.4 tests
/// pin both.
pub async fn trails_of_repo(db: &Db, repo_id: i64, f: &TrailFilter) -> DbResult<Vec<TrailRow>> {
    // `has_changes`/`has_sessions` bind 0/1 (never a boolean literal): 1 keeps
    // Trails with at least one match, 0 keeps Trails with none. The three-way
    // shape keeps the `NULL` (no filter) arm valid on both engines. The `$N`
    // placeholders are numbered by first appearance.
    let has_changes: Option<i64> = f.has_changes.map(i64::from);
    let has_sessions: Option<i64> = f.has_sessions.map(i64::from);
    let facts = &f.session_facts;
    // `s` is the candidate `sessions` row in both `EXISTS` bodies below.
    // Numbering is dense 1-17 in bind order: repo and the old filters keep
    // `$1`-`$8`, then the session flag and viewer facts, then the limit.
    let readable = "(($12 = 1) \
         OR (s.quarantine = 'quarantined' AND (s.uploader_id = $10 \
         OR (SELECT owner_id FROM repos WHERE id = $1) = $10 OR $14 = 1)) \
         OR (s.quarantine <> 'quarantined' AND ((SELECT owner_id FROM repos WHERE id = $1) = $10 \
         OR (s.visibility = 'published' AND ($13 = 1 OR $15 = 1 OR ($16 = 1 AND $11 = 1))) \
         OR (s.visibility <> 'published' AND (($15 = 1 AND $13 = 1) \
         OR ($15 = 0 AND ($13 = 1 OR ($16 = 1 AND $11 = 1))))))))";
    let linked_through_commits = format!(
        "EXISTS (SELECT 1 FROM changes c JOIN revisions r ON r.change_id = c.id \
         JOIN revision_commits rc ON rc.revision_id = r.id \
         JOIN commit_links cl ON cl.repo_id = $1 AND cl.sha = rc.sha AND cl.session_id IS NOT NULL \
         JOIN sessions s ON s.id = cl.session_id AND s.repo_id = $1 \
         WHERE c.trail_id = trails.id AND {readable})"
    );
    let linked_by_hand = format!(
        "EXISTS (SELECT 1 FROM trail_session_links tsl \
         JOIN sessions s ON s.id = tsl.session_id AND s.repo_id = $1 \
         WHERE tsl.trail_id = trails.id AND {readable})"
    );
    let sql = format!(
        "SELECT id, repo_id, number, title, intent, state, ready, author_id, imported_author, github_id, created_at, updated_at, \
         closed_at, merged_at FROM trails \
         WHERE repo_id = $1 AND ($2 IS NULL OR number > $2) AND ($3 IS NULL OR state = $3) \
         AND ($4 IS NULL OR author_id = $4) \
         AND ($5 IS NULL OR EXISTS (SELECT 1 FROM trail_labels WHERE trail_id = trails.id AND name = $5)) \
         AND ($6 IS NULL OR EXISTS (SELECT 1 FROM trail_assignees WHERE trail_id = trails.id AND user_id = $6)) \
         AND ($7 IS NULL OR ($7 = 1 AND EXISTS (SELECT 1 FROM changes WHERE trail_id = trails.id)) \
         OR ($7 = 0 AND NOT EXISTS (SELECT 1 FROM changes WHERE trail_id = trails.id))) \
         AND ($8 IS NULL OR EXISTS (SELECT 1 FROM trail_review_requests WHERE trail_id = trails.id AND user_id = $8)) \
         AND ($9 IS NULL OR (($9 = 1 AND ({linked_through_commits} OR {linked_by_hand})) \
         OR ($9 = 0 AND NOT ({linked_through_commits} OR {linked_by_hand})))) \
         ORDER BY number ASC LIMIT $17"
    );
    // Binds follow the placeholder numbers in order: $1 repo, $2 after,
    // $3 state, $4 author, $5 label, $6 assignee, $7 has_changes,
    // $8 review-requested, $9 has_sessions, $10 viewer id, $11 signed in,
    // $12 site admin, $13 explicit member, $14 repo admin, $15 repo public,
    // $16 repo internal, $17 limit.
    // Dynamic only in placeholder-free structure (the same `$N` grammar as
    // the old literal query); every value stays bound.
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(repo_id)
        .bind(f.after)
        .bind(f.state.as_deref())
        .bind(f.author_id)
        .bind(f.label.as_deref())
        .bind(f.assignee_id)
        .bind(has_changes)
        .bind(f.review_requested_id)
        .bind(has_sessions)
        .bind(facts.viewer_id)
        .bind(i64::from(facts.signed_in))
        .bind(i64::from(facts.site_admin))
        .bind(i64::from(facts.member))
        .bind(i64::from(facts.repo_admin))
        .bind(i64::from(facts.repo_public))
        .bind(i64::from(facts.repo_internal))
        .bind(f.limit)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(trail_from_row).collect()
}

/// One open Trail plus its repository coordinates, for the cross-repo
/// dashboard sections. The repository identity travels with the row so Core
/// can re-check the viewer's current effective read permission per row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardTrailRow {
    pub trail: TrailRow,
    pub owner: String,
    pub repo: String,
}

/// Open Trails assigned to `user_id` across live repositories, newest
/// `updated_at` first, at most `limit` rows. Callers filter by the viewer's
/// current effective read permission and truncate to the display cap.
pub async fn trails_assigned_to(
    db: &Db,
    user_id: i64,
    limit: i64,
) -> DbResult<Vec<DashboardTrailRow>> {
    dashboard_trails(db, user_id, limit, "trail_assignees").await
}

/// Open Trails with a pending review request for `user_id` across live
/// repositories, newest `updated_at` first, at most `limit` rows. Same
/// caller-side filtering contract as [`trails_assigned_to`].
pub async fn trails_awaiting_review(
    db: &Db,
    user_id: i64,
    limit: i64,
) -> DbResult<Vec<DashboardTrailRow>> {
    dashboard_trails(db, user_id, limit, "trail_review_requests").await
}

/// Shared body for the two dashboard sections: `link_table` is either
/// `trail_assignees` or `trail_review_requests` (both keyed by
/// `(trail_id, user_id)`), interpolated as an identifier, never a bind.
async fn dashboard_trails(
    db: &Db,
    user_id: i64,
    limit: i64,
    link_table: &str,
) -> DbResult<Vec<DashboardTrailRow>> {
    assert!(
        matches!(link_table, "trail_assignees" | "trail_review_requests"),
        "dashboard link table must be a known constant"
    );
    // Safe: only `$N` placeholders are interpolated alongside the asserted
    // constant table name; every value is a bound parameter.
    let sql = format!(
        "SELECT t.id, t.repo_id, t.number, t.title, t.intent, t.state, t.ready, t.author_id, t.imported_author, t.github_id, \
         t.created_at, t.updated_at, t.closed_at, t.merged_at, o.handle AS owner, r.name AS repo \
         FROM trails t JOIN repos r ON r.id = t.repo_id JOIN owners o ON o.id = r.owner_id \
         WHERE t.state = 'open' AND r.deleted_at IS NULL \
         AND EXISTS (SELECT 1 FROM {link_table} l WHERE l.trail_id = t.id AND l.user_id = $1) \
         ORDER BY t.updated_at DESC, t.id DESC LIMIT $2"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(user_id)
        .bind(limit)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(dashboard_trail_from_row).collect()
}

fn dashboard_trail_from_row(row: &AnyRow) -> DbResult<DashboardTrailRow> {
    Ok(DashboardTrailRow {
        trail: trail_from_row(row)?,
        owner: row.try_get("owner")?,
        repo: row.try_get("repo")?,
    })
}

pub async fn set_title_intent(
    db: &Db,
    id: i64,
    title: &str,
    intent: &str,
    now: i64,
) -> DbResult<()> {
    sqlx::query("UPDATE trails SET title = $1, intent = $2, updated_at = $3 WHERE id = $4")
        .bind(title)
        .bind(intent)
        .bind(now)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_state(
    db: &Db,
    id: i64,
    state: &str,
    now: i64,
    closed_at: Option<i64>,
) -> DbResult<()> {
    sqlx::query("UPDATE trails SET state = $1, updated_at = $2, closed_at = $3 WHERE id = $4")
        .bind(state)
        .bind(now)
        .bind(closed_at)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Marks the trail merged (`merged_at` = now). Only the merge path (M2c)
/// writes `state = 'merged'`; closes/reopens go through [`set_state`].
pub async fn set_merged(db: &Db, id: i64, now: i64) -> DbResult<()> {
    sqlx::query(
        "UPDATE trails SET state = 'merged', merged_at = $1, updated_at = $1 WHERE id = $2",
    )
    .bind(now)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn set_ready(db: &Db, id: i64, ready: i64, now: i64) -> DbResult<()> {
    sqlx::query("UPDATE trails SET ready = $1, updated_at = $2 WHERE id = $3")
        .bind(ready)
        .bind(now)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Bumps `updated_at` for mutations that touch only child rows (labels, assignees, comments).
pub async fn touch(db: &Db, id: i64, now: i64) -> DbResult<()> {
    sqlx::query("UPDATE trails SET updated_at = $1 WHERE id = $2")
        .bind(now)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Attaches the label; `false` when it was already present.
pub async fn add_label(db: &Db, trail_id: i64, name: &str) -> DbResult<bool> {
    match sqlx::query("INSERT INTO trail_labels (trail_id, name) VALUES ($1, $2)")
        .bind(trail_id)
        .bind(name)
        .execute(db.pool())
        .await
    {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn remove_label(db: &Db, trail_id: i64, name: &str) -> DbResult<bool> {
    let r = sqlx::query("DELETE FROM trail_labels WHERE trail_id = $1 AND name = $2")
        .bind(trail_id)
        .bind(name)
        .execute(db.pool())
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn labels_of(db: &Db, trail_id: i64) -> DbResult<Vec<String>> {
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM trail_labels WHERE trail_id = $1 ORDER BY name ASC")
            .bind(trail_id)
            .fetch_all(db.pool())
            .await?;
    Ok(names)
}

/// Assigns the user; `false` when they were already assigned.
pub async fn add_assignee(db: &Db, trail_id: i64, user_id: i64) -> DbResult<bool> {
    match sqlx::query("INSERT INTO trail_assignees (trail_id, user_id) VALUES ($1, $2)")
        .bind(trail_id)
        .bind(user_id)
        .execute(db.pool())
        .await
    {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn remove_assignee(db: &Db, trail_id: i64, user_id: i64) -> DbResult<bool> {
    let r = sqlx::query("DELETE FROM trail_assignees WHERE trail_id = $1 AND user_id = $2")
        .bind(trail_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn assignees_of(db: &Db, trail_id: i64) -> DbResult<Vec<i64>> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT user_id FROM trail_assignees WHERE trail_id = $1 ORDER BY user_id ASC",
    )
    .bind(trail_id)
    .fetch_all(db.pool())
    .await?;
    Ok(ids)
}

/// Records a review request; `false` when one already exists for the pair.
pub async fn add_review_request(
    db: &Db,
    trail_id: i64,
    user_id: i64,
    requested_by: i64,
    now: i64,
) -> DbResult<bool> {
    match sqlx::query(
        "INSERT INTO trail_review_requests (trail_id, user_id, requested_by, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(trail_id)
    .bind(user_id)
    .bind(requested_by)
    .bind(now)
    .execute(db.pool())
    .await
    {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn remove_review_request(db: &Db, trail_id: i64, user_id: i64) -> DbResult<bool> {
    let r = sqlx::query("DELETE FROM trail_review_requests WHERE trail_id = $1 AND user_id = $2")
        .bind(trail_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn review_requests_of(db: &Db, trail_id: i64) -> DbResult<Vec<i64>> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT user_id FROM trail_review_requests WHERE trail_id = $1 ORDER BY user_id ASC",
    )
    .bind(trail_id)
    .fetch_all(db.pool())
    .await?;
    Ok(ids)
}

pub async fn insert_comment(
    db: &Db,
    trail_id: i64,
    author_id: i64,
    body: &str,
    now: i64,
) -> DbResult<TrailCommentRow> {
    let row = sqlx::query(
        "INSERT INTO trail_comments (trail_id, author_id, body, created_at) VALUES ($1, $2, $3, $4) \
         RETURNING id, trail_id, author_id, imported_author, github_id, body, created_at, edited_at",
    )
    .bind(trail_id)
    .bind(author_id)
    .bind(body)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    comment_from_row(&row)
}

pub async fn comment_by_id(db: &Db, id: i64) -> DbResult<Option<TrailCommentRow>> {
    let row = sqlx::query(select_comment!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(comment_from_row).transpose()
}

pub async fn update_comment(db: &Db, id: i64, body: &str, now: i64) -> DbResult<()> {
    sqlx::query("UPDATE trail_comments SET body = $1, edited_at = $2 WHERE id = $3")
        .bind(body)
        .bind(now)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn comments_of(db: &Db, trail_id: i64) -> DbResult<Vec<TrailCommentRow>> {
    let rows = sqlx::query(select_comment!("WHERE trail_id = $1 ORDER BY id ASC"))
        .bind(trail_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(comment_from_row).collect()
}

/// Records a timeline event; `trail_id = None` is a repo-level event. Returns the row id.
pub async fn insert_timeline(
    db: &Db,
    repo_id: i64,
    trail_id: Option<i64>,
    kind: &str,
    actor_id: Option<i64>,
    payload: &str,
    now: i64,
) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO timeline_events (repo_id, trail_id, kind, actor_id, payload, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(repo_id)
    .bind(trail_id)
    .bind(kind)
    .bind(actor_id)
    .bind(payload)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

pub async fn timeline_of_trail(db: &Db, trail_id: i64) -> DbResult<Vec<TimelineEventRow>> {
    let rows = sqlx::query(select_timeline!("WHERE trail_id = $1 ORDER BY id ASC"))
        .bind(trail_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(timeline_from_row).collect()
}

/// One explicit hand link between a Trail and a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailSessionLinkRow {
    pub trail_id: i64,
    pub session_id: i64,
    pub linked_by: Option<i64>,
    pub created_at: i64,
}

fn session_link_from_row(row: &AnyRow) -> DbResult<TrailSessionLinkRow> {
    Ok(TrailSessionLinkRow {
        trail_id: row.try_get("trail_id")?,
        session_id: row.try_get("session_id")?,
        linked_by: row.try_get("linked_by")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Records an explicit link; `false` when it already exists (idempotent).
pub async fn add_trail_session_link(
    db: &Db,
    trail_id: i64,
    session_id: i64,
    linked_by: i64,
    now: i64,
) -> DbResult<bool> {
    let result = sqlx::query(
        "INSERT INTO trail_session_links (trail_id, session_id, linked_by, created_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(trail_id)
    .bind(session_id)
    .bind(linked_by)
    .bind(now)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Removes an explicit link; `false` when there was none.
pub async fn remove_trail_session_link(db: &Db, trail_id: i64, session_id: i64) -> DbResult<bool> {
    let result =
        sqlx::query("DELETE FROM trail_session_links WHERE trail_id = $1 AND session_id = $2")
            .bind(trail_id)
            .bind(session_id)
            .execute(db.pool())
            .await?;
    Ok(result.rows_affected() > 0)
}

/// Explicit links of the trail, oldest first.
pub async fn trail_session_links_of(db: &Db, trail_id: i64) -> DbResult<Vec<TrailSessionLinkRow>> {
    let rows = sqlx::query(
        "SELECT trail_id, session_id, linked_by, created_at FROM trail_session_links \
         WHERE trail_id = $1 ORDER BY created_at ASC, session_id ASC",
    )
    .bind(trail_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(session_link_from_row).collect()
}

/// How many explicit links the trail holds (the 50-link cap checks this).
pub async fn trail_session_link_count(db: &Db, trail_id: i64) -> DbResult<i64> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM trail_session_links WHERE trail_id = $1")
            .bind(trail_id)
            .fetch_one(db.pool())
            .await?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
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
            visibility: "private",
            default_branch: "main",
        }
    }

    fn new_trail(repo_id: i64, author_id: i64, title: &str) -> NewTrail<'_> {
        NewTrail {
            repo_id,
            title,
            intent: "do the thing",
            author_id,
        }
    }

    async fn setup() -> (TestDb, i64, i64, i64) {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("alice")).await.unwrap();
        let bob = users::insert(&t.db, &user("bob")).await.unwrap();
        let repo_id = repos::insert(&t.db, &repo(alice, "demo")).await.unwrap();
        (t, alice, bob, repo_id)
    }

    fn numbers(rows: &[TrailRow]) -> Vec<i64> {
        rows.iter().map(|r| r.number).collect()
    }

    #[tokio::test]
    async fn numbers_allocate_per_repo() {
        let (t, alice, _bob, repo_id) = setup().await;
        let a = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        let b = insert_trail(&t.db, &new_trail(repo_id, alice, "two"), 1_700_000_001)
            .await
            .unwrap();
        assert_eq!(a.number, 1);
        assert_eq!(b.number, 2);
        assert_eq!(a.state, "open");
        assert_eq!(a.ready, 0);
        assert_eq!(a.closed_at, None);
        assert_eq!(a.merged_at, None);

        let got = trail_by_number(&t.db, repo_id, 1)
            .await
            .unwrap()
            .expect("trail #1 present");
        assert_eq!(got.id, a.id);
        assert_eq!(got.title, "one");
        assert!(trail_by_number(&t.db, repo_id, 99).await.unwrap().is_none());

        let repo2 = repos::insert(&t.db, &repo(alice, "other")).await.unwrap();
        let c = insert_trail(&t.db, &new_trail(repo2, alice, "restart"), 1_700_000_002)
            .await
            .unwrap();
        assert_eq!(c.number, 1);
    }

    #[tokio::test]
    async fn duplicate_number_is_unique_violation() {
        let (t, alice, _bob, repo_id) = setup().await;
        insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        let err = sqlx::query(
            "INSERT INTO trails (repo_id, number, title, intent, state, ready, author_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'open', 0, $5, $6, $6)",
        )
        .bind(repo_id)
        .bind(1)
        .bind("dup")
        .bind("dup intent")
        .bind(alice)
        .bind(1_700_000_001)
        .execute(t.db.pool())
        .await
        .expect_err("duplicate (repo_id, number) must fail");
        assert!(
            err.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false),
            "expected a unique violation, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rolled_back_insert_does_not_consume_number() {
        let (t, alice, _bob, repo_id) = setup().await;
        let a = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        assert_eq!(a.number, 1);
        // A trail insert that fails after allocating (here: dangling author_id
        // trips the FK) rolls the sequence back with it …
        let err = insert_trail(
            &t.db,
            &NewTrail {
                repo_id,
                title: "bad",
                intent: "bad",
                author_id: 999_999,
            },
            1_700_000_001,
        )
        .await
        .expect_err("dangling author must fail");
        assert!(!err.is_unique_violation());
        // … so the next create reuses the number instead of skipping it.
        let b = insert_trail(&t.db, &new_trail(repo_id, alice, "two"), 1_700_000_002)
            .await
            .unwrap();
        assert_eq!(b.number, 2);
        // Same guarantee through the defensive path: a row written behind the
        // sequence's back fails the insert, and clearing it frees the number.
        sqlx::query(
            "INSERT INTO trails (repo_id, number, title, intent, state, ready, author_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'open', 0, $5, $6, $6)",
        )
        .bind(repo_id)
        .bind(3)
        .bind("squat")
        .bind("squat")
        .bind(alice)
        .bind(1_700_000_003)
        .execute(t.db.pool())
        .await
        .unwrap();
        let err = insert_trail(&t.db, &new_trail(repo_id, alice, "three"), 1_700_000_004)
            .await
            .expect_err("squatted number must fail");
        assert!(err.is_unique_violation());
        sqlx::query("DELETE FROM trails WHERE repo_id = $1 AND number = $2")
            .bind(repo_id)
            .bind(3)
            .execute(t.db.pool())
            .await
            .unwrap();
        let c = insert_trail(&t.db, &new_trail(repo_id, alice, "three"), 1_700_000_005)
            .await
            .unwrap();
        assert_eq!(c.number, 3);
    }

    #[tokio::test]
    async fn trails_of_repo_filters_and_keyset() {
        let (t, alice, bob, repo_id) = setup().await;
        let t1 = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        let t2 = insert_trail(&t.db, &new_trail(repo_id, bob, "two"), 1_700_000_001)
            .await
            .unwrap();
        let t3 = insert_trail(&t.db, &new_trail(repo_id, alice, "three"), 1_700_000_002)
            .await
            .unwrap();
        set_state(&t.db, t2.id, "closed", 1_700_000_010, Some(1_700_000_010))
            .await
            .unwrap();
        add_label(&t.db, t1.id, "bug").await.unwrap();
        add_label(&t.db, t3.id, "bug").await.unwrap();
        add_label(&t.db, t3.id, "ui").await.unwrap();
        add_assignee(&t.db, t1.id, bob).await.unwrap();
        add_assignee(&t.db, t3.id, alice).await.unwrap();

        // No filters: ascending, all three.
        let all = trails_of_repo(&t.db, repo_id, &TrailFilter::default())
            .await
            .unwrap();
        assert_eq!(numbers(&all), vec![1, 2, 3]);

        // State filter.
        let mut f = TrailFilter {
            state: Some("closed".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![2]
        );
        f.state = Some("open".to_owned());
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![1, 3]
        );

        // Label filter.
        let mut f = TrailFilter {
            label: Some("bug".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![1, 3]
        );
        f.label = Some("ui".to_owned());
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![3]
        );
        f.label = Some("nope".to_owned());
        assert!(trails_of_repo(&t.db, repo_id, &f).await.unwrap().is_empty());

        // Assignee filter.
        let mut f = TrailFilter {
            assignee_id: Some(bob),
            ..Default::default()
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![1]
        );
        f.assignee_id = Some(alice);
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![3]
        );

        // Author filter.
        let mut f = TrailFilter {
            author_id: Some(alice),
            ..Default::default()
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![1, 3]
        );
        f.author_id = Some(bob);
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![2]
        );

        // Keyset: `after` excludes everything at or below the cursor.
        let mut f = TrailFilter {
            after: Some(1),
            ..Default::default()
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![2, 3]
        );
        f.after = Some(2);
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![3]
        );
        f.after = Some(3);
        assert!(trails_of_repo(&t.db, repo_id, &f).await.unwrap().is_empty());

        // Combined filters intersect.
        let f = TrailFilter {
            state: Some("open".to_owned()),
            label: Some("bug".to_owned()),
            assignee_id: None,
            author_id: None,
            has_changes: None,
            has_sessions: None,
            session_facts: SessionViewerFacts::default(),
            review_requested_id: None,
            after: None,
            limit: 30,
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![1, 3]
        );
        let f = TrailFilter {
            state: None,
            label: None,
            assignee_id: Some(alice),
            author_id: Some(alice),
            has_changes: None,
            has_sessions: None,
            session_facts: SessionViewerFacts::default(),
            review_requested_id: None,
            after: Some(1),
            limit: 30,
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![3]
        );

        // Limit applies.
        let f = TrailFilter {
            limit: 2,
            ..TrailFilter::default()
        };
        assert_eq!(
            numbers(&trails_of_repo(&t.db, repo_id, &f).await.unwrap()),
            vec![1, 2]
        );
    }

    #[tokio::test]
    async fn labels_are_idempotent() {
        let (t, alice, _bob, repo_id) = setup().await;
        let trail = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        assert!(add_label(&t.db, trail.id, "bug").await.unwrap());
        assert!(!add_label(&t.db, trail.id, "bug").await.unwrap());
        assert_eq!(labels_of(&t.db, trail.id).await.unwrap(), vec!["bug"]);
        assert!(remove_label(&t.db, trail.id, "bug").await.unwrap());
        assert!(!remove_label(&t.db, trail.id, "bug").await.unwrap());
        assert!(labels_of(&t.db, trail.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn assignees_add_remove() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        assert!(add_assignee(&t.db, trail.id, bob).await.unwrap());
        assert!(!add_assignee(&t.db, trail.id, bob).await.unwrap());
        assert_eq!(assignees_of(&t.db, trail.id).await.unwrap(), vec![bob]);
        assert!(remove_assignee(&t.db, trail.id, bob).await.unwrap());
        assert!(!remove_assignee(&t.db, trail.id, bob).await.unwrap());
        assert!(assignees_of(&t.db, trail.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn review_requests_add_remove() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        assert!(
            add_review_request(&t.db, trail.id, bob, alice, 1_700_000_001)
                .await
                .unwrap()
        );
        assert!(
            !add_review_request(&t.db, trail.id, bob, alice, 1_700_000_002)
                .await
                .unwrap()
        );
        assert_eq!(
            review_requests_of(&t.db, trail.id).await.unwrap(),
            vec![bob]
        );
        assert!(remove_review_request(&t.db, trail.id, bob).await.unwrap());
        assert!(!remove_review_request(&t.db, trail.id, bob).await.unwrap());
        assert!(
            review_requests_of(&t.db, trail.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn comment_edit_bumps_edited_at() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        let c = insert_comment(&t.db, trail.id, bob, "hello", 1_700_000_001)
            .await
            .unwrap();
        assert_eq!(c.body, "hello");
        assert_eq!(c.edited_at, None);
        let got = comment_by_id(&t.db, c.id)
            .await
            .unwrap()
            .expect("comment present");
        assert_eq!(got.body, "hello");
        assert!(comment_by_id(&t.db, 999_999).await.unwrap().is_none());

        update_comment(&t.db, c.id, "hello v2", 1_700_000_002)
            .await
            .unwrap();
        let got = comment_by_id(&t.db, c.id)
            .await
            .unwrap()
            .expect("comment present");
        assert_eq!(got.body, "hello v2");
        assert_eq!(got.edited_at, Some(1_700_000_002));

        insert_comment(&t.db, trail.id, alice, "second", 1_700_000_003)
            .await
            .unwrap();
        let all = comments_of(&t.db, trail.id).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, c.id);
        assert_eq!(all[1].body, "second");
    }

    #[tokio::test]
    async fn metadata_mutations() {
        let (t, alice, _bob, repo_id) = setup().await;
        let trail = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();

        set_title_intent(&t.db, trail.id, "uno", "new intent", 1_700_000_010)
            .await
            .unwrap();
        let got = trail_by_number(&t.db, repo_id, 1).await.unwrap().unwrap();
        assert_eq!(got.title, "uno");
        assert_eq!(got.intent, "new intent");
        assert_eq!(got.updated_at, 1_700_000_010);

        set_ready(&t.db, trail.id, 1, 1_700_000_020).await.unwrap();
        let got = trail_by_number(&t.db, repo_id, 1).await.unwrap().unwrap();
        assert_eq!(got.ready, 1);

        set_state(
            &t.db,
            trail.id,
            "closed",
            1_700_000_030,
            Some(1_700_000_030),
        )
        .await
        .unwrap();
        let got = trail_by_number(&t.db, repo_id, 1).await.unwrap().unwrap();
        assert_eq!(got.state, "closed");
        assert_eq!(got.closed_at, Some(1_700_000_030));

        touch(&t.db, trail.id, 1_700_000_040).await.unwrap();
        let got = trail_by_number(&t.db, repo_id, 1).await.unwrap().unwrap();
        assert_eq!(got.updated_at, 1_700_000_040);
    }

    #[tokio::test]
    async fn timeline_repo_level_row_round_trips() {
        let (t, alice, _bob, repo_id) = setup().await;
        let trail = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        insert_timeline(
            &t.db,
            repo_id,
            Some(trail.id),
            "trail.open",
            Some(alice),
            "{}",
            1_700_000_001,
        )
        .await
        .unwrap();
        let repo_event = insert_timeline(
            &t.db,
            repo_id,
            None,
            "repo.rename",
            Some(alice),
            r#"{"from":"a"}"#,
            1_700_000_002,
        )
        .await
        .unwrap();

        let trail_events = timeline_of_trail(&t.db, trail.id).await.unwrap();
        assert_eq!(trail_events.len(), 1);
        assert_eq!(trail_events[0].kind, "trail.open");
        assert_eq!(trail_events[0].trail_id, Some(trail.id));
        assert_eq!(trail_events[0].actor_id, Some(alice));
        assert_eq!(trail_events[0].payload, "{}");

        // The repo-level row carries a NULL trail_id and is not listed under the trail.
        let row: (Option<i64>, String) =
            sqlx::query_as("SELECT trail_id, kind FROM timeline_events WHERE id = $1")
                .bind(repo_event)
                .fetch_one(t.db.pool())
                .await
                .unwrap();
        assert_eq!(row.0, None);
        assert_eq!(row.1, "repo.rename");
    }
    #[tokio::test]
    async fn author_set_null_on_user_delete() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail = insert_trail(&t.db, &new_trail(repo_id, alice, "one"), 1_700_000_000)
            .await
            .unwrap();
        let comment = insert_comment(&t.db, trail.id, bob, "hello", 1_700_000_001)
            .await
            .unwrap();
        assert_eq!(trail.author_id, Some(alice));
        assert_eq!(comment.author_id, Some(bob));
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(alice)
            .execute(t.db.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(bob)
            .execute(t.db.pool())
            .await
            .unwrap();
        let trail = trail_by_number(&t.db, repo_id, 1)
            .await
            .unwrap()
            .expect("trail survives author delete");
        assert_eq!(trail.author_id, None);
        let comments = comments_of(&t.db, trail.id).await.unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].author_id, None);
    }
}
