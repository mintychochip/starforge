//! `changes`: change proposals (branch/agit/imported), their immutable revisions,
//! reviews, and review threads/comments.
//!
//! Numbering is per parent (`UNIQUE (trail_id, number)`, `UNIQUE (change_id, number)`):
//! `insert_change` / `insert_revision` allocate from `change_sequences` /
//! `revision_sequences` inside the same transaction that inserts the row, so
//! concurrent creates serialize and a rolled-back insert returns its number.
//! The data-access layer stays thin — no validation or permission checks here
//! (those live in `starforged-core`).
//!
//! `topic` note: agit changes carry no head branch (`head_branch` is NULL for
//! them), so the push topic travels in the `topic` column. At insert time the
//! `head_branch` parameter doubles as the topic when `kind == "agit"` (it is
//! stored into `topic` and the `head_branch` column stays NULL); for other
//! kinds it is the head branch and `topic` stays `''`.
//!
//! `merged` is admitted by the state `CHECK` but never written in M2b; the merge
//! path owns it. `imported` is admitted by the kind `CHECK` for M4 mirrors;
//! never written in M2b. `merge_method` / `merge_commit` stay NULL in M2b.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRow {
    pub id: i64,
    pub trail_id: i64,
    pub number: i64,
    pub kind: String,
    pub head_branch: Option<String>,
    pub base_branch: String,
    pub topic: String,
    pub current_revision_id: Option<i64>,
    pub state: String,
    pub merge_method: Option<String>,
    pub merge_commit: Option<String>,
    pub creator_id: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub mergeability: String,
    pub conflict_paths: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRow {
    pub id: i64,
    pub change_id: i64,
    pub number: i64,
    pub head_sha: String,
    pub base_sha: String,
    pub merge_base_sha: Option<String>,
    pub pusher_id: Option<i64>,
    pub created_at: i64,
    pub mergeability: String,
    pub conflict_paths: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRow {
    pub id: i64,
    pub change_id: i64,
    pub revision_id: i64,
    pub author_id: Option<i64>,
    pub verdict: String,
    pub body: String,
    pub session_ulid: Option<String>,
    pub state: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadRow {
    pub id: i64,
    pub change_id: i64,
    pub anchor_revision_id: i64,
    pub path: String,
    pub side: String,
    pub start_line: i64,
    pub end_line: i64,
    pub resolved: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewCommentRow {
    pub id: i64,
    pub thread_id: i64,
    pub review_id: Option<i64>,
    pub author_id: Option<i64>,
    pub body: String,
    pub created_at: i64,
}

/// Alias kept for the G1 brief's `ThreadCommentRow` name; same row.
pub type ThreadCommentRow = ReviewCommentRow;

#[derive(Debug, Clone)]
pub struct NewChange<'a> {
    pub trail_id: i64,
    pub kind: &'a str,
    pub head_branch: Option<&'a str>,
    pub base_branch: &'a str,
    pub creator_id: i64,
}

#[derive(Debug, Clone)]
pub struct NewRevision<'a> {
    pub change_id: i64,
    pub head_sha: &'a str,
    pub base_sha: &'a str,
    pub pusher: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewReview<'a> {
    pub change_id: i64,
    pub revision_id: i64,
    pub author_id: i64,
    pub verdict: &'a str,
    pub body: &'a str,
    pub session_ulid: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct ChangeFilter {
    pub state: Option<String>,
    pub kind: Option<String>,
}

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult};

macro_rules! select_change {
    ($tail:literal) => {
        concat!(
            "SELECT id, trail_id, number, kind, head_branch, base_branch, topic, current_revision_id, ",
            "state, merge_method, merge_commit, creator_id, created_at, updated_at, mergeability, ",
            "conflict_paths FROM changes ",
            $tail
        )
    };
}

macro_rules! select_revision {
    ($tail:literal) => {
        concat!(
            "SELECT id, change_id, number, head_sha, base_sha, merge_base_sha, pusher_id, created_at, ",
            "mergeability, conflict_paths FROM revisions ",
            $tail
        )
    };
}

macro_rules! select_review {
    ($tail:literal) => {
        concat!(
            "SELECT id, change_id, revision_id, author_id, verdict, body, session_ulid, state, created_at ",
            "FROM reviews ",
            $tail
        )
    };
}

macro_rules! select_thread {
    ($tail:literal) => {
        concat!(
            "SELECT id, change_id, anchor_revision_id, path, side, start_line, end_line, resolved, created_at ",
            "FROM review_threads ",
            $tail
        )
    };
}

macro_rules! select_comment {
    ($tail:literal) => {
        concat!(
            "SELECT id, thread_id, review_id, author_id, body, created_at FROM review_comments ",
            $tail
        )
    };
}

fn change_from_row(row: &AnyRow) -> DbResult<ChangeRow> {
    Ok(ChangeRow {
        id: row.try_get("id")?,
        trail_id: row.try_get("trail_id")?,
        number: row.try_get("number")?,
        kind: row.try_get("kind")?,
        head_branch: row.try_get("head_branch")?,
        base_branch: row.try_get("base_branch")?,
        topic: row.try_get("topic")?,
        current_revision_id: row.try_get("current_revision_id")?,
        state: row.try_get("state")?,
        merge_method: row.try_get("merge_method")?,
        merge_commit: row.try_get("merge_commit")?,
        creator_id: row.try_get("creator_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        mergeability: row.try_get("mergeability")?,
        conflict_paths: row.try_get("conflict_paths")?,
    })
}

fn revision_from_row(row: &AnyRow) -> DbResult<RevisionRow> {
    Ok(RevisionRow {
        id: row.try_get("id")?,
        change_id: row.try_get("change_id")?,
        number: row.try_get("number")?,
        head_sha: row.try_get("head_sha")?,
        base_sha: row.try_get("base_sha")?,
        merge_base_sha: row.try_get("merge_base_sha")?,
        pusher_id: row.try_get("pusher_id")?,
        created_at: row.try_get("created_at")?,
        mergeability: row.try_get("mergeability")?,
        conflict_paths: row.try_get("conflict_paths")?,
    })
}

fn review_from_row(row: &AnyRow) -> DbResult<ReviewRow> {
    Ok(ReviewRow {
        id: row.try_get("id")?,
        change_id: row.try_get("change_id")?,
        revision_id: row.try_get("revision_id")?,
        author_id: row.try_get("author_id")?,
        verdict: row.try_get("verdict")?,
        body: row.try_get("body")?,
        session_ulid: row.try_get("session_ulid")?,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
    })
}

fn thread_from_row(row: &AnyRow) -> DbResult<ThreadRow> {
    Ok(ThreadRow {
        id: row.try_get("id")?,
        change_id: row.try_get("change_id")?,
        anchor_revision_id: row.try_get("anchor_revision_id")?,
        path: row.try_get("path")?,
        side: row.try_get("side")?,
        start_line: row.try_get("start_line")?,
        end_line: row.try_get("end_line")?,
        resolved: row.try_get("resolved")?,
        created_at: row.try_get("created_at")?,
    })
}

fn comment_from_row(row: &AnyRow) -> DbResult<ReviewCommentRow> {
    Ok(ReviewCommentRow {
        id: row.try_get("id")?,
        thread_id: row.try_get("thread_id")?,
        review_id: row.try_get("review_id")?,
        author_id: row.try_get("author_id")?,
        body: row.try_get("body")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Allocates the next per-trail change number from `change_sequences` inside the
/// caller's transaction: the upsert takes the sequence row lock, so concurrent
/// creates serialize and never collide; rolling back returns the allocated
/// number. A `UNIQUE (trail_id, number)` violation is still possible if rows
/// were inserted behind the sequence's back — callers map it to `Conflict` as
/// a defensive fallback and never retry it in a loop.
async fn alloc_change_number(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    trail_id: i64,
) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO change_sequences (trail_id, next_number) VALUES ($1, 2) \
         ON CONFLICT (trail_id) DO UPDATE SET next_number = change_sequences.next_number + 1 \
         RETURNING next_number - 1",
    )
    .bind(trail_id)
    .fetch_one(&mut **tx)
    .await?)
}

/// Same allocator for per-change revision numbers from `revision_sequences`.
async fn alloc_revision_number(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    change_id: i64,
) -> DbResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO revision_sequences (change_id, next_number) VALUES ($1, 2) \
         ON CONFLICT (change_id) DO UPDATE SET next_number = revision_sequences.next_number + 1 \
         RETURNING next_number - 1",
    )
    .bind(change_id)
    .fetch_one(&mut **tx)
    .await?)
}

async fn insert_change_row(db: &Db, n: &NewChange<'_>, now: i64) -> DbResult<ChangeRow> {
    // Agit changes carry the push topic, not a head branch: the parameter
    // doubles as the topic and the column stays NULL.
    let (head_branch, topic) = if n.kind == "agit" {
        (None, n.head_branch.unwrap_or(""))
    } else {
        (n.head_branch, "")
    };
    let mut tx = db.pool().begin().await?;
    let number = alloc_change_number(&mut tx, n.trail_id).await?;
    let row = sqlx::query(
        "INSERT INTO changes (trail_id, number, kind, head_branch, base_branch, topic, state, creator_id, \
         created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8, $8) \
         RETURNING id, trail_id, number, kind, head_branch, base_branch, topic, current_revision_id, \
         state, merge_method, merge_commit, creator_id, created_at, updated_at, mergeability, conflict_paths",
    )
    .bind(n.trail_id)
    .bind(number)
    .bind(n.kind)
    .bind(head_branch)
    .bind(n.base_branch)
    .bind(topic)
    .bind(n.creator_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let change = change_from_row(&row)?;
    tx.commit().await?;
    Ok(change)
}

/// Inserts the change, allocating the next per-trail number from
/// `change_sequences` inside the same transaction that inserts the row (see
/// `alloc_change_number`). When `kind == "agit"`, `head_branch` carries the
/// push topic: it is stored into `topic` and the `head_branch` column stays
/// NULL; for other kinds it is the head branch and `topic` stays `''`.
/// `merge_method` / `merge_commit` stay NULL in M2b.
pub async fn insert_change(
    db: &Db,
    trail_id: i64,
    kind: &str,
    head_branch: Option<&str>,
    base_branch: &str,
    creator_id: i64,
    now: i64,
) -> DbResult<ChangeRow> {
    insert_change_row(
        db,
        &NewChange {
            trail_id,
            kind,
            head_branch,
            base_branch,
            creator_id,
        },
        now,
    )
    .await
}

pub async fn change_by_trail_number(db: &Db, trail_id: i64, k: i64) -> DbResult<Option<ChangeRow>> {
    let row = sqlx::query(select_change!("WHERE trail_id = $1 AND number = $2"))
        .bind(trail_id)
        .bind(k)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(change_from_row).transpose()
}

/// Changes of the trail in ascending number order.
pub async fn changes_of_trail(db: &Db, trail_id: i64) -> DbResult<Vec<ChangeRow>> {
    let rows = sqlx::query(select_change!("WHERE trail_id = $1 ORDER BY number ASC"))
        .bind(trail_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(change_from_row).collect()
}

/// Changes of the trail in ascending number order, filtered to the states /
/// kinds in `f` (`None` means unfiltered).
pub async fn changes_of_trail_filtered(
    db: &Db,
    trail_id: i64,
    f: &ChangeFilter,
) -> DbResult<Vec<ChangeRow>> {
    let rows = sqlx::query(select_change!(
        "WHERE trail_id = $1 AND ($2 IS NULL OR state = $2) AND ($3 IS NULL OR kind = $3) \
         ORDER BY number ASC"
    ))
    .bind(trail_id)
    .bind(f.state.as_deref())
    .bind(f.kind.as_deref())
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(change_from_row).collect()
}

/// The open agit change for `(repo, user, base, topic)` — the update target for
/// an accepted `refs/for` push — optionally scoped to one trail. Joins trails
/// for the repo scope; closed/merged rows and other users' rows never match.
pub async fn open_agit_change(
    db: &Db,
    repo_id: i64,
    user_id: i64,
    base: &str,
    topic: &str,
    trail_id: Option<i64>,
) -> DbResult<Option<ChangeRow>> {
    // Column-qualified: the join would make the shared SELECT list ambiguous.
    let row = sqlx::query(
        "SELECT changes.id, changes.trail_id, changes.number, changes.kind, changes.head_branch, \
         changes.base_branch, changes.topic, changes.current_revision_id, changes.state, \
         changes.merge_method, changes.merge_commit, changes.creator_id, changes.created_at, \
         changes.updated_at, changes.mergeability, changes.conflict_paths \
         FROM changes JOIN trails t ON t.id = changes.trail_id \
         WHERE t.repo_id = $1 AND changes.creator_id = $2 AND changes.base_branch = $3 \
         AND changes.topic = $4 AND changes.state = 'open' AND changes.kind = 'agit' \
         AND ($5 IS NULL OR changes.trail_id = $5) ORDER BY changes.number ASC LIMIT 1",
    )
    .bind(repo_id)
    .bind(user_id)
    .bind(base)
    .bind(topic)
    .bind(trail_id)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(change_from_row).transpose()
}

pub async fn change_by_id(db: &Db, id: i64) -> DbResult<Option<ChangeRow>> {
    let row = sqlx::query(select_change!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(change_from_row).transpose()
}

pub async fn revision_by_id(db: &Db, id: i64) -> DbResult<Option<RevisionRow>> {
    let row = sqlx::query(select_revision!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(revision_from_row).transpose()
}

/// The open branch changes for `(repo, head branch)`: the update targets when a
/// head-branch push lands. Joins trails for the repo scope; closed/merged rows
/// and other branches never match.
pub async fn open_branch_changes(db: &Db, repo_id: i64, branch: &str) -> DbResult<Vec<ChangeRow>> {
    // Column-qualified: the join would make the shared SELECT list ambiguous.
    let rows = sqlx::query(
        "SELECT changes.id, changes.trail_id, changes.number, changes.kind, changes.head_branch, \
         changes.base_branch, changes.topic, changes.current_revision_id, changes.state, \
         changes.merge_method, changes.merge_commit, changes.creator_id, changes.created_at, \
         changes.updated_at, changes.mergeability, changes.conflict_paths \
         FROM changes JOIN trails t ON t.id = changes.trail_id \
         WHERE t.repo_id = $1 AND changes.head_branch = $2 AND changes.state = 'open' \
         AND changes.kind = 'branch' ORDER BY changes.id ASC",
    )
    .bind(repo_id)
    .bind(branch)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(change_from_row).collect()
}

/// Ids of every open change in the repo whose base branch is `base` (any kind):
/// a base-branch move recomputes mergeability for all of them but revises none.
pub async fn open_change_ids_with_base(db: &Db, repo_id: i64, base: &str) -> DbResult<Vec<i64>> {
    let rows: Vec<i64> = sqlx::query_scalar(
        "SELECT changes.id FROM changes JOIN trails t ON t.id = changes.trail_id \
         WHERE t.repo_id = $1 AND changes.base_branch = $2 AND changes.state = 'open' \
         ORDER BY changes.id ASC",
    )
    .bind(repo_id)
    .bind(base)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

pub async fn set_current_revision(
    db: &Db,
    change_id: i64,
    revision_id: i64,
    now: i64,
) -> DbResult<()> {
    sqlx::query("UPDATE changes SET current_revision_id = $1, updated_at = $2 WHERE id = $3")
        .bind(revision_id)
        .bind(now)
        .bind(change_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_change_state(db: &Db, change_id: i64, state: &str, now: i64) -> DbResult<()> {
    sqlx::query("UPDATE changes SET state = $1, updated_at = $2 WHERE id = $3")
        .bind(state)
        .bind(now)
        .bind(change_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_mergeability(db: &Db, change_id: i64, status: &str, paths: &str) -> DbResult<()> {
    sqlx::query("UPDATE changes SET mergeability = $1, conflict_paths = $2 WHERE id = $3")
        .bind(status)
        .bind(paths)
        .bind(change_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

async fn insert_revision_row(db: &Db, n: &NewRevision<'_>, now: i64) -> DbResult<RevisionRow> {
    let mut tx = db.pool().begin().await?;
    let number = alloc_revision_number(&mut tx, n.change_id).await?;
    let row = sqlx::query(
        "INSERT INTO revisions (change_id, number, head_sha, base_sha, pusher_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, change_id, number, head_sha, base_sha, merge_base_sha, pusher_id, created_at, \
         mergeability, conflict_paths",
    )
    .bind(n.change_id)
    .bind(number)
    .bind(n.head_sha)
    .bind(n.base_sha)
    .bind(n.pusher)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let revision = revision_from_row(&row)?;
    tx.commit().await?;
    Ok(revision)
}

/// Inserts the revision, allocating the next per-change number from
/// `revision_sequences` inside the same transaction (see `alloc_change_number`
/// for the guarantees). `merge_base_sha` starts NULL and the mergeability
/// snapshot starts `unknown`/empty, filled once by the mergeability worker.
pub async fn insert_revision(
    db: &Db,
    change_id: i64,
    head_sha: &str,
    base_sha: &str,
    pusher: Option<i64>,
    now: i64,
) -> DbResult<RevisionRow> {
    insert_revision_row(
        db,
        &NewRevision {
            change_id,
            head_sha,
            base_sha,
            pusher,
        },
        now,
    )
    .await
}

/// Reserves the next per-change revision number from `revision_sequences` in
/// its own transaction (same upsert pattern as the insert path, so concurrent
/// reservers serialize on the sequence row lock). The caller publishes side
/// effects (trail refs) against the reserved number and then inserts the row
/// with [`insert_revision_numbered`], so a visible revision always has its
/// refs. A crash between reserve and insert skips the number; that is the
/// price of publishing refs before the row commits.
pub async fn reserve_revision_number(db: &Db, change_id: i64) -> DbResult<i64> {
    let mut tx = db.pool().begin().await?;
    let number = alloc_revision_number(&mut tx, change_id).await?;
    tx.commit().await?;
    Ok(number)
}

/// Inserts the revision with an explicitly reserved number (see
/// [`reserve_revision_number`]). Same row defaults as [`insert_revision`]:
/// `merge_base_sha` starts NULL and the mergeability snapshot starts
/// `unknown`/empty.
pub async fn insert_revision_numbered(
    db: &Db,
    change_id: i64,
    number: i64,
    head_sha: &str,
    base_sha: &str,
    pusher: Option<i64>,
    now: i64,
) -> DbResult<RevisionRow> {
    let row = sqlx::query(
        "INSERT INTO revisions (change_id, number, head_sha, base_sha, pusher_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, change_id, number, head_sha, base_sha, merge_base_sha, pusher_id, created_at, \
         mergeability, conflict_paths",
    )
    .bind(change_id)
    .bind(number)
    .bind(head_sha)
    .bind(base_sha)
    .bind(pusher)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    revision_from_row(&row)
}

/// Inserts an agit change with its first revision and current pointer in one
/// transaction: allocates the change number, inserts the change, allocates
/// the revision number, inserts the revision, and points the change at it.
/// Readers polling for the change (the post-push scan's `open_agit_change`)
/// see it only once the revision and its current pointer exist — combined
/// with refs written before this commits (the fresh-trail `k == 1`, `r == 1`
/// pre-write), a visible first revision always has its refs and its current
/// pointer. The change row is re-read before commit so the returned row
/// carries the current revision id.
#[allow(clippy::too_many_arguments)]
pub async fn insert_agit_change_with_revision(
    db: &Db,
    trail_id: i64,
    base: &str,
    topic: &str,
    creator_id: i64,
    head_sha: &str,
    base_sha: &str,
    pusher: Option<i64>,
    now: i64,
) -> DbResult<(ChangeRow, RevisionRow)> {
    let mut tx = db.pool().begin().await?;
    let k = alloc_change_number(&mut tx, trail_id).await?;
    let change_id: i64 = sqlx::query_scalar(
        "INSERT INTO changes (trail_id, number, kind, head_branch, base_branch, topic, state, \
         creator_id, created_at, updated_at) \
         VALUES ($1, $2, 'agit', NULL, $3, $4, 'open', $5, $6, $6) RETURNING id",
    )
    .bind(trail_id)
    .bind(k)
    .bind(base)
    .bind(topic)
    .bind(creator_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let r = alloc_revision_number(&mut tx, change_id).await?;
    let rev_row = sqlx::query(
        "INSERT INTO revisions (change_id, number, head_sha, base_sha, pusher_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, change_id, number, head_sha, base_sha, merge_base_sha, pusher_id, created_at, \
         mergeability, conflict_paths",
    )
    .bind(change_id)
    .bind(r)
    .bind(head_sha)
    .bind(base_sha)
    .bind(pusher)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let revision = revision_from_row(&rev_row)?;
    sqlx::query("UPDATE changes SET current_revision_id = $1, updated_at = $2 WHERE id = $3")
        .bind(revision.id)
        .bind(now)
        .bind(change_id)
        .execute(&mut *tx)
        .await?;
    let change_row = sqlx::query(select_change!("WHERE id = $1"))
        .bind(change_id)
        .fetch_one(&mut *tx)
        .await?;
    let change = change_from_row(&change_row)?;
    tx.commit().await?;
    Ok((change, revision))
}

/// Revisions of the change in ascending number order.
pub async fn revisions_of_change(db: &Db, change_id: i64) -> DbResult<Vec<RevisionRow>> {
    let rows = sqlx::query(select_revision!("WHERE change_id = $1 ORDER BY number ASC"))
        .bind(change_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(revision_from_row).collect()
}

pub async fn revision_by_number(db: &Db, change_id: i64, r: i64) -> DbResult<Option<RevisionRow>> {
    let row = sqlx::query(select_revision!("WHERE change_id = $1 AND number = $2"))
        .bind(change_id)
        .bind(r)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(revision_from_row).transpose()
}

pub async fn set_revision_snapshot(
    db: &Db,
    revision_id: i64,
    merge_base: Option<&str>,
    status: &str,
    paths: &str,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE revisions SET merge_base_sha = $1, mergeability = $2, conflict_paths = $3 \
         WHERE id = $4",
    )
    .bind(merge_base)
    .bind(status)
    .bind(paths)
    .bind(revision_id)
    .execute(db.pool())
    .await?;
    Ok(())
}

async fn insert_review_row(db: &Db, n: &NewReview<'_>, now: i64) -> DbResult<ReviewRow> {
    let row = sqlx::query(
        "INSERT INTO reviews (change_id, revision_id, author_id, verdict, body, session_ulid, state, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'submitted', $7) \
         RETURNING id, change_id, revision_id, author_id, verdict, body, session_ulid, state, created_at",
    )
    .bind(n.change_id)
    .bind(n.revision_id)
    .bind(n.author_id)
    .bind(n.verdict)
    .bind(n.body)
    .bind(n.session_ulid)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    review_from_row(&row)
}

/// Inserts the review in `submitted` state. `session_ulid` is a plain TEXT
/// reference with no FK: the linked session lives partly outside the
/// DB-portable core, so existence is checked by the caller, never here.
#[allow(clippy::too_many_arguments)]
pub async fn insert_review(
    db: &Db,
    change_id: i64,
    revision_id: i64,
    author_id: i64,
    verdict: &str,
    body: &str,
    session_ulid: Option<&str>,
    now: i64,
) -> DbResult<ReviewRow> {
    insert_review_row(
        db,
        &NewReview {
            change_id,
            revision_id,
            author_id,
            verdict,
            body,
            session_ulid,
        },
        now,
    )
    .await
}

/// Reviews of the change in insert order.
pub async fn reviews_of_change(db: &Db, change_id: i64) -> DbResult<Vec<ReviewRow>> {
    let rows = sqlx::query(select_review!("WHERE change_id = $1 ORDER BY id ASC"))
        .bind(change_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(review_from_row).collect()
}

/// Reviews of one revision of the change, in insert order.
pub async fn reviews_of_change_revision(
    db: &Db,
    change_id: i64,
    revision_id: i64,
) -> DbResult<Vec<ReviewRow>> {
    let rows = sqlx::query(select_review!(
        "WHERE change_id = $1 AND revision_id = $2 ORDER BY id ASC"
    ))
    .bind(change_id)
    .bind(revision_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(review_from_row).collect()
}

pub async fn set_review_state(db: &Db, review_id: i64, state: &str) -> DbResult<()> {
    sqlx::query("UPDATE reviews SET state = $1 WHERE id = $2")
        .bind(state)
        .bind(review_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_thread(
    db: &Db,
    change_id: i64,
    anchor_revision_id: i64,
    path: &str,
    side: &str,
    start_line: i64,
    end_line: i64,
    now: i64,
) -> DbResult<ThreadRow> {
    let row = sqlx::query(
        "INSERT INTO review_threads (change_id, anchor_revision_id, path, side, start_line, end_line, \
         resolved, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 0, $7) \
         RETURNING id, change_id, anchor_revision_id, path, side, start_line, end_line, resolved, created_at",
    )
    .bind(change_id)
    .bind(anchor_revision_id)
    .bind(path)
    .bind(side)
    .bind(start_line)
    .bind(end_line)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    thread_from_row(&row)
}

/// Threads of the change in insert order, resolved and open alike.
pub async fn threads_of_change(db: &Db, change_id: i64) -> DbResult<Vec<ThreadRow>> {
    let rows = sqlx::query(select_thread!("WHERE change_id = $1 ORDER BY id ASC"))
        .bind(change_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(thread_from_row).collect()
}

pub async fn set_thread_resolved(db: &Db, thread_id: i64, resolved: i64) -> DbResult<()> {
    sqlx::query("UPDATE review_threads SET resolved = $1 WHERE id = $2")
        .bind(resolved)
        .bind(thread_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn insert_thread_comment(
    db: &Db,
    thread_id: i64,
    review_id: Option<i64>,
    author_id: i64,
    body: &str,
    now: i64,
) -> DbResult<ReviewCommentRow> {
    let row = sqlx::query(
        "INSERT INTO review_comments (thread_id, review_id, author_id, body, created_at) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, thread_id, review_id, author_id, body, created_at",
    )
    .bind(thread_id)
    .bind(review_id)
    .bind(author_id)
    .bind(body)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    comment_from_row(&row)
}

/// Comments of the thread in insert order.
pub async fn comments_of_thread(db: &Db, thread_id: i64) -> DbResult<Vec<ReviewCommentRow>> {
    let rows = sqlx::query(select_comment!("WHERE thread_id = $1 ORDER BY id ASC"))
        .bind(thread_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(comment_from_row).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
    use crate::testing::TestDb;
    use crate::trails::{self, NewTrail};
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

    async fn setup() -> (TestDb, i64, i64, i64) {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("alice")).await.unwrap();
        let bob = users::insert(&t.db, &user("bob")).await.unwrap();
        let repo_id = repos::insert(&t.db, &repo(alice, "demo")).await.unwrap();
        (t, alice, bob, repo_id)
    }

    async fn trail(t: &TestDb, repo_id: i64, alice: i64, title: &str, now: i64) -> i64 {
        trails::insert_trail(
            &t.db,
            &NewTrail {
                repo_id,
                title,
                intent: "do the thing",
                author_id: alice,
            },
            now,
        )
        .await
        .unwrap()
        .id
    }

    async fn agit(
        t: &TestDb,
        trail_id: i64,
        creator: i64,
        base: &str,
        topic: &str,
        now: i64,
    ) -> ChangeRow {
        insert_change(&t.db, trail_id, "agit", Some(topic), base, creator, now)
            .await
            .unwrap()
    }

    async fn revision(t: &TestDb, change_id: i64, sha: &str, pusher: i64, now: i64) -> RevisionRow {
        insert_revision(&t.db, change_id, sha, "base0", Some(pusher), now)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn numbers_allocate_per_trail() {
        let (t, alice, _bob, repo_id) = setup().await;
        let trail_a = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let trail_b = trail(&t, repo_id, alice, "b", 1_700_000_001).await;
        let a1 = agit(&t, trail_a, alice, "main", "one", 1_700_000_002).await;
        let a2 = agit(&t, trail_a, alice, "main", "two", 1_700_000_003).await;
        assert_eq!(a1.number, 1);
        assert_eq!(a2.number, 2);
        assert_eq!(a1.topic, "one");
        assert_eq!(a1.head_branch, None);
        assert_eq!(a1.base_branch, "main");
        assert_eq!(a1.state, "open");
        assert_eq!(a1.creator_id, Some(alice));
        assert_eq!(a1.mergeability, "unknown");
        assert_eq!(a1.conflict_paths, "");

        let got = change_by_trail_number(&t.db, trail_a, 1)
            .await
            .unwrap()
            .expect("change #1 present");
        assert_eq!(got.id, a1.id);
        assert!(
            change_by_trail_number(&t.db, trail_a, 99)
                .await
                .unwrap()
                .is_none()
        );

        let b1 = agit(&t, trail_b, alice, "main", "one", 1_700_000_004).await;
        assert_eq!(b1.number, 1, "numbering restarts per trail");

        let rows = changes_of_trail(&t.db, trail_a).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.number).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[tokio::test]
    async fn revisions_allocate_per_change() {
        let (t, alice, _bob, repo_id) = setup().await;
        let trail_id = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let c1 = agit(&t, trail_id, alice, "main", "one", 1_700_000_001).await;
        let c2 = agit(&t, trail_id, alice, "main", "two", 1_700_000_002).await;
        let r1 = revision(&t, c1.id, "a001", alice, 1_700_000_003).await;
        let r2 = revision(&t, c1.id, "a002", alice, 1_700_000_004).await;
        assert_eq!(r1.number, 1);
        assert_eq!(r2.number, 2);
        assert_eq!(r1.merge_base_sha, None);
        assert_eq!(r1.mergeability, "unknown");

        let got = revision_by_number(&t.db, c1.id, 2)
            .await
            .unwrap()
            .expect("revision #2 present");
        assert_eq!(got.id, r2.id);
        assert!(
            revision_by_number(&t.db, c1.id, 99)
                .await
                .unwrap()
                .is_none()
        );

        let other = revision(&t, c2.id, "b001", alice, 1_700_000_005).await;
        assert_eq!(other.number, 1, "numbering restarts per change");

        let rows = revisions_of_change(&t.db, c1.id).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.number).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[tokio::test]
    async fn duplicate_numbers_are_unique_violations() {
        let (t, alice, _bob, repo_id) = setup().await;
        let trail_id = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        agit(&t, trail_id, alice, "main", "one", 1_700_000_001).await;
        let err = sqlx::query(
            "INSERT INTO changes (trail_id, number, kind, base_branch, topic, creator_id, created_at, updated_at) \
             VALUES ($1, $2, 'agit', 'main', 'dup', $3, $4, $4)",
        )
        .bind(trail_id)
        .bind(1)
        .bind(alice)
        .bind(1_700_000_002)
        .execute(t.db.pool())
        .await
        .expect_err("duplicate (trail_id, number) must fail");
        assert!(
            err.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false),
            "expected a unique violation, got {err:?}"
        );

        let change = change_by_trail_number(&t.db, trail_id, 1)
            .await
            .unwrap()
            .unwrap();
        revision(&t, change.id, "a001", alice, 1_700_000_003).await;
        let err = sqlx::query(
            "INSERT INTO revisions (change_id, number, head_sha, base_sha, created_at) \
             VALUES ($1, $2, 'x', 'y', $3)",
        )
        .bind(change.id)
        .bind(1)
        .bind(1_700_000_004)
        .execute(t.db.pool())
        .await
        .expect_err("duplicate (change_id, number) must fail");
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
        let trail_id = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let a = agit(&t, trail_id, alice, "main", "one", 1_700_000_001).await;
        assert_eq!(a.number, 1);
        // A change insert that fails after allocating (here: dangling trail_id
        // trips the FK) rolls the sequence back with it …
        let err = insert_change(
            &t.db,
            999_999,
            "agit",
            Some("bad"),
            "main",
            alice,
            1_700_000_002,
        )
        .await
        .expect_err("dangling trail must fail");
        assert!(!crate::DbError::is_unique_violation(&err));
        // … so the next create reuses the number instead of skipping it.
        let b = agit(&t, trail_id, alice, "main", "two", 1_700_000_003).await;
        assert_eq!(b.number, 2);

        // Same guarantee for revisions: a dangling pusher trips the FK after
        // the sequence row was bumped, and the number is returned.
        let r1 = revision(&t, a.id, "a001", alice, 1_700_000_004).await;
        assert_eq!(r1.number, 1);
        let err = insert_revision(&t.db, a.id, "bad", "base0", Some(999_999), 1_700_000_005)
            .await
            .expect_err("dangling pusher must fail");
        assert!(!crate::DbError::is_unique_violation(&err));
        let r2 = revision(&t, a.id, "a002", alice, 1_700_000_006).await;
        assert_eq!(r2.number, 2);
    }

    #[tokio::test]
    async fn open_agit_change_scoping() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail_a = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let trail_b = trail(&t, repo_id, alice, "b", 1_700_000_001).await;
        let open = agit(&t, trail_a, alice, "main", "feat", 1_700_000_002).await;
        // Closed twin with the same key is ignored.
        let closed = agit(&t, trail_b, alice, "main", "feat", 1_700_000_003).await;
        set_change_state(&t.db, closed.id, "closed", 1_700_000_004)
            .await
            .unwrap();
        // Other user's twin with the same base/topic is ignored.
        let _bobs = agit(&t, trail_a, bob, "main", "feat", 1_700_000_005).await;

        let got = open_agit_change(&t.db, repo_id, alice, "main", "feat", None)
            .await
            .unwrap()
            .expect("open agit change present");
        assert_eq!(got.id, open.id);

        let scoped = open_agit_change(&t.db, repo_id, alice, "main", "feat", Some(trail_a))
            .await
            .unwrap()
            .expect("trail-scoped lookup finds the row");
        assert_eq!(scoped.id, open.id);

        let missing = open_agit_change(&t.db, repo_id, alice, "main", "feat", Some(trail_b))
            .await
            .unwrap();
        assert!(missing.is_none(), "closed twin stays ignored when scoped");

        assert!(
            open_agit_change(&t.db, repo_id, bob, "main", "feat", None)
                .await
                .unwrap()
                .is_some(),
            "bob finds his own twin"
        );
        assert!(
            open_agit_change(&t.db, repo_id, alice, "main", "nope", None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            open_agit_change(&t.db, repo_id, alice, "other", "feat", None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn review_thread_comment_round_trip() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail_id = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let change = agit(&t, trail_id, alice, "main", "one", 1_700_000_001).await;
        let rev = revision(&t, change.id, "a001", alice, 1_700_000_002).await;

        let review = insert_review(
            &t.db,
            change.id,
            rev.id,
            bob,
            "comment",
            "looks good",
            None,
            1_700_000_003,
        )
        .await
        .unwrap();
        assert_eq!(review.state, "submitted");
        assert_eq!(review.session_ulid, None);
        set_review_state(&t.db, review.id, "dismissed")
            .await
            .unwrap();

        let with_session = insert_review(
            &t.db,
            change.id,
            rev.id,
            alice,
            "approve",
            "ship it",
            Some("01SESSIONULID"),
            1_700_000_004,
        )
        .await
        .unwrap();
        assert_eq!(with_session.session_ulid.as_deref(), Some("01SESSIONULID"));

        let reviews = reviews_of_change(&t.db, change.id).await.unwrap();
        assert_eq!(reviews.len(), 2);
        assert_eq!(reviews[0].state, "dismissed");
        let scoped = reviews_of_change_revision(&t.db, change.id, rev.id + 999)
            .await
            .unwrap();
        assert!(scoped.is_empty());
        let scoped = reviews_of_change_revision(&t.db, change.id, rev.id)
            .await
            .unwrap();
        assert_eq!(scoped.len(), 2);

        let thread = insert_thread(
            &t.db,
            change.id,
            rev.id,
            "src/main.rs",
            "head",
            10,
            20,
            1_700_000_005,
        )
        .await
        .unwrap();
        assert_eq!(thread.resolved, 0);
        let threads = threads_of_change(&t.db, change.id).await.unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].path, "src/main.rs");
        set_thread_resolved(&t.db, thread.id, 1).await.unwrap();
        let threads = threads_of_change(&t.db, change.id).await.unwrap();
        assert_eq!(threads[0].resolved, 1);

        let c1 = insert_thread_comment(
            &t.db,
            thread.id,
            Some(review.id),
            bob,
            "first",
            1_700_000_006,
        )
        .await
        .unwrap();
        assert_eq!(c1.review_id, Some(review.id));
        let c2 = insert_thread_comment(&t.db, thread.id, None, alice, "second", 1_700_000_007)
            .await
            .unwrap();
        assert_eq!(c2.review_id, None);
        let comments = comments_of_thread(&t.db, thread.id).await.unwrap();
        assert_eq!(
            comments.iter().map(|c| c.body.clone()).collect::<Vec<_>>(),
            vec!["first".to_owned(), "second".to_owned()]
        );
    }

    #[tokio::test]
    async fn mergeability_and_current_revision_round_trip() {
        let (t, alice, _bob, repo_id) = setup().await;
        let trail_id = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let change = agit(&t, trail_id, alice, "main", "one", 1_700_000_001).await;
        let rev = revision(&t, change.id, "a001", alice, 1_700_000_002).await;

        set_current_revision(&t.db, change.id, rev.id, 1_700_000_003)
            .await
            .unwrap();
        set_mergeability(&t.db, change.id, "clean", "")
            .await
            .unwrap();
        let got = change_by_trail_number(&t.db, trail_id, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.current_revision_id, Some(rev.id));
        assert_eq!(got.mergeability, "clean");

        set_mergeability(&t.db, change.id, "conflict", "a.txt\nb.txt")
            .await
            .unwrap();
        set_revision_snapshot(&t.db, rev.id, Some("mb1"), "conflict", "a.txt\nb.txt")
            .await
            .unwrap();
        let revs = revisions_of_change(&t.db, change.id).await.unwrap();
        assert_eq!(revs[0].merge_base_sha.as_deref(), Some("mb1"));
        assert_eq!(revs[0].mergeability, "conflict");
        assert_eq!(revs[0].conflict_paths, "a.txt\nb.txt");
    }

    #[tokio::test]
    async fn user_delete_nulls_change_authors() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail_id = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let change = agit(&t, trail_id, alice, "main", "one", 1_700_000_001).await;
        let rev = revision(&t, change.id, "a001", bob, 1_700_000_002).await;
        let review = insert_review(
            &t.db,
            change.id,
            rev.id,
            bob,
            "comment",
            "hi",
            None,
            1_700_000_003,
        )
        .await
        .unwrap();
        let thread = insert_thread(
            &t.db,
            change.id,
            rev.id,
            "f.rs",
            "head",
            1,
            2,
            1_700_000_004,
        )
        .await
        .unwrap();
        insert_thread_comment(
            &t.db,
            thread.id,
            Some(review.id),
            bob,
            "note",
            1_700_000_005,
        )
        .await
        .unwrap();
        assert_eq!(change.creator_id, Some(alice));
        assert_eq!(rev.pusher_id, Some(bob));

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

        let change = change_by_trail_number(&t.db, trail_id, 1)
            .await
            .unwrap()
            .expect("change survives creator delete");
        assert_eq!(change.creator_id, None);
        let revs = revisions_of_change(&t.db, change.id).await.unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].pusher_id, None);
        let reviews = reviews_of_change(&t.db, change.id).await.unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].author_id, None);
        let comments = comments_of_thread(&t.db, thread.id).await.unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].author_id, None);
    }

    #[tokio::test]
    async fn change_cascade_deletes_aggregate() {
        let (t, alice, bob, repo_id) = setup().await;
        let trail_id = trail(&t, repo_id, alice, "a", 1_700_000_000).await;
        let change = agit(&t, trail_id, alice, "main", "one", 1_700_000_001).await;
        let rev = revision(&t, change.id, "a001", alice, 1_700_000_002).await;
        let review = insert_review(
            &t.db,
            change.id,
            rev.id,
            bob,
            "comment",
            "hi",
            None,
            1_700_000_003,
        )
        .await
        .unwrap();
        let thread = insert_thread(
            &t.db,
            change.id,
            rev.id,
            "f.rs",
            "head",
            1,
            2,
            1_700_000_004,
        )
        .await
        .unwrap();
        insert_thread_comment(
            &t.db,
            thread.id,
            Some(review.id),
            bob,
            "note",
            1_700_000_005,
        )
        .await
        .unwrap();

        sqlx::query("DELETE FROM changes WHERE id = $1")
            .bind(change.id)
            .execute(t.db.pool())
            .await
            .unwrap();
        assert!(
            revisions_of_change(&t.db, change.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            reviews_of_change(&t.db, change.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            threads_of_change(&t.db, change.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            comments_of_thread(&t.db, thread.id)
                .await
                .unwrap()
                .is_empty()
        );
        let seq: Option<i64> =
            sqlx::query_scalar("SELECT next_number FROM revision_sequences WHERE change_id = $1")
                .bind(change.id)
                .fetch_optional(t.db.pool())
                .await
                .unwrap()
                .flatten();
        assert!(seq.is_none(), "revision sequence cascades with the change");
    }

    #[tokio::test]
    async fn refs_for_access_default_and_update() {
        let (t, alice, _bob, _repo_id) = setup().await;
        let repo_id = repos::insert(&t.db, &repo(alice, "gated")).await.unwrap();
        assert_eq!(
            repos::refs_for_access(&t.db, repo_id).await.unwrap(),
            "anyone_with_read"
        );
        repos::set_refs_for_access(&t.db, repo_id, "members")
            .await
            .unwrap();
        assert_eq!(
            repos::refs_for_access(&t.db, repo_id).await.unwrap(),
            "members"
        );
        let err = repos::set_refs_for_access(&t.db, repo_id, "everyone")
            .await
            .expect_err("outside the CHECK set must fail");
        assert!(!crate::DbError::is_unique_violation(&err));
        assert_eq!(
            repos::refs_for_access(&t.db, repo_id).await.unwrap(),
            "members",
            "failed update changes nothing"
        );
    }
}
