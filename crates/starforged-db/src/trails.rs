//! `trails`: issue-like discussion objects scoped to a repository.
//!
//! Numbering is per repository (`UNIQUE (repo_id, number)`): `insert_trail`
//! allocates the next number with a single `INSERT … SELECT COALESCE(MAX(number), 0) + 1`
//! statement and the caller retries on unique violation. The data-access layer stays
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
    pub author_id: i64,
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
    pub author_id: i64,
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
    pub after: Option<i64>,
    pub limit: i64,
}

impl Default for TrailFilter {
    fn default() -> Self {
        TrailFilter {
            state: None,
            label: None,
            assignee_id: None,
            author_id: None,
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
            "SELECT id, repo_id, number, title, intent, state, ready, author_id, created_at, updated_at, closed_at, ",
            "merged_at FROM trails ",
            $tail
        )
    };
}

macro_rules! select_comment {
    ($tail:literal) => {
        concat!(
            "SELECT id, trail_id, author_id, body, created_at, edited_at FROM trail_comments ",
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

/// Inserts the trail, allocating the next per-repo number atomically: the aggregate
/// over the repo's rows yields one row even when the repo has no trails yet, so this
/// always inserts exactly one row. The caller retries on unique violation.
pub async fn insert_trail(db: &Db, t: &NewTrail<'_>, now: i64) -> DbResult<TrailRow> {
    let row = sqlx::query(
        "INSERT INTO trails (repo_id, number, title, intent, state, ready, author_id, created_at, updated_at) \
         SELECT $1, COALESCE(MAX(number), 0) + 1, $2, $3, 'open', 0, $4, $5, $5 FROM trails WHERE repo_id = $1 \
         RETURNING id, repo_id, number, title, intent, state, ready, author_id, created_at, updated_at, closed_at, merged_at",
    )
    .bind(t.repo_id)
    .bind(t.title)
    .bind(t.intent)
    .bind(t.author_id)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    trail_from_row(&row)
}

pub async fn trail_by_number(db: &Db, repo_id: i64, number: i64) -> DbResult<Option<TrailRow>> {
    let row = sqlx::query(select_trail!("WHERE repo_id = $1 AND number = $2"))
        .bind(repo_id)
        .bind(number)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(trail_from_row).transpose()
}

/// Trails of the repository in ascending number order, at most `f.limit` rows.
/// Every filter is optional: `after` is the keyset cursor (rows above it only),
/// label/assignee match through `EXISTS` subqueries, state/author directly.
pub async fn trails_of_repo(db: &Db, repo_id: i64, f: &TrailFilter) -> DbResult<Vec<TrailRow>> {
    let rows = sqlx::query(select_trail!(
        "WHERE repo_id = $1 AND ($2 IS NULL OR number > $2) AND ($3 IS NULL OR state = $3) \
         AND ($4 IS NULL OR author_id = $4) \
         AND ($5 IS NULL OR EXISTS (SELECT 1 FROM trail_labels WHERE trail_id = trails.id AND name = $5)) \
         AND ($6 IS NULL OR EXISTS (SELECT 1 FROM trail_assignees WHERE trail_id = trails.id AND user_id = $6)) \
         ORDER BY number ASC LIMIT $7"
    ))
    .bind(repo_id)
    .bind(f.after)
    .bind(f.state.as_deref())
    .bind(f.author_id)
    .bind(f.label.as_deref())
    .bind(f.assignee_id)
    .bind(f.limit)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(trail_from_row).collect()
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

pub async fn insert_comment(
    db: &Db,
    trail_id: i64,
    author_id: i64,
    body: &str,
    now: i64,
) -> DbResult<TrailCommentRow> {
    let row = sqlx::query(
        "INSERT INTO trail_comments (trail_id, author_id, body, created_at) VALUES ($1, $2, $3, $4) \
         RETURNING id, trail_id, author_id, body, created_at, edited_at",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbError;
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
        assert!(DbError::from(err).is_unique_violation());
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
}
