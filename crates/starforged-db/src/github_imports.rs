//! `github_imports`: the one resumable GitHub-import record per repository
//! (M4c, spec §8.6). The importer (a later task) advances `cursor_kind` /
//! `cursor_page` / `cursor_number` and the counts as it goes, so a
//! rate-limited or failed run resumes without duplicating an object: every
//! object import is keyed by its unique `github_id` column. `token_sealed`
//! holds the GitHub token sealed with the M4b credential box; it is never
//! read outside the job and is cleared with [`clear_token`] on finish or
//! failure. The data-access layer stays thin — no validation or permission
//! checks here (those live in `starforged-core`).

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubImportRow {
    pub id: i64,
    pub repo_id: i64,
    pub source: String,
    pub state: String,
    pub cursor_kind: String,
    pub cursor_page: i64,
    pub cursor_number: Option<i64>,
    pub issues_count: i64,
    pub pulls_count: i64,
    pub comments_count: i64,
    pub reviews_count: i64,
    pub review_comments_count: i64,
    pub dropped_assignees: String,
    pub token_sealed: Option<String>,
    pub error: Option<String>,
    pub failures: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

macro_rules! select_import {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, source, state, cursor_kind, cursor_page, cursor_number, ",
            "issues_count, pulls_count, comments_count, reviews_count, review_comments_count, ",
            "dropped_assignees, token_sealed, error, failures, created_at, updated_at, ",
            "started_at, finished_at FROM github_imports ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<GithubImportRow> {
    Ok(GithubImportRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        source: row.try_get("source")?,
        state: row.try_get("state")?,
        cursor_kind: row.try_get("cursor_kind")?,
        cursor_page: row.try_get("cursor_page")?,
        cursor_number: row.try_get("cursor_number")?,
        issues_count: row.try_get("issues_count")?,
        pulls_count: row.try_get("pulls_count")?,
        comments_count: row.try_get("comments_count")?,
        reviews_count: row.try_get("reviews_count")?,
        review_comments_count: row.try_get("review_comments_count")?,
        dropped_assignees: row.try_get("dropped_assignees")?,
        token_sealed: row.try_get("token_sealed")?,
        error: row.try_get("error")?,
        failures: row.try_get("failures")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

/// Creates (or returns the existing) import record for the repository:
/// starting an import is idempotent, so a retry never resets progress.
pub async fn get_or_create(db: &Db, repo_id: i64, source: &str) -> DbResult<GithubImportRow> {
    let t = now();
    sqlx::query(
        "INSERT INTO github_imports (repo_id, source, state, cursor_kind, cursor_page, created_at, updated_at) \
         VALUES ($1, $2, 'pending', '', 1, $3, $3) \
         ON CONFLICT (repo_id) DO NOTHING",
    )
    .bind(repo_id)
    .bind(source)
    .bind(t)
    .execute(db.pool())
    .await?;
    import_of_repo(db, repo_id)
        .await?
        .ok_or_else(|| crate::DbError::Sqlx(sqlx::Error::RowNotFound))
}

pub async fn import_of_repo(db: &Db, repo_id: i64) -> DbResult<Option<GithubImportRow>> {
    let row = sqlx::query(select_import!("WHERE repo_id = $1"))
        .bind(repo_id)
        .fetch_optional(db.read_pool())
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub async fn set_state(db: &Db, id: i64, state: &str) -> DbResult<()> {
    sqlx::query("UPDATE github_imports SET state = $1, updated_at = $2 WHERE id = $3")
        .bind(state)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Saves the resumption cursor: which listing phase, which page, and the
/// last imported GitHub number.
pub async fn set_cursor(
    db: &Db,
    id: i64,
    kind: &str,
    page: i64,
    number: Option<i64>,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE github_imports SET cursor_kind = $1, cursor_page = $2, cursor_number = $3, updated_at = $4 WHERE id = $5",
    )
    .bind(kind)
    .bind(page)
    .bind(number)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Adds to the object counts (the importer calls this once per imported
/// object, so a resumed run's totals stay exact).
pub async fn add_counts(
    db: &Db,
    id: i64,
    issues: i64,
    pulls: i64,
    comments: i64,
    reviews: i64,
    review_comments: i64,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE github_imports SET issues_count = issues_count + $1, pulls_count = pulls_count + $2, \
         comments_count = comments_count + $3, reviews_count = reviews_count + $4, \
         review_comments_count = review_comments_count + $5, updated_at = $6 WHERE id = $7",
    )
    .bind(issues)
    .bind(pulls)
    .bind(comments)
    .bind(reviews)
    .bind(review_comments)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn set_token_sealed(db: &Db, id: i64, sealed: Option<&str>) -> DbResult<()> {
    sqlx::query("UPDATE github_imports SET token_sealed = $1, updated_at = $2 WHERE id = $3")
        .bind(sealed)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Deletes the sealed token: called when the import finishes or fails.
pub async fn clear_token(db: &Db, id: i64) -> DbResult<()> {
    set_token_sealed(db, id, None).await
}

pub async fn set_error(db: &Db, id: i64, error: Option<&str>, failures: i64) -> DbResult<()> {
    sqlx::query(
        "UPDATE github_imports SET error = $1, failures = $2, updated_at = $3 WHERE id = $4",
    )
    .bind(error)
    .bind(failures)
    .bind(now())
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn set_dropped_assignees(db: &Db, id: i64, dropped: &str) -> DbResult<()> {
    sqlx::query("UPDATE github_imports SET dropped_assignees = $1, updated_at = $2 WHERE id = $3")
        .bind(dropped)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_started(db: &Db, id: i64, t: i64) -> DbResult<()> {
    sqlx::query("UPDATE github_imports SET started_at = $1, updated_at = $2 WHERE id = $3")
        .bind(t)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_finished(db: &Db, id: i64, t: i64) -> DbResult<()> {
    sqlx::query("UPDATE github_imports SET finished_at = $1, updated_at = $2 WHERE id = $3")
        .bind(t)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
