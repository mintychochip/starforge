//! `jobs`: the durable background queue (forge-basics design §8). Workers claim due rows with a guarded
//! `UPDATE … WHERE state = 'queued'`, which behaves the same on SQLite and Postgres.
//!
//! A request for a deduplicated job that arrives while the same-key job is running is dropped,
//! unless the job opted into reruns ([`NewJob`]): then `rerun_at` records it on the running row and
//! the job runs once more after the current run finishes.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbError, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
    pub id: i64,
    pub kind: String,
    pub payload: String,
    pub state: String,
    pub dedupe_key: Option<String>,
    pub run_at: i64,
    pub rerun_at: Option<i64>,
    pub attempts: i64,
    pub locked_until: Option<i64>,
    pub last_error: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct NewJob<'a> {
    pub kind: &'a str,
    pub payload: &'a str,
    /// At most one job per key is queued or running (partial unique index `jobs_dedupe`): a colliding
    /// request is dropped, unless `rerun_if_running` asks for a rerun while the same-key job runs.
    pub dedupe_key: Option<&'a str>,
    pub run_at: i64,
    /// When set, an insert that collides with a running same-key job records `rerun_at = run_at` on
    /// the running row, so it runs once more after the current run finishes. A collision with a
    /// queued copy records nothing: the queued copy re-reads state when it runs. Without this flag
    /// the colliding request is dropped as before.
    pub rerun_if_running: bool,
}

macro_rules! select_job {
    ($tail:literal) => {
        concat!(
            "SELECT id, kind, payload, state, dedupe_key, run_at, rerun_at, attempts, locked_until, last_error, created_at, updated_at ",
            "FROM jobs ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<JobRow> {
    Ok(JobRow {
        id: row.try_get("id")?,
        kind: row.try_get("kind")?,
        payload: row.try_get("payload")?,
        state: row.try_get("state")?,
        dedupe_key: row.try_get("dedupe_key")?,
        run_at: row.try_get("run_at")?,
        rerun_at: row.try_get("rerun_at")?,
        attempts: row.try_get("attempts")?,
        locked_until: row.try_get("locked_until")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// Queues a job and returns its id, or `None` when `dedupe_key` is set and a job with that key is
/// already queued or running. With `rerun_if_running`, a colliding request records `rerun_at` on a
/// running same-key job and still returns `None`; the running job runs once more after it finishes.
/// A collision with a queued copy records nothing.
pub async fn insert(db: &Db, job: &NewJob<'_>) -> DbResult<Option<i64>> {
    let ts = now();
    let mut round = 0;
    loop {
        let inserted: Result<i64, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO jobs (kind, payload, dedupe_key, run_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(job.kind)
        .bind(job.payload)
        .bind(job.dedupe_key.map(str::to_owned))
        .bind(job.run_at)
        .bind(ts)
        .bind(ts)
        .fetch_one(db.pool())
        .await;
        match inserted {
            Ok(id) => return Ok(Some(id)),
            Err(err) => {
                let err = DbError::from(err);
                if job.dedupe_key.is_none() || !err.is_unique_violation() {
                    return Err(err);
                }
                if !job.rerun_if_running {
                    return Ok(None);
                }
                let affected = sqlx::query(
                    "UPDATE jobs SET rerun_at = CASE WHEN state = 'running' AND (rerun_at IS NULL OR rerun_at > $1) THEN $1 ELSE rerun_at END \
                     WHERE dedupe_key = $2 AND state IN ('queued', 'running')",
                )
                .bind(job.run_at)
                .bind(job.dedupe_key.map(str::to_owned))
                .execute(db.pool())
                .await?
                .rows_affected();
                if affected >= 1 {
                    return Ok(None);
                }
                // The colliding row finished in between: retry the insert. Every
                // retry needs another same-key row to start and finish meanwhile,
                // so the bound is never hit in practice; when it is, the last
                // collision is the error.
                round += 1;
                if round == 8 {
                    return Err(err);
                }
            }
        }
    }
}

/// Makes the queued job for `dedupe_key` due at `run_at` (a "run now"
/// nudge while a scheduled copy is already queued). A running or absent
/// row is untouched: a running job already covers the request.
pub async fn expedite(db: &Db, dedupe_key: &str, run_at: i64) -> DbResult<()> {
    sqlx::query(
        "UPDATE jobs SET run_at = $1, updated_at = $1 \
         WHERE dedupe_key = $2 AND state = 'queued'",
    )
    .bind(run_at)
    .bind(dedupe_key)
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<JobRow>> {
    let row = sqlx::query(select_job!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// Claims the oldest due queued job for `lease_secs` and returns it; `None` when nothing is due.
pub async fn claim_next(db: &Db, now_ts: i64, lease_secs: i64) -> DbResult<Option<JobRow>> {
    loop {
        let id: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM jobs WHERE state = 'queued' AND run_at <= $1 ORDER BY run_at, id LIMIT 1",
        )
        .bind(now_ts)
        .fetch_optional(db.pool())
        .await?;
        let Some(id) = id else {
            return Ok(None);
        };
        let claimed = sqlx::query(
            "UPDATE jobs SET state = 'running', locked_until = $1, attempts = attempts + 1, updated_at = $2 \
             WHERE id = $3 AND state = 'queued'",
        )
        .bind(now_ts + lease_secs)
        .bind(now_ts)
        .bind(id)
        .execute(db.pool())
        .await?
        .rows_affected();
        if claimed == 1 {
            return by_id(db, id).await;
        }
        // Another worker claimed it between the SELECT and the UPDATE; look for the next one.
    }
}

/// Marks the row `done` and returns the `rerun_at` recorded by a request that arrived while it ran
/// (see [`insert`]); `None` when no rerun was requested or the id is unknown.
pub async fn complete(db: &Db, id: i64) -> DbResult<Option<i64>> {
    let rerun_at: Option<Option<i64>> = sqlx::query_scalar(
        "UPDATE jobs SET state = 'done', locked_until = NULL, updated_at = $1 WHERE id = $2 RETURNING rerun_at",
    )
    .bind(now())
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    Ok(rerun_at.flatten())
}

/// Records a failed attempt: back to `queued` at `retry_at`, or `failed` for good when `retry_at` is `None`.
/// A retry clears any recorded rerun (the retry re-reads state) and returns `None`; a permanent failure
/// returns the recorded rerun so the caller runs the job once more.
pub async fn fail(db: &Db, id: i64, error: &str, retry_at: Option<i64>) -> DbResult<Option<i64>> {
    let ts = now();
    match retry_at {
        Some(at) => {
            sqlx::query(
                "UPDATE jobs SET state = 'queued', run_at = $1, locked_until = NULL, last_error = $2, updated_at = $3, rerun_at = NULL \
                 WHERE id = $4",
            )
            .bind(at)
            .bind(error)
            .bind(ts)
            .bind(id)
            .execute(db.pool())
            .await?;
            Ok(None)
        }
        None => {
            let rerun_at: Option<Option<i64>> = sqlx::query_scalar(
                "UPDATE jobs SET state = 'failed', locked_until = NULL, last_error = $1, updated_at = $2 WHERE id = $3 RETURNING rerun_at",
            )
            .bind(error)
            .bind(ts)
            .bind(id)
            .fetch_optional(db.pool())
            .await?;
            Ok(rerun_at.flatten())
        }
    }
}

/// Running jobs whose lease ended before `now_ts` belonged to a worker that stopped. They go back to the
/// queue, or to `failed` once they have used `max_attempts`. Returns how many rows changed.
pub async fn requeue_expired(db: &Db, now_ts: i64, max_attempts: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "UPDATE jobs SET state = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'queued' END, \
         locked_until = NULL, rerun_at = CASE WHEN attempts >= $1 THEN rerun_at ELSE NULL END, \
         last_error = 'the worker stopped before finishing', updated_at = $2 \
         WHERE state = 'running' AND locked_until < $3",
    )
    .bind(max_attempts)
    .bind(now_ts)
    .bind(now_ts)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected())
}

/// Replaces a job's payload (to blank a sent message). Leaves `updated_at` alone.
pub async fn set_payload(db: &Db, id: i64, payload: &str) -> DbResult<()> {
    sqlx::query("UPDATE jobs SET payload = $1 WHERE id = $2")
        .bind(payload)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Deletes `done` jobs last updated before `done_before` and `failed` jobs last updated before
/// `failed_before`. Returns how many were deleted.
pub async fn prune(db: &Db, done_before: i64, failed_before: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "DELETE FROM jobs WHERE (state = 'done' AND updated_at < $1) OR (state = 'failed' AND updated_at < $2)",
    )
    .bind(done_before)
    .bind(failed_before)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected())
}

/// `failed` jobs of `kind` last updated before `before`, oldest first.
pub async fn failed_of_kind_before(db: &Db, kind: &str, before: i64) -> DbResult<Vec<JobRow>> {
    let rows = sqlx::query(select_job!(
        "WHERE state = 'failed' AND kind = $1 AND updated_at < $2 ORDER BY id"
    ))
    .bind(kind)
    .bind(before)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// The newest jobs first, capped; callers filter states in Rust to keep one static query.
pub async fn list_recent(db: &Db, limit: i64) -> DbResult<Vec<JobRow>> {
    let rows = sqlx::query(select_job!("ORDER BY run_at DESC, id DESC LIMIT $1"))
        .bind(limit)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(from_row).collect()
}

/// Re-queues a failed job now; false when the job is missing or not failed.
pub async fn retry_failed(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let changed = sqlx::query(
        "UPDATE jobs SET state = 'queued', run_at = $1, locked_until = NULL, rerun_at = NULL, updated_at = $1 WHERE id = $2 AND state = 'failed'",
    )
    .bind(now_ts)
    .bind(id)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(changed > 0)
}

/// Deletes a failed job; false when the job is missing or not failed.
pub async fn delete_job(db: &Db, id: i64) -> DbResult<bool> {
    let removed = sqlx::query("DELETE FROM jobs WHERE id = $1 AND state = 'failed'")
        .bind(id)
        .execute(db.pool())
        .await?
        .rows_affected();
    Ok(removed > 0)
}

pub async fn count_by_state(db: &Db, state: &str) -> DbResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE state = $1")
            .bind(state)
            .fetch_one(db.read_pool())
            .await?,
    )
}
/// Job counts grouped by kind and state, ordered by kind then state.
pub async fn counts_by_kind_state(db: &Db) -> DbResult<Vec<(String, String, i64)>> {
    let rows = sqlx::query("SELECT kind, state, COUNT(*) AS n FROM jobs GROUP BY kind, state ORDER BY kind ASC, state ASC")
        .fetch_all(db.read_pool())
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.push((
            row.try_get("kind")?,
            row.try_get("state")?,
            row.try_get("n")?,
        ));
    }
    Ok(out)
}

/// The `created_at` of the longest-waiting queued job, if any is queued.
pub async fn oldest_pending_created(db: &Db) -> DbResult<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT MIN(created_at) FROM jobs WHERE state = 'queued'")
            .fetch_one(db.read_pool())
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDb;

    fn job(key: Option<&'static str>, run_at: i64) -> NewJob<'static> {
        NewJob {
            kind: "test",
            payload: "{}",
            dedupe_key: key,
            run_at,
            rerun_if_running: false,
        }
    }

    fn rerun_job(key: Option<&'static str>, run_at: i64) -> NewJob<'static> {
        NewJob {
            kind: "test",
            payload: "{}",
            dedupe_key: key,
            run_at,
            rerun_if_running: true,
        }
    }

    #[tokio::test]
    async fn dedupe_keys_allow_one_pending_job() {
        let t = TestDb::new().await;
        let first = insert(&t.db, &job(Some("k"), 0)).await.unwrap().unwrap();
        assert_eq!(insert(&t.db, &job(Some("k"), 0)).await.unwrap(), None);
        assert!(insert(&t.db, &job(None, 0)).await.unwrap().is_some());
        assert!(
            insert(&t.db, &job(None, 0)).await.unwrap().is_some(),
            "jobs without a key never collide"
        );
        let claimed = claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        assert_eq!(claimed.id, first);
        assert_eq!(
            insert(&t.db, &job(Some("k"), 0)).await.unwrap(),
            None,
            "a running job still holds its key"
        );
        complete(&t.db, first).await.unwrap();
        assert!(
            insert(&t.db, &job(Some("k"), 0)).await.unwrap().is_some(),
            "a finished job frees its key"
        );
    }

    #[tokio::test]
    async fn claims_take_due_jobs_once_in_order() {
        let t = TestDb::new().await;
        let later = insert(&t.db, &job(None, 50)).await.unwrap().unwrap();
        let sooner = insert(&t.db, &job(None, 5)).await.unwrap().unwrap();
        assert!(
            claim_next(&t.db, 1, 600).await.unwrap().is_none(),
            "nothing is due yet"
        );
        let first = claim_next(&t.db, 100, 600).await.unwrap().unwrap();
        assert_eq!(
            (
                first.id,
                first.state.as_str(),
                first.attempts,
                first.locked_until
            ),
            (sooner, "running", 1, Some(700))
        );
        assert_eq!(
            claim_next(&t.db, 100, 600).await.unwrap().unwrap().id,
            later
        );
        assert!(
            claim_next(&t.db, 100, 600).await.unwrap().is_none(),
            "running jobs are not claimed again"
        );
    }

    #[tokio::test]
    async fn failures_retry_or_stop_and_expired_leases_return() {
        let t = TestDb::new().await;
        let id = insert(&t.db, &job(None, 0)).await.unwrap().unwrap();
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        fail(&t.db, id, "boom", Some(70)).await.unwrap();
        let row = by_id(&t.db, id).await.unwrap().unwrap();
        assert_eq!(
            (
                row.state.as_str(),
                row.run_at,
                row.last_error.as_str(),
                row.locked_until
            ),
            ("queued", 70, "boom", None)
        );
        claim_next(&t.db, 70, 600).await.unwrap().unwrap();
        fail(&t.db, id, "boom again", None).await.unwrap();
        assert_eq!(by_id(&t.db, id).await.unwrap().unwrap().state, "failed");

        let stuck = insert(&t.db, &job(None, 0)).await.unwrap().unwrap();
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        assert_eq!(
            requeue_expired(&t.db, 600, 5).await.unwrap(),
            0,
            "the lease has not ended"
        );
        assert_eq!(requeue_expired(&t.db, 611, 5).await.unwrap(), 1);
        let row = by_id(&t.db, stuck).await.unwrap().unwrap();
        assert_eq!((row.state.as_str(), row.attempts), ("queued", 1));
        claim_next(&t.db, 700, 600).await.unwrap().unwrap();
        assert_eq!(requeue_expired(&t.db, 1301, 2).await.unwrap(), 1);
        assert_eq!(
            by_id(&t.db, stuck).await.unwrap().unwrap().state,
            "failed",
            "a job that used all its attempts is not retried"
        );
    }

    #[tokio::test]
    async fn prune_removes_old_finished_jobs_and_payloads_can_change() {
        let t = TestDb::new().await;
        let done = insert(&t.db, &job(None, 0)).await.unwrap().unwrap();
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        complete(&t.db, done).await.unwrap();
        let failed = insert(&t.db, &job(None, 0)).await.unwrap().unwrap();
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        fail(&t.db, failed, "x", None).await.unwrap();
        let queued = insert(&t.db, &job(None, 0)).await.unwrap().unwrap();
        sqlx::query("UPDATE jobs SET updated_at = $1")
            .bind(100_i64)
            .execute(t.db.pool())
            .await
            .unwrap();

        let old_failures = failed_of_kind_before(&t.db, "test", 101).await.unwrap();
        assert_eq!(
            old_failures.iter().map(|j| j.id).collect::<Vec<_>>(),
            vec![failed]
        );
        set_payload(&t.db, failed, r#"{"blank":true}"#)
            .await
            .unwrap();
        let row = by_id(&t.db, failed).await.unwrap().unwrap();
        assert_eq!(
            (row.payload.as_str(), row.updated_at),
            (r#"{"blank":true}"#, 100),
            "rewriting a payload keeps the time of the failure"
        );

        assert_eq!(prune(&t.db, 50, 50).await.unwrap(), 0);
        assert_eq!(
            prune(&t.db, 200, 50).await.unwrap(),
            1,
            "only the done job is old enough"
        );
        assert_eq!(prune(&t.db, 200, 200).await.unwrap(), 1);
        assert!(
            by_id(&t.db, queued).await.unwrap().is_some(),
            "queued jobs are never pruned"
        );
    }
    #[tokio::test]
    async fn retry_and_delete_only_touch_failed_jobs() {
        let t = TestDb::new().await;
        let now = now();
        let failed = insert(
            &t.db,
            &NewJob {
                kind: "send_email",
                payload: "{}",
                dedupe_key: None,
                run_at: now,
                rerun_if_running: false,
            },
        )
        .await
        .unwrap()
        .unwrap();
        fail(&t.db, failed, "boom", None).await.unwrap();
        let queued = insert(
            &t.db,
            &NewJob {
                kind: "send_email",
                payload: "{}",
                dedupe_key: None,
                run_at: now,
                rerun_if_running: false,
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!retry_failed(&t.db, queued, now).await.unwrap());
        assert!(retry_failed(&t.db, failed, now).await.unwrap());
        assert_eq!(by_id(&t.db, failed).await.unwrap().unwrap().state, "queued");
        assert!(!delete_job(&t.db, queued).await.unwrap());
        // Re-fail it, then delete.
        fail(&t.db, failed, "again", None).await.unwrap();
        assert!(delete_job(&t.db, failed).await.unwrap());
        assert!(by_id(&t.db, failed).await.unwrap().is_none());
        assert_eq!(count_by_state(&t.db, "queued").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn rerun_requests_survive_the_running_job() {
        let t = TestDb::new().await;
        // A request that arrives while its job is running is recorded and returned by `complete`.
        let first = insert(&t.db, &rerun_job(Some("r"), 0))
            .await
            .unwrap()
            .unwrap();
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        assert_eq!(
            insert(&t.db, &rerun_job(Some("r"), 42)).await.unwrap(),
            None,
            "the request collides with the running row"
        );
        assert_eq!(
            complete(&t.db, first).await.unwrap(),
            Some(42),
            "a rerun is due at the request time"
        );
        // Without the opt-in the same request is dropped: nothing is returned.
        let plain = insert(&t.db, &job(Some("p"), 0)).await.unwrap().unwrap();
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        assert_eq!(insert(&t.db, &job(Some("p"), 0)).await.unwrap(), None);
        assert_eq!(complete(&t.db, plain).await.unwrap(), None);
        // A request that arrives while its job is queued needs no rerun: the queued copy re-reads state.
        let queued = insert(&t.db, &rerun_job(Some("q"), 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(insert(&t.db, &rerun_job(Some("q"), 0)).await.unwrap(), None);
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        assert_eq!(complete(&t.db, queued).await.unwrap(), None);
        // A retrying `fail` clears the recorded rerun: the retry re-reads state.
        let retried = insert(&t.db, &rerun_job(Some("f"), 0))
            .await
            .unwrap()
            .unwrap();
        claim_next(&t.db, 10, 600).await.unwrap().unwrap();
        assert_eq!(insert(&t.db, &rerun_job(Some("f"), 0)).await.unwrap(), None);
        fail(&t.db, retried, "boom", Some(70)).await.unwrap();
        claim_next(&t.db, 70, 600).await.unwrap().unwrap();
        assert_eq!(complete(&t.db, retried).await.unwrap(), None);
    }
}
