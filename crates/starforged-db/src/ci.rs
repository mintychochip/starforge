//! `runners`, `runner_registration_tokens`, `ci_jobs`, `ci_job_logs`,
//! `ci_artifacts`, `ci_job_sessions`, `ci_job_tokens`: the M6-0 CI control
//! plane (spec M6, decisions 6/13).
//!
//! The data-access layer stays thin — no validation or permission checks
//! here (those live in `starforged-core`). Token columns store SHA-256
//! hashes only; callers hash before calling and never persist plaintext.
//! `labels` and `ci_jobs.spec` are TEXT holding JSON (no JSON operators).
//! [`claim_next_ci_job`] follows the `jobs::claim_next` pattern: guarded
//! `UPDATE … WHERE state = 'queued'` with a per-claim `lease_token` fence
//! that every later trace/result call must present. `git_token_id` links
//! the short-lived git credential (`access_tokens`) minted for the job so
//! finish/cancel can revoke it.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerRow {
    pub id: i64,
    pub repo_id: i64,
    pub name: String,
    pub token_hash: String,
    pub token_hint: String,
    pub labels: String,
    pub ephemeral: i64,
    pub paused: i64,
    pub max_concurrent: i64,
    pub version: String,
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewRunner<'a> {
    pub repo_id: i64,
    pub name: &'a str,
    pub token_hash: &'a str,
    pub token_hint: &'a str,
    pub labels: &'a str,
    pub ephemeral: bool,
    pub max_concurrent: i64,
    pub version: &'a str,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationTokenRow {
    pub id: i64,
    pub repo_id: i64,
    pub token_hash: String,
    pub labels: String,
    pub created_by: Option<i64>,
    pub expires_at: i64,
    pub used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewRegistrationToken<'a> {
    pub repo_id: i64,
    pub token_hash: &'a str,
    pub labels: &'a str,
    pub created_by: Option<i64>,
    pub expires_at: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiJobRow {
    pub id: i64,
    pub repo_id: i64,
    pub trail_id: Option<i64>,
    pub change_id: Option<i64>,
    pub revision_id: Option<i64>,
    pub commit_sha: String,
    pub base_sha: Option<String>,
    pub job_name: String,
    pub spec: String,
    pub state: String,
    pub runner_id: Option<i64>,
    pub attempts: i64,
    pub run_at: i64,
    pub lease_until: Option<i64>,
    pub lease_token: Option<String>,
    pub deadline: i64,
    pub exit_code: Option<i64>,
    pub checksum: Option<String>,
    pub cancel_requested: i64,
    pub created_by: Option<i64>,
    pub git_token_id: Option<i64>,
    pub last_error: String,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewCiJob<'a> {
    pub repo_id: i64,
    pub trail_id: Option<i64>,
    pub change_id: Option<i64>,
    pub revision_id: Option<i64>,
    pub commit_sha: &'a str,
    pub base_sha: Option<&'a str>,
    pub job_name: &'a str,
    pub spec: &'a str,
    pub run_at: i64,
    pub deadline: i64,
    pub created_by: Option<i64>,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiJobLogRow {
    pub id: i64,
    pub job_id: i64,
    pub start_offset: i64,
    pub end_offset: i64,
    pub blake3: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewLogChunk<'a> {
    pub job_id: i64,
    pub start_offset: i64,
    pub end_offset: i64,
    pub blake3: &'a str,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiArtifactRow {
    pub id: i64,
    pub job_id: i64,
    pub name: String,
    pub size: i64,
    pub blake3: String,
    pub sha256: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewArtifact<'a> {
    pub job_id: i64,
    pub name: &'a str,
    pub size: i64,
    pub blake3: &'a str,
    pub sha256: Option<&'a str>,
    pub expires_at: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiJobSessionRow {
    pub job_id: i64,
    pub session_ulid: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiJobTokenRow {
    pub id: i64,
    pub job_id: i64,
    pub token_hash: String,
    pub token_hint: String,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewCiJobToken<'a> {
    pub job_id: i64,
    pub token_hash: &'a str,
    pub token_hint: &'a str,
    pub expires_at: i64,
    pub now: i64,
}

macro_rules! select_runner {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, name, token_hash, token_hint, labels, ephemeral, paused, ",
            "max_concurrent, version, last_seen_at, created_at, revoked_at FROM runners ",
            $tail
        )
    };
}

macro_rules! select_ci_job {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, trail_id, change_id, revision_id, commit_sha, base_sha, ",
            "job_name, spec, state, runner_id, attempts, run_at, lease_until, lease_token, ",
            "deadline, exit_code, checksum, cancel_requested, created_by, git_token_id, ",
            "last_error, created_at, started_at, finished_at FROM ci_jobs ",
            $tail
        )
    };
}

macro_rules! select_log_chunk {
    ($tail:literal) => {
        concat!(
            "SELECT id, job_id, start_offset, end_offset, blake3, created_at ",
            "FROM ci_job_logs ",
            $tail
        )
    };
}

macro_rules! select_artifact {
    ($tail:literal) => {
        concat!(
            "SELECT id, job_id, name, size, blake3, sha256, created_at, expires_at ",
            "FROM ci_artifacts ",
            $tail
        )
    };
}

macro_rules! select_job_session {
    ($tail:literal) => {
        concat!(
            "SELECT job_id, session_ulid, created_at FROM ci_job_sessions ",
            $tail
        )
    };
}

macro_rules! select_job_token {
    ($tail:literal) => {
        concat!(
            "SELECT id, job_id, token_hash, token_hint, expires_at, revoked_at ",
            "FROM ci_job_tokens ",
            $tail
        )
    };
}

fn runner_from_row(row: &AnyRow) -> DbResult<RunnerRow> {
    Ok(RunnerRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        name: row.try_get("name")?,
        token_hash: row.try_get("token_hash")?,
        token_hint: row.try_get("token_hint")?,
        labels: row.try_get("labels")?,
        ephemeral: row.try_get("ephemeral")?,
        paused: row.try_get("paused")?,
        max_concurrent: row.try_get("max_concurrent")?,
        version: row.try_get("version")?,
        last_seen_at: row.try_get("last_seen_at")?,
        created_at: row.try_get("created_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn registration_token_from_row(row: &AnyRow) -> DbResult<RegistrationTokenRow> {
    Ok(RegistrationTokenRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        token_hash: row.try_get("token_hash")?,
        labels: row.try_get("labels")?,
        created_by: row.try_get("created_by")?,
        expires_at: row.try_get("expires_at")?,
        used_at: row.try_get("used_at")?,
    })
}

fn ci_job_from_row(row: &AnyRow) -> DbResult<CiJobRow> {
    Ok(CiJobRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        trail_id: row.try_get("trail_id")?,
        change_id: row.try_get("change_id")?,
        revision_id: row.try_get("revision_id")?,
        commit_sha: row.try_get("commit_sha")?,
        base_sha: row.try_get("base_sha")?,
        job_name: row.try_get("job_name")?,
        spec: row.try_get("spec")?,
        state: row.try_get("state")?,
        runner_id: row.try_get("runner_id")?,
        attempts: row.try_get("attempts")?,
        run_at: row.try_get("run_at")?,
        lease_until: row.try_get("lease_until")?,
        lease_token: row.try_get("lease_token")?,
        deadline: row.try_get("deadline")?,
        exit_code: row.try_get("exit_code")?,
        checksum: row.try_get("checksum")?,
        cancel_requested: row.try_get("cancel_requested")?,
        created_by: row.try_get("created_by")?,
        git_token_id: row.try_get("git_token_id")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

fn log_chunk_from_row(row: &AnyRow) -> DbResult<CiJobLogRow> {
    Ok(CiJobLogRow {
        id: row.try_get("id")?,
        job_id: row.try_get("job_id")?,
        start_offset: row.try_get("start_offset")?,
        end_offset: row.try_get("end_offset")?,
        blake3: row.try_get("blake3")?,
        created_at: row.try_get("created_at")?,
    })
}

fn artifact_from_row(row: &AnyRow) -> DbResult<CiArtifactRow> {
    Ok(CiArtifactRow {
        id: row.try_get("id")?,
        job_id: row.try_get("job_id")?,
        name: row.try_get("name")?,
        size: row.try_get("size")?,
        blake3: row.try_get("blake3")?,
        sha256: row.try_get("sha256")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn job_session_from_row(row: &AnyRow) -> DbResult<CiJobSessionRow> {
    Ok(CiJobSessionRow {
        job_id: row.try_get("job_id")?,
        session_ulid: row.try_get("session_ulid")?,
        created_at: row.try_get("created_at")?,
    })
}

fn job_token_from_row(row: &AnyRow) -> DbResult<CiJobTokenRow> {
    Ok(CiJobTokenRow {
        id: row.try_get("id")?,
        job_id: row.try_get("job_id")?,
        token_hash: row.try_get("token_hash")?,
        token_hint: row.try_get("token_hint")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn bool_to_int(b: bool) -> i64 {
    i64::from(b)
}

/// Inserts a runner; `token_hash` is the SHA-256 of the runner auth token
/// (plaintext shown once at registration, never stored).
pub async fn insert_runner(db: &Db, n: &NewRunner<'_>) -> DbResult<RunnerRow> {
    let row = sqlx::query(
        "INSERT INTO runners (repo_id, name, token_hash, token_hint, labels, ephemeral, max_concurrent, version, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING id, repo_id, name, token_hash, token_hint, labels, ephemeral, paused, max_concurrent, version, last_seen_at, created_at, revoked_at",
    )
    .bind(n.repo_id)
    .bind(n.name)
    .bind(n.token_hash)
    .bind(n.token_hint)
    .bind(n.labels)
    .bind(bool_to_int(n.ephemeral))
    .bind(n.max_concurrent)
    .bind(n.version)
    .bind(n.now)
    .fetch_one(db.pool())
    .await?;
    runner_from_row(&row)
}

/// The non-revoked runner with this auth-token hash, if any.
pub async fn runner_by_token_hash(db: &Db, token_hash: &str) -> DbResult<Option<RunnerRow>> {
    let row = sqlx::query(select_runner!(
        "WHERE token_hash = $1 AND revoked_at IS NULL"
    ))
    .bind(token_hash)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(runner_from_row).transpose()
}
/// One runner by id, including revoked ones (callers check `revoked_at`).
pub async fn runner_by_id(db: &Db, id: i64) -> DbResult<Option<RunnerRow>> {
    let row = sqlx::query(select_runner!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(runner_from_row).transpose()
}

/// Non-revoked runners of the repo in insert order.
pub async fn runners_for_repo(db: &Db, repo_id: i64) -> DbResult<Vec<RunnerRow>> {
    let rows = sqlx::query(select_runner!(
        "WHERE repo_id = $1 AND revoked_at IS NULL ORDER BY id ASC"
    ))
    .bind(repo_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(runner_from_row).collect()
}

/// Revokes the runner (`revoked_at` set); false when already revoked/missing.
pub async fn revoke_runner(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let affected =
        sqlx::query("UPDATE runners SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
            .bind(now_ts)
            .bind(id)
            .execute(db.pool())
            .await?
            .rows_affected();
    Ok(affected == 1)
}

/// Records a heartbeat: `last_seen_at` (and `version` when given).
pub async fn touch_runner(db: &Db, id: i64, version: Option<&str>, now_ts: i64) -> DbResult<()> {
    sqlx::query(
        "UPDATE runners SET last_seen_at = $1, version = CASE WHEN $2 IS NULL THEN version ELSE $2 END \
         WHERE id = $3",
    )
    .bind(now_ts)
    .bind(version.map(str::to_owned))
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Inserts a one-time registration token; `token_hash` is the SHA-256 of
/// the token (plaintext shown once at mint time, never stored).
pub async fn insert_registration_token(
    db: &Db,
    n: &NewRegistrationToken<'_>,
) -> DbResult<RegistrationTokenRow> {
    let row = sqlx::query(
        "INSERT INTO runner_registration_tokens (repo_id, token_hash, labels, created_by, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, repo_id, token_hash, labels, created_by, expires_at, used_at",
    )
    .bind(n.repo_id)
    .bind(n.token_hash)
    .bind(n.labels)
    .bind(n.created_by)
    .bind(n.expires_at)
    .bind(n.now)
    .fetch_one(db.pool())
    .await?;
    registration_token_from_row(&row)
}

/// Consumes the registration token with this hash exactly once: marks
/// `used_at` and returns the row, or `None` when unknown, expired
/// (`expires_at <= now_ts`), or already used.
pub async fn consume_registration_token(
    db: &Db,
    token_hash: &str,
    now_ts: i64,
) -> DbResult<Option<RegistrationTokenRow>> {
    let row = sqlx::query(
        "UPDATE runner_registration_tokens SET used_at = $1 \
         WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1 \
         RETURNING id, repo_id, token_hash, labels, created_by, expires_at, used_at",
    )
    .bind(now_ts)
    .bind(token_hash)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(registration_token_from_row).transpose()
}

/// Queues a CI job and returns its id. A colliding active job for
/// `(repo_id, commit_sha, job_name)` violates the partial unique index.
pub async fn insert_ci_job(db: &Db, n: &NewCiJob<'_>) -> DbResult<CiJobRow> {
    let row = sqlx::query(
        "INSERT INTO ci_jobs (repo_id, trail_id, change_id, revision_id, commit_sha, base_sha, job_name, spec, run_at, deadline, created_by, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         RETURNING id, repo_id, trail_id, change_id, revision_id, commit_sha, base_sha, job_name, spec, state, runner_id, attempts, run_at, lease_until, lease_token, deadline, exit_code, checksum, cancel_requested, created_by, git_token_id, last_error, created_at, started_at, finished_at",
    )
    .bind(n.repo_id)
    .bind(n.trail_id)
    .bind(n.change_id)
    .bind(n.revision_id)
    .bind(n.commit_sha)
    .bind(n.base_sha)
    .bind(n.job_name)
    .bind(n.spec)
    .bind(n.run_at)
    .bind(n.deadline)
    .bind(n.created_by)
    .bind(n.now)
    .fetch_one(db.pool())
    .await?;
    ci_job_from_row(&row)
}

/// One CI job by id, if it still exists.
pub async fn ci_job_by_id(db: &Db, id: i64) -> DbResult<Option<CiJobRow>> {
    let row = sqlx::query(select_ci_job!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(ci_job_from_row).transpose()
}

/// Claims the oldest due queued job of the runner's repo for `runner_id`:
/// `state = 'claimed'`, `attempts + 1`, `lease_until = now + lease_secs`,
/// and the per-claim `lease_token` fence. Returns the claimed row (with
/// `lease_token`/`lease_until`), or `None` when nothing is due. The
/// guarded update makes concurrent claims safe on both engines.
pub async fn claim_next_ci_job(
    db: &Db,
    runner_id: i64,
    repo_id: i64,
    now_ts: i64,
    lease_secs: i64,
    lease_token: &str,
) -> DbResult<Option<CiJobRow>> {
    loop {
        let id: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM ci_jobs WHERE state = 'queued' AND run_at <= $1 AND repo_id = $2 \
             ORDER BY run_at, id LIMIT 1",
        )
        .bind(now_ts)
        .bind(repo_id)
        .fetch_optional(db.pool())
        .await?;
        let Some(id) = id else {
            return Ok(None);
        };
        let claimed = sqlx::query(
            "UPDATE ci_jobs SET state = 'claimed', runner_id = $1, attempts = attempts + 1, lease_until = $2, \
             lease_token = $3, started_at = COALESCE(started_at, $4) \
             WHERE id = $5 AND state = 'queued'",
        )
        .bind(runner_id)
        .bind(now_ts + lease_secs)
        .bind(lease_token)
        .bind(now_ts)
        .bind(id)
        .execute(db.pool())
        .await?
        .rows_affected();
        if claimed == 1 {
            return ci_job_by_id(db, id).await;
        }
        // Another runner claimed it between the SELECT and the UPDATE;
        // loop and look for the next one.
    }
}

/// Finishes a claimed/running job under its lease fence: sets the terminal
/// `state`, exit code, checksum, and error, stamps `finished_at`, and
/// revokes the job's tokens. Returns false on a stale/missing fence or a
/// job that is not claimed/running (canceled already won).
#[allow(clippy::too_many_arguments)]
pub async fn finish_ci_job(
    db: &Db,
    id: i64,
    lease_token: &str,
    state: &str,
    exit_code: Option<i64>,
    checksum: Option<&str>,
    last_error: &str,
    now_ts: i64,
) -> DbResult<bool> {
    let affected = sqlx::query(
        "UPDATE ci_jobs SET state = $1, exit_code = $2, checksum = $3, last_error = $4, finished_at = $5 \
         WHERE id = $6 AND lease_token = $7 AND state IN ('claimed', 'running')",
    )
    .bind(state)
    .bind(exit_code)
    .bind(checksum)
    .bind(last_error)
    .bind(now_ts)
    .bind(id)
    .bind(lease_token)
    .execute(db.pool())
    .await?
    .rows_affected();
    if affected == 1 {
        revoke_job_tokens_for_job(db, id, now_ts).await?;
    }
    Ok(affected == 1)
}

/// Records a cancel request on an active job; the runner observes
/// `cancel_requested` on its next trace/finish call. False when the job
/// is missing or already terminal.
pub async fn request_cancel_ci_job(db: &Db, id: i64, _now_ts: i64) -> DbResult<bool> {
    let affected = sqlx::query(
        "UPDATE ci_jobs SET cancel_requested = 1 WHERE id = $1 AND state IN ('queued', 'claimed', 'running')",
    )
    .bind(id)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Terminally cancels a job: when `lease_token` is given it must match the
/// current fence (runner path); `None` cancels unconditionally (user path).
/// Revokes the job's tokens. False when already terminal or fenced out.
pub async fn cancel_ci_job(
    db: &Db,
    id: i64,
    lease_token: Option<&str>,
    now_ts: i64,
) -> DbResult<bool> {
    let affected = match lease_token {
        Some(token) => sqlx::query(
            "UPDATE ci_jobs SET state = 'canceled', finished_at = $1, lease_until = NULL \
                 WHERE id = $2 AND lease_token = $3 AND state IN ('queued', 'claimed', 'running')",
        )
        .bind(now_ts)
        .bind(id)
        .bind(token)
        .execute(db.pool())
        .await?
        .rows_affected(),
        None => sqlx::query(
            "UPDATE ci_jobs SET state = 'canceled', finished_at = $1, lease_until = NULL \
                 WHERE id = $2 AND state IN ('queued', 'claimed', 'running')",
        )
        .bind(now_ts)
        .bind(id)
        .execute(db.pool())
        .await?
        .rows_affected(),
    };
    if affected == 1 {
        revoke_job_tokens_for_job(db, id, now_ts).await?;
    }
    Ok(affected == 1)
}

/// Claimed/running jobs whose lease ended before `now_ts` belonged to a
/// runner that stopped. They go back to `queued`, or to `failed` once they
/// have used `max_attempts`. Returns how many rows changed.
pub async fn requeue_expired_ci_jobs(db: &Db, now_ts: i64, max_attempts: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "UPDATE ci_jobs SET state = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'queued' END, \
         lease_until = NULL, lease_token = NULL, runner_id = NULL, \
         last_error = CASE WHEN attempts >= $1 THEN last_error ELSE 'the runner stopped before finishing' END, \
         finished_at = CASE WHEN attempts >= $1 THEN $2 ELSE finished_at END \
         WHERE state IN ('claimed', 'running') AND lease_until < $3",
    )
    .bind(max_attempts)
    .bind(now_ts)
    .bind(now_ts)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected())
}

/// Inserts a per-job token; `token_hash` is the SHA-256 of the token
/// (plaintext shown once at mint time, never stored).
pub async fn insert_job_token(db: &Db, n: &NewCiJobToken<'_>) -> DbResult<CiJobTokenRow> {
    let row = sqlx::query(
        "INSERT INTO ci_job_tokens (job_id, token_hash, token_hint, expires_at) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, job_id, token_hash, token_hint, expires_at, revoked_at",
    )
    .bind(n.job_id)
    .bind(n.token_hash)
    .bind(n.token_hint)
    .bind(n.expires_at)
    .fetch_one(db.pool())
    .await?;
    job_token_from_row(&row)
}

/// The live (unrevoked, unexpired at `now_ts`) job token with this hash.
pub async fn job_token_by_hash(
    db: &Db,
    token_hash: &str,
    now_ts: i64,
) -> DbResult<Option<CiJobTokenRow>> {
    let row = sqlx::query(select_job_token!(
        "WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2"
    ))
    .bind(token_hash)
    .bind(now_ts)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(job_token_from_row).transpose()
}

/// Revokes one job token; false when already revoked/missing.
pub async fn revoke_job_token(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let affected = sqlx::query(
        "UPDATE ci_job_tokens SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL",
    )
    .bind(now_ts)
    .bind(id)
    .execute(db.pool())
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Revokes every live token of the job; returns how many rows changed.
pub async fn revoke_job_tokens_for_job(db: &Db, job_id: i64, now_ts: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "UPDATE ci_job_tokens SET revoked_at = $1 WHERE job_id = $2 AND revoked_at IS NULL",
    )
    .bind(now_ts)
    .bind(job_id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected())
}

/// Appends one log chunk (append-only; offsets are caller-validated).
pub async fn append_log_chunk(db: &Db, n: &NewLogChunk<'_>) -> DbResult<CiJobLogRow> {
    let row = sqlx::query(
        "INSERT INTO ci_job_logs (job_id, start_offset, end_offset, blake3, created_at) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, job_id, start_offset, end_offset, blake3, created_at",
    )
    .bind(n.job_id)
    .bind(n.start_offset)
    .bind(n.end_offset)
    .bind(n.blake3)
    .bind(n.now)
    .fetch_one(db.pool())
    .await?;
    log_chunk_from_row(&row)
}

/// Log chunks of the job in offset order.
pub async fn log_chunks_for_job(db: &Db, job_id: i64) -> DbResult<Vec<CiJobLogRow>> {
    let rows = sqlx::query(select_log_chunk!(
        "WHERE job_id = $1 ORDER BY start_offset ASC, id ASC"
    ))
    .bind(job_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(log_chunk_from_row).collect()
}

/// Inserts one artifact row.
pub async fn insert_artifact(db: &Db, n: &NewArtifact<'_>) -> DbResult<CiArtifactRow> {
    let row = sqlx::query(
        "INSERT INTO ci_artifacts (job_id, name, size, blake3, sha256, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id, job_id, name, size, blake3, sha256, created_at, expires_at",
    )
    .bind(n.job_id)
    .bind(n.name)
    .bind(n.size)
    .bind(n.blake3)
    .bind(n.sha256)
    .bind(n.now)
    .bind(n.expires_at)
    .fetch_one(db.pool())
    .await?;
    artifact_from_row(&row)
}

/// Artifacts of the job in insert order.
pub async fn artifacts_for_job(db: &Db, job_id: i64) -> DbResult<Vec<CiArtifactRow>> {
    let rows = sqlx::query(select_artifact!("WHERE job_id = $1 ORDER BY id ASC"))
        .bind(job_id)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(artifact_from_row).collect()
}

/// Links a session to a job (idempotent on the `(job_id, session_ulid)` PK).
pub async fn insert_job_session(
    db: &Db,
    job_id: i64,
    session_ulid: &str,
    now_ts: i64,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO ci_job_sessions (job_id, session_ulid, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT (job_id, session_ulid) DO NOTHING",
    )
    .bind(job_id)
    .bind(session_ulid)
    .bind(now_ts)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Sessions linked to the job in insert order.
pub async fn job_sessions_for_job(db: &Db, job_id: i64) -> DbResult<Vec<CiJobSessionRow>> {
    let rows = sqlx::query(select_job_session!(
        "WHERE job_id = $1 ORDER BY created_at ASC, session_ulid ASC"
    ))
    .bind(job_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(job_session_from_row).collect()
}

/// Points `sessions.ci_job_id` at the job (the upload-auth binding);
/// false when the session is missing.
pub async fn set_session_ci_job(db: &Db, session_id: i64, ci_job_id: i64) -> DbResult<bool> {
    let affected = sqlx::query("UPDATE sessions SET ci_job_id = $1 WHERE id = $2")
        .bind(ci_job_id)
        .bind(session_id)
        .execute(db.pool())
        .await?
        .rows_affected();
    Ok(affected == 1)
}

/// Links the short-lived git credential (`access_tokens`) minted for the
/// job so finish/cancel can revoke it.
pub async fn set_ci_job_git_token(db: &Db, job_id: i64, token_id: i64) -> DbResult<()> {
    sqlx::query("UPDATE ci_jobs SET git_token_id = $1 WHERE id = $2")
        .bind(token_id)
        .bind(job_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// The `ci_jobs` id a session was uploaded for, if any.
pub async fn session_ci_job_id(db: &Db, session_id: i64) -> DbResult<Option<i64>> {
    let ci_job_id: Option<Option<i64>> =
        sqlx::query_scalar("SELECT ci_job_id FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(db.read_pool())
            .await?;
    Ok(ci_job_id.flatten())
}

/// Current time helper re-export for callers that only import this module.
pub fn now_ts() -> i64 {
    now()
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

    async fn setup() -> (TestDb, i64, i64) {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("ci-alice")).await.unwrap();
        let repo_id = repos::insert(&t.db, &repo(alice, "ci-demo")).await.unwrap();
        (t, alice, repo_id)
    }

    fn ci_job(repo_id: i64, created_by: i64, name: &'static str, run_at: i64) -> NewCiJob<'static> {
        NewCiJob {
            repo_id,
            trail_id: None,
            change_id: None,
            revision_id: None,
            commit_sha: "abc123",
            base_sha: None,
            job_name: name,
            spec: r#"{"commands":["cargo test"]}"#,
            run_at,
            deadline: 1_700_003_600,
            created_by: Some(created_by),
            now: 1_700_000_000,
        }
    }

    fn runner(repo_id: i64, token_hash: &'static str) -> NewRunner<'static> {
        NewRunner {
            repo_id,
            name: "r1",
            token_hash,
            token_hint: "abcd…",
            labels: "[]",
            ephemeral: false,
            max_concurrent: 1,
            version: "0.1.0",
            now: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn runner_lifecycle_and_registration_token_once() {
        let (t, alice, repo_id) = setup().await;
        let r = insert_runner(&t.db, &runner(repo_id, "hash-r1"))
            .await
            .unwrap();
        assert_eq!(r.token_hash, "hash-r1");
        assert_eq!(
            runner_by_token_hash(&t.db, "hash-r1")
                .await
                .unwrap()
                .unwrap()
                .id,
            r.id
        );
        touch_runner(&t.db, r.id, Some("0.2.0"), 1_700_000_100)
            .await
            .unwrap();
        let touched = runner_by_token_hash(&t.db, "hash-r1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (touched.last_seen_at, touched.version.as_str()),
            (Some(1_700_000_100), "0.2.0")
        );
        assert_eq!(runners_for_repo(&t.db, repo_id).await.unwrap().len(), 1);

        let token = insert_registration_token(
            &t.db,
            &NewRegistrationToken {
                repo_id,
                token_hash: "reg-hash",
                labels: "[]",
                created_by: Some(alice),
                expires_at: 1_700_000_600,
                now: 1_700_000_000,
            },
        )
        .await
        .unwrap();
        let consumed = consume_registration_token(&t.db, "reg-hash", 1_700_000_100)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed.id, token.id);
        assert!(
            consume_registration_token(&t.db, "reg-hash", 1_700_000_200)
                .await
                .unwrap()
                .is_none(),
            "one-time"
        );

        assert!(revoke_runner(&t.db, r.id, 1_700_000_300).await.unwrap());
        assert!(
            runner_by_token_hash(&t.db, "hash-r1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(!revoke_runner(&t.db, r.id, 1_700_000_400).await.unwrap());
    }

    #[tokio::test]
    async fn claim_finish_and_requeue() {
        let (t, alice, repo_id) = setup().await;
        let r = insert_runner(&t.db, &runner(repo_id, "hash-r1"))
            .await
            .unwrap();
        let job = insert_ci_job(&t.db, &ci_job(repo_id, alice, "test", 0))
            .await
            .unwrap();
        assert_eq!(job.state, "queued");
        // A second active job for the same (repo, sha, name) violates dedupe.
        assert!(
            insert_ci_job(&t.db, &ci_job(repo_id, alice, "test", 0))
                .await
                .is_err()
        );

        let claimed = claim_next_ci_job(&t.db, r.id, repo_id, 10, 60, "fence-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.state, "claimed");
        assert_eq!(
            (claimed.lease_token.as_deref(), claimed.lease_until),
            (Some("fence-1"), Some(70))
        );
        assert_eq!(claimed.attempts, 1);
        // Nothing else due.
        assert!(
            claim_next_ci_job(&t.db, r.id, repo_id, 10, 60, "fence-2")
                .await
                .unwrap()
                .is_none()
        );

        // Stale fence cannot finish.
        assert!(
            !finish_ci_job(&t.db, job.id, "stale", "succeeded", Some(0), None, "", 20)
                .await
                .unwrap()
        );
        let tok = insert_job_token(
            &t.db,
            &NewCiJobToken {
                job_id: job.id,
                token_hash: "job-hash",
                token_hint: "j…",
                expires_at: 1_700_003_600,
                now: 1_700_000_000,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            job_token_by_hash(&t.db, "job-hash", 20)
                .await
                .unwrap()
                .unwrap()
                .id,
            tok.id
        );
        assert!(
            finish_ci_job(
                &t.db,
                job.id,
                "fence-1",
                "succeeded",
                Some(0),
                Some("blake"),
                "",
                30
            )
            .await
            .unwrap()
        );
        assert!(
            job_token_by_hash(&t.db, "job-hash", 40)
                .await
                .unwrap()
                .is_none(),
            "finish revokes job tokens"
        );
        let row = ci_job_by_id(&t.db, job.id).await.unwrap().unwrap();
        assert_eq!((row.state.as_str(), row.exit_code), ("succeeded", Some(0)));

        // Expired lease requeues, then fails at max attempts.
        let stuck = insert_ci_job(&t.db, &ci_job(repo_id, alice, "lint", 0))
            .await
            .unwrap();
        claim_next_ci_job(&t.db, r.id, repo_id, 10, 60, "fence-9")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requeue_expired_ci_jobs(&t.db, 71, 3).await.unwrap(), 1);
        assert_eq!(
            ci_job_by_id(&t.db, stuck.id).await.unwrap().unwrap().state,
            "queued"
        );
        claim_next_ci_job(&t.db, r.id, repo_id, 80, 60, "fence-10")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requeue_expired_ci_jobs(&t.db, 141, 3).await.unwrap(), 1);
        claim_next_ci_job(&t.db, r.id, repo_id, 200, 60, "fence-11")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requeue_expired_ci_jobs(&t.db, 261, 3).await.unwrap(), 1);
        assert_eq!(
            ci_job_by_id(&t.db, stuck.id).await.unwrap().unwrap().state,
            "failed"
        );
    }

    #[tokio::test]
    async fn logs_artifacts_sessions_and_cancel() {
        let (t, alice, repo_id) = setup().await;
        let job = insert_ci_job(&t.db, &ci_job(repo_id, alice, "test", 0))
            .await
            .unwrap();
        append_log_chunk(
            &t.db,
            &NewLogChunk {
                job_id: job.id,
                start_offset: 0,
                end_offset: 10,
                blake3: "b0",
                now: 1_700_000_010,
            },
        )
        .await
        .unwrap();
        append_log_chunk(
            &t.db,
            &NewLogChunk {
                job_id: job.id,
                start_offset: 10,
                end_offset: 25,
                blake3: "b1",
                now: 1_700_000_020,
            },
        )
        .await
        .unwrap();
        let chunks = log_chunks_for_job(&t.db, job.id).await.unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!((chunks[1].start_offset, chunks[1].end_offset), (10, 25));

        insert_artifact(
            &t.db,
            &NewArtifact {
                job_id: job.id,
                name: "out.bin",
                size: 42,
                blake3: "b",
                sha256: Some("s"),
                expires_at: 1_700_100_000,
                now: 1_700_000_030,
            },
        )
        .await
        .unwrap();
        assert_eq!(artifacts_for_job(&t.db, job.id).await.unwrap().len(), 1);

        insert_job_session(&t.db, job.id, "01JSESSION", 1_700_000_040)
            .await
            .unwrap();
        insert_job_session(&t.db, job.id, "01JSESSION", 1_700_000_041)
            .await
            .unwrap();
        assert_eq!(
            job_sessions_for_job(&t.db, job.id).await.unwrap().len(),
            1,
            "link is idempotent"
        );

        // sessions.ci_job_id binding via a minimal session row.
        let session_id: i64 = sqlx::query_scalar(
            "INSERT INTO sessions (repo_id, ulid, uploader_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $4) RETURNING id",
        )
        .bind(repo_id)
        .bind("01JSESSION")
        .bind(alice)
        .bind(1_700_000_040_i64)
        .fetch_one(t.db.pool())
        .await
        .unwrap();
        assert!(set_session_ci_job(&t.db, session_id, job.id).await.unwrap());
        let linked: Option<i64> =
            sqlx::query_scalar("SELECT ci_job_id FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(t.db.pool())
                .await
                .unwrap();
        assert_eq!(linked, Some(job.id));

        assert!(
            request_cancel_ci_job(&t.db, job.id, 1_700_000_050)
                .await
                .unwrap()
        );
        assert!(
            cancel_ci_job(&t.db, job.id, None, 1_700_000_060)
                .await
                .unwrap()
        );
        assert_eq!(
            ci_job_by_id(&t.db, job.id).await.unwrap().unwrap().state,
            "canceled"
        );
    }
}
