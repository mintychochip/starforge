# Starforge M0.5 Plan A (Foundations and Accounts) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `starforged` a durable background-jobs queue, optional email, email verification, registration modes with invites, password reset, and account settings, so people can join and manage their own accounts without shell access.

**Architecture:** A `jobs` table plus workers inside `starforged serve` runs background work; tests run due jobs directly with `Core::run_due_jobs`. `starforged-core` gains a lettre-based `Mailer` (SMTP over rustls, or `.eml` files for `file://`), one-time email tokens (SHA-256 stored), verification, sign-up, invites, and password reset. `starforged-web` gains server-rendered pages for sign-up, email confirmation, password recovery, and account settings. Every new rule lives in `starforged-core`; the web layer stays thin.

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8, askama 0.16 (HTML pages and plain-text email templates), sqlx 0.9 (`Any`, SQLite and Postgres), lettre 0.11.23, serde_json job payloads.

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-forge-basics-design.md` (forge basics, milestone M0.5). This plan implements §3 (configuration), §4 (accounts), §8 (jobs), §9 (mail), the account rows of §10, the Plan A tables of §11, §12, and §13. The main spec `docs/superpowers/specs/2026-11-03-starforge-design.md` still applies where the forge-basics design is silent. M0.5 runs as three plans: **A** (this one), **B** (repositories and code views), **C** (site administration).

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide.
- **Runtime:** system `git` 2.38 or newer on `PATH`.
- **License:** every crate is `AGPL-3.0-or-later`.
- **Dependencies:** versions exactly as in the root `Cargo.toml` `[workspace.dependencies]` table; crates inherit them with `dep.workspace = true`; internal crates depend on each other by relative path. The only new third-party dependency in this plan is, exactly:
  `lettre = { version = "0.11.23", default-features = false, features = ["builder", "file-transport", "hostname", "ring", "rustls-platform-verifier", "smtp-transport", "tokio1", "tokio1-rustls"] }`.
- **SQL portability:** every statement in `starforged-db` runs unchanged on SQLite and Postgres: placeholders `$1, $2, …` with each number first appearing in ascending order; integer columns `INTEGER` (SQLite) / `BIGINT` (Postgres) decoded as `i64`; booleans stored as `0`/`1` and decoded as `i64`; timestamps in unix seconds; SQL strings are `'static` literals.
- **Migrations:** each task that changes the schema adds its own numbered pair `crates/starforged-db/migrations/{sqlite,postgres}/000N_<name>.sql` (0002 jobs, 0003 email verification, 0004 invites). Never edit an existing migration file. Both files of a pair define identical tables, columns, constraints, and indexes.
- **Both engines are tested:** DB-touching tests use `starforged_db::testing::TestDb`. Tasks that add SQL run `STARFORGE_TEST_PG=1 scripts/check.sh` (podman, Postgres 17) before committing; it must pass on SQLite and Postgres.
- **Error mapping:** `starforged-db` returns `DbResult<T>`; `starforged-core` returns `CoreResult<T>`. HTTP layers map `NotFound`→404, `Forbidden`→403, `Unauthenticated`→401 (API, git) or a redirect to `/login` (web), `Invalid`→422 (API, web forms), `Conflict`→409 (API) / 422 (web forms). This plan adds `CoreError::EmailUnverified`: the sign-in page renders it as its "verify your email first" state (403); every other surface maps it to 403.
- **No existence leaks:** a private repository looks exactly like a missing one. The resend-verification and forgot-password forms answer identically for unknown addresses; the "verify your email first" message appears only after a correct password.
- **Secrets:** personal access tokens, session cookies, email tokens, and invite codes are stored only as SHA-256 hex of 32 random bytes; CSRF tokens are compared in constant time (`subtle`); secrets are never logged. A sent email's body is blanked in its job row. `Mailer`'s `Debug` output never contains SMTP credentials.
- **Anonymous forms** (sign-in, sign-up, resend verification, forgot password, reset password, email confirmation) use the double-submit CSRF cookie `sf_login_csrf` through `auth::anonymous_csrf` and `auth::verify_anonymous_csrf`.
- **git subprocesses** are built only through `starforged_git::command::git()`; nothing goes through a shell.
- **HTML:** askama auto-escaping everywhere; `|safe` only on Markdown output from `starforged_web::markdown::render`. Email templates are `.txt` askama templates (no HTML escaping) under `crates/starforged-core/templates/mail/`.
- **Tests:** integration tests that start a server use `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`. `TestServer` does not run job workers: tests deliver queued email with `s.inbox().await`, which calls `s.core.run_due_jobs()` first. Only `starforged serve` starts workers.
- **Every commit:** `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` pass, and `cargo test --workspace` is green.
- **Deferred to Plan B:** repository settings, rename and redirects, archive, delete and restore, `/settings/repositories`, account deletion, branches, tags, compare, syntax highlighting, and `git maintenance` after pushes. **Deferred to Plan C:** the `/admin` pages. Plan A ships the core APIs those pages call for invites (`Core::{create_invite, list_invites, revoke_invite}`) and admin password resets (`Core::admin_password_reset`).
- **Decisions this plan makes where the spec is silent:**
  - Email confirmation links open a page with a Confirm button (`GET`), and the `POST` uses the link, so mail scanners that prefetch links cannot use them up.
  - After a successful sign-up that needs no verification, the new account is signed in immediately.
  - Display names are at most 100 characters without control characters (`validate::display_name`), checked at sign-up and in profile settings.
  - The `sf_login_csrf` cookie is reused while it exists, so several signed-out forms can be open in different tabs.
  - A session's last-activity time is written at most every 5 minutes, so normal browsing does not write to the database on every request.

## File Structure

```
Cargo.toml                                        + lettre in [workspace.dependencies] (A2)
crates/starforged-db/
  migrations/{sqlite,postgres}/0002_jobs.sql                 jobs table (A1)
  migrations/{sqlite,postgres}/0003_email_verification.sql   users.email_verified + email_tokens (A3)
  migrations/{sqlite,postgres}/0004_invites.sql              invites (A4)
  src/jobs.rs            queue: insert/claim/complete/fail/requeue/prune (A1)
  src/email_tokens.rs    one-time emailed links (A3)
  src/invites.rs         invites (A4)
  src/users.rs           + email_verified, set_email_verified (A3), set_password_hash (A5), set_display_name, set_email (A6)
  src/web_sessions.rs    + delete_expired (A1), delete_for_user (A5), last_seen_at, touch, list/revoke (A6)
crates/starforged-core/
  templates/mail/*.txt   test, verify_email, invite, reset_password, confirm_email
  src/jobs.rs            Job enum, Core::{enqueue, enqueue_at, run_due_jobs}, start_workers (A1)
  src/mail.rs            Mailer, Email, message builders, mail::testing helpers (A2)
  src/email_tokens.rs    Purpose, issue/consume/peek with throttle (A3)
  src/verification.rs    send_verification, resend_verification, verify_email, email_link_valid (A3)
  src/registration.rs    RegistrationMode, Registration, SignUp, SignedUp, Core::sign_up (A4)
  src/invites.rs         create/list/revoke invites, invite_email (A4)
  src/passwords.rs       request_password_reset, admin_password_reset, reset_password (A5)
  src/account.rs         profile, password, email change, sessions (A6)
crates/starforged/
  src/config.rs          + [mail] (A2), [registration] (A4)
  src/admin.rs           open_core wiring; `admin mail test` (A2)
  src/main.rs            + `admin mail test` (A2)
  src/serve.rs           run() starts job workers (A1)
  tests/common/mod.rs    + start_with, start_with_mail, inbox, link_in, try_login
  tests/mail_cli.rs  web_verify.rs  web_join.rs  web_password_reset.rs  web_account.rs  e2e_sign_up.rs
crates/starforged-web/
  src/auth.rs            + anonymous_csrf, verify_anonymous_csrf (A3)
  src/pages/message.rs   MessagePage (A3)
  src/pages/verify.rs    /verify/{token}, /verify/resend (A3)
  src/pages/join.rs      /join (A4)
  src/pages/password.rs  /forgot, /reset/{token} (A5)
  src/pages/settings.rs  /settings/{profile,email,password,sessions} (A6)
  templates/             message, verify, join, forgot, reset, settings_nav, settings_* pages
README.md                accounts and email (A7)
```

---

### Task A1: Background jobs queue and workers

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0002_jobs.sql`, `crates/starforged-db/migrations/postgres/0002_jobs.sql`
- Create: `crates/starforged-db/src/jobs.rs`; Modify: `crates/starforged-db/src/lib.rs` (add `pub mod jobs;`), `crates/starforged-db/src/web_sessions.rs` (add `delete_expired`)
- Create: `crates/starforged-core/src/jobs.rs`; Modify: `crates/starforged-core/src/lib.rs`, `crates/starforged-core/Cargo.toml`
- Modify: `crates/starforged/src/serve.rs`
- Test: unit tests in both `jobs.rs` files

**Interfaces:**
- Consumes: `Db`, `DbError::is_unique_violation`, `now()`, `testing::TestDb` (M0 Task 2); `web_sessions::NewWebSession` (M0 Task 8); `Core`, `CoreResult`, `crate::testing::{test_core, user}` (M0 Tasks 3–5).
- Produces:
  - `starforged_db::jobs::{JobRow { id, kind, payload, state, dedupe_key, run_at, attempts, locked_until, last_error, created_at, updated_at }, NewJob { kind, payload, dedupe_key, run_at }, insert, by_id, claim_next, complete, fail, requeue_expired, set_payload, prune, failed_of_kind_before}`.
  - `starforged_db::web_sessions::delete_expired(db, now_ts) -> DbResult<u64>`.
  - `starforged_core::jobs::{Job::{HourlyCleanup, DailyPrune}, MAX_ATTEMPTS, LEASE_SECS, POLL_INTERVAL, retry_delay, start_workers}`; `Job::kind() -> &'static str`.
  - `Core::{enqueue(&Job), enqueue_at(&Job, run_at), run_due_jobs() -> CoreResult<usize>}`. Later tasks add `Job` variants and extend `Core::hourly_cleanup` (private) and `Core::execute` (private).

- [ ] **Step 1: Write the migrations**

`crates/starforged-db/migrations/sqlite/0002_jobs.sql`:

```sql
-- Starforge M0.5: the background jobs queue (forge-basics design §8).
-- Keep in lockstep with ../postgres/0002_jobs.sql.

CREATE TABLE jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
    dedupe_key TEXT,
    run_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX jobs_due ON jobs (state, run_at);
-- At most one queued or running job per deduplication key (recurring jobs).
CREATE UNIQUE INDEX jobs_dedupe ON jobs (dedupe_key) WHERE state IN ('queued', 'running');
```

`crates/starforged-db/migrations/postgres/0002_jobs.sql`:

```sql
-- Starforge M0.5: the background jobs queue (forge-basics design §8).
-- Keep in lockstep with ../sqlite/0002_jobs.sql.

CREATE TABLE jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
    dedupe_key TEXT,
    run_at BIGINT NOT NULL,
    attempts BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX jobs_due ON jobs (state, run_at);
-- At most one queued or running job per deduplication key (recurring jobs).
CREATE UNIQUE INDEX jobs_dedupe ON jobs (dedupe_key) WHERE state IN ('queued', 'running');
```

- [ ] **Step 2: Write the failing data-access tests**

Add `pub mod jobs;` to `crates/starforged-db/src/lib.rs`, between `pub mod collaborators;` and `pub mod repos;`.

Create `crates/starforged-db/src/jobs.rs` with only this test module for now:

```rust
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
            (first.id, first.state.as_str(), first.attempts, first.locked_until),
            (sooner, "running", 1, Some(700))
        );
        assert_eq!(claim_next(&t.db, 100, 600).await.unwrap().unwrap().id, later);
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
            (row.state.as_str(), row.run_at, row.last_error.as_str(), row.locked_until),
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
        assert_eq!(old_failures.iter().map(|j| j.id).collect::<Vec<_>>(), vec![failed]);
        set_payload(&t.db, failed, r#"{"blank":true}"#).await.unwrap();
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
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test -p starforged-db jobs`
Expected: compile errors (`NewJob`, `insert`, and the other functions do not exist yet).

- [ ] **Step 4: Implement the jobs data access**

Insert at the top of `crates/starforged-db/src/jobs.rs`, above the test module:

```rust
//! `jobs`: the durable background queue (forge-basics design §8). Workers claim due rows with a guarded
//! `UPDATE … WHERE state = 'queued'`, which behaves the same on SQLite and Postgres.

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
    pub attempts: i64,
    pub locked_until: Option<i64>,
    pub last_error: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct NewJob<'a> {
    pub kind: &'a str,
    pub payload: &'a str,
    /// At most one job per key is queued or running (partial unique index `jobs_dedupe`).
    pub dedupe_key: Option<&'a str>,
    pub run_at: i64,
}

macro_rules! select_job {
    ($tail:literal) => {
        concat!(
            "SELECT id, kind, payload, state, dedupe_key, run_at, attempts, locked_until, last_error, created_at, updated_at ",
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
        attempts: row.try_get("attempts")?,
        locked_until: row.try_get("locked_until")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// Queues a job and returns its id, or `None` when `dedupe_key` is set and a job with that key is
/// already queued or running.
pub async fn insert(db: &Db, job: &NewJob<'_>) -> DbResult<Option<i64>> {
    let ts = now();
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
        Ok(id) => Ok(Some(id)),
        Err(err) => {
            let err = DbError::from(err);
            if job.dedupe_key.is_some() && err.is_unique_violation() {
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<JobRow>> {
    let row = sqlx::query(select_job!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
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

pub async fn complete(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("UPDATE jobs SET state = 'done', locked_until = NULL, updated_at = $1 WHERE id = $2")
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Records a failed attempt: back to `queued` at `retry_at`, or `failed` for good when `retry_at` is `None`.
pub async fn fail(db: &Db, id: i64, error: &str, retry_at: Option<i64>) -> DbResult<()> {
    let ts = now();
    match retry_at {
        Some(at) => {
            sqlx::query(
                "UPDATE jobs SET state = 'queued', run_at = $1, locked_until = NULL, last_error = $2, updated_at = $3 \
                 WHERE id = $4",
            )
            .bind(at)
            .bind(error)
            .bind(ts)
            .bind(id)
            .execute(db.pool())
            .await?;
        }
        None => {
            sqlx::query(
                "UPDATE jobs SET state = 'failed', locked_until = NULL, last_error = $1, updated_at = $2 WHERE id = $3",
            )
            .bind(error)
            .bind(ts)
            .bind(id)
            .execute(db.pool())
            .await?;
        }
    }
    Ok(())
}

/// Running jobs whose lease ended before `now_ts` belonged to a worker that stopped. They go back to the
/// queue, or to `failed` once they have used `max_attempts`. Returns how many rows changed.
pub async fn requeue_expired(db: &Db, now_ts: i64, max_attempts: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "UPDATE jobs SET state = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'queued' END, \
         locked_until = NULL, last_error = 'the worker stopped before finishing', updated_at = $2 \
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
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}
```

Append to `crates/starforged-db/src/web_sessions.rs`:

```rust
/// Deletes sessions whose expiry is at or before `now_ts`; returns how many.
pub async fn delete_expired(db: &Db, now_ts: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE expires_at <= $1")
        .bind(now_ts)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}
```

- [ ] **Step 5: Run the data-access tests**

Run: `cargo test -p starforged-db jobs`
Expected: 4 passed.

- [ ] **Step 6: Write the failing core tests**

Add to `crates/starforged-core/Cargo.toml` `[dependencies]` (keep the list alphabetical):

```toml
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
```

Add `pub mod jobs;` to `crates/starforged-core/src/lib.rs`, after `pub mod error;`. Create `crates/starforged-core/src/jobs.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use starforged_db::web_sessions::NewWebSession;

    use super::*;
    use crate::testing::{test_core, user};

    #[test]
    fn payloads_are_tagged_with_the_kind() {
        for job in [Job::HourlyCleanup, Job::DailyPrune] {
            let json = serde_json::to_string(&job).unwrap();
            assert_eq!(json, format!(r#"{{"kind":"{}"}}"#, job.kind()));
            assert_eq!(serde_json::from_str::<Job>(&json).unwrap(), job);
        }
    }

    #[test]
    fn retries_back_off_then_stop() {
        let delays: Vec<Option<i64>> = (1..=MAX_ATTEMPTS).map(retry_delay).collect();
        assert_eq!(
            delays,
            vec![Some(60), Some(300), Some(1_800), Some(7_200), None]
        );
    }

    #[tokio::test]
    async fn recurring_jobs_run_then_reschedule() {
        let (core, _f) = test_core().await;
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        assert_eq!(
            core.run_due_jobs().await.unwrap(),
            1,
            "one pending copy per recurring kind"
        );
        assert_eq!(
            core.run_due_jobs().await.unwrap(),
            0,
            "the next run is an hour away"
        );
        let rows: Vec<(String, i64)> = sqlx::query_as("SELECT state, run_at FROM jobs ORDER BY id")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "done");
        assert_eq!(rows[1].0, "queued");
        assert!(rows[1].1 >= now() + 3_600 - 5, "next run at {}", rows[1].1);
    }

    #[tokio::test]
    async fn hourly_cleanup_removes_expired_sessions() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        for (hash, expires_at) in [("old", 10), ("current", now() + 3_600)] {
            web_sessions::insert(
                core.db(),
                &NewWebSession {
                    session_hash: hash,
                    user_id: alice.id,
                    csrf_token: "csrf",
                    expires_at,
                    user_agent: "",
                    ip: "",
                },
            )
            .await
            .unwrap();
        }
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let left: Vec<String> = sqlx::query_scalar("SELECT session_hash FROM web_sessions")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        assert_eq!(left, vec!["current".to_owned()]);
    }

    #[tokio::test]
    async fn unreadable_payloads_fail_without_retrying() {
        let (core, _f) = test_core().await;
        jobs::insert(
            core.db(),
            &NewJob {
                kind: "mystery",
                payload: r#"{"kind":"mystery"}"#,
                dedupe_key: None,
                run_at: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(core.run_due_jobs().await.unwrap(), 1);
        let (state, error): (String, String) = sqlx::query_as("SELECT state, last_error FROM jobs")
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(state, "failed");
        assert!(error.contains("unreadable job payload"), "{error}");
    }

    #[tokio::test]
    async fn workers_run_due_jobs_in_the_background() {
        let (core, _f) = test_core().await;
        start_workers(&core, 2).await.unwrap();
        for _ in 0..100 {
            let done: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE state = 'done'")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
            if done == 2 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("the workers did not run the two recurring jobs");
    }
}
```

- [ ] **Step 7: Run them to see them fail**

Run: `cargo test -p starforged-core jobs`
Expected: compile errors (`Job`, `retry_delay`, `start_workers`, and `Core::enqueue` do not exist yet).

- [ ] **Step 8: Implement the queue in core**

In `crates/starforged-core/src/lib.rs`, give `Inner` a wake-up handle and initialize it in `Core::new`:

```rust
#[derive(Debug)]
struct Inner {
    db: Db,
    config: CoreConfig,
    /// Wakes one idle job worker when a job is queued.
    job_wakeup: tokio::sync::Notify,
}
```

```rust
    pub fn new(db: Db, config: CoreConfig) -> Core {
        Core {
            inner: Arc::new(Inner {
                db,
                config,
                job_wakeup: tokio::sync::Notify::new(),
            }),
        }
    }
```

Insert at the top of `crates/starforged-core/src/jobs.rs`, above the test module:

```rust
//! Background jobs (forge-basics design §8): a durable queue in the `jobs` table, run by workers inside
//! `starforged serve`. Tests run due jobs directly with [`Core::run_due_jobs`].

use std::time::Duration;

use serde::{Deserialize, Serialize};
use starforged_db::jobs::{self, NewJob};
use starforged_db::{now, web_sessions};

use crate::{Core, CoreError, CoreResult};

/// A job is tried this many times before it is marked `failed`.
pub const MAX_ATTEMPTS: i64 = 5;
/// How long a claimed job may run before its worker is presumed dead and the job is queued again.
pub const LEASE_SECS: i64 = 600;
/// Idle workers look for due jobs this often; enqueueing wakes one immediately.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

/// Delay before the next attempt after `attempts` failed ones, or `None` when all [`MAX_ATTEMPTS`] are used.
pub fn retry_delay(attempts: i64) -> Option<i64> {
    match attempts {
        1 => Some(60),
        2 => Some(300),
        3 => Some(1_800),
        4 => Some(7_200),
        _ => None,
    }
}

/// Everything a worker can run, stored as JSON in `jobs.payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Job {
    /// Hourly housekeeping: expired web sessions and, from later tasks, other expired rows.
    HourlyCleanup,
    /// Daily: deletes `done` jobs after 7 days and `failed` jobs after 30.
    DailyPrune,
}

impl Job {
    /// The `jobs.kind` column; equal to the payload's `kind` tag.
    pub fn kind(&self) -> &'static str {
        match self {
            Job::HourlyCleanup => "hourly_cleanup",
            Job::DailyPrune => "daily_prune",
        }
    }

    /// How often a recurring job runs. Recurring jobs use their kind as the deduplication key, so at most one
    /// copy is pending.
    fn recurrence(&self) -> Option<i64> {
        match self {
            Job::HourlyCleanup => Some(HOUR),
            Job::DailyPrune => Some(DAY),
        }
    }
}

impl Core {
    /// Queues `job` to run now.
    pub async fn enqueue(&self, job: &Job) -> CoreResult<()> {
        self.enqueue_at(job, now()).await
    }

    /// Queues `job` to run at `run_at` (unix seconds). A recurring job that is already pending is left alone.
    pub async fn enqueue_at(&self, job: &Job, run_at: i64) -> CoreResult<()> {
        let payload = serde_json::to_string(job).map_err(|e| CoreError::Internal(e.to_string()))?;
        let dedupe_key = job.recurrence().map(|_| job.kind());
        jobs::insert(
            self.db(),
            &NewJob {
                kind: job.kind(),
                payload: &payload,
                dedupe_key,
                run_at,
            },
        )
        .await?;
        self.inner.job_wakeup.notify_one();
        Ok(())
    }

    /// Runs every due job in this task and returns how many ran. `serve` uses workers; tests call this.
    pub async fn run_due_jobs(&self) -> CoreResult<usize> {
        let mut ran = 0;
        while self.run_one_job().await? {
            ran += 1;
        }
        Ok(ran)
    }

    /// Claims and runs one due job; `false` when none is due.
    async fn run_one_job(&self) -> CoreResult<bool> {
        let start = now();
        jobs::requeue_expired(self.db(), start, MAX_ATTEMPTS).await?;
        let Some(row) = jobs::claim_next(self.db(), start, LEASE_SECS).await? else {
            return Ok(false);
        };
        let job = serde_json::from_str::<Job>(&row.payload);
        let outcome = match &job {
            Ok(job) => self.execute(job).await,
            Err(err) => Err(CoreError::Internal(format!("unreadable job payload: {err}"))),
        };
        let finished = match outcome {
            Ok(()) => {
                jobs::complete(self.db(), row.id).await?;
                true
            }
            Err(err) => {
                // A payload that cannot be read will not become readable later.
                let retry_at = if job.is_ok() {
                    retry_delay(row.attempts).map(|delay| now() + delay)
                } else {
                    None
                };
                tracing::warn!(job = row.id, kind = %row.kind, attempts = row.attempts, error = %err, "job failed");
                jobs::fail(self.db(), row.id, &err.to_string(), retry_at).await?;
                retry_at.is_none()
            }
        };
        // A recurring job schedules its next run once it is finished, whether it succeeded or gave up.
        if finished
            && let Ok(job) = &job
            && let Some(interval) = job.recurrence()
        {
            self.enqueue_at(job, now() + interval).await?;
        }
        Ok(true)
    }

    async fn execute(&self, job: &Job) -> CoreResult<()> {
        match job {
            Job::HourlyCleanup => self.hourly_cleanup().await,
            Job::DailyPrune => {
                let ts = now();
                jobs::prune(self.db(), ts - 7 * DAY, ts - 30 * DAY).await?;
                Ok(())
            }
        }
    }

    async fn hourly_cleanup(&self) -> CoreResult<()> {
        web_sessions::delete_expired(self.db(), now()).await?;
        Ok(())
    }

    async fn worker(self) {
        loop {
            match self.run_one_job().await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => tracing::error!(error = %err, "job worker"),
            }
            tokio::select! {
                () = self.inner.job_wakeup.notified() => {}
                () = tokio::time::sleep(POLL_INTERVAL) => {}
            }
        }
    }
}

/// Queues the recurring jobs (when none is pending) and starts `count` workers on the current runtime.
pub async fn start_workers(core: &Core, count: usize) -> CoreResult<()> {
    for job in [Job::HourlyCleanup, Job::DailyPrune] {
        core.enqueue(&job).await?;
    }
    for _ in 0..count {
        tokio::spawn(core.clone().worker());
    }
    Ok(())
}
```

- [ ] **Step 9: Run the core tests**

Run: `cargo test -p starforged-core jobs`
Expected: 6 passed.

- [ ] **Step 10: Start workers in `serve`**

In `crates/starforged/src/serve.rs`, start the workers in `run` right after the app is built, and add the constant below `App`:

```rust
/// Background job workers per process (forge-basics design §8.2).
const JOB_WORKERS: usize = 2;
```

```rust
    let app = build(&config, std::env::current_exe()?).await?;
    starforged_core::jobs::start_workers(&app.core, JOB_WORKERS).await?;
```

`build` stays worker-free: in-process test servers run jobs through `Core::run_due_jobs`.

- [ ] **Step 11: Full suite, lint, format, both engines, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
STARFORGE_TEST_PG=1 scripts/check.sh
git add crates/starforged-db crates/starforged-core crates/starforged/src/serve.rs Cargo.lock
git commit -m "feat(jobs): durable background job queue with workers"
```

Expected: everything green on SQLite and Postgres.

### Task A2: Optional email: `[mail]`, the mailer, the send-email job, and `admin mail test`

**Files:**
- Modify: root `Cargo.toml` (`lettre` in `[workspace.dependencies]`), `crates/starforged-core/Cargo.toml`, `crates/starforged/Cargo.toml` (dev-dependency feature)
- Create: `crates/starforged-core/src/mail.rs`, `crates/starforged-core/templates/mail/test.txt`
- Modify: `crates/starforged-core/src/lib.rs` (`pub mod mail;`, `CoreConfig`, test fixture), `crates/starforged-core/src/jobs.rs` (`Job::SendEmail`, blanking)
- Modify: `crates/starforged/src/config.rs`, `crates/starforged/src/init.rs`, `crates/starforged/src/admin.rs`, `crates/starforged/src/main.rs`
- Modify: `crates/starforged/tests/common/mod.rs`
- Test: unit tests in `mail.rs`, `jobs.rs`, `config.rs`; `crates/starforged/tests/mail_cli.rs`

**Interfaces:**
- Consumes: `Core::{enqueue, run_due_jobs}`, `Job`, `jobs::{set_payload, failed_of_kind_before}`, `start_workers` (Task A1).
- Produces:
  - `starforged_core::mail::{Email { to, subject, body }, Mailer, test_email(to, base_url) -> CoreResult<Email>}`; `Mailer::from_config(url, from) -> CoreResult<Option<Mailer>>`, `Mailer::send(&Email) -> CoreResult<()>`.
  - `starforged_core::mail::testing::{read_mailbox(dir) -> Vec<String>, decode_eml(raw) -> String, find_link(message, path_prefix) -> Option<String>}` behind the new `testing` feature of `starforged-core`.
  - `CoreConfig { repos_dir, hook_exe, base_url: String, mailer: Option<Mailer> }`; `Core::mail_enabled() -> bool`; `Core::queue_email(Email)` (crate-private).
  - `Job::SendEmail { to, subject, body }`; the worker blanks `body` after sending, and the hourly cleanup blanks `failed` mail jobs 7 days after they failed.
  - Test fixture (`crate::testing`): `test_core_with(configure: impl FnOnce(&mut CoreConfig, &Path))`, `with_file_mail(&mut CoreConfig, &Path)`, `Fixture::mail() -> Vec<String>`.
  - `starforged::config::{MailConfig { url, from }}`, `Config.mail`, `Config::mailer() -> anyhow::Result<Option<Mailer>>`; overrides `STARFORGE__MAIL__URL`, `STARFORGE__MAIL__FROM`.
  - CLI: `starforged admin mail test --to <address>` prints `sent a test email to <address>`.
  - Harness: `TestServer::{start_with(configure), start_with_mail(configure), mail_dir(), inbox(), last_email_to(to), link_in(message, path_prefix)}`.

- [ ] **Step 1: Add the dependency and the plain-text template**

In the root `Cargo.toml` `[workspace.dependencies]`, between `hex` and `percent-encoding`:

```toml
lettre = { version = "0.11.23", default-features = false, features = ["builder", "file-transport", "hostname", "ring", "rustls-platform-verifier", "smtp-transport", "tokio1", "tokio1-rustls"] }
```

`crates/starforged-core/Cargo.toml`: add to `[dependencies]` (alphabetical) and add a `testing` feature:

```toml
askama.workspace = true
lettre.workspace = true
percent-encoding.workspace = true
url.workspace = true
```

```toml
[features]
# Exposes `mail::testing` (reading `.eml` files) to other crates' tests.
testing = []
```

`crates/starforged/Cargo.toml` `[dev-dependencies]`: add

```toml
starforged-core = { path = "../starforged-core", features = ["testing"] }
```

`crates/starforged-core/templates/mail/test.txt`:

```
This is a test message from Starforge at {{ base_url }}.

If you can read it, outgoing email works.
```

- [ ] **Step 2: Write the failing mail tests**

Add `pub mod mail;` to `crates/starforged-core/src/lib.rs`, after `pub mod jobs;`. Create `crates/starforged-core/src/mail.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;
    use crate::testing::{test_core_with, with_file_mail};

    const FROM: &str = "Starforge <forge@example.com>";

    fn error_of(url: &str, from: &str) -> String {
        Mailer::from_config(url, from).unwrap_err().to_string()
    }

    #[test]
    fn mail_urls_are_checked() {
        assert!(Mailer::from_config("", FROM).unwrap().is_none());
        for good in [
            "smtp://user:p%40ss@mail.example.com:2525",
            "smtps://mail.example.com",
            "smtp://127.0.0.1:25?tls=none",
            "smtp://localhost?tls=none",
            "file:///tmp/starforge-mail",
        ] {
            assert!(Mailer::from_config(good, FROM).unwrap().is_some(), "{good}");
        }
        assert!(error_of("smtp://mail.example.com?tls=none", FROM).contains("loopback"));
        assert!(error_of("smtps://localhost?tls=none", FROM).contains("only to smtp://"));
        assert!(error_of("smtp://mail.example.com?port=1", FROM).contains("unsupported parameter"));
        assert!(error_of("ftp://mail.example.com", FROM).contains("smtp://, smtps://, or file://"));
        assert!(error_of("smtp://mail.example.com", "").contains("mail.from"));
    }

    #[test]
    fn debug_output_hides_credentials() {
        let mailer = Mailer::from_config("smtp://mailuser:hunter2secret@mail.example.com", FROM)
            .unwrap()
            .unwrap();
        let shown = format!("{mailer:?}");
        assert!(
            !shown.contains("hunter2secret") && !shown.contains("mailuser"),
            "{shown}"
        );
    }

    /// A minimal SMTP server that never offers STARTTLS. Returns its port and, once the client hangs up, the
    /// lines it received.
    async fn plaintext_smtp_server() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let mut seen = Vec::new();
            write.write_all(b"220 test ESMTP\r\n").await.unwrap();
            let mut in_data = false;
            while let Ok(Some(line)) = lines.next_line().await {
                seen.push(line.clone());
                if in_data {
                    if line == "." {
                        in_data = false;
                        write.write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let command = line.to_ascii_uppercase();
                let reply: &[u8] = if command.starts_with("EHLO") {
                    b"250-test\r\n250 AUTH PLAIN\r\n"
                } else if command == "DATA" {
                    in_data = true;
                    b"354 go ahead\r\n"
                } else if command == "QUIT" {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                write.write_all(reply).await.unwrap();
            }
            seen
        });
        (port, server)
    }

    #[tokio::test]
    async fn smtp_requires_starttls_unless_tls_none_on_loopback() {
        let email = test_email("ops@example.com", "http://forge.test").unwrap();

        let (port, server) = plaintext_smtp_server().await;
        let mailer = Mailer::from_config(&format!("smtp://user:secret@127.0.0.1:{port}"), FROM)
            .unwrap()
            .unwrap();
        let err = mailer.send(&email).await.unwrap_err();
        assert!(err.to_string().contains("STARTTLS"), "{err}");
        drop(mailer);
        let seen = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !seen
                .iter()
                .any(|l| l.starts_with("AUTH") || l.starts_with("MAIL")),
            "nothing may be sent in clear: {seen:?}"
        );

        let (port, server) = plaintext_smtp_server().await;
        let mailer = Mailer::from_config(&format!("smtp://127.0.0.1:{port}?tls=none"), FROM)
            .unwrap()
            .unwrap();
        mailer.send(&email).await.unwrap();
        drop(mailer);
        let seen = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            seen.iter()
                .any(|l| l.starts_with("MAIL FROM:<forge@example.com>")),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn queued_email_is_sent_and_its_body_blanked() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        assert!(core.mail_enabled());
        core.queue_email(test_email("ops@example.com", "http://forge.test").unwrap())
            .await
            .unwrap();
        assert_eq!(core.run_due_jobs().await.unwrap(), 1);
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(
            mail[0].contains("To: ops@example.com")
                && mail[0].contains("Subject: Starforge test email")
                && mail[0].contains("This is a test message from Starforge at http://forge.test."),
            "{}",
            mail[0]
        );
        let payload: String =
            sqlx::query_scalar("SELECT payload FROM jobs WHERE kind = 'send_email'")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
        assert_eq!(
            serde_json::from_str::<Job>(&payload).unwrap(),
            Job::SendEmail {
                to: "ops@example.com".into(),
                subject: "Starforge test email".into(),
                body: String::new(),
            }
        );
    }

    #[tokio::test]
    async fn running_workers_send_queued_email_promptly() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        crate::jobs::start_workers(&core, 1).await.unwrap();
        core.queue_email(test_email("ops@example.com", "http://forge.test").unwrap())
            .await
            .unwrap();
        // Three seconds is less than the five-second poll interval: only the wake-up delivers it this fast.
        for _ in 0..60 {
            if !fixture.mail().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("queued email was not sent within 3 seconds");
    }

    #[test]
    fn quoted_printable_bodies_are_decoded_and_links_found() {
        let raw = "To: a@example.com\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\
                   Open http://forge.test/verify/ab=\r\ncd?x=3Dy now\r\n";
        let decoded = testing::decode_eml(raw);
        assert!(decoded.contains("http://forge.test/verify/abcd?x=y"), "{decoded}");
        assert_eq!(
            testing::find_link(&decoded, "/verify/").as_deref(),
            Some("http://forge.test/verify/abcd?x=y")
        );
        let seven_bit = "To: a@example.com\r\n\r\nhttp://forge.test/join?invite=ab12\r\n";
        assert!(
            testing::decode_eml(seven_bit).contains("invite=ab12"),
            "bodies that are not quoted-printable stay as they are"
        );
    }
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test -p starforged-core mail`
Expected: compile errors (`Mailer`, `test_email`, `testing`, `test_core_with` do not exist yet).

- [ ] **Step 4: Implement the mailer**

Insert at the top of `crates/starforged-core/src/mail.rs`, above the test module:

```rust
//! Outgoing email (forge-basics design §3, §9): plain-text messages, queued as jobs and sent over SMTP, or
//! written as `.eml` files with `file://` (development and tests).

use std::net::IpAddr;
use std::path::PathBuf;

use askama::Template;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncFileTransport, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use percent_encoding::percent_decode_str;

use crate::jobs::Job;
use crate::{Core, CoreError, CoreResult};

/// One message, ready to queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Delivers messages; built from `[mail]` by [`Mailer::from_config`]. Cheap to clone.
#[derive(Clone)]
pub struct Mailer {
    transport: Transport,
    from: Mailbox,
}

#[derive(Clone)]
enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    File {
        dir: PathBuf,
        transport: AsyncFileTransport<Tokio1Executor>,
    },
}

/// Never prints the transport's settings: they can hold SMTP credentials.
impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let transport = match &self.transport {
            Transport::Smtp(_) => "smtp",
            Transport::File { .. } => "file",
        };
        f.debug_struct("Mailer")
            .field("transport", &transport)
            .field("from", &self.from.to_string())
            .finish()
    }
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::Invalid(message.into())
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Mailer {
    /// Reads `mail.url` and `mail.from` (forge-basics design §3). `Ok(None)` when `url` is empty: the instance
    /// sends no email.
    pub fn from_config(url: &str, from: &str) -> CoreResult<Option<Mailer>> {
        let url = url.trim();
        if url.is_empty() {
            return Ok(None);
        }
        let from: Mailbox = from
            .trim()
            .parse()
            .map_err(|_| invalid("mail.from must be a mailbox such as \"Starforge <forge@example.com>\""))?;
        let parsed = url::Url::parse(url).map_err(|e| invalid(format!("mail.url is not a valid URL: {e}")))?;
        let transport = match parsed.scheme() {
            "file" => {
                let dir = parsed
                    .to_file_path()
                    .map_err(|()| invalid("mail.url must look like file:///absolute/path"))?;
                Transport::File {
                    transport: AsyncFileTransport::new(&dir),
                    dir,
                }
            }
            "smtp" | "smtps" => Transport::Smtp(smtp_transport(&parsed)?),
            other => {
                return Err(invalid(format!(
                    "mail.url must start with smtp://, smtps://, or file://, not {other}://"
                )));
            }
        };
        Ok(Some(Mailer { transport, from }))
    }

    /// Sends one message now. Workers call this for queued mail; `starforged admin mail test` calls it directly.
    pub async fn send(&self, email: &Email) -> CoreResult<()> {
        let to: Mailbox = email
            .to
            .parse()
            .map_err(|_| invalid(format!("not an email address: {}", email.to)))?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(email.body.clone())
            .map_err(|e| CoreError::Internal(format!("building a message: {e}")))?;
        match &self.transport {
            Transport::Smtp(smtp) => {
                smtp.send(message)
                    .await
                    .map_err(|e| CoreError::Internal(format!("smtp: {e}")))?;
            }
            Transport::File { dir, transport } => {
                tokio::fs::create_dir_all(dir)
                    .await
                    .map_err(|e| CoreError::Internal(format!("creating {}: {e}", dir.display())))?;
                transport
                    .send(message)
                    .await
                    .map_err(|e| CoreError::Internal(format!("writing mail: {e}")))?;
            }
        }
        Ok(())
    }
}

/// `smtp://` requires STARTTLS unless `?tls=none` names a loopback host; `smtps://` is implicit TLS.
fn smtp_transport(url: &url::Url) -> CoreResult<AsyncSmtpTransport<Tokio1Executor>> {
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| invalid("mail.url needs a host"))?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let mut tls_none = false;
    for (key, value) in url.query_pairs() {
        if key == "tls" && value == "none" {
            tls_none = true;
        } else {
            return Err(invalid(format!("mail.url: unsupported parameter {key}={value}")));
        }
    }
    let builder = match (url.scheme(), tls_none) {
        ("smtps", true) => return Err(invalid("mail.url: tls=none applies only to smtp://")),
        ("smtps", false) => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| invalid(format!("mail.url: {e}")))?
            .port(url.port().unwrap_or(465)),
        (_, true) if !is_loopback(host) => {
            return Err(invalid("mail.url: tls=none is allowed only for loopback hosts"));
        }
        (_, true) => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(url.port().unwrap_or(25)),
        (_, false) => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| invalid(format!("mail.url: {e}")))?
            .port(url.port().unwrap_or(587)),
    };
    let builder = if url.username().is_empty() {
        builder
    } else {
        let decode = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
        builder.credentials(Credentials::new(
            decode(url.username()),
            decode(url.password().unwrap_or("")),
        ))
    };
    Ok(builder.build())
}

fn render(template: &impl Template) -> CoreResult<String> {
    template
        .render()
        .map_err(|e| CoreError::Internal(format!("rendering an email: {e}")))
}

#[derive(Template)]
#[template(path = "mail/test.txt")]
struct TestText<'a> {
    base_url: &'a str,
}

/// The `starforged admin mail test` message.
pub fn test_email(to: &str, base_url: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: "Starforge test email".into(),
        body: render(&TestText { base_url })?,
    })
}

impl Core {
    /// Whether this instance sends email (`[mail] url` is set).
    pub fn mail_enabled(&self) -> bool {
        self.config().mailer.is_some()
    }

    /// Queues `email` for the workers. Callers check [`Core::mail_enabled`] first.
    pub(crate) async fn queue_email(&self, email: Email) -> CoreResult<()> {
        if !self.mail_enabled() {
            return Err(CoreError::Internal("mail is not configured".into()));
        }
        self.enqueue(&Job::SendEmail {
            to: email.to,
            subject: email.subject,
            body: email.body,
        })
        .await
    }
}

/// Reading `.eml` files written by the `file://` transport (tests only).
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::path::Path;

    /// Every message in `dir`, oldest first, with quoted-printable bodies decoded.
    pub fn read_mailbox(dir: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
            .map(|path| (std::fs::metadata(&path).unwrap().modified().unwrap(), path))
            .collect();
        files.sort();
        files
            .into_iter()
            .map(|(_, path)| decode_eml(&std::fs::read_to_string(path).unwrap()))
            .collect()
    }

    /// Normalizes line endings and decodes a quoted-printable body (lettre encodes long lines that way).
    pub fn decode_eml(raw: &str) -> String {
        let raw = raw.replace("\r\n", "\n");
        let Some((headers, body)) = raw.split_once("\n\n") else {
            return raw;
        };
        if !headers
            .to_ascii_lowercase()
            .contains("content-transfer-encoding: quoted-printable")
        {
            return raw;
        }
        let bytes = body.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'=' {
                if bytes.get(i + 1) == Some(&b'\n') {
                    i += 2;
                    continue;
                }
                if let (Some(&high), Some(&low)) = (bytes.get(i + 1), bytes.get(i + 2))
                    && high.is_ascii_hexdigit()
                    && low.is_ascii_hexdigit()
                {
                    let hex = [high, low];
                    let text = std::str::from_utf8(&hex).unwrap();
                    out.push(u8::from_str_radix(text, 16).unwrap());
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        format!("{headers}\n\n{}", String::from_utf8_lossy(&out))
    }

    /// The first `http://` or `https://` link in `message` whose path starts with `path_prefix`.
    pub fn find_link(message: &str, path_prefix: &str) -> Option<String> {
        message
            .split_whitespace()
            .filter(|word| word.starts_with("http://") || word.starts_with("https://"))
            .find(|word| url::Url::parse(word).is_ok_and(|u| u.path().starts_with(path_prefix)))
            .map(str::to_owned)
    }
}
```

- [ ] **Step 5: Give `CoreConfig` the base URL and the mailer**

In `crates/starforged-core/src/lib.rs`, extend `CoreConfig`:

```rust
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Directory holding bare repositories (`<data_dir>/repos`).
    pub repos_dir: PathBuf,
    /// Program that repository hooks execute (`starforged`); tests point it at the built binary.
    pub hook_exe: PathBuf,
    /// Public URL without a trailing slash; links in emails start with it.
    pub base_url: String,
    /// `None`: this instance sends no email.
    pub mailer: Option<mail::Mailer>,
}
```

Replace the test fixture module at the bottom of `lib.rs` with:

```rust
#[cfg(test)]
pub(crate) mod testing {
    use std::path::Path;

    use super::*;
    use crate::accounts::{CreateUser, User};
    use crate::mail::Mailer;

    pub(crate) struct Fixture {
        _db: starforged_db::testing::TestDb,
        dir: tempfile::TempDir,
    }

    impl Fixture {
        /// Messages sent through [`with_file_mail`] so far, oldest first. Run queued jobs first.
        pub(crate) fn mail(&self) -> Vec<String> {
            crate::mail::testing::read_mailbox(&self.dir.path().join("mail"))
        }
    }

    pub(crate) async fn test_core() -> (Core, Fixture) {
        test_core_with(|_, _| {}).await
    }

    /// Like [`test_core`], after `configure` adjusts the configuration. The path is the fixture's
    /// temporary directory.
    pub(crate) async fn test_core_with(
        configure: impl FnOnce(&mut CoreConfig, &Path),
    ) -> (Core, Fixture) {
        let db = starforged_db::testing::TestDb::new().await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = CoreConfig {
            repos_dir: dir.path().join("repos"),
            hook_exe: PathBuf::from("/bin/false"),
            base_url: "http://forge.test".into(),
            mailer: None,
        };
        configure(&mut config, dir.path());
        (
            Core::new(db.db.clone(), config),
            Fixture { _db: db, dir },
        )
    }

    /// Sends email as `.eml` files into `<dir>/mail`; read them with [`Fixture::mail`].
    pub(crate) fn with_file_mail(config: &mut CoreConfig, dir: &Path) {
        config.mailer = Mailer::from_config(
            &format!("file://{}", dir.join("mail").display()),
            "Starforge <forge@example.test>",
        )
        .unwrap();
    }

    pub(crate) async fn user(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            ..Default::default()
        })
        .await
        .unwrap()
    }
}
```

- [ ] **Step 6: Add the send-email job**

In `crates/starforged-core/src/jobs.rs`:

1. Add `use crate::mail::Email;` to the imports.
2. Add the variant to `Job`, its kind, and its recurrence:

```rust
    /// One email. The worker blanks `body` once it is sent: links in it carry secrets.
    SendEmail {
        to: String,
        subject: String,
        body: String,
    },
```

```rust
            Job::SendEmail { .. } => "send_email",
```

```rust
            Job::SendEmail { .. } => None,
```

3. `execute` now receives the job id. In `run_one_job`, call it as `Ok(job) => self.execute(row.id, job).await,` and replace `execute` and `hourly_cleanup` with:

```rust
    async fn execute(&self, id: i64, job: &Job) -> CoreResult<()> {
        match job {
            Job::HourlyCleanup => self.hourly_cleanup().await,
            Job::DailyPrune => {
                let ts = now();
                jobs::prune(self.db(), ts - 7 * DAY, ts - 30 * DAY).await?;
                Ok(())
            }
            Job::SendEmail { to, subject, body } => {
                let mailer = self
                    .config()
                    .mailer
                    .as_ref()
                    .ok_or_else(|| CoreError::Internal("mail is not configured".into()))?;
                mailer
                    .send(&Email {
                        to: to.clone(),
                        subject: subject.clone(),
                        body: body.clone(),
                    })
                    .await?;
                self.blank_email(id, to, subject).await
            }
        }
    }

    async fn hourly_cleanup(&self) -> CoreResult<()> {
        let ts = now();
        web_sessions::delete_expired(self.db(), ts).await?;
        // Every link in a message is dead 7 days after it was sent (invites live longest), so a failed
        // message's body is kept no longer than that.
        for row in jobs::failed_of_kind_before(self.db(), "send_email", ts - 7 * DAY).await? {
            if let Ok(Job::SendEmail { to, subject, body }) = serde_json::from_str::<Job>(&row.payload)
                && !body.is_empty()
            {
                self.blank_email(row.id, &to, &subject).await?;
            }
        }
        Ok(())
    }

    /// Replaces a message's body with nothing, keeping the recipient and subject for the admin Jobs page.
    async fn blank_email(&self, id: i64, to: &str, subject: &str) -> CoreResult<()> {
        let blank = Job::SendEmail {
            to: to.to_owned(),
            subject: subject.to_owned(),
            body: String::new(),
        };
        let payload = serde_json::to_string(&blank).map_err(|e| CoreError::Internal(e.to_string()))?;
        jobs::set_payload(self.db(), id, &payload).await?;
        Ok(())
    }
```

4. Add this test to the `jobs.rs` test module:

```rust
    #[tokio::test]
    async fn hourly_cleanup_blanks_week_old_failed_mail() {
        let (core, _f) = test_core().await;
        let message = Job::SendEmail {
            to: "a@example.com".into(),
            subject: "Hello".into(),
            body: "a secret link".into(),
        };
        core.enqueue(&message).await.unwrap();
        core.enqueue(&message).await.unwrap();
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM jobs ORDER BY id")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        for (id, failed_at) in [(ids[0], now() - 8 * DAY), (ids[1], now() - DAY)] {
            sqlx::query("UPDATE jobs SET state = 'failed', updated_at = $1 WHERE id = $2")
                .bind(failed_at)
                .bind(id)
                .execute(core.db().pool())
                .await
                .unwrap();
        }
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let mut bodies = Vec::new();
        for id in ids {
            let payload: String = sqlx::query_scalar("SELECT payload FROM jobs WHERE id = $1")
                .bind(id)
                .fetch_one(core.db().pool())
                .await
                .unwrap();
            match serde_json::from_str::<Job>(&payload).unwrap() {
                Job::SendEmail { body, .. } => bodies.push(body),
                other => panic!("unexpected job {other:?}"),
            }
        }
        assert_eq!(bodies, vec![String::new(), "a secret link".to_owned()]);
    }
```

- [ ] **Step 7: Run the core tests**

Run: `cargo test -p starforged-core`
Expected: all pass (7 jobs tests, 6 mail tests, and the M0 tests).

- [ ] **Step 8: Write the failing config and CLI tests**

Add to the test module of `crates/starforged/src/config.rs` (and add `mail: MailConfig::default(),` to `sample()`):

```rust
    #[test]
    fn mail_settings_are_validated() {
        let mut config = sample();
        assert!(config.mailer().unwrap().is_none());
        config
            .apply_env([
                (
                    "STARFORGE__MAIL__URL".to_owned(),
                    "smtp://mail.example.com?tls=none".to_owned(),
                ),
                (
                    "STARFORGE__MAIL__FROM".to_owned(),
                    "Starforge <forge@example.com>".to_owned(),
                ),
            ])
            .unwrap();
        assert!(config.validate().unwrap_err().to_string().contains("loopback"));
        config.mail.url = "smtps://user:pw@mail.example.com".into();
        assert!(config.validate().is_ok());
        assert!(config.mailer().unwrap().is_some());
        config.mail.from = "not a mailbox".into();
        assert!(config.validate().is_err());
    }
```

Create `crates/starforged/tests/mail_cli.rs`:

```rust
use std::path::Path;
use std::process::{Command, Output};

fn starforged(config: &Path, args: &[&str], mail_url: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_starforged"));
    command.arg("--config").arg(config).args(args);
    if let Some(url) = mail_url {
        command
            .env("STARFORGE__MAIL__URL", url)
            .env("STARFORGE__MAIL__FROM", "Starforge <forge@example.test>");
    }
    command.output().unwrap()
}

#[test]
fn admin_mail_test_sends_one_message() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("starforged.toml");
    let data = dir.path().join("data");
    let init = starforged(&config, &["init", "--data-dir", data.to_str().unwrap()], None);
    assert!(init.status.success(), "{}", String::from_utf8_lossy(&init.stderr));

    let not_configured = starforged(&config, &["admin", "mail", "test", "--to", "ops@example.com"], None);
    assert!(!not_configured.status.success());
    assert!(String::from_utf8_lossy(&not_configured.stderr).contains("mail.url is empty"));

    let mail_dir = dir.path().join("mail");
    let url = format!("file://{}", mail_dir.display());
    let sent = starforged(&config, &["admin", "mail", "test", "--to", "ops@example.com"], Some(&url));
    assert!(sent.status.success(), "{}", String::from_utf8_lossy(&sent.stderr));
    assert_eq!(
        String::from_utf8_lossy(&sent.stdout).trim(),
        "sent a test email to ops@example.com"
    );
    let messages = starforged_core::mail::testing::read_mailbox(&mail_dir);
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("Subject: Starforge test email"), "{}", messages[0]);
}
```

- [ ] **Step 9: Run them to see them fail**

Run: `cargo test -p starforged --lib config` and `cargo test -p starforged --test mail_cli`
Expected: compile errors (`MailConfig`, `Config::mailer`) and an unknown `mail` subcommand.

- [ ] **Step 10: Implement `[mail]`, the wiring, and the CLI command**

`crates/starforged/src/config.rs`:

1. Add `use starforged_core::mail::Mailer;`.
2. Add the section to `Config` (after `security`) and define it:

```rust
    #[serde(default)]
    pub mail: MailConfig,
```

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailConfig {
    /// Empty: no email. Otherwise `smtp://`, `smtps://`, or `file:///dir` (forge-basics design §3).
    #[serde(default)]
    pub url: String,
    /// Sender mailbox, e.g. `Starforge <forge@example.com>`.
    #[serde(default)]
    pub from: String,
}
```

3. In `apply_env`, add two arms before the catch-all:

```rust
                "mail__url" => self.mail.url = value,
                "mail__from" => self.mail.from = value,
```

4. In `validate`, check the mail settings last (before `Ok(())`):

```rust
        self.mailer()?;
```

5. Add to `impl Config`:

```rust
    /// The `[mail]` section as a mailer; `None` when `mail.url` is empty.
    pub fn mailer(&self) -> anyhow::Result<Option<Mailer>> {
        Ok(Mailer::from_config(&self.mail.url, &self.mail.from)?)
    }
```

`crates/starforged/src/init.rs`: import `MailConfig` and add `mail: MailConfig::default(),` to the `Config` literal (the written file gains an empty `[mail]` section).

`crates/starforged/src/admin.rs`: in `open_core`, build the extended `CoreConfig`:

```rust
    Ok(Core::new(
        db,
        CoreConfig {
            repos_dir: config.repos_dir(),
            hook_exe,
            base_url: config.server.base_url.clone(),
            mailer: config.mailer()?,
        },
    ))
```

and add:

```rust
/// `starforged admin mail test`: sends one message directly, bypassing the job queue.
pub async fn mail_test(config: &Config, to: &str) -> anyhow::Result<()> {
    let mailer = config
        .mailer()?
        .context("mail.url is empty; configure [mail] in starforged.toml first")?;
    let email = starforged_core::mail::test_email(to, &config.server.base_url)?;
    mailer.send(&email).await?;
    Ok(())
}
```

`crates/starforged/src/main.rs`: add a `Mail` admin subcommand and its dispatch:

```rust
    /// Email.
    Mail {
        #[command(subcommand)]
        command: AdminMailCommand,
    },
```

```rust
#[derive(Subcommand)]
enum AdminMailCommand {
    /// Send a test message directly (not through the job queue) to check the [mail] settings.
    Test {
        #[arg(long)]
        to: String,
    },
}
```

```rust
                AdminCommand::Mail {
                    command: AdminMailCommand::Test { to },
                } => {
                    admin::mail_test(&config, &to).await?;
                    println!("sent a test email to {to}");
                }
```

- [ ] **Step 11: Give the test harness an inbox**

In `crates/starforged/tests/common/mod.rs`:

1. Import `MailConfig` from `starforged::config` and add `mail: MailConfig::default(),` to the `Config` literal in `start`.
2. Rename `start` to `start_with`, give it a `configure: impl FnOnce(&mut Config)` parameter that runs right after the `Config` literal (`let mut config = …; configure(&mut config);`), and add:

```rust
    pub async fn start() -> TestServer {
        TestServer::start_with(|_| {}).await
    }

    /// Starts a server whose email goes to [`TestServer::mail_dir`] as `.eml` files.
    pub async fn start_with_mail(configure: impl FnOnce(&mut Config)) -> TestServer {
        TestServer::start_with(|config| {
            config.mail.url = format!(
                "file://{}",
                config.storage.data_dir.join("mail").display()
            );
            config.mail.from = "Starforge <forge@example.test>".into();
            configure(config);
        })
        .await
    }

    pub fn mail_dir(&self) -> PathBuf {
        self.data.path().join("mail")
    }

    /// Runs queued jobs (delivering email), then returns every message so far, oldest first.
    pub async fn inbox(&self) -> Vec<String> {
        self.core.run_due_jobs().await.unwrap();
        starforged_core::mail::testing::read_mailbox(&self.mail_dir())
    }

    /// The newest message to `to`, after running queued jobs.
    pub async fn last_email_to(&self, to: &str) -> String {
        self.inbox()
            .await
            .into_iter()
            .rev()
            .find(|m| m.contains(&format!("To: {to}")))
            .unwrap_or_else(|| panic!("no email to {to}"))
    }

    /// The link in `message` whose path starts with `path_prefix`; it must point at this server.
    pub fn link_in(&self, message: &str, path_prefix: &str) -> String {
        let link = starforged_core::mail::testing::find_link(message, path_prefix)
            .unwrap_or_else(|| panic!("no {path_prefix} link in:\n{message}"));
        assert!(link.starts_with(&self.base), "{link} does not point at {}", self.base);
        link
    }
```

- [ ] **Step 12: Run the tests**

Run: `cargo test -p starforged --lib config` and `cargo test -p starforged --test mail_cli`
Expected: pass.

- [ ] **Step 13: Full suite, lint, format, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add Cargo.toml Cargo.lock crates/starforged-core crates/starforged
git commit -m "feat(mail): optional SMTP or file email, queued as jobs, with admin mail test"
```

### Task A3: Email verification and one-time email links

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0003_email_verification.sql`, `crates/starforged-db/migrations/postgres/0003_email_verification.sql`
- Create: `crates/starforged-db/src/email_tokens.rs`; Modify: `crates/starforged-db/src/lib.rs`, `crates/starforged-db/src/users.rs`
- Create: `crates/starforged-core/src/email_tokens.rs`, `crates/starforged-core/src/verification.rs`, `crates/starforged-core/templates/mail/verify_email.txt`
- Modify: `crates/starforged-core/src/{lib.rs, error.rs, accounts.rs, sessions.rs, mail.rs, jobs.rs}`
- Modify: `crates/starforged/src/admin.rs`, `crates/starforged-api/src/error.rs`
- Create: `crates/starforged-web/src/pages/message.rs`, `crates/starforged-web/src/pages/verify.rs`, `crates/starforged-web/templates/message.html`, `crates/starforged-web/templates/verify.html`
- Modify: `crates/starforged-web/src/{auth.rs, error.rs, lib.rs, pages/mod.rs, pages/login.rs}`, `crates/starforged-web/templates/login.html`
- Modify: `crates/starforged/tests/common/mod.rs`
- Test: unit tests in the new db and core modules, `auth.rs`, `jobs.rs`, `users.rs`; `crates/starforged/tests/web_verify.rs`

**Interfaces:**
- Consumes: `Core::{mail_enabled, queue_email, run_due_jobs}`, `mail::{Email, render}`, `mail::testing::find_link`, `test_core_with`, `with_file_mail`, `Fixture::mail` (Task A2); `crypto::{random_hex, sha256_hex}` (M0).
- Produces:
  - `UserRow.email_verified`, `NewUser.email_verified`, `users::set_email_verified(db, id, verified)`.
  - `starforged_db::email_tokens::{EmailTokenRow { id, user_id, purpose, email, created_at, expires_at, used_at }, NewEmailToken { user_id, purpose, token_hash, email, expires_at }, newest_created_at, replace, peek, consume, delete_expired}`.
  - `starforged_core::email_tokens::{Purpose::{VerifyEmail, ChangeEmail, ResetPassword}, VERIFY_TTL_SECS, RESET_TTL_SECS, ADMIN_RESET_TTL_SECS, EMAIL_THROTTLE_SECS}`; crate-private `Core::{issue_email_token(user_id, purpose, email, ttl_secs, throttle) -> Option<String>, consume_email_token(secret, purpose), peek_email_token(secret, purpose)}`.
  - `Core::{send_verification(&User) -> CoreResult<bool>, resend_verification(email), verify_email(secret) -> CoreResult<User>, email_link_valid(secret) -> CoreResult<bool>}`.
  - `User.email_verified`; `CreateUser.email_verified` (the caller vouches for the address); `CoreError::EmailUnverified`, returned by `Core::login` when mail is on and the account's address is unverified.
  - Web: `auth::{anonymous_csrf(jar, secure) -> (CookieJar, String), verify_anonymous_csrf(&jar, submitted)}`; `pages::message::MessagePage::{new(nav_user, title, message), with_link(href, text)}`; routes `GET|POST /verify/{token}`, `POST /verify/resend`.
  - Harness: `TestServer::try_login(login, password) -> (reqwest::Client, reqwest::Response)`; `login` now uses it.

- [ ] **Step 1: Write the migrations**

`crates/starforged-db/migrations/sqlite/0003_email_verification.sql`:

```sql
-- Starforge M0.5: verified email addresses and one-time emailed links (forge-basics design §4.2-§4.3).
-- Keep in lockstep with ../postgres/0003_email_verification.sql.

ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
-- Accounts created before this migration were made by an administrator, who vouches for their addresses.
UPDATE users SET email_verified = 1 WHERE email IS NOT NULL;

CREATE TABLE email_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'change_email', 'reset_password')),
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX email_tokens_user ON email_tokens (user_id, purpose);
```

`crates/starforged-db/migrations/postgres/0003_email_verification.sql`:

```sql
-- Starforge M0.5: verified email addresses and one-time emailed links (forge-basics design §4.2-§4.3).
-- Keep in lockstep with ../sqlite/0003_email_verification.sql.

ALTER TABLE users ADD COLUMN email_verified BIGINT NOT NULL DEFAULT 0;
-- Accounts created before this migration were made by an administrator, who vouches for their addresses.
UPDATE users SET email_verified = 1 WHERE email IS NOT NULL;

CREATE TABLE email_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'change_email', 'reset_password')),
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT
);
CREATE INDEX email_tokens_user ON email_tokens (user_id, purpose);
```

- [ ] **Step 2: Write the failing data-access tests**

Add `pub mod email_tokens;` to `crates/starforged-db/src/lib.rs` after `pub mod collaborators;`. Create `crates/starforged-db/src/email_tokens.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    #[tokio::test]
    async fn tokens_work_once_until_they_expire_and_newer_ones_retire_older() {
        let t = TestDb::new().await;
        let user = users::insert(
            &t.db,
            &NewUser {
                handle: "alice",
                display_name: "",
                email: Some("a@example.com"),
                email_verified: false,
                password_hash: None,
                is_admin: false,
            },
        )
        .await
        .unwrap();
        let token = |token_hash: &'static str, expires_at: i64| NewEmailToken {
            user_id: user,
            purpose: "verify_email",
            token_hash,
            email: "a@example.com",
            expires_at,
        };
        assert_eq!(newest_created_at(&t.db, user, "verify_email").await.unwrap(), None);
        replace(&t.db, &token("h1", i64::MAX)).await.unwrap();
        replace(&t.db, &token("h2", i64::MAX)).await.unwrap();
        assert!(newest_created_at(&t.db, user, "verify_email").await.unwrap().is_some());
        assert!(
            consume(&t.db, "h1", "verify_email", 10).await.unwrap().is_none(),
            "the newer token retired h1"
        );
        assert!(
            consume(&t.db, "h2", "reset_password", 10).await.unwrap().is_none(),
            "wrong purpose"
        );
        let row = consume(&t.db, "h2", "verify_email", 10).await.unwrap().unwrap();
        assert_eq!((row.user_id, row.email.as_str()), (user, "a@example.com"));
        assert!(
            consume(&t.db, "h2", "verify_email", 10).await.unwrap().is_none(),
            "tokens work once"
        );
        replace(&t.db, &token("h3", 100)).await.unwrap();
        assert!(peek(&t.db, "h3", "verify_email", 99).await.unwrap().is_some());
        assert!(
            peek(&t.db, "h3", "verify_email", 99).await.unwrap().is_some(),
            "peeking does not use the token"
        );
        assert!(
            consume(&t.db, "h3", "verify_email", 100).await.unwrap().is_none(),
            "expired"
        );
        assert_eq!(delete_expired(&t.db, 101).await.unwrap(), 1);
    }
}
```

Add to the test module of `crates/starforged-db/src/users.rs` (and add `email_verified: false,` to `alice()`):

```rust
    #[tokio::test]
    async fn email_verification_is_stored() {
        let t = TestDb::new().await;
        let id = insert(
            &t.db,
            &NewUser {
                email_verified: true,
                ..alice()
            },
        )
        .await
        .unwrap();
        assert!(by_id(&t.db, id).await.unwrap().unwrap().email_verified);
        set_email_verified(&t.db, id, false).await.unwrap();
        assert!(!by_id(&t.db, id).await.unwrap().unwrap().email_verified);
    }
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test -p starforged-db`
Expected: compile errors.

- [ ] **Step 4: Implement the data access**

`crates/starforged-db/src/users.rs`:

1. Add `email_verified` to `UserRow` (after `email`) and `NewUser` (after `email`):

```rust
    /// The owner of `email` confirmed it, or an administrator vouched for it.
    pub email_verified: bool,
```

2. Select it: `"SELECT u.id, o.handle, u.display_name, u.email, u.email_verified, u.password_hash, u.is_admin, u.state, u.created_at "`, and read it in `from_row`: `email_verified: row.try_get::<i64, _>("email_verified")? != 0,`.
3. Insert it:

```rust
    sqlx::query(
        "INSERT INTO users (id, display_name, email, email_verified, password_hash, is_admin, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(new.display_name)
    .bind(new.email.map(str::to_owned))
    .bind(i64::from(new.email_verified))
    .bind(new.password_hash.map(str::to_owned))
    .bind(i64::from(new.is_admin))
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
```

4. Add:

```rust
pub async fn set_email_verified(db: &Db, id: i64, verified: bool) -> DbResult<()> {
    sqlx::query("UPDATE users SET email_verified = $1 WHERE id = $2")
        .bind(i64::from(verified))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
```

Insert at the top of `crates/starforged-db/src/email_tokens.rs`, above the test module:

```rust
//! `email_tokens`: one-time links sent by email (forge-basics design §4.3), stored as SHA-256 of the secret.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailTokenRow {
    pub id: i64,
    pub user_id: i64,
    pub purpose: String,
    /// The address the link was sent to (for `change_email`, the new address).
    pub email: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
}

pub struct NewEmailToken<'a> {
    pub user_id: i64,
    /// `verify_email`, `change_email`, or `reset_password`.
    pub purpose: &'a str,
    pub token_hash: &'a str,
    pub email: &'a str,
    pub expires_at: i64,
}

macro_rules! select_token {
    ($tail:literal) => {
        concat!(
            "SELECT id, user_id, purpose, email, created_at, expires_at, used_at FROM email_tokens ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<EmailTokenRow> {
    Ok(EmailTokenRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        purpose: row.try_get("purpose")?,
        email: row.try_get("email")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        used_at: row.try_get("used_at")?,
    })
}

/// When the newest token for `user_id` and `purpose` was issued; the email throttle reads it.
pub async fn newest_created_at(db: &Db, user_id: i64, purpose: &str) -> DbResult<Option<i64>> {
    let newest: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(created_at) FROM email_tokens WHERE user_id = $1 AND purpose = $2",
    )
    .bind(user_id)
    .bind(purpose)
    .fetch_one(db.pool())
    .await?;
    Ok(newest)
}

/// Inserts a token after retiring the user's unused tokens for the same purpose: only the newest link works.
pub async fn replace(db: &Db, token: &NewEmailToken<'_>) -> DbResult<i64> {
    let ts = now();
    let mut tx = db.pool().begin().await?;
    sqlx::query(
        "UPDATE email_tokens SET used_at = $1 WHERE user_id = $2 AND purpose = $3 AND used_at IS NULL",
    )
    .bind(ts)
    .bind(token.user_id)
    .bind(token.purpose)
    .execute(&mut *tx)
    .await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO email_tokens (user_id, purpose, token_hash, email, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(token.user_id)
    .bind(token.purpose)
    .bind(token.token_hash)
    .bind(token.email)
    .bind(ts)
    .bind(token.expires_at)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// The unused token with this hash and purpose that expires after `now_ts`, without using it.
pub async fn peek(
    db: &Db,
    token_hash: &str,
    purpose: &str,
    now_ts: i64,
) -> DbResult<Option<EmailTokenRow>> {
    let row = sqlx::query(select_token!(
        "WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3"
    ))
    .bind(token_hash)
    .bind(purpose)
    .bind(now_ts)
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(from_row).transpose()
}

/// Uses a token once: returns it when it was unused, unexpired, and for `purpose`, and marks it used.
pub async fn consume(
    db: &Db,
    token_hash: &str,
    purpose: &str,
    now_ts: i64,
) -> DbResult<Option<EmailTokenRow>> {
    let Some(row) = peek(db, token_hash, purpose, now_ts).await? else {
        return Ok(None);
    };
    let used = sqlx::query("UPDATE email_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL")
        .bind(now_ts)
        .bind(row.id)
        .execute(db.pool())
        .await?
        .rows_affected();
    Ok((used == 1).then_some(row))
}

/// Deletes tokens whose expiry is at or before `now_ts`; returns how many.
pub async fn delete_expired(db: &Db, now_ts: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM email_tokens WHERE expires_at <= $1")
        .bind(now_ts)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}
```

Run: `cargo test -p starforged-db`
Expected: all pass.

- [ ] **Step 5: Write the failing core tests**

Add `pub mod email_tokens;` (after `pub mod crypto;`) and `pub mod verification;` (after `pub mod validate;`) to `crates/starforged-core/src/lib.rs`. Create `crates/starforged-core/src/verification.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, test_core_with, with_file_mail};

    const PASSWORD: &str = "correct horse battery";

    async fn unverified(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            email: Some(format!("{handle}@example.com")),
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    fn secret_in(message: &str) -> String {
        let link = crate::mail::testing::find_link(message, "/verify/").unwrap();
        link.rsplit('/').next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn verification_links_work_once() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = unverified(&core, "alice").await;
        assert!(!alice.email_verified);
        assert!(core.send_verification(&alice).await.unwrap());
        assert!(
            !core.send_verification(&alice).await.unwrap(),
            "throttled for five minutes"
        );
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(mail[0].contains("Subject: Verify your email address"), "{}", mail[0]);
        let secret = secret_in(&mail[0]);

        assert!(core.email_link_valid(&secret).await.unwrap());
        assert!(matches!(
            core.login("alice", PASSWORD, "ua", "127.0.0.1").await,
            Err(CoreError::EmailUnverified)
        ));
        let verified = core.verify_email(&secret).await.unwrap();
        assert!(verified.email_verified);
        assert!(!core.email_link_valid(&secret).await.unwrap());
        assert!(matches!(
            core.verify_email(&secret).await,
            Err(CoreError::NotFound)
        ));
        core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();
        assert!(
            !core.send_verification(&verified).await.unwrap(),
            "nothing left to verify"
        );
    }

    #[tokio::test]
    async fn links_for_an_old_address_do_not_verify_a_new_one() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = unverified(&core, "alice").await;
        core.send_verification(&alice).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let secret = secret_in(&fixture.mail()[0]);
        sqlx::query("UPDATE users SET email = $1 WHERE id = $2")
            .bind("new@example.com")
            .bind(alice.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        assert!(matches!(
            core.verify_email(&secret).await,
            Err(CoreError::NotFound)
        ));
        assert!(!core.user_by_id(alice.id).await.unwrap().unwrap().email_verified);
    }

    #[tokio::test]
    async fn sign_in_needs_verification_only_when_mail_is_on() {
        let (core, _f) = test_core().await;
        unverified(&core, "alice").await;
        core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();

        let (core, _f) = test_core_with(with_file_mail).await;
        core.create_user(CreateUser {
            handle: "bob".into(),
            email: Some("bob@example.com".into()),
            password: Some(PASSWORD.into()),
            email_verified: true,
            ..Default::default()
        })
        .await
        .unwrap();
        core.login("bob", PASSWORD, "ua", "127.0.0.1").await.unwrap();
    }

    #[tokio::test]
    async fn resending_is_silent_for_unknown_addresses() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        unverified(&core, "alice").await;
        core.resend_verification("nobody@example.com").await.unwrap();
        core.resend_verification("not an address").await.unwrap();
        core.resend_verification("ALICE@example.com").await.unwrap();
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(mail[0].contains("To: alice@example.com"), "{}", mail[0]);
    }
}
```

Add this test to the test module of `crates/starforged-core/src/jobs.rs`:

```rust
    #[tokio::test]
    async fn hourly_cleanup_deletes_expired_email_tokens() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        for (purpose, token_hash, expires_at) in [
            ("verify_email", "expired", 10),
            ("reset_password", "live", now() + 3_600),
        ] {
            starforged_db::email_tokens::replace(
                core.db(),
                &starforged_db::email_tokens::NewEmailToken {
                    user_id: alice.id,
                    purpose,
                    token_hash,
                    email: "alice@example.com",
                    expires_at,
                },
            )
            .await
            .unwrap();
        }
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let left: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM email_tokens")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        assert_eq!(left, vec!["live".to_owned()]);
    }
```

- [ ] **Step 6: Run them to see them fail**

Run: `cargo test -p starforged-core`
Expected: compile errors.

- [ ] **Step 7: Implement verification in core**

`crates/starforged-core/src/error.rs`: add after `Unauthenticated`:

```rust
    #[error("the email address is not verified")]
    EmailUnverified,
```

`crates/starforged-core/src/accounts.rs`:

1. `User` gains `pub email_verified: bool,` after `email`; the `From<UserRow> for User` impl sets `email_verified: row.email_verified,`.
2. `CreateUser` gains, after `email`:

```rust
    /// The caller vouches for `email`: site admins creating accounts, and sign-ups through an invite that was
    /// sent to that address.
    pub email_verified: bool,
```

3. `create_user` stores it: add `email_verified: input.email_verified && email.is_some(),` to the `NewUser` literal.

`crates/starforged/src/admin.rs`: `create_user` passes `email_verified: true` (the admin vouches for the address).

`crates/starforged-core/templates/mail/verify_email.txt`:

```
Hello {{ handle }},

Confirm the email address of your Starforge account by opening this link:

{{ link }}

The link works once and expires in 24 hours. If you did not create an account, ignore this message.
```

Add to `crates/starforged-core/src/mail.rs` (after `test_email`):

```rust
#[derive(Template)]
#[template(path = "mail/verify_email.txt")]
struct VerifyEmailText<'a> {
    handle: &'a str,
    link: &'a str,
}

/// "Verify your email address", with a link valid for 24 hours.
pub(crate) fn verify_email(to: &str, handle: &str, link: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: "Verify your email address".into(),
        body: render(&VerifyEmailText { handle, link })?,
    })
}
```

`crates/starforged-core/src/email_tokens.rs`:

```rust
//! One-time links sent by email (forge-basics design §4.3–§4.4). Secrets are 32 random bytes in hex; only
//! their SHA-256 is stored.

use starforged_db::email_tokens::{self, EmailTokenRow, NewEmailToken};
use starforged_db::now;

use crate::{Core, CoreResult, crypto};

/// Lifetime of verify-email and confirm-new-email links.
pub const VERIFY_TTL_SECS: i64 = 24 * 3_600;
/// Lifetime of emailed password-reset links.
pub const RESET_TTL_SECS: i64 = 3_600;
/// Lifetime of password-reset links an admin passes on by hand when mail is off.
pub const ADMIN_RESET_TTL_SECS: i64 = 24 * 3_600;
/// At most one email per address and purpose within this window.
pub const EMAIL_THROTTLE_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    VerifyEmail,
    ChangeEmail,
    ResetPassword,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::VerifyEmail => "verify_email",
            Purpose::ChangeEmail => "change_email",
            Purpose::ResetPassword => "reset_password",
        }
    }
}

/// Whether `secret` has the shape of an issued secret: 64 lowercase hex characters.
fn well_formed(secret: &str) -> bool {
    secret.len() == 64 && secret.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Core {
    /// Issues a link secret for `user_id` and `purpose`, sent to `email` and valid for `ttl_secs`; the user's
    /// earlier unused links for the same purpose stop working. With `throttle`, returns `None` instead when a
    /// link for the same purpose was issued within [`EMAIL_THROTTLE_SECS`].
    pub(crate) async fn issue_email_token(
        &self,
        user_id: i64,
        purpose: Purpose,
        email: &str,
        ttl_secs: i64,
        throttle: bool,
    ) -> CoreResult<Option<String>> {
        let ts = now();
        if throttle
            && let Some(last) =
                email_tokens::newest_created_at(self.db(), user_id, purpose.as_str()).await?
            && ts - last < EMAIL_THROTTLE_SECS
        {
            return Ok(None);
        }
        let secret = crypto::random_hex(32);
        email_tokens::replace(
            self.db(),
            &NewEmailToken {
                user_id,
                purpose: purpose.as_str(),
                token_hash: &crypto::sha256_hex(&secret),
                email,
                expires_at: ts + ttl_secs,
            },
        )
        .await?;
        Ok(Some(secret))
    }

    /// Uses a link once: its token when `secret` is unused, unexpired, and for `purpose`.
    pub(crate) async fn consume_email_token(
        &self,
        secret: &str,
        purpose: Purpose,
    ) -> CoreResult<Option<EmailTokenRow>> {
        if !well_formed(secret) {
            return Ok(None);
        }
        Ok(email_tokens::consume(self.db(), &crypto::sha256_hex(secret), purpose.as_str(), now()).await?)
    }

    /// Like [`Core::consume_email_token`], without using the link.
    pub(crate) async fn peek_email_token(
        &self,
        secret: &str,
        purpose: Purpose,
    ) -> CoreResult<Option<EmailTokenRow>> {
        if !well_formed(secret) {
            return Ok(None);
        }
        Ok(email_tokens::peek(self.db(), &crypto::sha256_hex(secret), purpose.as_str(), now()).await?)
    }
}
```

Insert at the top of `crates/starforged-core/src/verification.rs`, above the test module:

```rust
//! Email verification (forge-basics design §4.2).

use starforged_db::users;

use crate::accounts::User;
use crate::email_tokens::{Purpose, VERIFY_TTL_SECS};
use crate::{Core, CoreError, CoreResult, mail, validate};

impl Core {
    /// Emails `user` a verification link. `Ok(false)` when nothing was sent: mail is off, the address is
    /// already verified or missing, or a link went out within the throttle window.
    pub async fn send_verification(&self, user: &User) -> CoreResult<bool> {
        if !self.mail_enabled() || user.email_verified {
            return Ok(false);
        }
        let Some(email) = user.email.as_deref() else {
            return Ok(false);
        };
        let Some(secret) = self
            .issue_email_token(user.id, Purpose::VerifyEmail, email, VERIFY_TTL_SECS, true)
            .await?
        else {
            return Ok(false);
        };
        let link = format!("{}/verify/{secret}", self.config().base_url);
        self.queue_email(mail::verify_email(email, &user.handle, &link)?)
            .await?;
        Ok(true)
    }

    /// The resend form: the same outcome whether or not an unverified account uses `email`.
    pub async fn resend_verification(&self, email: &str) -> CoreResult<()> {
        let Ok(email) = validate::email(email) else {
            return Ok(());
        };
        if let Some(row) = users::by_email(self.db(), &email).await? {
            let user = User::from(row);
            if user.active {
                self.send_verification(&user).await?;
            }
        }
        Ok(())
    }

    /// Whether a confirmation link can still be used; the confirm page is shown only for these.
    pub async fn email_link_valid(&self, secret: &str) -> CoreResult<bool> {
        Ok(self
            .peek_email_token(secret, Purpose::VerifyEmail)
            .await?
            .is_some())
    }

    /// Uses a link from a verification email; returns the now verified user. `NotFound` for unknown, used, or
    /// expired links, and for links sent to an address the account no longer uses.
    pub async fn verify_email(&self, secret: &str) -> CoreResult<User> {
        let token = self
            .consume_email_token(secret, Purpose::VerifyEmail)
            .await?
            .ok_or(CoreError::NotFound)?;
        let user = self.user_by_id(token.user_id).await?.ok_or(CoreError::NotFound)?;
        if user.email.as_deref() != Some(token.email.as_str()) {
            return Err(CoreError::NotFound);
        }
        users::set_email_verified(self.db(), user.id, true).await?;
        self.audit(
            Some(user.id),
            "account.email_verified",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        self.user_by_id(user.id).await?.ok_or(CoreError::NotFound)
    }
}
```

`crates/starforged-core/src/sessions.rs`: in `login`, right after the `match` that authenticates the password, refuse unverified addresses when mail is on:

```rust
        if self.mail_enabled() && user.email.is_some() && !user.email_verified {
            self.audit_client(
                Some(user.id),
                "auth.login_unverified",
                &format!("user:{}", user.handle),
                "",
                ip,
                &user_agent,
            )
            .await?;
            return Err(CoreError::EmailUnverified);
        }
```

`crates/starforged-core/src/jobs.rs`: in `hourly_cleanup`, after deleting expired sessions:

```rust
        starforged_db::email_tokens::delete_expired(self.db(), ts).await?;
```

Run: `cargo test -p starforged-core`
Expected: all pass.

- [ ] **Step 8: Map the new error in both HTTP layers**

`crates/starforged-web/src/error.rs`: `CoreError::Forbidden | CoreError::Unauthenticated | CoreError::EmailUnverified => WebError::Forbidden,`.

`crates/starforged-api/src/error.rs`: add an arm before the catch-all:

```rust
            CoreError::EmailUnverified => ApiError::Forbidden("email address not verified".into()),
```

- [ ] **Step 9: Write the failing web tests**

Add to the test module of `crates/starforged-web/src/auth.rs`:

```rust
    #[test]
    fn anonymous_csrf_reuses_its_cookie() {
        let (jar, first) = anonymous_csrf(CookieJar::new(), false);
        assert_eq!(first.len(), 64);
        let (jar, second) = anonymous_csrf(jar, false);
        assert_eq!(first, second, "open forms keep working when another one is loaded");
        assert!(verify_anonymous_csrf(&jar, &first).is_ok());
        assert!(verify_anonymous_csrf(&jar, "forged").is_err());
        assert!(verify_anonymous_csrf(&CookieJar::new(), "").is_err());
    }
```

In `crates/starforged/tests/common/mod.rs`, add `try_login` and rebuild `login` on it:

```rust
    /// Submits the sign-in form from a fresh browser; returns the browser and the response.
    pub async fn try_login(&self, login: &str, password: &str) -> (reqwest::Client, reqwest::Response) {
        let client = self.browser();
        let page = get_text(&client, &self.url("/login")).await;
        let csrf = extract_input(&page, "_csrf");
        let response = client
            .post(self.url("/login"))
            .form(&[
                ("_csrf", csrf.as_str()),
                ("next", "/"),
                ("login", login),
                ("password", password),
            ])
            .send()
            .await
            .unwrap();
        (client, response)
    }

    /// Signs `handle` in with [`PASSWORD`]; returns the browser and the session's CSRF token.
    pub async fn login(&self, handle: &str) -> (reqwest::Client, String) {
        let (client, response) = self.try_login(handle, PASSWORD).await;
        assert_eq!(response.status(), 303, "signing in as {handle} failed");
        let dashboard = get_text(&client, &self.url("/")).await;
        (client, extract_input(&dashboard, "_csrf"))
    }
```

Create `crates/starforged/tests/web_verify.rs`:

```rust
mod common;

use common::*;
use starforged_core::accounts::CreateUser;

async fn unverified(s: &TestServer, handle: &str, email: &str) {
    s.core
        .create_user(CreateUser {
            handle: handle.into(),
            email: Some(email.into()),
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_accounts_confirm_their_address_before_signing_in() {
    let s = TestServer::start_with_mail(|_| {}).await;
    unverified(&s, "alice", "alice@example.com").await;

    let (_, wrong) = s.try_login("alice", "not the password").await;
    assert_eq!(wrong.status(), 401);
    assert!(
        !wrong.text().await.unwrap().contains("Verify your email"),
        "the reminder needs the right password"
    );
    let (client, blocked) = s.try_login("alice", PASSWORD).await;
    assert_eq!(blocked.status(), 403);
    let page = blocked.text().await.unwrap();
    assert!(page.contains("Verify your email address before signing in"), "{page}");
    let csrf = extract_input(&page, "_csrf");

    let forged = client
        .post(s.url("/verify/resend"))
        .form(&[("_csrf", "forged"), ("email", "alice@example.com")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    for email in ["alice@example.com", "alice@example.com", "nobody@example.com"] {
        let response = client
            .post(s.url("/verify/resend"))
            .form(&[("_csrf", csrf.as_str()), ("email", email)])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(response
            .text()
            .await
            .unwrap()
            .contains("If an unverified account uses that address"));
    }
    let inbox = s.inbox().await;
    assert_eq!(
        inbox.len(),
        1,
        "the second request was throttled and the unknown address got nothing"
    );
    let link = s.link_in(&inbox[0], "/verify/");

    let confirm = get_text(&client, &link).await;
    assert!(confirm.contains("Confirm your email address"));
    let confirm_csrf = extract_input(&confirm, "_csrf");
    let done = client
        .post(&link)
        .form(&[("_csrf", confirm_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    assert!(done.text().await.unwrap().contains("Your email address is verified"));
    assert_eq!(
        client.get(&link).send().await.unwrap().status(),
        404,
        "links work once"
    );

    s.login("alice").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_mail_unverified_accounts_sign_in() {
    let s = TestServer::start().await;
    unverified(&s, "bob", "bob@example.com").await;
    s.login("bob").await;
    let unknown = s
        .browser()
        .get(s.url(&format!("/verify/{}", "a".repeat(64))))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);
}
```

- [ ] **Step 10: Run them to see them fail**

Run: `cargo test -p starforged-web auth` and `cargo test -p starforged --test web_verify`
Expected: compile errors (`anonymous_csrf`), then 404s for `/verify/...` routes.

- [ ] **Step 11: Implement the web side**

Add to `crates/starforged-web/src/auth.rs`:

```rust
/// The CSRF token for a form shown to signed-out visitors, kept in the double-submit cookie `sf_login_csrf`.
/// An existing cookie is reused (and its lifetime renewed), so several such forms can be open at once.
pub fn anonymous_csrf(jar: CookieJar, secure: bool) -> (CookieJar, String) {
    let csrf = jar
        .get(LOGIN_CSRF_COOKIE)
        .map(|c| c.value().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| starforged_core::crypto::random_hex(32));
    (jar.add(login_csrf_cookie(csrf.clone(), secure)), csrf)
}

/// Checks a signed-out form's `_csrf` field against its cookie.
pub fn verify_anonymous_csrf(jar: &CookieJar, submitted: &str) -> Result<(), WebError> {
    let expected = jar
        .get(LOGIN_CSRF_COOKIE)
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    verify_csrf(&expected, submitted)
}
```

`crates/starforged-web/src/pages/message.rs`:

```rust
//! A page with a title, one paragraph, and an optional link: confirmations and dead ends.

use askama::Template;
use askama_web::WebTemplate;

use crate::views::NavUser;

#[derive(Template, WebTemplate)]
#[template(path = "message.html")]
pub struct MessagePage {
    nav_user: Option<NavUser>,
    title: &'static str,
    message: String,
    link_href: &'static str,
    link_text: &'static str,
}

impl MessagePage {
    pub fn new(nav_user: Option<NavUser>, title: &'static str, message: impl Into<String>) -> MessagePage {
        MessagePage {
            nav_user,
            title,
            message: message.into(),
            link_href: "",
            link_text: "",
        }
    }

    pub fn with_link(mut self, href: &'static str, text: &'static str) -> MessagePage {
        self.link_href = href;
        self.link_text = text;
        self
    }
}
```

`crates/starforged-web/templates/message.html`:

```html
{% extends "base.html" %}
{% block title %}{{ title }} · Starforge{% endblock %}
{% block content %}
<h1>{{ title }}</h1>
<p>{{ message }}</p>
{% if !link_href.is_empty() %}<p><a href="{{ link_href }}">{{ link_text }}</a></p>{% endif %}
{% endblock %}
```

`crates/starforged-web/src/pages/verify.rs`:

```rust
//! Email confirmation links (forge-basics design §4.2). `GET` shows a Confirm button and `POST` uses the link,
//! so mail scanners that prefetch links cannot use them up.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{
    CsrfForm, MaybeUser, anonymous_csrf, verify_anonymous_csrf, verify_csrf,
};
use crate::error::WebError;
use crate::pages::message::MessagePage;
use crate::views::{NavUser, nav};

#[derive(Template, WebTemplate)]
#[template(path = "verify.html")]
pub struct ConfirmPage {
    nav_user: Option<NavUser>,
    csrf: String,
    token: String,
}

#[derive(Deserialize)]
pub struct ResendForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    email: String,
}

fn invalid_link(session: Option<&WebSession>) -> Response {
    (
        StatusCode::NOT_FOUND,
        MessagePage::new(
            nav(session),
            "Link not valid",
            "This link is invalid, was already used, or has expired.",
        ),
    )
        .into_response()
}

pub async fn confirm_form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Path(token): Path<String>,
) -> Result<Response, WebError> {
    if !state.core.email_link_valid(&token).await? {
        return Ok(invalid_link(session.as_ref()));
    }
    // Signed-in visitors already carry a CSRF token (the page header's sign-out form uses it).
    let (jar, csrf) = match &session {
        Some(session) => (jar, session.csrf_token.clone()),
        None => anonymous_csrf(jar, state.settings.secure_cookies),
    };
    let page = ConfirmPage {
        nav_user: nav(session.as_ref()),
        csrf,
        token,
    };
    Ok((jar, page).into_response())
}

pub async fn confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Path(token): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    match &session {
        Some(session) => verify_csrf(&session.csrf_token, &form.csrf)?,
        None => verify_anonymous_csrf(&jar, &form.csrf)?,
    }
    match state.core.verify_email(&token).await {
        Ok(_) => {
            let (href, text) = if session.is_some() {
                ("/", "Continue")
            } else {
                ("/login", "Sign in")
            };
            let page = MessagePage::new(
                nav(session.as_ref()),
                "Email verified",
                "Your email address is verified.",
            )
            .with_link(href, text);
            Ok(page.into_response())
        }
        Err(CoreError::NotFound) => Ok(invalid_link(session.as_ref())),
        Err(other) => Err(other.into()),
    }
}

pub async fn resend(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ResendForm>,
) -> Result<MessagePage, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    state.core.resend_verification(&form.email).await?;
    Ok(MessagePage::new(
        None,
        "Check your email",
        "If an unverified account uses that address, we sent it a new link. It expires in 24 hours.",
    ))
}
```

`crates/starforged-web/templates/verify.html`:

```html
{% extends "base.html" %}
{% block title %}Confirm your email address · Starforge{% endblock %}
{% block content %}
<h1>Confirm your email address</h1>
<form method="post" action="/verify/{{ token }}" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <button type="submit">Confirm</button>
</form>
{% endblock %}
```

`crates/starforged-web/src/pages/mod.rs`: add `pub mod message;` and `pub mod verify;`.

`crates/starforged-web/src/lib.rs` `page_routes`: add

```rust
        .route("/verify/resend", post(pages::verify::resend))
        .route(
            "/verify/{token}",
            get(pages::verify::confirm_form).post(pages::verify::confirm),
        )
```

`crates/starforged-web/src/pages/login.rs`:

1. `LoginPage` gains `unverified: bool` ("the password was right but the address is unverified: show the resend form"); every `LoginPage` literal sets it (`false` except below).
2. `form` builds its token with `let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);` instead of generating one inline. Drop the imports this leaves unused (`login_csrf_cookie`); `LOGIN_CSRF_COOKIE` stays for the cookie removal on success.
3. `submit` checks the token with `verify_anonymous_csrf(&jar, &form.csrf)?;` instead of reading the cookie inline, and handles the new error:

```rust
        Err(CoreError::EmailUnverified) => {
            let page = LoginPage {
                nav_user: None,
                csrf: form.csrf,
                next,
                login: form.login,
                error: None,
                unverified: true,
            };
            Ok((StatusCode::FORBIDDEN, page).into_response())
        }
```

`crates/starforged-web/templates/login.html`: after the error paragraph, add

```html
{% if unverified %}
<div class="notice">
<p>Verify your email address before signing in. We sent you a link when you signed up; we can send a new one:</p>
<form method="post" action="/verify/resend" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Email <input name="email" type="email" autocomplete="email" required></label>
  <button type="submit">Send a new link</button>
</form>
</div>
{% endif %}
```

- [ ] **Step 12: Run the web tests**

Run: `cargo test -p starforged-web` and `cargo test -p starforged --test web_verify --test web_auth`
Expected: pass.

- [ ] **Step 13: Full suite, lint, format, both engines, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
STARFORGE_TEST_PG=1 scripts/check.sh
git add crates Cargo.lock
git commit -m "feat(accounts): email verification with one-time links"
```

### Task A4: Registration modes, invites, and the sign-up page

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0004_invites.sql`, `crates/starforged-db/migrations/postgres/0004_invites.sql`
- Create: `crates/starforged-db/src/invites.rs`; Modify: `crates/starforged-db/src/lib.rs`
- Create: `crates/starforged-core/src/registration.rs`, `crates/starforged-core/src/invites.rs`, `crates/starforged-core/templates/mail/invite.txt`
- Modify: `crates/starforged-core/src/{lib.rs, validate.rs, accounts.rs, mail.rs, jobs.rs}`
- Modify: `crates/starforged/src/{config.rs, init.rs, admin.rs}`, `crates/starforged/tests/common/mod.rs`
- Create: `crates/starforged-web/src/pages/join.rs`, `crates/starforged-web/templates/join.html`
- Modify: `crates/starforged-web/src/{lib.rs, pages/mod.rs, pages/login.rs, pages/dashboard.rs}`, `crates/starforged-web/templates/{login.html, dashboard.html}`
- Test: unit tests in `invites.rs` (db and core), `registration.rs`, `validate.rs`, `config.rs`; `crates/starforged/tests/web_join.rs`

**Interfaces:**
- Consumes: `Core::{send_verification, queue_email, mail_enabled, create_user, login, audit}`, `CreateUser.email_verified`, `mail::render` (Tasks A2–A3); `anonymous_csrf`, `verify_anonymous_csrf`, `MessagePage`, `TestServer::try_login` (Task A3).
- Produces:
  - `starforged_db::invites::{InviteRow { id, email, created_by, created_at, expires_at, used_at, used_by, revoked_at }, NewInvite { code_hash, email, created_by, expires_at }, insert, by_code_hash, claim, release, set_used_by, list, revoke, delete_expired_before}`.
  - `starforged_core::registration::{RegistrationMode::{Invite, Open, Domains}, Registration { mode, allowed_domains }, SignUp { handle, email, password, display_name, invite }, SignedUp::{Active(User), VerificationSent(User)}}`; `RegistrationMode::{parse, as_str}`; `SignedUp::user()`; `Core::{registration(), sign_up_open(), sign_up(SignUp) -> CoreResult<SignedUp>}`.
  - `starforged_core::invites::{INVITE_TTL_SECS, InviteStatus::{Pending, Used, Expired, Revoked}, InviteInfo { id, email, created_at, expires_at, status }, CreatedInvite { id, link, emailed }}`; `Core::{create_invite(admin, email) -> CreatedInvite, list_invites(admin), revoke_invite(admin, id), invite_email(code) -> CoreResult<Option<String>>}` (Plan C's admin pages call the first three).
  - `CoreConfig.registration: Registration`; `validate::display_name`; `RESERVED_HANDLES` gains `forgot`, `join`, `reset`, `verify`.
  - `starforged::config::{RegistrationConfig { mode, allowed_domains }}`, `Config.registration`, `Config::registration_settings() -> anyhow::Result<Registration>`; overrides `STARFORGE__REGISTRATION__MODE`, `STARFORGE__REGISTRATION__ALLOWED_DOMAINS` (comma-separated).
  - Web: `GET|POST /join` (`?invite=<code>`); the sign-in page and the signed-out dashboard link to `/join` when sign-up is open.

- [ ] **Step 1: Write the migrations**

`crates/starforged-db/migrations/sqlite/0004_invites.sql`:

```sql
-- Starforge M0.5: single-use sign-up invites (forge-basics design §4.1).
-- Keep in lockstep with ../postgres/0004_invites.sql.

CREATE TABLE invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash TEXT NOT NULL UNIQUE,
    email TEXT,
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    used_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    revoked_at INTEGER
);
```

`crates/starforged-db/migrations/postgres/0004_invites.sql`:

```sql
-- Starforge M0.5: single-use sign-up invites (forge-basics design §4.1).
-- Keep in lockstep with ../sqlite/0004_invites.sql.

CREATE TABLE invites (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    email TEXT,
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    used_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    revoked_at BIGINT
);
```

- [ ] **Step 2: Write the failing data-access test**

Add `pub mod invites;` to `crates/starforged-db/src/lib.rs` after `pub mod email_tokens;`. Create `crates/starforged-db/src/invites.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    #[tokio::test]
    async fn invites_are_claimed_once_and_can_be_released_or_revoked() {
        let t = TestDb::new().await;
        let admin = users::insert(
            &t.db,
            &NewUser {
                handle: "root",
                display_name: "",
                email: None,
                email_verified: false,
                password_hash: None,
                is_admin: true,
            },
        )
        .await
        .unwrap();
        let id = insert(
            &t.db,
            &NewInvite {
                code_hash: "c1",
                email: Some("a@example.com"),
                created_by: admin,
                expires_at: 1_000,
            },
        )
        .await
        .unwrap();
        let row = by_code_hash(&t.db, "c1").await.unwrap().unwrap();
        assert_eq!(
            (row.id, row.email.as_deref(), row.created_by),
            (id, Some("a@example.com"), Some(admin))
        );
        assert!(
            !claim(&t.db, id, 1_000).await.unwrap(),
            "an invite has expired at its expiry time"
        );
        assert!(claim(&t.db, id, 10).await.unwrap());
        assert!(!claim(&t.db, id, 10).await.unwrap(), "single use");
        release(&t.db, id).await.unwrap();
        assert!(claim(&t.db, id, 10).await.unwrap(), "a released invite works again");
        set_used_by(&t.db, id, admin).await.unwrap();
        release(&t.db, id).await.unwrap();
        assert!(
            !claim(&t.db, id, 10).await.unwrap(),
            "a completed sign-up keeps its invite"
        );

        let other = insert(
            &t.db,
            &NewInvite {
                code_hash: "c2",
                email: None,
                created_by: admin,
                expires_at: 1_000,
            },
        )
        .await
        .unwrap();
        assert!(revoke(&t.db, other, 20).await.unwrap());
        assert!(!revoke(&t.db, other, 20).await.unwrap());
        assert!(!claim(&t.db, other, 30).await.unwrap(), "revoked");
        assert_eq!(
            list(&t.db, 10).await.unwrap().iter().map(|i| i.id).collect::<Vec<_>>(),
            vec![other, id]
        );
        assert_eq!(delete_expired_before(&t.db, 1_001).await.unwrap(), 2);
    }
}
```

- [ ] **Step 3: Run it to see it fail, then implement the invites data access**

Run: `cargo test -p starforged-db invites` — expected: compile errors.

Insert at the top of `crates/starforged-db/src/invites.rs`:

```rust
//! `invites`: single-use sign-up links issued by site admins (forge-basics design §4.1), stored as SHA-256 of
//! the code.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    pub id: i64,
    /// When set, only this address can sign up with the invite.
    pub email: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub struct NewInvite<'a> {
    pub code_hash: &'a str,
    pub email: Option<&'a str>,
    pub created_by: i64,
    pub expires_at: i64,
}

macro_rules! select_invite {
    ($tail:literal) => {
        concat!(
            "SELECT id, email, created_by, created_at, expires_at, used_at, used_by, revoked_at FROM invites ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<InviteRow> {
    Ok(InviteRow {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        used_at: row.try_get("used_at")?,
        used_by: row.try_get("used_by")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub async fn insert(db: &Db, invite: &NewInvite<'_>) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO invites (code_hash, email, created_by, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(invite.code_hash)
    .bind(invite.email.map(str::to_owned))
    .bind(invite.created_by)
    .bind(now())
    .bind(invite.expires_at)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

pub async fn by_code_hash(db: &Db, code_hash: &str) -> DbResult<Option<InviteRow>> {
    let row = sqlx::query(select_invite!("WHERE code_hash = $1"))
        .bind(code_hash)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// Marks the invite used if it is unused, unrevoked, and unexpired at `now_ts`; `false` otherwise.
pub async fn claim(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "UPDATE invites SET used_at = $1 \
         WHERE id = $2 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $3",
    )
    .bind(now_ts)
    .bind(id)
    .bind(now_ts)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Undoes [`claim`] after the sign-up that claimed the invite failed.
pub async fn release(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("UPDATE invites SET used_at = NULL WHERE id = $1 AND used_by IS NULL")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_used_by(db: &Db, id: i64, user_id: i64) -> DbResult<()> {
    sqlx::query("UPDATE invites SET used_by = $1 WHERE id = $2")
        .bind(user_id)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Newest first.
pub async fn list(db: &Db, limit: i64) -> DbResult<Vec<InviteRow>> {
    let rows = sqlx::query(select_invite!("ORDER BY id DESC LIMIT $1"))
        .bind(limit)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(from_row).collect()
}

/// Revokes an unused, unrevoked invite; `false` when there is no such invite.
pub async fn revoke(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "UPDATE invites SET revoked_at = $1 WHERE id = $2 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(now_ts)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes invites that expired before `before`; returns how many.
pub async fn delete_expired_before(db: &Db, before: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM invites WHERE expires_at < $1")
        .bind(before)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}
```

Run: `cargo test -p starforged-db invites` — expected: pass.

- [ ] **Step 4: Write the failing core tests**

Add `pub mod invites;` (after `pub mod error;`) and `pub mod registration;` (after `pub mod permission;`) to `crates/starforged-core/src/lib.rs`.

Add to the test module of `crates/starforged-core/src/validate.rs`:

```rust
    #[test]
    fn display_names() {
        assert_eq!(display_name("  Alice A.  ").unwrap(), "Alice A.");
        assert_eq!(display_name(&"é".repeat(100)).unwrap().chars().count(), 100);
        assert!(display_name(&"x".repeat(101)).is_err());
        assert!(display_name("tab\there").is_err());
    }

    #[test]
    fn sign_up_routes_are_reserved() {
        for reserved in ["forgot", "join", "reset", "verify"] {
            assert!(handle(reserved).is_err(), "{reserved}");
        }
    }
```

Create `crates/starforged-core/src/registration.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, test_core_with, with_file_mail};

    fn sign_up(handle: &str, email: &str, invite: Option<&str>) -> SignUp {
        SignUp {
            handle: handle.into(),
            email: email.into(),
            password: "correct horse battery".into(),
            display_name: String::new(),
            invite: invite.map(str::to_owned),
        }
    }

    async fn admin(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    fn code_of(link: &str) -> String {
        link.split("invite=").nth(1).unwrap().to_owned()
    }

    #[tokio::test]
    async fn invite_mode_needs_an_invite_and_invites_work_once() {
        let (core, _f) = test_core().await;
        assert!(!core.sign_up_open());
        let closed = core
            .sign_up(sign_up("alice", "alice@example.com", None))
            .await
            .unwrap_err();
        assert!(matches!(&closed, CoreError::Invalid(m) if m.contains("invitation")), "{closed}");

        let root = admin(&core).await;
        let invite = core.create_invite(&root, None).await.unwrap();
        assert!(!invite.emailed);
        let code = code_of(&invite.link);
        assert_eq!(core.invite_email(&code).await.unwrap(), None);
        let taken = core
            .sign_up(sign_up("root", "x@example.com", Some(&code)))
            .await
            .unwrap_err();
        assert!(matches!(taken, CoreError::Conflict(_)), "the handle is taken");
        let alice = match core
            .sign_up(sign_up("alice", "alice@example.com", Some(&code)))
            .await
            .unwrap()
        {
            SignedUp::Active(user) => user,
            other => panic!("{other:?}"),
        };
        assert!(!alice.email_verified, "an invite without an address verifies nothing");
        let reused = core
            .sign_up(sign_up("bob", "bob@example.com", Some(&code)))
            .await
            .unwrap_err();
        assert!(matches!(&reused, CoreError::Invalid(m) if m.contains("invite")), "{reused}");
    }

    #[tokio::test]
    async fn email_bound_invites_verify_that_address() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let root = admin(&core).await;
        let invite = core
            .create_invite(&root, Some("Carol@Example.com"))
            .await
            .unwrap();
        assert!(invite.emailed);
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(
            mail[0].contains("To: carol@example.com") && mail[0].contains("root invited you"),
            "{}",
            mail[0]
        );
        let code = code_of(&invite.link);
        assert_eq!(
            core.invite_email(&code).await.unwrap().as_deref(),
            Some("carol@example.com")
        );
        let wrong = core
            .sign_up(sign_up("carol", "mallory@example.com", Some(&code)))
            .await
            .unwrap_err();
        assert!(matches!(&wrong, CoreError::Invalid(m) if m.contains("different email")), "{wrong}");
        match core
            .sign_up(sign_up("carol", "carol@example.com", Some(&code)))
            .await
            .unwrap()
        {
            SignedUp::Active(user) => assert!(user.email_verified),
            other => panic!("{other:?}"),
        }
        core.run_due_jobs().await.unwrap();
        assert_eq!(fixture.mail().len(), 1, "no verification email for an invited address");
    }

    #[tokio::test]
    async fn open_and_domains_modes() {
        let (core, fixture) = test_core_with(|config, dir| {
            with_file_mail(config, dir);
            config.registration.mode = RegistrationMode::Open;
        })
        .await;
        assert!(core.sign_up_open());
        match core
            .sign_up(sign_up("dana", "dana@example.com", None))
            .await
            .unwrap()
        {
            SignedUp::VerificationSent(user) => assert!(!user.email_verified),
            other => panic!("{other:?}"),
        }
        core.run_due_jobs().await.unwrap();
        assert!(fixture.mail()[0].contains("Subject: Verify your email address"));

        let (core, _f) = test_core_with(|config, dir| {
            with_file_mail(config, dir);
            config.registration = Registration {
                mode: RegistrationMode::Domains,
                allowed_domains: vec!["example.com".into()],
            };
        })
        .await;
        let outside = core
            .sign_up(sign_up("eve", "eve@elsewhere.org", None))
            .await
            .unwrap_err();
        assert!(matches!(&outside, CoreError::Invalid(m) if m.contains("example.com")), "{outside}");
        assert!(matches!(
            core.sign_up(sign_up("erin", "erin@example.com", None))
                .await
                .unwrap(),
            SignedUp::VerificationSent(_)
        ));
    }
}
```

Create `crates/starforged-core/src/invites.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, user};

    #[tokio::test]
    async fn only_site_admins_manage_invites() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        assert!(matches!(core.create_invite(&alice, None).await, Err(CoreError::Forbidden)));
        assert!(matches!(core.list_invites(&alice).await, Err(CoreError::Forbidden)));
        let root = core
            .create_user(CreateUser {
                handle: "root".into(),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let first = core.create_invite(&root, None).await.unwrap();
        assert!(matches!(
            core.revoke_invite(&alice, first.id).await,
            Err(CoreError::Forbidden)
        ));
        core.revoke_invite(&root, first.id).await.unwrap();
        assert!(matches!(
            core.revoke_invite(&root, first.id).await,
            Err(CoreError::NotFound)
        ));
        let first_code = first.link.split("invite=").nth(1).unwrap();
        assert!(core.invite_email(first_code).await.is_err(), "revoked invites are unusable");

        let second = core.create_invite(&root, Some("x@example.com")).await.unwrap();
        assert!(!second.emailed, "no mail configured");
        sqlx::query("UPDATE invites SET expires_at = $1 WHERE id = $2")
            .bind(1_i64)
            .bind(second.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        let listed: Vec<(i64, InviteStatus)> = core
            .list_invites(&root)
            .await
            .unwrap()
            .into_iter()
            .map(|i| (i.id, i.status))
            .collect();
        assert_eq!(
            listed,
            vec![(second.id, InviteStatus::Expired), (first.id, InviteStatus::Revoked)]
        );
    }
}
```

- [ ] **Step 5: Run them to see them fail**

Run: `cargo test -p starforged-core`
Expected: compile errors.

- [ ] **Step 6: Implement registration and invites in core**

`crates/starforged-core/src/validate.rs`: add `"forgot"`, `"join"`, `"reset"`, and `"verify"` to `RESERVED_HANDLES`, keeping the list alphabetical, and add:

```rust
/// Display names: surrounding whitespace dropped, at most 100 characters, no control characters.
pub fn display_name(input: &str) -> Result<String, CoreError> {
    let name = input.trim();
    if name.chars().count() > 100 || name.chars().any(char::is_control) {
        Err(CoreError::Invalid(
            "display names are at most 100 characters, without control characters".into(),
        ))
    } else {
        Ok(name.to_owned())
    }
}
```

`crates/starforged-core/src/accounts.rs`: `create_user` validates the display name before inserting — `let display_name = validate::display_name(&input.display_name)?;` — and stores `display_name: &display_name` in the `NewUser` literal (instead of `input.display_name.trim()`).

`crates/starforged-core/templates/mail/invite.txt`:

```
{{ inviter }} invited you to join Starforge.

Create your account here:

{{ link }}

The invite works once and expires in 7 days.
```

Add to `crates/starforged-core/src/mail.rs`:

```rust
#[derive(Template)]
#[template(path = "mail/invite.txt")]
struct InviteText<'a> {
    inviter: &'a str,
    link: &'a str,
}

/// An invite to sign up, with a link valid for 7 days.
pub(crate) fn invite_email(to: &str, inviter: &str, link: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: format!("{inviter} invited you to Starforge"),
        body: render(&InviteText { inviter, link })?,
    })
}
```

Insert at the top of `crates/starforged-core/src/registration.rs`, above the test module:

```rust
//! Sign-up (forge-basics design §4.1): registration modes, invites, and verification of new addresses.

use starforged_db::invites::{self, InviteRow};
use starforged_db::now;

use crate::accounts::{CreateUser, User};
use crate::{Core, CoreError, CoreResult, crypto, validate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    /// Only holders of an invite link sign up.
    Invite,
    /// Anyone signs up.
    Open,
    /// Addresses at `allowed_domains` sign up; requires mail.
    Domains,
}

impl RegistrationMode {
    pub fn parse(s: &str) -> Option<RegistrationMode> {
        match s {
            "invite" => Some(RegistrationMode::Invite),
            "open" => Some(RegistrationMode::Open),
            "domains" => Some(RegistrationMode::Domains),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationMode::Invite => "invite",
            RegistrationMode::Open => "open",
            RegistrationMode::Domains => "domains",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub mode: RegistrationMode,
    /// Lowercase domains that `domains` mode accepts.
    pub allowed_domains: Vec<String>,
}

impl Default for Registration {
    fn default() -> Registration {
        Registration {
            mode: RegistrationMode::Invite,
            allowed_domains: Vec::new(),
        }
    }
}

pub struct SignUp {
    pub handle: String,
    pub email: String,
    pub password: String,
    pub display_name: String,
    /// The code from an invite link; an invite lets its holder sign up in every mode.
    pub invite: Option<String>,
}

#[derive(Debug)]
pub enum SignedUp {
    /// The account can sign in now.
    Active(User),
    /// A verification link went to the account's address.
    VerificationSent(User),
}

impl SignedUp {
    pub fn user(&self) -> &User {
        match self {
            SignedUp::Active(user) | SignedUp::VerificationSent(user) => user,
        }
    }
}

fn unusable_invite() -> CoreError {
    CoreError::Invalid("This invite link is invalid, already used, or expired.".into())
}

impl Core {
    pub fn registration(&self) -> &Registration {
        &self.config().registration
    }

    /// Whether `/join` accepts people without an invite link (`open` and `domains` modes).
    pub fn sign_up_open(&self) -> bool {
        self.registration().mode != RegistrationMode::Invite
    }

    pub async fn sign_up(&self, input: SignUp) -> CoreResult<SignedUp> {
        let email = validate::email(&input.email)?;
        let code = input
            .invite
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_owned);
        let invite = match code {
            Some(code) => Some(self.claim_invite(&code).await?),
            None => None,
        };
        let result = self.sign_up_as(input, &email, invite.as_ref()).await;
        if let Some(invite) = &invite {
            match &result {
                Ok(signed_up) => invites::set_used_by(self.db(), invite.id, signed_up.user().id).await?,
                Err(_) => invites::release(self.db(), invite.id).await?,
            }
        }
        result
    }

    async fn sign_up_as(
        &self,
        input: SignUp,
        email: &str,
        invite: Option<&InviteRow>,
    ) -> CoreResult<SignedUp> {
        let verified_by_invite = match invite {
            Some(invite) => match &invite.email {
                Some(bound) if bound != email => {
                    return Err(CoreError::Invalid(
                        "This invite is for a different email address.".into(),
                    ));
                }
                Some(_) => true,
                None => false,
            },
            None => {
                self.check_open_sign_up(email)?;
                false
            }
        };
        let user = self
            .create_user(CreateUser {
                handle: input.handle,
                display_name: input.display_name,
                email: Some(email.to_owned()),
                email_verified: verified_by_invite,
                password: Some(input.password),
                is_admin: false,
            })
            .await?;
        let how = if invite.is_some() { "invite" } else { "" };
        self.audit(Some(user.id), "account.sign_up", &format!("user:{}", user.handle), how)
            .await?;
        if self.mail_enabled() && !user.email_verified {
            self.send_verification(&user).await?;
            Ok(SignedUp::VerificationSent(user))
        } else {
            Ok(SignedUp::Active(user))
        }
    }

    /// Sign-up without an invite: refused in `invite` mode, limited to the listed domains in `domains` mode.
    fn check_open_sign_up(&self, email: &str) -> CoreResult<()> {
        let registration = self.registration();
        match registration.mode {
            RegistrationMode::Invite => Err(CoreError::Invalid(
                "Sign-up is by invitation only.".into(),
            )),
            RegistrationMode::Open => Ok(()),
            RegistrationMode::Domains => {
                let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                if registration.allowed_domains.iter().any(|d| d == domain) {
                    Ok(())
                } else {
                    Err(CoreError::Invalid(format!(
                        "Sign-up is limited to addresses at {}.",
                        registration.allowed_domains.join(", ")
                    )))
                }
            }
        }
    }

    /// Claims the invite behind `code` for a sign-up in progress.
    async fn claim_invite(&self, code: &str) -> CoreResult<InviteRow> {
        let row = invites::by_code_hash(self.db(), &crypto::sha256_hex(code))
            .await?
            .ok_or_else(unusable_invite)?;
        if invites::claim(self.db(), row.id, now()).await? {
            Ok(row)
        } else {
            Err(unusable_invite())
        }
    }

    /// For the sign-up form: the address a usable invite is bound to. `Invalid` when the code is unknown,
    /// used, revoked, or expired.
    pub async fn invite_email(&self, code: &str) -> CoreResult<Option<String>> {
        let row = invites::by_code_hash(self.db(), &crypto::sha256_hex(code))
            .await?
            .filter(|r| r.used_at.is_none() && r.revoked_at.is_none() && r.expires_at > now())
            .ok_or_else(unusable_invite)?;
        Ok(row.email)
    }
}
```

Insert at the top of `crates/starforged-core/src/invites.rs`, above the test module:

```rust
//! Invites (forge-basics design §4.1, §7): site admins issue single-use sign-up links.

use starforged_db::invites::{self, InviteRow, NewInvite};
use starforged_db::now;

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, crypto, mail, validate};

/// Invites expire 7 days after they are issued.
pub const INVITE_TTL_SECS: i64 = 7 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteStatus {
    Pending,
    Used,
    Expired,
    Revoked,
}

impl InviteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            InviteStatus::Pending => "pending",
            InviteStatus::Used => "used",
            InviteStatus::Expired => "expired",
            InviteStatus::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInfo {
    pub id: i64,
    pub email: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: InviteStatus,
}

#[derive(Debug, Clone)]
pub struct CreatedInvite {
    pub id: i64,
    /// Shown once; only the code's hash is stored.
    pub link: String,
    /// The link was also emailed to the invite's address.
    pub emailed: bool,
}

fn status(row: &InviteRow, now_ts: i64) -> InviteStatus {
    if row.revoked_at.is_some() {
        InviteStatus::Revoked
    } else if row.used_at.is_some() {
        InviteStatus::Used
    } else if row.expires_at <= now_ts {
        InviteStatus::Expired
    } else {
        InviteStatus::Pending
    }
}

impl Core {
    /// Site admins only. When `email` is set, only that address can use the invite, and the link is emailed
    /// if mail is configured.
    pub async fn create_invite(&self, admin: &User, email: Option<&str>) -> CoreResult<CreatedInvite> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let email = email
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(validate::email)
            .transpose()?;
        let code = crypto::random_hex(32);
        let id = invites::insert(
            self.db(),
            &NewInvite {
                code_hash: &crypto::sha256_hex(&code),
                email: email.as_deref(),
                created_by: admin.id,
                expires_at: now() + INVITE_TTL_SECS,
            },
        )
        .await?;
        let link = format!("{}/join?invite={code}", self.config().base_url);
        let emailed = match &email {
            Some(to) if self.mail_enabled() => {
                self.queue_email(mail::invite_email(to, &admin.handle, &link)?)
                    .await?;
                true
            }
            _ => false,
        };
        self.audit(
            Some(admin.id),
            "invite.create",
            &format!("invite:{id}"),
            email.as_deref().unwrap_or(""),
        )
        .await?;
        Ok(CreatedInvite { id, link, emailed })
    }

    /// Site admins only; newest first.
    pub async fn list_invites(&self, admin: &User) -> CoreResult<Vec<InviteInfo>> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let ts = now();
        Ok(invites::list(self.db(), 500)
            .await?
            .into_iter()
            .map(|row| InviteInfo {
                id: row.id,
                status: status(&row, ts),
                email: row.email,
                created_at: row.created_at,
                expires_at: row.expires_at,
            })
            .collect())
    }

    /// Site admins only. `NotFound` when the invite is unknown, used, or already revoked.
    pub async fn revoke_invite(&self, admin: &User, id: i64) -> CoreResult<()> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        if !invites::revoke(self.db(), id, now()).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(Some(admin.id), "invite.revoke", &format!("invite:{id}"), "")
            .await
    }
}
```

`crates/starforged-core/src/lib.rs`: add `pub registration: registration::Registration,` to `CoreConfig` (doc: "who may sign up") and `registration: registration::Registration::default(),` to the fixture's `CoreConfig` literal.

`crates/starforged-core/src/jobs.rs` `hourly_cleanup`: also delete invites 30 days after they expired, so the admin list keeps showing recently expired ones:

```rust
        starforged_db::invites::delete_expired_before(self.db(), ts - 30 * DAY).await?;
```

Run: `cargo test -p starforged-core`
Expected: all pass.

- [ ] **Step 7: Add `[registration]` to the configuration**

Add to the test module of `crates/starforged/src/config.rs` (and `registration: RegistrationConfig::default(),` to `sample()`):

```rust
    #[test]
    fn registration_settings_are_validated() {
        let mut config = sample();
        assert_eq!(config.registration_settings().unwrap(), Registration::default());
        config
            .apply_env([
                (
                    "STARFORGE__REGISTRATION__MODE".to_owned(),
                    "domains".to_owned(),
                ),
                (
                    "STARFORGE__REGISTRATION__ALLOWED_DOMAINS".to_owned(),
                    " Example.com, @corp.example ".to_owned(),
                ),
            ])
            .unwrap();
        assert!(config.validate().unwrap_err().to_string().contains("needs [mail]"));
        config.mail = MailConfig {
            url: "file:///tmp/starforge-mail".into(),
            from: "Starforge <forge@example.com>".into(),
        };
        assert_eq!(
            config.registration_settings().unwrap().allowed_domains,
            vec!["example.com".to_owned(), "corp.example".to_owned()]
        );
        assert!(config.validate().is_ok());
        config.registration.allowed_domains.clear();
        assert!(config.validate().unwrap_err().to_string().contains("allowed_domains"));
        config.registration.mode = "everyone".into();
        assert!(config.validate().unwrap_err().to_string().contains("registration.mode"));
    }
```

Implement in `crates/starforged/src/config.rs`:

1. `use starforged_core::registration::{Registration, RegistrationMode};`
2. A `registration` section between `security` and `mail`:

```rust
    #[serde(default)]
    pub registration: RegistrationConfig,
```

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationConfig {
    /// `invite` (default), `open`, or `domains` (forge-basics design §4.1).
    #[serde(default = "default_registration_mode")]
    pub mode: String,
    /// Email domains that `domains` mode accepts, e.g. `["example.com"]`.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_registration_mode() -> String {
    "invite".into()
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        RegistrationConfig {
            mode: default_registration_mode(),
            allowed_domains: Vec::new(),
        }
    }
}
```

3. `apply_env` arms:

```rust
                "registration__mode" => self.registration.mode = value,
                "registration__allowed_domains" => {
                    self.registration.allowed_domains = value
                        .split(',')
                        .map(str::trim)
                        .filter(|d| !d.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
```

4. `validate` calls `self.registration_settings()?;` before `self.mailer()?;`, and:

```rust
    /// The `[registration]` section as core settings, with domains lowercased.
    pub fn registration_settings(&self) -> anyhow::Result<Registration> {
        let mode = RegistrationMode::parse(&self.registration.mode).with_context(|| {
            format!(
                "registration.mode must be \"invite\", \"open\", or \"domains\", not {:?}",
                self.registration.mode
            )
        })?;
        let allowed_domains: Vec<String> = self
            .registration
            .allowed_domains
            .iter()
            .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        if mode == RegistrationMode::Domains {
            if allowed_domains.is_empty() {
                bail!("registration.mode = \"domains\" needs registration.allowed_domains");
            }
            if self.mail.url.trim().is_empty() {
                bail!("registration.mode = \"domains\" needs [mail], because addresses must be verified");
            }
        }
        Ok(Registration { mode, allowed_domains })
    }
```

`crates/starforged/src/init.rs`: add `registration: RegistrationConfig::default(),` to the `Config` literal (import it).
`crates/starforged/src/admin.rs` `open_core`: add `registration: config.registration_settings()?,` to the `CoreConfig` literal.
`crates/starforged/tests/common/mod.rs`: add `registration: RegistrationConfig::default(),` to the `Config` literal (import it).

Run: `cargo test -p starforged --lib config`
Expected: pass.

- [ ] **Step 8: Write the failing web tests**

Create `crates/starforged/tests/web_join.rs`:

```rust
mod common;

use common::*;
use starforged_core::accounts::{CreateUser, User};

const NEW_PASSWORD: &str = "a long enough password";

async fn admin(s: &TestServer) -> User {
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Loads the sign-up form at `path` (`/join` or an invite link's path), fills in `fields`, and posts it.
async fn join(
    s: &TestServer,
    client: &reqwest::Client,
    path: &str,
    fields: &[(&str, &str)],
) -> reqwest::Response {
    let page = get_text(client, &s.url(path)).await;
    let csrf = extract_input(&page, "_csrf");
    let invite = extract_input(&page, "invite");
    let mut form = vec![
        ("_csrf", csrf.as_str()),
        ("invite", invite.as_str()),
        ("password", NEW_PASSWORD),
    ];
    form.extend_from_slice(fields);
    client.post(s.url("/join")).form(&form).send().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invite_mode_signs_up_only_with_an_invite() {
    let s = TestServer::start().await;
    let client = s.browser();
    let closed = client.get(s.url("/join")).send().await.unwrap();
    assert_eq!(closed.status(), 403);
    assert!(closed.text().await.unwrap().contains("Sign-up is by invitation"));
    assert!(!get_text(&client, &s.url("/login")).await.contains(r#"href="/join""#));

    let root = admin(&s).await;
    let invite = s.core.create_invite(&root, None).await.unwrap();
    let path = invite.link.strip_prefix(&s.base).unwrap().to_owned();
    let taken = join(&s, &client, &path, &[("handle", "root"), ("email", "alice@example.com")]).await;
    assert_eq!(taken.status(), 422);
    assert!(taken.text().await.unwrap().contains("already taken"));
    let joined = join(&s, &client, &path, &[("handle", "alice"), ("email", "alice@example.com")]).await;
    assert_eq!(joined.status(), 303, "a sign-up that needs no verification signs in");
    assert!(get_text(&client, &s.url("/")).await.contains("Your repositories"));

    let reused = s.browser().get(s.url(&path)).send().await.unwrap();
    assert_eq!(reused.status(), 404);
    assert!(reused.text().await.unwrap().contains("Invite not valid"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_bound_invites_skip_verification() {
    let s = TestServer::start_with_mail(|_| {}).await;
    let root = admin(&s).await;
    s.core
        .create_invite(&root, Some("carol@example.com"))
        .await
        .unwrap();
    let link = s.link_in(&s.last_email_to("carol@example.com").await, "/join");
    let path = link.strip_prefix(&s.base).unwrap().to_owned();
    let client = s.browser();
    let form = get_text(&client, &s.url(&path)).await;
    assert!(form.contains(r#"value="carol@example.com" readonly"#), "{form}");
    let wrong = join(&s, &client, &path, &[("handle", "carol"), ("email", "mallory@example.com")]).await;
    assert_eq!(wrong.status(), 422);
    assert!(
        wrong
            .text()
            .await
            .unwrap()
            .contains(r#"value="carol@example.com" readonly"#),
        "the form keeps the invited address"
    );
    let joined = join(&s, &client, &path, &[("handle", "carol"), ("email", "carol@example.com")]).await;
    assert_eq!(joined.status(), 303);
    assert_eq!(
        s.inbox().await.len(),
        1,
        "only the invite: an invited address needs no verification"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_mode_verifies_new_addresses_by_email() {
    let s = TestServer::start_with_mail(|config| config.registration.mode = "open".into()).await;
    let client = s.browser();
    assert!(get_text(&client, &s.url("/login")).await.contains(r#"href="/join""#));
    assert!(get_text(&client, &s.url("/")).await.contains(r#"href="/join""#));
    let forged = client
        .post(s.url("/join"))
        .form(&[
            ("_csrf", "forged"),
            ("invite", ""),
            ("handle", "dana"),
            ("email", "dana@example.com"),
            ("password", NEW_PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    let reserved = join(&s, &client, "/join", &[("handle", "verify"), ("email", "v@example.com")]).await;
    assert_eq!(reserved.status(), 422);
    let joined = join(&s, &client, "/join", &[("handle", "dana"), ("email", "dana@example.com")]).await;
    assert_eq!(joined.status(), 200);
    assert!(joined.text().await.unwrap().contains("We sent a link to dana@example.com"));
    let (_, blocked) = s.try_login("dana", NEW_PASSWORD).await;
    assert_eq!(blocked.status(), 403);

    let link = s.link_in(&s.last_email_to("dana@example.com").await, "/verify/");
    let confirm = get_text(&client, &link).await;
    let csrf = extract_input(&confirm, "_csrf");
    let confirmed = client
        .post(&link)
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.status(), 200);
    let (_, signed_in) = s.try_login("dana", NEW_PASSWORD).await;
    assert_eq!(signed_in.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domains_mode_limits_sign_up_to_listed_domains() {
    let s = TestServer::start_with_mail(|config| {
        config.registration.mode = "domains".into();
        config.registration.allowed_domains = vec!["example.com".into()];
    })
    .await;
    let client = s.browser();
    let outside = join(&s, &client, "/join", &[("handle", "eve"), ("email", "eve@elsewhere.org")]).await;
    assert_eq!(outside.status(), 422);
    assert!(outside
        .text()
        .await
        .unwrap()
        .contains("limited to addresses at example.com"));
    let inside = join(&s, &client, "/join", &[("handle", "erin"), ("email", "erin@example.com")]).await;
    assert_eq!(inside.status(), 200);
}
```

Run: `cargo test -p starforged --test web_join`
Expected: failures (`/join` does not exist).

- [ ] **Step 9: Implement the sign-up page**

`crates/starforged-web/src/pages/join.rs`:

```rust
//! Sign-up (forge-basics design §4.1).

use std::net::SocketAddr;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::registration::{SignUp, SignedUp};

use crate::AppState;
use crate::auth::{
    LOGIN_CSRF_COOKIE, MaybeUser, anonymous_csrf, removal, session_cookie, verify_anonymous_csrf,
};
use crate::error::WebError;
use crate::pages::message::MessagePage;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct JoinQuery {
    invite: Option<String>,
}

#[derive(Deserialize)]
pub struct JoinForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    invite: String,
    handle: String,
    email: String,
    #[serde(default)]
    display_name: String,
    password: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "join.html")]
pub struct JoinPage {
    nav_user: Option<NavUser>,
    csrf: String,
    invite: String,
    handle: String,
    email: String,
    /// The invite is bound to `email`, which cannot be changed.
    email_locked: bool,
    display_name: String,
    error: Option<String>,
}

pub async fn form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Query(query): Query<JoinQuery>,
) -> Result<Response, WebError> {
    if session.is_some() {
        return Ok(Redirect::to("/").into_response());
    }
    let invite = query.invite.unwrap_or_default();
    let bound_email = if invite.is_empty() {
        if !state.core.sign_up_open() {
            let page = MessagePage::new(
                None,
                "Sign-up is by invitation",
                "Ask an administrator of this Starforge for an invite link.",
            );
            return Ok((StatusCode::FORBIDDEN, page).into_response());
        }
        None
    } else {
        match state.core.invite_email(&invite).await {
            Ok(email) => email,
            Err(CoreError::Invalid(message)) => {
                let page = MessagePage::new(None, "Invite not valid", message);
                return Ok((StatusCode::NOT_FOUND, page).into_response());
            }
            Err(other) => return Err(other.into()),
        }
    };
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    let page = JoinPage {
        nav_user: None,
        csrf,
        invite,
        handle: String::new(),
        email_locked: bound_email.is_some(),
        email: bound_email.unwrap_or_default(),
        display_name: String::new(),
        error: None,
    };
    Ok((jar, page).into_response())
}

pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<JoinForm>,
) -> Result<Response, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    let input = SignUp {
        handle: form.handle.clone(),
        email: form.email.clone(),
        password: form.password.clone(),
        display_name: form.display_name.clone(),
        invite: Some(form.invite.clone()),
    };
    match state.core.sign_up(input).await {
        Ok(SignedUp::VerificationSent(user)) => Ok(MessagePage::new(
            None,
            "Check your email",
            format!(
                "We sent a link to {} to verify your address. It expires in 24 hours.",
                user.email.unwrap_or_default()
            ),
        )
        .into_response()),
        Ok(SignedUp::Active(user)) => {
            let user_agent = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let (_, session) = state
                .core
                .login(&user.handle, &form.password, user_agent, &addr.ip().to_string())
                .await?;
            let cookie = session_cookie(
                session.cookie_value,
                state.settings.secure_cookies,
                session.max_age_secs,
            );
            let jar = jar.remove(removal(LOGIN_CSRF_COOKIE)).add(cookie);
            Ok((jar, Redirect::to("/")).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let bound = if form.invite.is_empty() {
                None
            } else {
                state.core.invite_email(&form.invite).await.ok().flatten()
            };
            let page = JoinPage {
                nav_user: None,
                csrf: form.csrf,
                invite: form.invite,
                handle: form.handle,
                email_locked: bound.is_some(),
                email: bound.unwrap_or(form.email),
                display_name: form.display_name,
                error: Some(message),
            };
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}
```

`crates/starforged-web/templates/join.html`:

```html
{% extends "base.html" %}
{% block title %}Sign up · Starforge{% endblock %}
{% block content %}
<h1>Create your account</h1>
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/join" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <input type="hidden" name="invite" value="{{ invite }}">
  <label>Handle <input name="handle" autocomplete="username" required maxlength="39" value="{{ handle }}"></label>
  <label>Email <input name="email" type="email" autocomplete="email" required value="{{ email }}"{% if email_locked %} readonly{% endif %}></label>
  <label>Display name (optional) <input name="display_name" maxlength="100" value="{{ display_name }}"></label>
  <label>Password <input name="password" type="password" autocomplete="new-password" required minlength="10"></label>
  <button type="submit">Create account</button>
</form>
<p>Already have an account? <a href="/login">Sign in</a>.</p>
{% endblock %}
```

`crates/starforged-web/src/pages/mod.rs`: add `pub mod join;`. `crates/starforged-web/src/lib.rs` `page_routes`: add `.route("/join", get(pages::join::form).post(pages::join::submit))`.

Link to sign-up where it is open:

1. `crates/starforged-web/src/pages/login.rs`: `LoginPage` gains `sign_up_open: bool`, set from `state.core.sign_up_open()` in every literal. `templates/login.html`, after the sign-in form:

```html
{% if sign_up_open %}<p>No account yet? <a href="/join">Sign up</a>.</p>{% endif %}
```

2. `crates/starforged-web/src/pages/dashboard.rs`: `DashboardPage` gains `sign_up_open: bool`, set from `state.core.sign_up_open()`. In `templates/dashboard.html`, the signed-out paragraph becomes:

```html
<p>A self-hosted forge for code and the agent sessions behind it. <a href="/login">Sign in</a>{% if sign_up_open %} or <a href="/join">create an account</a>{% endif %} to continue.</p>
```

- [ ] **Step 10: Run the web tests**

Run: `cargo test -p starforged --test web_join --test web_auth --test web_verify`
Expected: pass.

- [ ] **Step 11: Full suite, lint, format, both engines, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
STARFORGE_TEST_PG=1 scripts/check.sh
git add crates Cargo.lock
git commit -m "feat(accounts): registration modes, invites, and the sign-up page"
```

### Task A5: Password reset

**Files:**
- Create: `crates/starforged-core/src/passwords.rs`, `crates/starforged-core/templates/mail/reset_password.txt`
- Modify: `crates/starforged-core/src/{lib.rs, accounts.rs, mail.rs}`
- Modify: `crates/starforged-db/src/users.rs` (`set_password_hash`), `crates/starforged-db/src/web_sessions.rs` (`delete_for_user`)
- Create: `crates/starforged-web/src/pages/password.rs`, `crates/starforged-web/templates/forgot.html`, `crates/starforged-web/templates/reset.html`
- Modify: `crates/starforged-web/src/{lib.rs, pages/mod.rs, pages/login.rs}`, `crates/starforged-web/templates/login.html`
- Test: unit tests in `passwords.rs`; `crates/starforged/tests/web_password_reset.rs`

**Interfaces:**
- Consumes: `Core::{issue_email_token, consume_email_token, peek_email_token, queue_email, mail_enabled}`, `Purpose::ResetPassword`, `RESET_TTL_SECS`, `ADMIN_RESET_TTL_SECS` (Tasks A2–A3); `anonymous_csrf`, `verify_anonymous_csrf`, `MessagePage`, `try_login` (Task A3).
- Produces:
  - `users::set_password_hash(db, id, hash)`, `web_sessions::delete_for_user(db, user_id) -> DbResult<u64>`.
  - `accounts::hash_password` becomes `pub(crate)`.
  - `starforged_core::passwords::AdminReset::{Emailed, Link(String)}`; `Core::{request_password_reset(email), admin_password_reset(admin, target) -> AdminReset, password_reset_valid(secret) -> bool, reset_password(secret, new_password) -> User}`. Plan C's admin user page calls `admin_password_reset`.
  - Web: `GET|POST /forgot` (404 without mail), `GET|POST /reset/{token}`; the sign-in page links to `/forgot` when mail is on.

- [ ] **Step 1: Write the failing core tests**

Add `pub mod passwords;` to `crates/starforged-core/src/lib.rs` after `pub mod mail;`. Create `crates/starforged-core/src/passwords.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, test_core_with, user, with_file_mail};

    const PASSWORD: &str = "correct horse battery";
    const NEW_PASSWORD: &str = "a brand new password";

    async fn member(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            email: Some(format!("{handle}@example.com")),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn site_admin(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    fn secret_in(message: &str) -> String {
        let link = crate::mail::testing::find_link(message, "/reset/").unwrap();
        link.rsplit('/').next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn reset_links_change_the_password_and_end_sessions() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = member(&core, "alice").await;
        let (_, session) = core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();
        core.request_password_reset("alice@example.com").await.unwrap();
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert!(mail[0].contains("Subject: Reset your Starforge password"), "{}", mail[0]);
        let secret = secret_in(&mail[0]);

        assert!(core.password_reset_valid(&secret).await.unwrap());
        assert!(matches!(
            core.reset_password(&secret, "short").await,
            Err(CoreError::Invalid(_))
        ));
        assert!(
            core.password_reset_valid(&secret).await.unwrap(),
            "a rejected password keeps the link usable"
        );
        let user = core.reset_password(&secret, NEW_PASSWORD).await.unwrap();
        assert_eq!(user.id, alice.id);
        assert!(
            core.web_session(&session.cookie_value).await.unwrap().is_none(),
            "the reset ended existing sessions"
        );
        core.login("alice", NEW_PASSWORD, "ua", "127.0.0.1").await.unwrap();
        assert!(matches!(
            core.reset_password(&secret, "another new password").await,
            Err(CoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn forgot_password_needs_mail_and_reveals_nothing() {
        let (core, _f) = test_core().await;
        assert!(matches!(
            core.request_password_reset("a@example.com").await,
            Err(CoreError::NotFound)
        ));

        let (core, fixture) = test_core_with(with_file_mail).await;
        member(&core, "alice").await;
        core.request_password_reset("nobody@example.com").await.unwrap();
        core.request_password_reset("alice@example.com").await.unwrap();
        core.request_password_reset("alice@example.com").await.unwrap();
        core.run_due_jobs().await.unwrap();
        assert_eq!(fixture.mail().len(), 1, "the repeat request was throttled");
    }

    #[tokio::test]
    async fn admins_reset_by_email_or_by_link() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let admin = site_admin(&core).await;
        let alice = member(&core, "alice").await;
        assert!(matches!(
            core.admin_password_reset(&alice, &admin).await,
            Err(CoreError::Forbidden)
        ));
        assert_eq!(
            core.admin_password_reset(&admin, &alice).await.unwrap(),
            AdminReset::Emailed
        );
        core.run_due_jobs().await.unwrap();
        assert!(fixture.mail()[0].contains("To: alice@example.com"));
        let no_address = user(&core, "bob").await;
        match core.admin_password_reset(&admin, &no_address).await.unwrap() {
            AdminReset::Link(link) => assert!(link.starts_with("http://forge.test/reset/"), "{link}"),
            other => panic!("{other:?}"),
        }

        let (core, _f) = test_core().await;
        let admin = site_admin(&core).await;
        let carol = member(&core, "carol").await;
        let AdminReset::Link(link) = core.admin_password_reset(&admin, &carol).await.unwrap() else {
            panic!("without mail the admin gets a link");
        };
        assert!(link.contains("/reset/"));
        let expires_at: i64 = sqlx::query_scalar(
            "SELECT expires_at FROM email_tokens WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(carol.id)
        .fetch_one(core.db().pool())
        .await
        .unwrap();
        assert!(
            expires_at >= starforged_db::now() + ADMIN_RESET_TTL_SECS - 5,
            "links an admin passes on last 24 hours"
        );
    }
}
```

Run: `cargo test -p starforged-core passwords`
Expected: compile errors.

- [ ] **Step 2: Implement password reset in core**

`crates/starforged-db/src/users.rs`:

```rust
pub async fn set_password_hash(db: &Db, id: i64, password_hash: &str) -> DbResult<()> {
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(password_hash)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
```

`crates/starforged-db/src/web_sessions.rs`:

```rust
/// Signs a user out everywhere; returns how many sessions ended.
pub async fn delete_for_user(db: &Db, user_id: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}
```

`crates/starforged-core/src/accounts.rs`: make `hash_password` `pub(crate)`.

`crates/starforged-core/templates/mail/reset_password.txt`:

```
Hello {{ handle }},

Someone asked to reset the password of your Starforge account. To choose a new password, open:

{{ link }}

The link works once and expires in 1 hour. If you did not ask for this, ignore this message: your password stays the same.
```

Add to `crates/starforged-core/src/mail.rs`:

```rust
#[derive(Template)]
#[template(path = "mail/reset_password.txt")]
struct ResetPasswordText<'a> {
    handle: &'a str,
    link: &'a str,
}

/// A password-reset link valid for 1 hour.
pub(crate) fn reset_email(to: &str, handle: &str, link: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: "Reset your Starforge password".into(),
        body: render(&ResetPasswordText { handle, link })?,
    })
}
```

Insert at the top of `crates/starforged-core/src/passwords.rs`, above the test module:

```rust
//! Password recovery (forge-basics design §4.5, §7): emailed reset links, and links issued by site admins.

use starforged_db::{users, web_sessions};

use crate::accounts::{User, hash_password};
use crate::email_tokens::{ADMIN_RESET_TTL_SECS, Purpose, RESET_TTL_SECS};
use crate::{Core, CoreError, CoreResult, mail, validate};

/// How an admin-issued password reset reaches the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminReset {
    /// A link valid for 1 hour went to the account's address.
    Emailed,
    /// Mail is off or the account has no address: the admin passes this link on. It is valid for 24 hours.
    Link(String),
}

fn unusable_link() -> CoreError {
    CoreError::Invalid("This reset link is invalid, already used, or expired.".into())
}

impl Core {
    /// The "Forgot password?" form, which exists only with mail. The same outcome whether or not an active
    /// account uses `email`; at most one email per 5 minutes.
    pub async fn request_password_reset(&self, email: &str) -> CoreResult<()> {
        if !self.mail_enabled() {
            return Err(CoreError::NotFound);
        }
        let Ok(email) = validate::email(email) else {
            return Ok(());
        };
        let Some(user) = users::by_email(self.db(), &email)
            .await?
            .map(User::from)
            .filter(|u| u.active)
        else {
            return Ok(());
        };
        if let Some(secret) = self
            .issue_email_token(user.id, Purpose::ResetPassword, &email, RESET_TTL_SECS, true)
            .await?
        {
            let link = self.reset_link(&secret);
            self.queue_email(mail::reset_email(&email, &user.handle, &link)?)
                .await?;
        }
        Ok(())
    }

    /// Site admins reset another account's password: by email when mail is on and the account has an address,
    /// otherwise as a link for the admin to pass on.
    pub async fn admin_password_reset(&self, admin: &User, target: &User) -> CoreResult<AdminReset> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let emailed_to = target.email.as_deref().filter(|_| self.mail_enabled());
        let ttl_secs = if emailed_to.is_some() {
            RESET_TTL_SECS
        } else {
            ADMIN_RESET_TTL_SECS
        };
        let secret = self
            .issue_email_token(
                target.id,
                Purpose::ResetPassword,
                target.email.as_deref().unwrap_or(""),
                ttl_secs,
                false,
            )
            .await?
            .ok_or_else(|| CoreError::Internal("an unthrottled reset link was not issued".into()))?;
        let link = self.reset_link(&secret);
        let outcome = match emailed_to {
            Some(email) => {
                self.queue_email(mail::reset_email(email, &target.handle, &link)?)
                    .await?;
                AdminReset::Emailed
            }
            None => AdminReset::Link(link),
        };
        self.audit(
            Some(admin.id),
            "user.password_reset_issued",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        Ok(outcome)
    }

    /// Whether a reset link can still be used; the reset form is shown only for these.
    pub async fn password_reset_valid(&self, secret: &str) -> CoreResult<bool> {
        Ok(self
            .peek_email_token(secret, Purpose::ResetPassword)
            .await?
            .is_some())
    }

    /// Uses a reset link: sets `new_password` and ends every web session of the account. A password that
    /// fails validation leaves the link usable.
    pub async fn reset_password(&self, secret: &str, new_password: &str) -> CoreResult<User> {
        validate::password(new_password)?;
        let token = self
            .consume_email_token(secret, Purpose::ResetPassword)
            .await?
            .ok_or_else(unusable_link)?;
        let user = self
            .user_by_id(token.user_id)
            .await?
            .ok_or_else(unusable_link)?;
        let hash = hash_password(new_password.to_owned()).await?;
        users::set_password_hash(self.db(), user.id, &hash).await?;
        web_sessions::delete_for_user(self.db(), user.id).await?;
        self.audit(
            Some(user.id),
            "account.password_reset",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(user)
    }

    fn reset_link(&self, secret: &str) -> String {
        format!("{}/reset/{secret}", self.config().base_url)
    }
}
```

Run: `cargo test -p starforged-core passwords`
Expected: 3 passed.

- [ ] **Step 3: Write the failing web tests**

Create `crates/starforged/tests/web_password_reset.rs`:

```rust
mod common;

use common::*;
use starforged_core::accounts::CreateUser;
use starforged_core::passwords::AdminReset;

const NEW_PASSWORD: &str = "a brand new password";

/// Loads the reset form behind `link` and submits `password` twice (or `password` and `confirm`).
async fn submit_reset(
    client: &reqwest::Client,
    link: &str,
    password: &str,
    confirm: &str,
) -> reqwest::Response {
    let form = get_text(client, link).await;
    let csrf = extract_input(&form, "_csrf");
    client
        .post(link)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("password", password),
            ("confirm", confirm),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forgotten_passwords_reset_by_email() {
    let s = TestServer::start_with_mail(|_| {}).await;
    s.core
        .create_user(CreateUser {
            handle: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (old_session, _) = s.login("alice").await;

    let client = s.browser();
    assert!(get_text(&client, &s.url("/login")).await.contains(r#"href="/forgot""#));
    let form = get_text(&client, &s.url("/forgot")).await;
    let csrf = extract_input(&form, "_csrf");
    for email in ["nobody@example.com", "alice@example.com", "alice@example.com"] {
        let response = client
            .post(s.url("/forgot"))
            .form(&[("_csrf", csrf.as_str()), ("email", email)])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(response
            .text()
            .await
            .unwrap()
            .contains("If an account uses that address"));
    }
    let inbox = s.inbox().await;
    assert_eq!(
        inbox.len(),
        1,
        "unknown addresses get nothing and the repeat was throttled"
    );
    let link = s.link_in(&inbox[0], "/reset/");

    let mismatch = submit_reset(&client, &link, NEW_PASSWORD, "something else").await;
    assert_eq!(mismatch.status(), 422);
    let short = submit_reset(&client, &link, "short", "short").await;
    assert_eq!(short.status(), 422, "a rejected password does not use up the link");
    let done = submit_reset(&client, &link, NEW_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(done.status(), 200);
    assert!(done.text().await.unwrap().contains("Password changed"));

    let signed_out = old_session.get(s.url("/settings/tokens")).send().await.unwrap();
    assert_eq!(signed_out.status(), 303, "the reset ended existing sessions");
    assert_eq!(s.try_login("alice", PASSWORD).await.1.status(), 401);
    assert_eq!(s.try_login("alice", NEW_PASSWORD).await.1.status(), 303);
    assert_eq!(
        client.get(&link).send().await.unwrap().status(),
        404,
        "links work once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_mail_there_is_no_forgot_page() {
    let s = TestServer::start().await;
    let client = s.browser();
    assert_eq!(client.get(s.url("/forgot")).send().await.unwrap().status(), 404);
    assert!(!get_text(&client, &s.url("/login")).await.contains(r#"href="/forgot""#));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn links_issued_by_admins_reset_passwords() {
    let s = TestServer::start().await;
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let bob = s.user("bob").await;
    let AdminReset::Link(link) = s.core.admin_password_reset(&root, &bob).await.unwrap() else {
        panic!("without mail the admin gets a link");
    };
    let done = submit_reset(&s.browser(), &link, NEW_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(done.status(), 200);
    assert_eq!(s.try_login("bob", NEW_PASSWORD).await.1.status(), 303);
}
```

Run: `cargo test -p starforged --test web_password_reset`
Expected: failures (no `/forgot` or `/reset/...` routes).

- [ ] **Step 4: Implement the pages**

`crates/starforged-web/src/pages/password.rs`:

```rust
//! Password recovery pages (forge-basics design §4.5): `/forgot` asks for a link, `/reset/{token}` uses it.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;

use crate::AppState;
use crate::auth::{
    MaybeUser, SESSION_COOKIE, anonymous_csrf, removal, verify_anonymous_csrf,
};
use crate::error::WebError;
use crate::pages::message::MessagePage;
use crate::views::{NavUser, nav};

#[derive(Template, WebTemplate)]
#[template(path = "forgot.html")]
pub struct ForgotPage {
    nav_user: Option<NavUser>,
    csrf: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "reset.html")]
pub struct ResetPage {
    nav_user: Option<NavUser>,
    csrf: String,
    token: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct ForgotForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    email: String,
}

#[derive(Deserialize)]
pub struct ResetForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    password: String,
    confirm: String,
}

pub async fn forgot_form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
) -> Result<Response, WebError> {
    if !state.core.mail_enabled() {
        return Err(WebError::NotFound);
    }
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    let page = ForgotPage {
        nav_user: nav(session.as_ref()),
        csrf,
    };
    Ok((jar, page).into_response())
}

pub async fn forgot(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ForgotForm>,
) -> Result<MessagePage, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    state.core.request_password_reset(&form.email).await?;
    Ok(MessagePage::new(
        None,
        "Check your email",
        "If an account uses that address, we sent it a link to choose a new password. The link expires in 1 hour.",
    ))
}

pub async fn reset_form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Path(token): Path<String>,
) -> Result<Response, WebError> {
    if !state.core.password_reset_valid(&token).await? {
        let page = MessagePage::new(
            nav(session.as_ref()),
            "Link not valid",
            "This reset link is invalid, already used, or expired.",
        );
        return Ok((StatusCode::NOT_FOUND, page).into_response());
    }
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    let page = ResetPage {
        nav_user: nav(session.as_ref()),
        csrf,
        token,
        error: None,
    };
    Ok((jar, page).into_response())
}

pub async fn reset(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(token): Path<String>,
    Form(form): Form<ResetForm>,
) -> Result<Response, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    let error = if form.password != form.confirm {
        "The two passwords do not match.".to_owned()
    } else {
        match state.core.reset_password(&token, &form.password).await {
            Ok(_) => {
                // The reset ended every session of the account, including any in this browser.
                let page = MessagePage::new(
                    None,
                    "Password changed",
                    "Your password is changed, and every session of your account was signed out.",
                )
                .with_link("/login", "Sign in");
                return Ok((jar.remove(removal(SESSION_COOKIE)), page).into_response());
            }
            Err(CoreError::Invalid(message)) => message,
            Err(other) => return Err(other.into()),
        }
    };
    let page = ResetPage {
        nav_user: None,
        csrf: form.csrf,
        token,
        error: Some(error),
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
}
```

`crates/starforged-web/templates/forgot.html`:

```html
{% extends "base.html" %}
{% block title %}Forgot password · Starforge{% endblock %}
{% block content %}
<h1>Forgot your password?</h1>
<p>Enter the email address of your account, and we will send you a link to choose a new password.</p>
<form method="post" action="/forgot" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Email <input name="email" type="email" autocomplete="email" required></label>
  <button type="submit">Send the link</button>
</form>
{% endblock %}
```

`crates/starforged-web/templates/reset.html`:

```html
{% extends "base.html" %}
{% block title %}Choose a new password · Starforge{% endblock %}
{% block content %}
<h1>Choose a new password</h1>
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/reset/{{ token }}" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>New password <input name="password" type="password" autocomplete="new-password" required minlength="10"></label>
  <label>Repeat it <input name="confirm" type="password" autocomplete="new-password" required minlength="10"></label>
  <button type="submit">Change password</button>
</form>
{% endblock %}
```

`crates/starforged-web/src/pages/mod.rs`: add `pub mod password;`. `crates/starforged-web/src/lib.rs` `page_routes`: add

```rust
        .route("/forgot", get(pages::password::forgot_form).post(pages::password::forgot))
        .route(
            "/reset/{token}",
            get(pages::password::reset_form).post(pages::password::reset),
        )
```

`crates/starforged-web/src/pages/login.rs`: `LoginPage` gains `forgot_password: bool`, set from `state.core.mail_enabled()` in every literal. `templates/login.html`, after the sign-in form (before the sign-up link):

```html
{% if forgot_password %}<p><a href="/forgot">Forgot password?</a></p>{% endif %}
```

- [ ] **Step 5: Run the web tests**

Run: `cargo test -p starforged --test web_password_reset --test web_auth`
Expected: pass.

- [ ] **Step 6: Full suite, lint, format, both engines, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
STARFORGE_TEST_PG=1 scripts/check.sh
git add crates Cargo.lock
git commit -m "feat(accounts): password reset by email and by admin-issued link"
```

### Task A6: Account settings

**Files:**
- Modify: `crates/starforged-db/src/users.rs` (`set_display_name`, `set_email`), `crates/starforged-db/src/web_sessions.rs` (`last_seen_at`, `touch`, `list_for_user`, `delete_by_id_for_user`, `delete_for_user_except`)
- Create: `crates/starforged-core/src/account.rs`, `crates/starforged-core/templates/mail/confirm_email.txt`
- Modify: `crates/starforged-core/src/{lib.rs, sessions.rs, verification.rs, mail.rs}`
- Create: `crates/starforged-web/src/pages/settings.rs`, `crates/starforged-web/templates/{settings_nav.html, settings_profile.html, settings_email.html, settings_password.html, settings_sessions.html}`
- Modify: `crates/starforged-web/src/{lib.rs, pages/mod.rs, pages/tokens.rs}`, `crates/starforged-web/templates/{base.html, tokens.html}`, `crates/starforged-web/static/starforge.css`
- Test: unit tests in `account.rs`; `crates/starforged/tests/web_account.rs`

**Interfaces:**
- Consumes: `Core::{authenticate_password, issue_email_token, consume_email_token, peek_email_token, queue_email, mail_enabled}`, `hash_password`, `users::set_password_hash`, `Purpose::ChangeEmail`, `VERIFY_TTL_SECS` (Tasks A3, A5); `validate::display_name` (Task A4); `/verify/{token}` pages (Task A3).
- Produces:
  - `users::{set_display_name(db, id, name), set_email(db, id, email: Option<&str>, verified)}`.
  - `WebSessionRow.last_seen_at`; `web_sessions::{SessionListRow { id, created_at, last_seen_at, user_agent, ip }, touch, list_for_user(db, user_id, now_ts), delete_by_id_for_user(db, id, user_id) -> bool, delete_for_user_except(db, user_id, keep_id) -> u64}`.
  - `WebSession.session_id: i64`; `Core::web_session` refreshes `last_seen_at` when it is at least 5 minutes old.
  - `starforged_core::account::{SessionInfo { id, created_at, last_seen_at, user_agent, ip }, EmailChange::{Changed, ConfirmationSent, Throttled}}`; `Core::{update_profile(user, display_name) -> User, change_password(user, current_session, current, new), change_email(user, new_email) -> EmailChange, list_sessions(user), revoke_session(user, session_id), revoke_other_sessions(user, keep) -> u64}`.
  - `Core::verify_email` and `Core::email_link_valid` also accept confirm-new-email links.
  - Web: `GET /settings` (→ `/settings/profile`), `GET|POST /settings/profile`, `GET|POST /settings/email`, `GET|POST /settings/password`, `GET /settings/sessions`, `POST /settings/sessions/{id}/revoke`, `POST /settings/sessions/revoke-others`. The header's "Tokens" link becomes "Settings". Settings pages (tokens included) share a `settings_nav.html` tab bar and a `settings_tab: &'static str` field.

- [ ] **Step 1: Write the failing core tests**

Add `pub mod account;` to `crates/starforged-core/src/lib.rs` before `pub mod accounts;`. Create `crates/starforged-core/src/account.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, test_core_with, user, with_file_mail};

    const PASSWORD: &str = "correct horse battery";
    const NEW_PASSWORD: &str = "a brand new password";

    async fn alice(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn changing_the_password_ends_other_sessions() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        let (_, first) = core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();
        let (_, second) = core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();
        let current = core
            .web_session(&first.cookie_value)
            .await
            .unwrap()
            .unwrap()
            .session_id;
        let wrong = core
            .change_password(&alice, current, "not my password", NEW_PASSWORD)
            .await
            .unwrap_err();
        assert!(matches!(&wrong, CoreError::Invalid(m) if m.contains("current password")), "{wrong}");
        core.change_password(&alice, current, PASSWORD, NEW_PASSWORD)
            .await
            .unwrap();
        assert!(core.web_session(&first.cookie_value).await.unwrap().is_some());
        assert!(core.web_session(&second.cookie_value).await.unwrap().is_none());
        core.login("alice", NEW_PASSWORD, "ua", "127.0.0.1").await.unwrap();
    }

    #[tokio::test]
    async fn sessions_are_listed_and_revoked_by_their_owner() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        let bob = user(&core, "bob").await;
        core.login("alice", PASSWORD, "firefox", "10.0.0.1").await.unwrap();
        core.login("alice", PASSWORD, "curl", "10.0.0.2").await.unwrap();
        let listed = core.list_sessions(&alice).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|s| s.user_agent == "firefox" && s.ip == "10.0.0.1"));
        assert!(matches!(
            core.revoke_session(&bob, listed[0].id).await,
            Err(CoreError::NotFound)
        ));
        core.revoke_session(&alice, listed[0].id).await.unwrap();
        assert_eq!(core.list_sessions(&alice).await.unwrap().len(), 1);
        assert_eq!(
            core.revoke_other_sessions(&alice, listed[1].id).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn activity_is_recorded_at_most_every_five_minutes() {
        let (core, _f) = test_core().await;
        alice(&core).await;
        let (_, session) = core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();
        let last_seen = || async {
            let ts: i64 = sqlx::query_scalar("SELECT last_seen_at FROM web_sessions")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
            ts
        };
        sqlx::query("UPDATE web_sessions SET last_seen_at = $1")
            .bind(100_i64)
            .execute(core.db().pool())
            .await
            .unwrap();
        core.web_session(&session.cookie_value).await.unwrap().unwrap();
        assert!(last_seen().await >= starforged_db::now() - 5);
        let recent = starforged_db::now() - 60;
        sqlx::query("UPDATE web_sessions SET last_seen_at = $1")
            .bind(recent)
            .execute(core.db().pool())
            .await
            .unwrap();
        core.web_session(&session.cookie_value).await.unwrap().unwrap();
        assert_eq!(last_seen().await, recent, "recent activity is not rewritten");
    }

    #[tokio::test]
    async fn email_changes_need_confirmation_when_mail_is_on() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = alice(&core).await;
        core.create_user(CreateUser {
            handle: "bob".into(),
            email: Some("bob@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(matches!(
            core.change_email(&alice, "bob@example.com").await,
            Err(CoreError::Conflict(_))
        ));
        assert!(matches!(
            core.change_email(&alice, "alice@example.com").await,
            Err(CoreError::Invalid(_))
        ));
        assert_eq!(
            core.change_email(&alice, "alice@new.example").await.unwrap(),
            EmailChange::ConfirmationSent
        );
        assert_eq!(
            core.change_email(&alice, "alice@other.example").await.unwrap(),
            EmailChange::Throttled
        );
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(mail[0].contains("To: alice@new.example"), "{}", mail[0]);
        assert_eq!(
            core.user_by_id(alice.id).await.unwrap().unwrap().email.as_deref(),
            Some("alice@example.com"),
            "the old address stays until the link is used"
        );
        let link = crate::mail::testing::find_link(&mail[0], "/verify/").unwrap();
        let secret = link.rsplit('/').next().unwrap();
        assert!(core.email_link_valid(secret).await.unwrap());
        let user = core.verify_email(secret).await.unwrap();
        assert_eq!(
            (user.email.as_deref(), user.email_verified),
            (Some("alice@new.example"), true)
        );
    }

    #[tokio::test]
    async fn without_mail_email_changes_apply_unverified() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert_eq!(
            core.change_email(&alice, "Alice@New.example").await.unwrap(),
            EmailChange::Changed
        );
        let user = core.user_by_id(alice.id).await.unwrap().unwrap();
        assert_eq!(
            (user.email.as_deref(), user.email_verified),
            (Some("alice@new.example"), false)
        );
    }

    #[tokio::test]
    async fn display_names_are_validated() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert_eq!(
            core.update_profile(&alice, "  Alice L.  ").await.unwrap().display_name,
            "Alice L."
        );
        assert!(matches!(
            core.update_profile(&alice, &"x".repeat(101)).await,
            Err(CoreError::Invalid(_))
        ));
    }
}
```

Run: `cargo test -p starforged-core account`
Expected: compile errors.

- [ ] **Step 2: Implement the data access**

`crates/starforged-db/src/users.rs`:

```rust
pub async fn set_display_name(db: &Db, id: i64, display_name: &str) -> DbResult<()> {
    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(display_name)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Sets the (lowercase) address and whether it is verified.
pub async fn set_email(db: &Db, id: i64, email: Option<&str>, verified: bool) -> DbResult<()> {
    sqlx::query("UPDATE users SET email = $1, email_verified = $2 WHERE id = $3")
        .bind(email.map(str::to_owned))
        .bind(i64::from(verified))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
```

`crates/starforged-db/src/web_sessions.rs`:

1. `WebSessionRow` gains `pub last_seen_at: i64`; `active_by_hash` selects it (`SELECT id, user_id, csrf_token, expires_at, last_seen_at FROM web_sessions WHERE …`) and reads it (`last_seen_at: row.try_get("last_seen_at")?`).
2. Add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListRow {
    pub id: i64,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub user_agent: String,
    pub ip: String,
}

/// The user's unexpired sessions, most recently active first.
pub async fn list_for_user(db: &Db, user_id: i64, now_ts: i64) -> DbResult<Vec<SessionListRow>> {
    let rows = sqlx::query(
        "SELECT id, created_at, last_seen_at, user_agent, ip FROM web_sessions \
         WHERE user_id = $1 AND expires_at > $2 ORDER BY last_seen_at DESC, id DESC",
    )
    .bind(user_id)
    .bind(now_ts)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(SessionListRow {
                id: row.try_get("id")?,
                created_at: row.try_get("created_at")?,
                last_seen_at: row.try_get("last_seen_at")?,
                user_agent: row.try_get("user_agent")?,
                ip: row.try_get("ip")?,
            })
        })
        .collect()
}

pub async fn touch(db: &Db, id: i64, now_ts: i64) -> DbResult<()> {
    sqlx::query("UPDATE web_sessions SET last_seen_at = $1 WHERE id = $2")
        .bind(now_ts)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Ends one of the user's sessions; `false` when the user has no session with that id.
pub async fn delete_by_id_for_user(db: &Db, id: i64, user_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Ends every session of the user except `keep_id`; returns how many ended.
pub async fn delete_for_user_except(db: &Db, user_id: i64, keep_id: i64) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM web_sessions WHERE user_id = $1 AND id <> $2")
        .bind(user_id)
        .bind(keep_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected())
}
```

- [ ] **Step 3: Implement account settings in core**

`crates/starforged-core/src/sessions.rs`:

1. `WebSession` gains `pub session_id: i64` ("the `web_sessions` row, for the sessions page").
2. Add `const TOUCH_INTERVAL_SECS: i64 = 300;` ("a session's last-activity time is written at most this often").
3. `web_session` becomes:

```rust
    pub async fn web_session(&self, cookie_value: &str) -> CoreResult<Option<WebSession>> {
        let hash = crypto::sha256_hex(cookie_value);
        let ts = starforged_db::now();
        let Some(row) = web_sessions::active_by_hash(self.db(), &hash, ts).await? else {
            return Ok(None);
        };
        let Some(user) = self.user_by_id(row.user_id).await?.filter(|u| u.active) else {
            return Ok(None);
        };
        if ts - row.last_seen_at >= TOUCH_INTERVAL_SECS {
            web_sessions::touch(self.db(), row.id, ts).await?;
        }
        Ok(Some(WebSession {
            user,
            csrf_token: row.csrf_token,
            session_id: row.id,
        }))
    }
```

`crates/starforged-core/templates/mail/confirm_email.txt`:

```
Hello {{ handle }},

You asked to change the email address of your Starforge account to this one. To confirm, open:

{{ link }}

The link works once and expires in 24 hours. Until then your account keeps its current address.
```

Add to `crates/starforged-core/src/mail.rs`:

```rust
#[derive(Template)]
#[template(path = "mail/confirm_email.txt")]
struct ConfirmEmailText<'a> {
    handle: &'a str,
    link: &'a str,
}

/// Confirms a new address before it replaces the old one; the link is valid for 24 hours.
pub(crate) fn confirm_email(to: &str, handle: &str, link: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: "Confirm your new email address".into(),
        body: render(&ConfirmEmailText { handle, link })?,
    })
}
```

Insert at the top of `crates/starforged-core/src/account.rs`, above the test module:

```rust
//! Account settings (forge-basics design §4.6): profile, email address, password, and web sessions.

use starforged_db::{now, users, web_sessions};

use crate::accounts::{User, hash_password};
use crate::email_tokens::{Purpose, VERIFY_TTL_SECS};
use crate::{Core, CoreError, CoreResult, mail, validate};

/// One signed-in browser, for the sessions page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: i64,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub user_agent: String,
    pub ip: String,
}

/// What a request to change the email address did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailChange {
    /// Mail is off: the new address is in use now, unverified.
    Changed,
    /// A confirmation link went to the new address; the change happens when it is used.
    ConfirmationSent,
    /// A confirmation link went out less than 5 minutes ago, so nothing was sent.
    Throttled,
}

pub(crate) fn email_taken() -> CoreError {
    CoreError::Conflict("That email address is already in use.".into())
}

impl Core {
    pub async fn update_profile(&self, user: &User, display_name: &str) -> CoreResult<User> {
        let display_name = validate::display_name(display_name)?;
        users::set_display_name(self.db(), user.id, &display_name).await?;
        self.audit(Some(user.id), "account.profile", &format!("user:{}", user.handle), "")
            .await?;
        self.user_by_id(user.id).await?.ok_or(CoreError::NotFound)
    }

    /// Changes the password after checking the current one; every session except `current_session` ends.
    pub async fn change_password(
        &self,
        user: &User,
        current_session: i64,
        current: &str,
        new: &str,
    ) -> CoreResult<()> {
        if self.authenticate_password(&user.handle, current).await.is_err() {
            return Err(CoreError::Invalid("The current password is incorrect.".into()));
        }
        validate::password(new)?;
        let hash = hash_password(new.to_owned()).await?;
        users::set_password_hash(self.db(), user.id, &hash).await?;
        web_sessions::delete_for_user_except(self.db(), user.id, current_session).await?;
        self.audit(
            Some(user.id),
            "account.password_change",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(())
    }

    /// With mail, a confirmation link goes to the new address and the change waits for it; without mail,
    /// the new address applies at once, unverified.
    pub async fn change_email(&self, user: &User, new_email: &str) -> CoreResult<EmailChange> {
        let email = validate::email(new_email)?;
        if user.email.as_deref() == Some(email.as_str()) {
            return Err(CoreError::Invalid("That is already your email address.".into()));
        }
        if users::by_email(self.db(), &email).await?.is_some() {
            return Err(email_taken());
        }
        if !self.mail_enabled() {
            users::set_email(self.db(), user.id, Some(&email), false)
                .await
                .map_err(|e| if e.is_unique_violation() { email_taken() } else { e.into() })?;
            self.audit(
                Some(user.id),
                "account.email_change",
                &format!("user:{}", user.handle),
                "",
            )
            .await?;
            return Ok(EmailChange::Changed);
        }
        let Some(secret) = self
            .issue_email_token(user.id, Purpose::ChangeEmail, &email, VERIFY_TTL_SECS, true)
            .await?
        else {
            return Ok(EmailChange::Throttled);
        };
        let link = format!("{}/verify/{secret}", self.config().base_url);
        self.queue_email(mail::confirm_email(&email, &user.handle, &link)?)
            .await?;
        Ok(EmailChange::ConfirmationSent)
    }

    pub async fn list_sessions(&self, user: &User) -> CoreResult<Vec<SessionInfo>> {
        Ok(web_sessions::list_for_user(self.db(), user.id, now())
            .await?
            .into_iter()
            .map(|row| SessionInfo {
                id: row.id,
                created_at: row.created_at,
                last_seen_at: row.last_seen_at,
                user_agent: row.user_agent,
                ip: row.ip,
            })
            .collect())
    }

    /// Ends one of the user's sessions; `NotFound` for a session that is not theirs.
    pub async fn revoke_session(&self, user: &User, session_id: i64) -> CoreResult<()> {
        if !web_sessions::delete_by_id_for_user(self.db(), session_id, user.id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "account.session_revoke",
            &format!("user:{}", user.handle),
            &format!("session:{session_id}"),
        )
        .await
    }

    /// Ends every session of the user except `keep`; returns how many ended.
    pub async fn revoke_other_sessions(&self, user: &User, keep: i64) -> CoreResult<u64> {
        let ended = web_sessions::delete_for_user_except(self.db(), user.id, keep).await?;
        self.audit(
            Some(user.id),
            "account.session_revoke",
            &format!("user:{}", user.handle),
            "others",
        )
        .await?;
        Ok(ended)
    }
}
```

`crates/starforged-core/src/verification.rs`: confirm-new-email links share `/verify/{token}`.

1. `email_link_valid` accepts both purposes:

```rust
    pub async fn email_link_valid(&self, secret: &str) -> CoreResult<bool> {
        Ok(self.peek_email_token(secret, Purpose::VerifyEmail).await?.is_some()
            || self.peek_email_token(secret, Purpose::ChangeEmail).await?.is_some())
    }
```

2. `verify_email` first tries a confirm-new-email link (insert at the start of the function, and update its doc comment to mention both kinds of link):

```rust
        if let Some(token) = self.consume_email_token(secret, Purpose::ChangeEmail).await? {
            let user = self.user_by_id(token.user_id).await?.ok_or(CoreError::NotFound)?;
            users::set_email(self.db(), user.id, Some(&token.email), true)
                .await
                .map_err(|e| {
                    if e.is_unique_violation() {
                        crate::account::email_taken()
                    } else {
                        e.into()
                    }
                })?;
            self.audit(
                Some(user.id),
                "account.email_change",
                &format!("user:{}", user.handle),
                "",
            )
            .await?;
            return self.user_by_id(user.id).await?.ok_or(CoreError::NotFound);
        }
```

Run: `cargo test -p starforged-core`
Expected: all pass.

- [ ] **Step 4: Write the failing web tests**

Create `crates/starforged/tests/web_account.rs`:

```rust
mod common;

use common::*;
use starforged_core::accounts::CreateUser;

const NEW_PASSWORD: &str = "a brand new password";

async fn post_form(client: &reqwest::Client, url: &str, fields: &[(&str, &str)]) -> reqwest::Response {
    client.post(url).form(fields).send().await.unwrap()
}

/// `(session id, is the current session)` for each row of the sessions page.
fn sessions_on(page: &str) -> Vec<(i64, bool)> {
    page.split("<tr>")
        .filter_map(|row| {
            let start = row.find("/settings/sessions/")? + "/settings/sessions/".len();
            let id = row[start..].split('/').next()?.parse().ok()?;
            Some((id, row.contains("this session")))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_and_password_settings() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let (other, _) = s.login("alice").await;
    let csrf = csrf.as_str();

    let index = client.get(s.url("/settings")).send().await.unwrap();
    assert_eq!(index.status(), 303);
    assert_eq!(index.headers()["location"], "/settings/profile");
    let home = get_text(&client, &s.url("/")).await;
    assert!(home.contains(r#"<a href="/settings/profile">Settings</a>"#));

    let profile = s.url("/settings/profile");
    let saved = post_form(&client, &profile, &[("_csrf", csrf), ("display_name", "Alice Liddell")]).await;
    assert_eq!(saved.status(), 200);
    assert!(saved.text().await.unwrap().contains(r#"value="Alice Liddell""#));
    let too_long = "x".repeat(101);
    let rejected = post_form(&client, &profile, &[("_csrf", csrf), ("display_name", too_long.as_str())]).await;
    assert_eq!(rejected.status(), 422);
    let forged = post_form(&client, &profile, &[("_csrf", "forged"), ("display_name", "x")]).await;
    assert_eq!(forged.status(), 403);

    let password = s.url("/settings/password");
    let wrong = post_form(
        &client,
        &password,
        &[("_csrf", csrf), ("current", "not my password"), ("password", NEW_PASSWORD), ("confirm", NEW_PASSWORD)],
    )
    .await;
    assert_eq!(wrong.status(), 422);
    assert!(wrong.text().await.unwrap().contains("current password is incorrect"));
    let mismatch = post_form(
        &client,
        &password,
        &[("_csrf", csrf), ("current", PASSWORD), ("password", NEW_PASSWORD), ("confirm", "something else")],
    )
    .await;
    assert_eq!(mismatch.status(), 422);
    let changed = post_form(
        &client,
        &password,
        &[("_csrf", csrf), ("current", PASSWORD), ("password", NEW_PASSWORD), ("confirm", NEW_PASSWORD)],
    )
    .await;
    assert_eq!(changed.status(), 200);
    assert_eq!(
        other.get(&profile).send().await.unwrap().status(),
        303,
        "the other session was signed out"
    );
    assert_eq!(client.get(&profile).send().await.unwrap().status(), 200, "this session stays");
    assert_eq!(s.try_login("alice", NEW_PASSWORD).await.1.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_can_be_listed_and_revoked() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let (second, _) = s.login("alice").await;
    let sessions_page = s.url("/settings/sessions");

    let listed = sessions_on(&get_text(&client, &sessions_page).await);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed.iter().filter(|(_, current)| *current).count(), 1);
    let other_id = listed.iter().find(|(_, current)| !current).unwrap().0;
    let revoked = post_form(
        &client,
        &s.url(&format!("/settings/sessions/{other_id}/revoke")),
        &[("_csrf", csrf.as_str())],
    )
    .await;
    assert_eq!(revoked.status(), 303);
    assert_eq!(
        second.get(s.url("/settings/profile")).send().await.unwrap().status(),
        303,
        "the revoked session is signed out"
    );

    let (third, _) = s.login("alice").await;
    let others = post_form(&client, &s.url("/settings/sessions/revoke-others"), &[("_csrf", csrf.as_str())]).await;
    assert_eq!(others.status(), 303);
    assert_eq!(third.get(s.url("/settings/profile")).send().await.unwrap().status(), 303);
    let remaining = sessions_on(&get_text(&client, &sessions_page).await);
    assert_eq!(remaining.len(), 1);

    s.user("bob").await;
    let (bob, bob_csrf) = s.login("bob").await;
    let not_his = post_form(
        &bob,
        &s.url(&format!("/settings/sessions/{}/revoke", remaining[0].0)),
        &[("_csrf", bob_csrf.as_str())],
    )
    .await;
    assert_eq!(not_his.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_apply_at_once_without_mail() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.core
        .create_user(CreateUser {
            handle: "bob".into(),
            email: Some("bob@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (client, csrf) = s.login("alice").await;
    let email = s.url("/settings/email");
    let taken = post_form(&client, &email, &[("_csrf", csrf.as_str()), ("email", "bob@example.com")]).await;
    assert_eq!(taken.status(), 422);
    let changed = post_form(&client, &email, &[("_csrf", csrf.as_str()), ("email", "Alice@Example.com")]).await;
    assert_eq!(changed.status(), 200);
    let page = changed.text().await.unwrap();
    assert!(page.contains("alice@example.com") && page.contains("unverified"), "{page}");
    let user = s.core.user_by_id(alice.id).await.unwrap().unwrap();
    assert_eq!(
        (user.email.as_deref(), user.email_verified),
        (Some("alice@example.com"), false)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_wait_for_confirmation_with_mail() {
    let s = TestServer::start_with_mail(|_| {}).await;
    let alice = s
        .core
        .create_user(CreateUser {
            handle: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (client, csrf) = s.login("alice").await;
    let requested = post_form(
        &client,
        &s.url("/settings/email"),
        &[("_csrf", csrf.as_str()), ("email", "alice@new.example")],
    )
    .await;
    assert_eq!(requested.status(), 200);
    assert!(requested
        .text()
        .await
        .unwrap()
        .contains("We sent a confirmation link to alice@new.example"));
    assert_eq!(
        s.core.user_by_id(alice.id).await.unwrap().unwrap().email.as_deref(),
        Some("alice@example.com"),
        "the old address stays until the link is used"
    );

    let link = s.link_in(&s.last_email_to("alice@new.example").await, "/verify/");
    let confirm = get_text(&client, &link).await;
    let confirm_csrf = extract_input(&confirm, "_csrf");
    let done = client
        .post(&link)
        .form(&[("_csrf", confirm_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    let user = s.core.user_by_id(alice.id).await.unwrap().unwrap();
    assert_eq!(
        (user.email.as_deref(), user.email_verified),
        (Some("alice@new.example"), true)
    );
}
```

Run: `cargo test -p starforged --test web_account`
Expected: failures (no settings routes).

- [ ] **Step 5: Implement the settings pages**

`crates/starforged-web/src/pages/settings.rs`:

```rust
//! Account settings pages (forge-basics design §4.6).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::account::EmailChange;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, SESSION_COOKIE, removal, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, format_time};

pub async fn index() -> Redirect {
    Redirect::to("/settings/profile")
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_profile.html")]
pub struct ProfilePage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    handle: String,
    display_name: String,
    notice: Option<&'static str>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct ProfileForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    display_name: String,
}

fn profile_page(
    session: &WebSession,
    display_name: String,
    notice: Option<&'static str>,
    error: Option<String>,
) -> ProfilePage {
    ProfilePage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "profile",
        handle: session.user.handle.clone(),
        display_name,
        notice,
        error,
    }
}

pub async fn profile(RequireUser(session): RequireUser) -> ProfilePage {
    let display_name = session.user.display_name.clone();
    profile_page(&session, display_name, None, None)
}

pub async fn save_profile(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<ProfileForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state.core.update_profile(&session.user, &form.display_name).await {
        Ok(user) => Ok(profile_page(&session, user.display_name, Some("Profile saved."), None).into_response()),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            profile_page(&session, form.display_name, None, Some(message)),
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_email.html")]
pub struct EmailPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    email: Option<String>,
    verified: bool,
    new_email: String,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct EmailForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    email: String,
}

async fn email_page(
    state: &AppState,
    session: &WebSession,
    new_email: String,
    notice: Option<String>,
    error: Option<String>,
) -> Result<EmailPage, WebError> {
    // Read the account again: this request may have just changed the address.
    let user = state
        .core
        .user_by_id(session.user.id)
        .await?
        .ok_or(WebError::NotFound)?;
    Ok(EmailPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "email",
        email: user.email,
        verified: user.email_verified,
        new_email,
        notice,
        error,
    })
}

pub async fn email(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<EmailPage, WebError> {
    email_page(&state, &session, String::new(), None, None).await
}

pub async fn change_email(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<EmailForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let notice = match state.core.change_email(&session.user, &form.email).await {
        Ok(EmailChange::Changed) => {
            "Your email address is changed. It stays unverified, because this Starforge does not send email."
                .to_owned()
        }
        Ok(EmailChange::ConfirmationSent) => format!(
            "We sent a confirmation link to {}. Your address changes when you open it.",
            form.email.trim().to_ascii_lowercase()
        ),
        Ok(EmailChange::Throttled) => {
            "We sent a confirmation link a few minutes ago. Check your inbox, or try again later.".to_owned()
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = email_page(&state, &session, form.email, None, Some(message)).await?;
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response());
        }
        Err(other) => return Err(other.into()),
    };
    Ok(email_page(&state, &session, String::new(), Some(notice), None)
        .await?
        .into_response())
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_password.html")]
pub struct PasswordPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    notice: Option<&'static str>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    current: String,
    password: String,
    confirm: String,
}

fn password_page(
    session: &WebSession,
    notice: Option<&'static str>,
    error: Option<String>,
) -> PasswordPage {
    PasswordPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "password",
        notice,
        error,
    }
}

pub async fn password(RequireUser(session): RequireUser) -> PasswordPage {
    password_page(&session, None, None)
}

pub async fn change_password(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<PasswordForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = if form.password != form.confirm {
        Err(CoreError::Invalid("The two new passwords do not match.".into()))
    } else {
        state
            .core
            .change_password(&session.user, session.session_id, &form.current, &form.password)
            .await
    };
    match result {
        Ok(()) => Ok(password_page(
            &session,
            Some("Password changed. Your other sessions were signed out."),
            None,
        )
        .into_response()),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            password_page(&session, None, Some(message)),
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

pub struct SessionRow {
    id: i64,
    browser: String,
    ip: String,
    signed_in: String,
    last_active: String,
    current: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_sessions.html")]
pub struct SessionsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    sessions: Vec<SessionRow>,
}

pub async fn sessions(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<SessionsPage, WebError> {
    let sessions = state
        .core
        .list_sessions(&session.user)
        .await?
        .into_iter()
        .map(|s| SessionRow {
            id: s.id,
            browser: if s.user_agent.is_empty() {
                "Unknown browser".to_owned()
            } else {
                s.user_agent
            },
            ip: s.ip,
            signed_in: format_time(s.created_at),
            last_active: format_time(s.last_seen_at),
            current: s.id == session.session_id,
        })
        .collect();
    Ok(SessionsPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "sessions",
        sessions,
    })
}

pub async fn revoke_session(
    State(state): State<AppState>,
    jar: CookieJar,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.revoke_session(&session.user, id).await?;
    if id == session.session_id {
        return Ok((jar.remove(removal(SESSION_COOKIE)), Redirect::to("/login")).into_response());
    }
    Ok(Redirect::to("/settings/sessions").into_response())
}

pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .revoke_other_sessions(&session.user, session.session_id)
        .await?;
    Ok(Redirect::to("/settings/sessions"))
}
```

`crates/starforged-web/templates/settings_nav.html` (included by every settings page; each page struct has `settings_tab`):

```html
<nav class="tabs" aria-label="Settings">
  <a href="/settings/profile"{% if settings_tab == "profile" %} aria-current="page"{% endif %}>Profile</a>
  <a href="/settings/email"{% if settings_tab == "email" %} aria-current="page"{% endif %}>Email</a>
  <a href="/settings/password"{% if settings_tab == "password" %} aria-current="page"{% endif %}>Password</a>
  <a href="/settings/sessions"{% if settings_tab == "sessions" %} aria-current="page"{% endif %}>Sessions</a>
  <a href="/settings/tokens"{% if settings_tab == "tokens" %} aria-current="page"{% endif %}>Tokens</a>
</nav>
```

`crates/starforged-web/templates/settings_profile.html`:

```html
{% extends "base.html" %}
{% block title %}Profile · Settings · Starforge{% endblock %}
{% block content %}
{% include "settings_nav.html" %}
<h1>Profile</h1>
{% if let Some(n) = notice %}<p class="notice">{{ n }}</p>{% endif %}
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/settings/profile" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Handle <input value="{{ handle }}" disabled></label>
  <label>Display name <input name="display_name" maxlength="100" value="{{ display_name }}"></label>
  <button type="submit">Save</button>
</form>
{% endblock %}
```

`crates/starforged-web/templates/settings_email.html`:

```html
{% extends "base.html" %}
{% block title %}Email · Settings · Starforge{% endblock %}
{% block content %}
{% include "settings_nav.html" %}
<h1>Email</h1>
{% if let Some(n) = notice %}<p class="notice">{{ n }}</p>{% endif %}
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<p>Current address:
{% if let Some(address) = email %}<strong>{{ address }}</strong> {% if verified %}<span class="badge">verified</span>{% else %}<span class="badge">unverified</span>{% endif %}{% else %}none{% endif %}
</p>
<form method="post" action="/settings/email" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>New address <input name="email" type="email" autocomplete="email" required value="{{ new_email }}"></label>
  <button type="submit">Change address</button>
</form>
{% endblock %}
```

`crates/starforged-web/templates/settings_password.html`:

```html
{% extends "base.html" %}
{% block title %}Password · Settings · Starforge{% endblock %}
{% block content %}
{% include "settings_nav.html" %}
<h1>Password</h1>
{% if let Some(n) = notice %}<p class="notice">{{ n }}</p>{% endif %}
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/settings/password" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Current password <input name="current" type="password" autocomplete="current-password" required></label>
  <label>New password <input name="password" type="password" autocomplete="new-password" required minlength="10"></label>
  <label>Repeat the new password <input name="confirm" type="password" autocomplete="new-password" required minlength="10"></label>
  <button type="submit">Change password</button>
</form>
{% endblock %}
```

`crates/starforged-web/templates/settings_sessions.html`:

```html
{% extends "base.html" %}
{% block title %}Sessions · Settings · Starforge{% endblock %}
{% block content %}
{% include "settings_nav.html" %}
<h1>Sessions</h1>
<table class="list">
<thead><tr><th>Browser</th><th>IP address</th><th>Signed in</th><th>Last active</th><th></th></tr></thead>
<tbody>
{% for s in sessions %}
<tr>
<td>{{ s.browser }}{% if s.current %} <span class="badge">this session</span>{% endif %}</td><td>{{ s.ip }}</td><td>{{ s.signed_in }}</td><td>{{ s.last_active }}</td>
<td><form method="post" action="/settings/sessions/{{ s.id }}/revoke" class="inline"><input type="hidden" name="_csrf" value="{{ csrf }}"><button type="submit">{% if s.current %}Sign out{% else %}Revoke{% endif %}</button></form></td>
</tr>
{% endfor %}
</tbody>
</table>
<form method="post" action="/settings/sessions/revoke-others" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <button type="submit">Sign out everywhere else</button>
</form>
{% endblock %}
```

Bring the token page into the settings layout: `TokensPage` in `crates/starforged-web/src/pages/tokens.rs` gains `settings_tab: &'static str` (set to `"tokens"`), and `templates/tokens.html` starts its content block with `{% include "settings_nav.html" %}` (before its `<h1>`).

`crates/starforged-web/templates/base.html`: the signed-in header link `<a href="/settings/tokens">Tokens</a>` becomes `<a href="/settings/profile">Settings</a>`.

`crates/starforged-web/static/starforge.css`: append

```css
nav.tabs a[aria-current] { font-weight: 600; text-decoration: underline; }
```

`crates/starforged-web/src/pages/mod.rs`: add `pub mod settings;`. `crates/starforged-web/src/lib.rs` `page_routes`: add

```rust
        .route("/settings", get(pages::settings::index))
        .route(
            "/settings/profile",
            get(pages::settings::profile).post(pages::settings::save_profile),
        )
        .route(
            "/settings/email",
            get(pages::settings::email).post(pages::settings::change_email),
        )
        .route(
            "/settings/password",
            get(pages::settings::password).post(pages::settings::change_password),
        )
        .route("/settings/sessions", get(pages::settings::sessions))
        .route(
            "/settings/sessions/revoke-others",
            post(pages::settings::revoke_other_sessions),
        )
        .route(
            "/settings/sessions/{id}/revoke",
            post(pages::settings::revoke_session),
        )
```

- [ ] **Step 6: Run the web tests**

Run: `cargo test -p starforged --test web_account --test web_settings --test web_auth --test web_verify`
Expected: pass.

- [ ] **Step 7: Full suite, lint, format, both engines, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
STARFORGE_TEST_PG=1 scripts/check.sh
git add crates Cargo.lock
git commit -m "feat(accounts): settings for profile, email, password, and sessions"
```

### Task A7: End-to-end sign-up with the real binary, and the README

**Files:**
- Create: `crates/starforged/tests/e2e_sign_up.rs`
- Modify: `README.md`

**Interfaces:**
- Consumes: `starforged init`, `starforged serve` with job workers (Task A1), `STARFORGE__REGISTRATION__MODE` and `STARFORGE__MAIL__*` overrides (Tasks A2, A4), `/join`, `/verify/{token}`, `/login`, `mail::testing::{read_mailbox, find_link}`, `common::{extract_input, get_text}`.
- Produces: proof that the shipped binary signs a new account up, delivers the verification email through its own workers, and lets the verified account sign in; README documentation of `[registration]`, `[mail]`, `admin mail test`, and the settings pages.

- [ ] **Step 1: Write the end-to-end test**

`crates/starforged/tests/e2e_sign_up.rs`:

```rust
mod common;

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{extract_input, get_text};

const PASSWORD: &str = "a long enough password";

/// Stops the server when the test ends, even when it fails.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_sign_up_verifies_email_through_the_real_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_starforged");
    let config = tmp.path().join("starforged.toml");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let base = format!("http://127.0.0.1:{port}");
    let init = Command::new(bin)
        .arg("--config")
        .arg(&config)
        .args(["init", "--data-dir"])
        .arg(tmp.path().join("data"))
        .args(["--base-url", &base, "--http-addr", &format!("127.0.0.1:{port}")])
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", String::from_utf8_lossy(&init.stderr));

    let mail_dir = tmp.path().join("mail");
    let child = Command::new(bin)
        .arg("--config")
        .arg(&config)
        .arg("serve")
        .env("STARFORGE__REGISTRATION__MODE", "open")
        .env("STARFORGE__MAIL__URL", format!("file://{}", mail_dir.display()))
        .env("STARFORGE__MAIL__FROM", "Starforge <forge@example.test>")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _server = Server(child);

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut healthy = false;
    for _ in 0..100 {
        let response = client.get(format!("{base}/healthz")).send().await;
        if response.is_ok_and(|r| r.status().is_success()) {
            healthy = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(healthy, "starforged did not become healthy");

    let form = get_text(&client, &format!("{base}/join")).await;
    let csrf = extract_input(&form, "_csrf");
    let joined = client
        .post(format!("{base}/join"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("invite", ""),
            ("handle", "dana"),
            ("email", "dana@example.test"),
            ("display_name", "Dana"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(joined.status(), 200);
    assert!(joined.text().await.unwrap().contains("Check your email"));

    // The server's own job workers deliver the message.
    let mut messages = Vec::new();
    for _ in 0..100 {
        messages = starforged_core::mail::testing::read_mailbox(&mail_dir);
        if !messages.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(messages.len(), 1, "the verification email did not arrive");
    let link = starforged_core::mail::testing::find_link(&messages[0], "/verify/").unwrap();
    assert!(link.starts_with(&base), "{link}");

    let confirm = get_text(&client, &link).await;
    let confirm_csrf = extract_input(&confirm, "_csrf");
    let verified = client
        .post(&link)
        .form(&[("_csrf", confirm_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(verified.status(), 200);

    let login = get_text(&client, &format!("{base}/login")).await;
    let login_csrf = extract_input(&login, "_csrf");
    let signed_in = client
        .post(format!("{base}/login"))
        .form(&[
            ("_csrf", login_csrf.as_str()),
            ("next", "/"),
            ("login", "dana"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), 303);
    assert!(get_text(&client, &format!("{base}/")).await.contains("Your repositories"));
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p starforged --test e2e_sign_up`
Expected: 1 passed. A failure here after Tasks A1–A6 passed means the pieces disagree in the shipped binary (workers not started by `serve`, environment overrides not applied, or a link built from the wrong base URL); fix the cause in the task that owns it rather than in the test.

- [ ] **Step 3: Document accounts and email in `README.md`**

1. In "Run it", the sentence after the commands says to create a token under **Tokens**; it becomes **Settings → Tokens**.
2. Add these rows to the configuration table, after `security.secret_key`:

```markdown
| `registration.mode` | Who can sign up: `invite` (default; invite links only), `open`, or `domains` |
| `registration.allowed_domains` | Email domains that `domains` mode accepts, e.g. `["example.com"]` |
| `mail.url` | Empty for no email; `smtp://user:pass@host:587` (STARTTLS), `smtps://user:pass@host:465`, or `file:///dir` (writes `.eml` files) |
| `mail.from` | Sender, e.g. `Starforge <forge@example.com>` |
```

3. Add this section after "Configuration":

````markdown
## Accounts and email

New instances are invite-only: sign-up needs an invite link from a site admin. Until the admin pages ship, create
accounts with `starforged admin user create`. Set `registration.mode = "open"` to let anyone sign up, or `"domains"`
with `registration.allowed_domains` to accept only addresses at those domains (this mode requires email).

Email is optional. With `[mail]` configured, new accounts confirm their address before they can sign in, the sign-in
page offers "Forgot password?", and invites can be emailed. `smtp://` always uses STARTTLS;
`smtp://localhost:25?tls=none` is accepted only for a mail server on the same machine. Check the settings with:

```bash
./target/release/starforged admin mail test --to you@example.com
```

For local development, `url = "file:///tmp/starforge-mail"` writes each message to that directory instead of sending
it.

Signed-in users manage their display name, email address, password, sessions, and tokens under **Settings**.
````

- [ ] **Step 4: Full check on both databases, commit**

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
git add crates/starforged/tests/e2e_sign_up.rs README.md
git commit -m "test: end-to-end sign-up with email verification; document accounts and email"
```

Expected: fmt, clippy, and the whole suite green on SQLite and Postgres.

---

## Spec coverage (Plan A)

| Forge-basics design | Task |
|---|---|
| §3 `[registration]`, `[mail]`, URL forms, startup validation | A2, A4 |
| §4.1 registration modes, invites | A4 |
| §4.2 email verification, sign-in gating, resend | A3 |
| §4.3 email tokens (lifetimes, single use, newest wins) | A3, A5, A6 |
| §4.4 email throttle | A3 |
| §4.5 password reset | A5 |
| §4.6 account settings (profile, email, password, sessions, tokens) | A6 |
| §4.6 repositories tab, delete account | Plan B |
| §4.7 audit of account events | A3–A6 |
| §7 admin password reset (core), invites (core) | A4, A5 (pages in Plan C) |
| §8 jobs: table, claiming, workers, leases, retries, retention, scheduled cleanup | A1–A4 |
| §8.4 purge of deleted repositories, `git maintenance` after pushes | Plan B |
| §9 mail: templates, blanking, `admin mail test` | A2–A6 |
| §10 routes: sign-up and recovery, account settings | A3–A6 |
| §11 `users.email_verified`, `email_tokens`, `invites`, `jobs` | A1, A3, A4 |
| §12 security notes for accounts | A3–A6 |
| §13 testing: inbox harness, account flows, jobs, end-to-end sign-up | A1–A7 |
