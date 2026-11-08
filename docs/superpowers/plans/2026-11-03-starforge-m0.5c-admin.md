# Starforge M0.5 Plan C (Site Administration) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `/admin` site-administration area: overview, user management, invites, repository oversight (restore/purge-now), and job queue management, all hidden behind a 404 for non-admins.

**Architecture:** Every rule lives in a new `starforged-core/src/admin.rs` (`Core::{admin_list_users, admin_get_user, suspend_user, unsuspend_user, grant_admin, revoke_admin, admin_create_user, admin_delete_user, admin_list_jobs, retry_job, delete_job, admin_deleted_repos, purge_repo_now, admin_overview}`) on top of small new `starforged-db` queries (`users::{list_users, set_is_admin, count}`, `jobs::{list_recent, retry_failed, delete_job, count_by_state}`, `repos::{list_all_deleted, count_all}`); invites and password-reset admin flows are reused as-is (`Core::{create_invite, list_invites, revoke_invite, admin_password_reset}`). `starforged-web` gains a `RequireAdmin` extractor (non-admins get `WebError::NotFound`), one `pages/admin.rs` module, an `admin_nav.html` tabs partial cloned from `settings_nav.html`, and the six `admin_*.html` templates. No schema change, so no new migration.

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8, askama 0.16, sqlx 0.9 (`Any`, SQLite and Postgres).

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-forge-basics-design.md` (forge basics, milestone M0.5). This plan implements §7 (site administration), the admin row of §10, the admin parts of §12–§13. Plans A (foundations/accounts) and B (repositories/code views) are merged. The main spec `docs/superpowers/specs/2026-11-03-starforge-design.md` still applies where the forge-basics design is silent.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide.
- **License:** every crate is `AGPL-3.0-or-later`.
- **Dependencies:** versions exactly as in the root `Cargo.toml` `[workspace.dependencies]` table; crates inherit them with `dep.workspace = true`; internal crates depend on each other by relative path. This plan adds no new dependencies.
- **SQL portability:** every statement in `starforged-db` runs unchanged on SQLite and Postgres: placeholders `$1, $2, …` with each number first appearing in ascending order; integer columns `INTEGER` (SQLite) / `BIGINT` (Postgres) decoded as `i64`; booleans stored as `0`/`1`; timestamps in unix seconds; SQL strings are `'static` literals (no dynamically built SQL).
- **Migrations:** none in this plan. The latest migration is the `0007_repo_deletion` pair; every admin query in this plan reads or updates existing columns, so no `0008` file is added. Never edit an existing migration file.
- **Both engines are tested:** DB-touching tasks use `starforged_db::testing::TestDb` (through `test_core()` or `TestServer`). Tasks that add SQL run `STARFORGE_TEST_PG=1 scripts/check.sh` (podman, Postgres 17) before committing; it must pass on SQLite and Postgres.
- **Error mapping (unchanged):** `starforged-db` returns `DbResult<T>`; `starforged-core` returns `CoreResult<T>`. HTTP layers map `NotFound`→404, `Forbidden`→403, `Unauthenticated`→401, `Invalid`→422 on web forms (re-render with status 422), `Conflict`→422 on web forms.
- **No existence leaks:** the admin area answers 404 to non-admins (anonymous and signed-in alike) via `RequireAdmin` → `WebError::NotFound`, whose page says "That place does not exist, or you do not have access to it." fragment: the exact message in `crates/starforged-web/src/error.rs` is `"That page does not exist, or you do not have access to it."`.
- **Audit actions** (spec §7: every action recorded), with `target` = `user:<handle>` / `repo:<owner>/<name>` / `invite:<id>` / `job:<id>`: new in this plan — `user.suspend`, `user.unsuspend`, `user.grant_admin`, `user.revoke_admin`, `user.create`, `user.delete`, `job.retry`, `job.delete`. Reused — `invite.create`, `invite.revoke`, `user.password_reset_issued`, `repo.restore`, `repo.purge`. An action that changes nothing is not audited.
- **Admin pages** share `templates/admin_nav.html` (tabs: Overview · Users · Invites · Repositories · Jobs, `admin_tab` with `aria-current="page"`, cloned from `templates/settings_nav.html`) and every page struct carries `nav_user: Option<NavUser>, csrf: String, admin_tab: &'static str`.
- **Admin forms** follow post-redirect-get: success answers `303` to the page the row lives on; refused input (`Invalid`, `Conflict`) re-renders the page with the message and status `422`. Every form carries the session's `_csrf` token, checked with `auth::verify_csrf(&session.csrf_token, &form.csrf)` first.
- **HTML:** askama auto-escaping everywhere. No `|safe` in this plan (no Markdown, no highlighted source on admin pages).
- **Tests:** integration tests that start a server use `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`. `TestServer` runs no job workers: tests run queued jobs with `s.core.run_due_jobs().await`. Only `starforged serve` starts workers. Helpers live in `crates/starforged/tests/common/mod.rs`: `TestServer::start()`, `start_with_mail`, `s.user(handle)` (password is `PASSWORD`), `s.login(handle)` → `(client, csrf)`, `s.try_login`, `s.browser()`, `s.url(path)`, `s.repo(owner, name, visibility)`, `extract_input(html, name)`, `get_text(client, url)`, `post_form(client, url, fields)`.
- **Every commit:** `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` pass, and `cargo test --workspace` is green.
- **Decisions this plan makes where the spec is silent:**
  - Admin user search matches handle or email by case-insensitive substring (`LIKE '%' || $1 || '%'`, both sides lowered in Rust first); empty query lists everyone, newest-admins-first is wrong — order is by handle ascending; cap 200 rows.
  - Suspending an already-suspended user (or unsuspending an active one) is `Invalid`, not silent success, so the button always means something.
  - Retrying a failed job re-queues it immediately (`state = 'queued'`, `run_at = now`, attempts kept as history, `locked_until` cleared); only `failed` rows can be retried or deleted.
  - The admin "purge now" button skips the 7-day window but still only purges rows that are actually deleted; a live repository id gets `NotFound`.
  - The admin-created user form requires a password (10–1024 chars, the existing `create_user` rule); the address counts as verified (`email_verified: true`).
  - Admin user deletion mirrors self-service `delete_account` (§4.6): refused while the target owns non-deleted repositories or is the last active admin; purges their deleted repositories at once; audit entry `user.delete` survives with the actor set (the admin), unlike self-deletion which clears the actor.

---

## File Structure

```
crates/starforged-db/
  src/users.rs     + list_users (search, C1); set_is_admin (C1); count (C1)
  src/jobs.rs      + list_recent (C2); retry_failed (C2); delete_job (C2); count_by_state (C2)
  src/repos.rs     + list_all_deleted (C3); count_all (C3)
crates/starforged-core/
  src/admin.rs     NEW: UserSummary, JobInfo, AdminRepo, AdminOverview + every Core::admin_* method (C1, C2, C3)
  src/lib.rs       + `pub mod admin;` (C1)
crates/starforged-web/
  src/auth.rs      + RequireAdmin extractor (C4)
  src/pages/admin.rs  NEW: overview, users, user detail + actions, create user, invites,
                      repositories, jobs handlers (C4–C9)
  src/pages/mod.rs + `pub mod admin;` (C4)
  src/lib.rs       + /admin* routes before /{owner} (C4)
  templates/admin_nav.html       tabs partial (C4)
  templates/admin_overview.html  counts, registration mode, mail status, versions (C4)
  templates/admin_users.html     searchable list (C5)
  templates/admin_user.html      detail + every action form (C5, C6)
  templates/admin_invites.html   create + list w/ status + revoke (C7)
  templates/admin_repos.html     every repository incl. deleted + restore/purge (C8)
  templates/admin_jobs.html      queued/running/failed + retry/delete (C9)
crates/starforged/
  tests/web_admin.rs         overview + 404 sweep + CSRF (C4, C10)
  tests/web_admin_users.rs   list/detail/actions/create/guards (C5, C6, C7)
  tests/web_admin_repos.rs   restore + purge-now (C8)
  tests/web_admin_jobs.rs    retry + delete (C9)
README.md            + site-administration section (C10)
```

---

### Task C1: Core user administration — list, suspend, roles, create, delete

**Files:**
- Modify: `crates/starforged-db/src/users.rs` (`list_users`, `set_is_admin`, `count`)
- Create: `crates/starforged-core/src/admin.rs` (`UserSummary`, guard helpers, `admin_list_users`, `admin_get_user`, `suspend_user`, `unsuspend_user`, `grant_admin`, `revoke_admin`, `admin_create_user`, `admin_delete_user`)
- Modify: `crates/starforged-core/src/lib.rs` (add `pub mod admin;` after the `audit` line)
- Test: core unit tests inside `crates/starforged-core/src/admin.rs` (`#[cfg(test)] mod tests`, using the existing `crate::testing::test_core()` fixture like `account.rs` tests do)

**Interfaces:**
- Consumes: `starforged_db::users::{UserRow, NewUser, by_id, by_handle, set_state, delete, count_active_admins_except}` (exist), `starforged_db::repos::list_by_owner` (exists — live repos only, used by the delete guard), `starforged_db::web_sessions::delete_for_user` (exists — ends every web session), `Core::{create_user, audit, db}` (exist), `CreateUser` (`crates/starforged-core/src/accounts.rs`: `{handle, display_name, email, email_verified, password, is_admin}`), `CoreError::{Forbidden, NotFound, Invalid}` (exist).
- Produces:
  - `starforged_db::users::list_users(db: &Db, query: &str, limit: i64) -> DbResult<Vec<UserRow>>` — `query` already lowercased by the caller; empty query matches all; `ORDER BY handle ASC LIMIT $2`.
  - `starforged_db::users::set_is_admin(db: &Db, id: i64, is_admin: bool) -> DbResult<()>` — stores `0`/`1`.
  - `starforged_db::users::count(db: &Db) -> DbResult<i64>` — `SELECT COUNT(*) FROM users`.
  - `pub struct UserSummary { pub user: User, pub repo_count: i64 }` in `core::admin`.
  - `impl Core` (all take `admin: &User` first and return `Err(CoreError::Forbidden)` when `!admin.is_admin`):
    - `pub async fn admin_list_users(&self, admin: &User, query: &str, limit: i64) -> CoreResult<Vec<User>>`
    - `pub async fn admin_get_user(&self, admin: &User, handle: &str) -> CoreResult<UserSummary>` — `NotFound` for unknown handles; `repo_count` counts live owned repos via `list_by_owner`.
    - `pub async fn suspend_user(&self, admin: &User, target_id: i64) -> CoreResult<User>` — guards (below), then `set_state("suspended")`, `delete_for_user`, audit `user.suspend` with `target = "user:<handle>"`; returns the refreshed user.
    - `pub async fn unsuspend_user(&self, admin: &User, target_id: i64) -> CoreResult<User>` — `set_state("active")`, audit `user.unsuspend`.
    - `pub async fn grant_admin(&self, admin: &User, target_id: i64) -> CoreResult<User>` — `set_is_admin(true)`, audit `user.grant_admin`.
    - `pub async fn revoke_admin(&self, admin: &User, target_id: i64) -> CoreResult<User>` — last-admin guard, then `set_is_admin(false)`, audit `user.revoke_admin`.
    - `pub async fn admin_create_user(&self, admin: &User, input: CreateUser) -> CoreResult<User>` — forces `input.email_verified = true`, delegates to `create_user`, audits `user.create`.
    - `pub async fn admin_delete_user(&self, admin: &User, target_id: i64) -> CoreResult<()>` — §4.6 guards, purges the target's deleted repos via `purge_deleted_repos_of` (same crate), `users::delete`, audits `user.delete`.
  - Guard rule shared by suspend/revoke/delete paths: the last active site admin cannot be demoted, suspended, or deleted — when the target `is_admin && active` and `count_active_admins_except(target_id) == 0`, return `Err(CoreError::Invalid("You are the only site administrator; make another user an administrator first.".into()))` (same message as `delete_account` in `account.rs`). Admins cannot suspend or delete themselves: `admin.id == target_id` → `Err(CoreError::Invalid("You cannot suspend yourself.".into()))` / `Invalid("You cannot delete yourself.".into())`. Demoting yourself when other admins exist is allowed (only the last-admin rule blocks it). Suspending an already-suspended user → `Invalid("The account is already suspended.")`; unsuspending an active user → `Invalid("The account is not suspended.")`.

- [ ] **Step 1: Write the failing db tests**

Add to the existing `#[cfg(test)]` module in `crates/starforged-db/src/users.rs` (follow the file's current test style with `TestDb`):

```rust
#[tokio::test]
async fn list_users_searches_handle_and_email() {
    let db = TestDb::new().await;
    insert(&db, &NewUser { handle: "alice".into(), display_name: "A".into(), email: Some("alice@example.com".into()), email_verified: true, password_hash: None, is_admin: true }).await.unwrap();
    insert(&db, &NewUser { handle: "bob".into(), display_name: "B".into(), email: Some("bob@example.com".into()), email_verified: false, password_hash: None, is_admin: false }).await.unwrap();
    let handles = |rows: Vec<UserRow>| rows.into_iter().map(|r| r.handle).collect::<Vec<_>>();
    assert_eq!(handles(list_users(&db, "", 200).await.unwrap()), vec!["alice", "bob"]);
    assert_eq!(handles(list_users(&db, "ali", 200).await.unwrap()), vec!["alice"]);
    assert_eq!(handles(list_users(&db, "BOB@EXAMPLE", 200).await.unwrap()), vec!["bob"]);
    assert_eq!(count(&db).await.unwrap(), 2);
}
```

- [ ] **Step 2: Run the db test to verify it fails**

Run: `cargo test -p starforged-db users::tests::list_users_searches_handle_and_email`
Expected: FAIL with "cannot find function `list_users`" (and `count`).

- [ ] **Step 3: Implement the db queries**

In `crates/starforged-db/src/users.rs`, next to `set_state`, add (placeholder order ascending; `query` is matched with `LIKE '%' || $1 || '%'` so the caller lowercases it):

```rust
/// All users whose handle or email contains `query` (already lowercased; empty matches all),
/// by handle, at most `limit` rows.
pub async fn list_users(db: &Db, query: &str, limit: i64) -> DbResult<Vec<UserRow>> {
    let rows = sqlx::query(select_user!(
        "WHERE LOWER(o.handle) LIKE '%' || $1 || '%' OR LOWER(u.email) LIKE '%' || $1 || '%' ORDER BY o.handle ASC LIMIT $2"
    ))
    .bind(query)
    .bind(limit)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Sets or clears the site-admin flag (`0`/`1` on both engines).
pub async fn set_is_admin(db: &Db, id: i64, is_admin: bool) -> DbResult<()> {
    sqlx::query("UPDATE users SET is_admin = $1 WHERE id = $2")
        .bind(if is_admin { 1 } else { 0 })
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Total user count, for the admin overview.
pub async fn count(db: &Db) -> DbResult<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(db.pool()).await?)
}
```

Check the file's `select_user!` macro first: it selects `u.id, o.handle, …` joining `owners o` (see lines 32–35). If the alias in the macro is not `o`, use the alias the macro uses. Check `from_row`'s name in the file (`from_row` is assumed from the `jobs.rs` pattern; verify and use the local name).

- [ ] **Step 4: Run the db test to verify it passes**

Run: `cargo test -p starforged-db users::`
Expected: PASS.

- [ ] **Step 5: Write the failing core admin tests**

Create `crates/starforged-core/src/admin.rs` with the types plus tests first. Test style follows `account.rs` tests (`test_core()` fixture, `CreateUser`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::test_core;

    async fn two_admins() -> (Core, User, User) {
        let core = test_core().await;
        let root = core.create_user(CreateUser { handle: "root".into(), password: Some("correct horse battery staple extra".into()), is_admin: true, ..Default::default() }).await.unwrap();
        let vice = core.create_user(CreateUser { handle: "vice".into(), password: Some("correct horse battery staple extra".into()), is_admin: true, ..Default::default() }).await.unwrap();
        (core, root, vice)
    }

    #[tokio::test]
    async fn suspend_ends_sessions_and_last_admin_is_protected() {
        let (core, root, vice) = two_admins().await;
        // Non-admin cannot suspend.
        let bob = core.create_user(CreateUser { handle: "bob".into(), password: Some("correct horse battery staple extra".into()), ..Default::default() }).await.unwrap();
        assert!(matches!(core.suspend_user(&bob, &bob).await, Err(CoreError::Forbidden)));
        // Self-suspend refused.
        assert!(matches!(core.suspend_user(&root, &root.id).await, Err(CoreError::Invalid(_))));
        // Suspend works and ends web sessions.
        let suspended = core.suspend_user(&root, &bob.id).await.unwrap();
        assert!(!suspended.active);
        // Last active admin cannot be suspended: suspend vice first so root is last.
        core.suspend_user(&root, &vice.id).await.unwrap();
        assert!(matches!(core.suspend_user(&root, &root.id).await, Err(CoreError::Invalid(_))));
    }
}
```

Note: `suspend_user` takes `target_id: i64`, so calls are `core.suspend_user(&root, &bob.id)`. Adjust the sketch accordingly (the sketch above already does). Add matching tests for `revoke_admin` (last-admin `Invalid`, self-demote allowed when another admin exists), `grant_admin`, `unsuspend_user` (`Invalid` when active), `admin_create_user` (verified address), and `admin_delete_user` (refused with live repos; refused for last admin; refused for self; purges deleted repos — create a repo for the target, delete it, then admin-delete and assert `deleted_repos` is empty and `user_by_handle` is `NotFound`).

- [ ] **Step 6: Run the core tests to verify they fail**

Run: `cargo test -p starforged-core admin::`
Expected: FAIL — `admin.rs` does not exist yet (`can't find crate for…` / file-not-found at `mod admin`).

- [ ] **Step 7: Implement `core::admin` user methods**

Add `pub mod admin;` to `crates/starforged-core/src/lib.rs`. Implement the methods exactly per the Produces signatures above. Skeleton with the shared guards:

```rust
use starforged_db::{repos as db_repos, users, web_sessions};
use crate::{Core, CoreError, CoreResult};
use crate::accounts::{CreateUser, User};

/// A user plus how many live repositories they own, for the admin detail page.
#[derive(Debug, Clone)]
pub struct UserSummary {
    pub user: User,
    pub repo_count: i64,
}

fn forbidden_unless_admin(admin: &User) -> CoreResult<()> {
    if !admin.is_admin { return Err(CoreError::Forbidden); }
    Ok(())
}

async fn refresh(core: &Core, id: i64) -> CoreResult<User> {
    core.user_by_id(id).await?.ok_or(CoreError::NotFound)
}
```

Check `user_by_id`'s exact return type first: scout says `Core::user_by_id / user_by_handle` are point lookups — verify whether they return `CoreResult<Option<User>>` or `CoreResult<User>` and shape `refresh` to match (if they return `User` with `NotFound` already, `refresh` is just `core.user_by_id(id).await`). Each mutating method audits with `self.audit(Some(admin.id), "<action>", &format!("user:{}", target.handle), "").await?` — verify `audit`'s signature in `audit.rs` (`audit(actor_id: Option<i64>, action: &str, target: &str, detail: &str)`).

`suspend_user`: `forbidden_unless_admin`, load target (`users::by_id` → `User::from`, `None` → `NotFound`), self-check, already-suspended check, last-admin check when target is an active admin, `set_state("suspended")`, `delete_for_user`, audit, return refreshed user. `admin_delete_user`: `forbidden_unless_admin`, load target, self-check, last-admin check, `!db_repos::list_by_owner(db, target.id).is_empty()` → `Invalid("The account still owns repositories.")`-style message, `purge_deleted_repos_of(target.id, Some(admin.id))`, `users::delete`, audit `user.delete`.

- [ ] **Step 8: Run all core + db tests**

Run: `cargo test -p starforged-core -p starforged-db`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p starforged-core -p starforged-db
git add crates/starforged-db/src/users.rs crates/starforged-core/src/admin.rs crates/starforged-core/src/lib.rs
git commit -m "Add core user-administration methods with last-admin guards"
```

---

### Task C2: Core job administration — list, retry, delete

**Files:**
- Modify: `crates/starforged-db/src/jobs.rs` (`list_recent`, `retry_failed`, `delete_job`, `count_by_state`)
- Modify: `crates/starforged-core/src/admin.rs` (`JobInfo`, `admin_list_jobs`, `retry_job`, `delete_job`)
- Test: extend the `#[cfg(test)] mod tests` in `crates/starforged-core/src/admin.rs`; db tests in `crates/starforged-db/src/jobs.rs`

**Interfaces:**
- Consumes: `starforged_db::jobs::{JobRow, by_id}` (exist), `Core::enqueue` (exists — to seed jobs in tests), `now()` (`starforged_db::now`, exists).
- Produces:
  - `starforged_db::jobs::list_recent(db: &Db, limit: i64) -> DbResult<Vec<JobRow>>` — `ORDER BY run_at DESC, id DESC LIMIT $1`; state filtering happens in Rust (no dynamic SQL).
  - `starforged_db::jobs::retry_failed(db: &Db, id: i64, now_ts: i64) -> DbResult<bool>` — `UPDATE jobs SET state = 'queued', run_at = $1, locked_until = NULL, updated_at = $1 WHERE id = $2 AND state = 'failed'`; returns whether a row changed.
  - `starforged_db::jobs::delete_job(db: &Db, id: i64) -> DbResult<bool>` — `DELETE FROM jobs WHERE id = $1 AND state = 'failed'`; returns whether a row was removed.
  - `starforged_db::jobs::count_by_state(db: &Db, state: &str) -> DbResult<i64>` — `SELECT COUNT(*) FROM jobs WHERE state = $1`.
  - `pub struct JobInfo { pub id: i64, pub kind: String, pub state: String, pub attempts: i64, pub last_error: String, pub run_at: i64, pub created_at: i64 }` in `core::admin`.
  - `pub async fn admin_list_jobs(&self, admin: &User) -> CoreResult<Vec<JobInfo>>` — admin-only; queued/running/failed rows only (filter `row.state != "done"` in Rust), newest first, cap 200.
  - `pub async fn retry_job(&self, admin: &User, id: i64) -> CoreResult<()>` — admin-only; `retry_failed(..., now())`, `false` → `NotFound`; audits `job.retry` with `target = "job:<id>"`.
  - `pub async fn delete_job(&self, admin: &User, id: i64) -> CoreResult<()>` — admin-only; `delete_job`, `false` → `NotFound`; audits `job.delete`.

- [ ] **Step 1: Write the failing db tests**

Append to the tests module in `crates/starforged-db/src/jobs.rs`:

```rust
#[tokio::test]
async fn retry_and_delete_only_touch_failed_jobs() {
    let db = TestDb::new().await;
    let now = now();
    let failed = insert(&db, &NewJob { kind: "send_email", payload: "{}", dedupe_key: None, run_at: now }).await.unwrap().unwrap();
    fail(&db, failed, "boom", None).await.unwrap();
    let queued = insert(&db, &NewJob { kind: "send_email", payload: "{}", dedupe_key: None, run_at: now }).await.unwrap().unwrap();
    assert!(!retry_failed(&db, queued, now).await.unwrap());
    assert!(retry_failed(&db, failed, now).await.unwrap());
    assert_eq!(by_id(&db, failed).await.unwrap().unwrap().state, "queued");
    assert!(!delete_job(&db, queued).await.unwrap());
    // Re-fail it, then delete.
    fail(&db, failed, "again", None).await.unwrap();
    assert!(delete_job(&db, failed).await.unwrap());
    assert!(by_id(&db, failed).await.unwrap().is_none());
    assert_eq!(count_by_state(&db, "queued").await.unwrap(), 1);
}
```

Verify `fail`'s exact signature in `jobs.rs` before using it (`fail(id, err, retry_at: Option)` per scout — confirm arg order `(&db, id, err, retry_at)`).

- [ ] **Step 2: Run the db test to verify it fails**

Run: `cargo test -p starforged-db jobs::tests::retry_and_delete_only_touch_failed_jobs`
Expected: FAIL with "cannot find function".

- [ ] **Step 3: Implement the db queries**

```rust
/// The newest jobs first, capped; callers filter states in Rust to keep one static query.
pub async fn list_recent(db: &Db, limit: i64) -> DbResult<Vec<JobRow>> {
    let rows = sqlx::query(select_job!("ORDER BY run_at DESC, id DESC LIMIT $1"))
        .bind(limit)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(from_row).collect()
}

/// Re-queues a failed job now; false when the job is missing or not failed.
pub async fn retry_failed(db: &Db, id: i64, now_ts: i64) -> DbResult<bool> {
    let changed = sqlx::query(
        "UPDATE jobs SET state = 'queued', run_at = $1, locked_until = NULL, updated_at = $1 WHERE id = $2 AND state = 'failed'",
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
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE state = $1").bind(state).fetch_one(db.pool()).await?)
}
```

- [ ] **Step 4: Run the db tests**

Run: `cargo test -p starforged-db jobs::`
Expected: PASS.

- [ ] **Step 5: Write the failing core tests**

In `admin.rs` tests:

```rust
#[tokio::test]
async fn failed_jobs_retry_and_delete() {
    let core = test_core().await;
    let root = core.create_user(CreateUser { handle: "root".into(), password: Some("correct horse battery staple extra".into()), is_admin: true, ..Default::default() }).await.unwrap();
    let bob = core.create_user(CreateUser { handle: "bob".into(), ..Default::default() }).await.unwrap();
    assert!(matches!(core.admin_list_jobs(&bob).await, Err(CoreError::Forbidden)));
    // Seed a failed job directly through the queue.
    let id = core.enqueue(crate::jobs::Job::SendEmail { to: "x@example.com".into(), subject: "s".into(), body: "b".into() }).await.unwrap();
    // …fail it, retry it, delete it (see implementation for the fail path)…
}
```

How to fail a job in a test: check how existing `jobs.rs` core tests force failures (a test-only hook or a mail job with mail off?). Read `crates/starforged-core/src/jobs.rs` tests first and reuse their exact mechanism — e.g. if there is a `Job::FailForTest` variant or if tests call `db::jobs::fail` directly, do that. Keep this step concrete after reading that file; do not invent a helper.

- [ ] **Step 6: Run to verify failure, then implement**

Run: `cargo test -p starforged-core admin::tests::failed_jobs`
Expected: FAIL (no `admin_list_jobs` yet). Then implement `JobInfo` + the three methods in `admin.rs` per Produces.

- [ ] **Step 7: Run tests on both engines**

Run: `cargo test -p starforged-core -p starforged-db` then `STARFORGE_TEST_PG=1 scripts/check.sh`
Expected: PASS on SQLite and Postgres.

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged-db/src/jobs.rs crates/starforged-core/src/admin.rs
git commit -m "Add core job-administration methods"
```

---

### Task C3: Core repository oversight + overview counts

**Files:**
- Modify: `crates/starforged-db/src/repos.rs` (`list_all_deleted`, `count_all`)
- Modify: `crates/starforged-core/src/admin.rs` (`AdminRepo`, `AdminOverview`, `admin_deleted_repos`, `purge_repo_now`, `admin_overview`)
- Test: extend `admin.rs` tests; db tests in `repos.rs`

**Interfaces:**
- Consumes: `starforged_db::repos::{by_id, deleted_before, list_deleted_by_owner}` (exist), `Core::{restore_repo, deleted_repos}` (exist — `restore_repo` already allows site admins), `Core::purge_repo` (`pub(crate)`, exists — `purge_repo(&self, repo: &Repo, actor_id: Option<i64>)`), `Core::{registration, mail_enabled}` (exist), `RegistrationMode::as_str` (exists), `RESTORE_SECS` (exists).
- Produces:
  - `starforged_db::repos::list_all_deleted(db: &Db) -> DbResult<Vec<RepoRow>>` — every soft-deleted repo, most-recently-deleted first, cap 200: `WHERE r.deleted_at IS NOT NULL ORDER BY r.deleted_at DESC LIMIT $1`.
  - `starforged_db::repos::count_all(db: &Db) -> DbResult<i64>` — `SELECT COUNT(*) FROM repos` (live and deleted).
  - `pub struct AdminRepo { pub id: i64, pub owner: String, pub name: String, pub visibility: String, pub archived: bool, pub deleted_at: Option<i64> }` in `core::admin`.
  - `pub async fn admin_deleted_repos(&self, admin: &User) -> CoreResult<Vec<DeletedRepo>>` — admin-only; every deleted repo still in its window (reuse `restorable`), most-recently-deleted first. (`DeletedRepo { id, name, deleted_at, purge_after }` exists in `core::repos`.)
  - `pub async fn purge_repo_now(&self, admin: &User, repo_id: i64) -> CoreResult<()>` — admin-only; `by_id` → `None` or `deleted_at IS NULL` gives `NotFound` (never reveal liveness: both cases are `NotFound`); otherwise `purge_repo(&repo, Some(admin.id))`. The `repo.purge` audit inside `purge_repo` is reused (verify its target format is `repo:<owner>/<name>`).
  - `pub struct AdminOverview { pub user_count: i64, pub repo_count: i64, pub queued_jobs: i64, pub running_jobs: i64, pub failed_jobs: i64, pub registration_mode: String, pub allowed_domains: Vec<String>, pub mail_enabled: bool }` in `core::admin`.
  - `pub async fn admin_overview(&self, admin: &User) -> CoreResult<AdminOverview>` — admin-only; fills counts from `users::count`, `repos::count_all`, `jobs::count_by_state("queued"/"running"/"failed")`, mode via `self.registration().mode.as_str()` (verify `as_str` spelling in `registration.rs`), domains from `self.registration().allowed_domains`, `self.mail_enabled()`.

- [ ] **Step 1: Write the failing db tests**

In `crates/starforged-db/src/repos.rs` tests (follow the file's existing repo-seeding helpers):

```rust
#[tokio::test]
async fn all_deleted_lists_every_owner() {
    // seed two owners each with a deleted repo (set_deleted(Some(now))), assert both appear
    // most-recently-deleted first, and count_all counts live + deleted.
}
```

Write the full test with the file's real helpers after reading its test module.

- [ ] **Step 2: Run to verify failure, implement db queries, re-run**

Run: `cargo test -p starforged-db repos::` → FAIL, then add:

```rust
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

/// Live plus deleted repositories, for the admin overview.
pub async fn count_all(db: &Db) -> DbResult<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM repos").fetch_one(db.pool()).await?)
}
```

Verify `select_repo!`/`from_row` names in `repos.rs` first (scout shows `select_repo!("WHERE …")` and a row mapper; use the file's exact identifiers). Re-run → PASS.

- [ ] **Step 3: Write the failing core tests**

```rust
#[tokio::test]
async fn admins_see_all_deleted_and_purge_now() {
    // root (admin), alice, bob; alice deletes her repo, bob deletes his.
    // admin_deleted_repos(&bob) → Forbidden; (&root) lists both.
    // purge_repo_now(&root, live_id) → NotFound; (&root, alice_deleted) → Ok;
    // after purge, by handle is gone and admin_deleted_repos no longer lists it.
}

#[tokio::test]
async fn overview_counts_everything() {
    // 2 users, 1 repo, one queued + one failed job → AdminOverview matches;
    // registration_mode == "invite"; mail_enabled == false without mail config.
}
```

For the failed job, reuse the exact failure mechanism found in Task C2 Step 5.

- [ ] **Step 4: Run to verify failure, implement, re-run**

Run: `cargo test -p starforged-core admin::` → FAIL. Implement `AdminRepo` (map from `RepoRow`: `archived = row.archived_at.is_some()` — verify `RepoRow`'s field name for the archive column first), `admin_deleted_repos` (filter `restorable(row.deleted_at, now)` — `restorable` is private in `repos.rs`; re-implement the one-line check `deleted_at > now - RESTORE_SECS` in `admin.rs` with a comment citing `RESTORE_SECS`), `purge_repo_now`, `AdminOverview`, `admin_overview`. Note: `admin_deleted_repos` can return `DeletedRepo` (owner-agnostic struct) — the web layer joins owner/name from `AdminRepo`-style data; simpler: return `Vec<AdminRepo>` filtered to restorable rows and let the page show owner/name/state. Decide: return `Vec<AdminRepo>` (id, owner, name, visibility, archived, deleted_at). Update the Produces line accordingly when implementing (keep the decision in the final code; the test asserts owner/name presence).

- [ ] **Step 5: Both engines + commit**

Run: `STARFORGE_TEST_PG=1 scripts/check.sh`
Expected: PASS.

```bash
git add crates/starforged-db/src/repos.rs crates/starforged-core/src/admin.rs
git commit -m "Add core repository oversight and overview counts"
```

---

### Task C4: `RequireAdmin`, admin nav, overview page, routes

**Files:**
- Modify: `crates/starforged-web/src/auth.rs` (`RequireAdmin`)
- Create: `crates/starforged-web/src/pages/admin.rs` (overview handler + shared `AdminPage` bits)
- Modify: `crates/starforged-web/src/pages/mod.rs` (`pub mod admin;`)
- Modify: `crates/starforged-web/src/lib.rs` (admin routes, placed before the `/{owner}` route)
- Create: `templates/admin_nav.html`, `templates/admin_overview.html`
- Test: Create `crates/starforged/tests/web_admin.rs` (overview content + 404 sweep for every `/admin*` path)

**Interfaces:**
- Consumes: `MaybeUser`, `WebSession`, `WebError::NotFound`, `NavUser::from_session` (exist), `Core::admin_overview` + `AdminOverview` (C3), `starforged_git::command::check_version` (exists — `async fn check_version() -> Result<(u32, u32), GitError>`), `env!("CARGO_PKG_VERSION")`.
- Produces:
  - `pub struct RequireAdmin(pub WebSession)` in `auth.rs` with `impl FromRequestParts<AppState>`: `Ok(RequireAdmin(session))` when `session.user.is_admin`, else `Err(WebError::NotFound)`. Model it on `RequireUser` (lines 36–52 of `auth.rs`): anonymous users also get `NotFound` (not a login redirect — spec §12: the admin area answers 404 to non-admins).
  - `templates/admin_nav.html`: copy of `settings_nav.html` with tabs Overview(`/admin`), Users(`/admin/users`), Invites(`/admin/invites`), Repositories(`/admin/repositories`), Jobs(`/admin/jobs`), selected via `admin_tab`.
  - `GET /admin` → `pages::admin::overview`: renders `admin_overview.html` with user/repo/queued/running/failed counts, registration mode + allowed domains (read-only), mail status (`"configured"`/`"not configured"` — never the URL), git version `"2.53"`-style `"major.minor"`, app version.
  - Routes (all in `page_routes()`, before `/{owner}` so the literal `admin` segment wins):
    `GET /admin`, `GET/POST /admin/users`, `POST /admin/users/{handle}/suspend`, `/unsuspend`, `/grant`, `/revoke`, `/delete`, `/reset-password`, `GET/POST /admin/invites`, `POST /admin/invites/{id}/revoke`, `GET /admin/repositories`, `POST /admin/repositories/{id}/restore`, `POST /admin/repositories/{id}/purge`, `GET /admin/jobs`, `POST /admin/jobs/{id}/retry`, `POST /admin/jobs/{id}/delete`. Later tasks add their handlers to `pages/admin.rs` + `lib.rs`; this task wires only `GET /admin` and leaves the rest to those tasks (each later task edits `lib.rs` to add its routes).

- [ ] **Step 1: Write the failing 404 + overview tests**

Create `crates/starforged/tests/web_admin.rs`:

```rust
use common::{TestServer, extract_input, get_text, post_form};
mod common;

async fn admin_client(s: &TestServer) -> (reqwest::Client, String) {
    s.core.create_user(starforged_core::accounts::CreateUser { handle: "root".into(), password: Some(common::PASSWORD.into()), is_admin: true, ..Default::default() }).await.unwrap();
    s.login("root").await
}
```

Check `common::PASSWORD` visibility first (tests use `PASSWORD` directly in-file, e.g. `web_account.rs` line 126 uses `PASSWORD` — verify it is `pub`/`pub(crate)` in `common/mod.rs` and import accordingly). Tests:
  1. `overview_shows_counts_and_config`: admin sees user count `2`, repo count `1`, `registration mode invite`, `mail not configured`, a `git \d+\.\d+` version, and tabs linking `/admin/users`, `/admin/invites`, `/admin/repositories`, `/admin/jobs`.
  2. `admin_pages_404_to_non_admins`: for paths `/admin`, `/admin/users`, `/admin/invites`, `/admin/repositories`, `/admin/jobs` — anonymous `GET` → 404 and signed-in non-admin `GET` → 404 (NOT 302/403). POST actions are covered in their own tasks; include `POST /admin/users` (create) here as the CSRF/404 shape precedent? No — keep this file to GET paths + one POST 404 (`/admin/users/alice/suspend` with no session → 404) to lock the extractor behavior for POSTs.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test web_admin`
Expected: FAIL — no `/admin` route (404 body differs? Actually missing route also 404… assert on the overview content test failing and on the exact error page for 404s: missing routes fall through to the repo-pages 404? `/admin` would hit `/{owner}` with owner=`admin` → renders repo-not-found 404, which coincidentally is `WebError::NotFound` with the same message. So the 404 sweep may pass vacuously; the overview content test fails. That is fine — the failing test is the content one. Note this explicitly in the commit.)

- [ ] **Step 3: Implement `RequireAdmin`, overview handler, templates, route**

In `auth.rs`, after `RequireUser`'s impl:

```rust
/// A site administrator. Anyone else — anonymous or signed-in — gets `NotFound`,
/// so the admin area is indistinguishable from a missing page (spec §12).
pub struct RequireAdmin(pub WebSession);

impl FromRequestParts<AppState> for RequireAdmin {
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, WebError> {
        let session = MaybeUser::from_request_parts(parts, state).await?.0;
        match session {
            Some(session) if session.user.is_admin => Ok(RequireAdmin(session)),
            _ => Err(WebError::NotFound),
        }
    }
}
```

Verify `MaybeUser`'s `from_request_parts` signature and `AppState`/`Parts` imports by copying the `RequireUser` impl exactly (auth.rs lines 39–52). `pages/admin.rs`:

```rust
use askama::Template;
use axum::response::Redirect;
use crate::{AppState, auth::RequireAdmin, error::WebError, views::NavUser};
use starforged_core::admin::AdminOverview;

#[derive(Template)]
#[template(path = "admin_overview.html")]
struct OverviewPage {
    nav_user: Option<NavUser>,
    csrf: String,
    admin_tab: &'static str,
    overview: AdminOverview,
    git_version: String,
    app_version: &'static str,
}

pub async fn overview(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
) -> Result<OverviewPage, WebError> {
    let overview = state.core.admin_overview(&session.user).await?;
    let (major, minor) = starforged_git::command::check_version().await.map_err(|e| WebError::Internal(e.to_string()))?;
    Ok(OverviewPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "overview",
        overview,
        git_version: format!("{major}.{minor}"),
        app_version: env!("CARGO_PKG_VERSION"),
    })
}
```

Check `NavUser::from_session` takes `&session` (settings.rs line 123: `NavUser::from_session(session)` — takes what? verify `&WebSession` vs `WebSession`; match the call site). Check `starforged-web` depends on `starforged-git` (it does — Plan B: highlight/githttp; `starforged_git::command` usable). If `check_version` fails (git missing), overview 500s — acceptable: startup already gates on it (`serve.rs` runs `check_version()` gate), and tests always have git.

`admin_overview.html`:

```html
{% extends "base.html" %}
{% block title %}Site administration{% endblock %}
{% block content %}
<h1>Site administration</h1>
{% include "admin_nav.html" %}
<section>
  <h2>Overview</h2>
  <dl>
    <dt>Users</dt><dd>{{ overview.user_count }}</dd>
    <dt>Repositories</dt><dd>{{ overview.repo_count }}</dd>
    <dt>Queued jobs</dt><dd>{{ overview.queued_jobs }}</dd>
    <dt>Running jobs</dt><dd>{{ overview.running_jobs }}</dd>
    <dt>Failed jobs</dt><dd>{{ overview.failed_jobs }}</dd>
    <dt>Registration mode</dt><dd>{{ overview.registration_mode }}</dd>
    {% if overview.allowed_domains.len() > 0 %}
    <dt>Allowed domains</dt><dd>{{ overview.allowed_domains|join(", ") }}</dd>
    {% endif %}
    <dt>Email</dt><dd>{% if overview.mail_enabled %}configured{% else %}not configured{% endif %}</dd>
    <dt>Git version</dt><dd>{{ git_version }}</dd>
    <dt>Starforge version</dt><dd>{{ app_version }}</dd>
  </dl>
</section>
{% endblock %}
```

Verify askama `join` filter availability (`{{ x|join(", ") }}` — askama has a `join` filter; if unsure, loop instead — safer: use `{% for d in overview.allowed_domains %}{{ d }}{% if !loop.last %}, {% endif %}{% endfor %}`). Use the loop form to avoid filter uncertainty. Also verify `base.html` block names (`title`, `content` — confirmed via scout) and that `nav_user`/`csrf` fields are expected by `base.html` (settings pages pass `nav_user`; check how `base.html` consumes `csrf` — the sign-out form needs it; mirror a settings template's struct fields exactly).

Route in `lib.rs` before `/{owner}`:

```rust
.route("/admin", get(pages::admin::overview))
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --test web_admin`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --test web_admin
git add crates/starforged-web/src/auth.rs crates/starforged-web/src/pages/admin.rs crates/starforged-web/src/pages/mod.rs crates/starforged-web/src/lib.rs crates/starforged-web/templates/admin_nav.html crates/starforged-web/templates/admin_overview.html crates/starforged/tests/web_admin.rs
git commit -m "Add RequireAdmin, admin nav, and overview page"
```

---

### Task C5: Users list + detail pages

**Files:**
- Modify: `crates/starforged-web/src/pages/admin.rs` (list + detail handlers)
- Modify: `crates/starforged-web/src/lib.rs` (`GET /admin/users`, `GET /admin/users/{handle}`)
- Create: `templates/admin_users.html`, `templates/admin_user.html` (detail shows user fields + empty action forms; C6 wires the POST targets)
- Test: Create `crates/starforged/tests/web_admin_users.rs`

**Interfaces:**
- Consumes: `Core::{admin_list_users, admin_get_user}` + `UserSummary` (C1), `RequireAdmin`, `verify_csrf` (for later forms — not this task), `format_time` (`views::format_time`, exists — check its signature; settings email page uses it).
- Produces:
  - `GET /admin/users?q=<query>` → `pages::admin::users`: search box (GET form, keeps `q`), table handle / email / admin badge / state / actions link. Empty state: "No users match."
  - `GET /admin/users/{handle}` → `pages::admin::user_detail`: handle (lowercased before lookup), display name, email + verified flag, admin flag, state, live repo count; suspend/unsuspend button (label depends on state), grant/revoke button (label depends on `is_admin`), delete form (confirm = handle), reset-password form. Each form posts to its C6 route with `_csrf`. Unknown handle → 404 (from `CoreError::NotFound` → `WebError::NotFound`).

- [ ] **Step 1: Write the failing tests**

In `web_admin_users.rs` (helpers: `root_client` creating an admin + `login`, as in C4):

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_list_searches_and_detail_shows_state() {
    let s = TestServer::start().await;
    let (client, _) = root_client(&s).await;
    s.user("alice").await;
    let list = get_text(&client, &s.url("/admin/users")).await;
    assert!(list.contains("/admin/users/alice"), "{list}");
    assert!(list.contains("/admin/users/root"), "{list}");
    let searched = get_text(&client, &s.url("/admin/users?q=ali")).await;
    assert!(searched.contains("/admin/users/alice"), "{searched}");
    assert!(!searched.contains("/admin/users/root"), "{searched}");
    let detail = get_text(&client, &s.url("/admin/users/alice")).await;
    assert!(detail.contains("alice"), "{detail}");
    assert!(detail.contains("action=\"/admin/users/alice/suspend\""), "{detail}");
    let missing = client.get(s.url("/admin/users/nobody")).send().await.unwrap();
    assert_eq!(missing.status(), 404);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test web_admin_users`
Expected: FAIL — routes/handlers missing (404 on `/admin/users` or compile error on missing handler — either way red).

- [ ] **Step 3: Implement handlers + templates + routes**

```rust
#[derive(Template)]
#[template(path = "admin_users.html")]
struct UsersPage {
    nav_user: Option<NavUser>,
    csrf: String,
    admin_tab: &'static str,
    query: String,
    users: Vec<User>,
}

pub async fn users(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<ListParams>,
) -> Result<UsersPage, WebError> { ... }
```

Use `axum::extract::Query` with `#[derive(serde::Deserialize)] struct ListParams { q: Option<String> }`. `admin_list_users(&session.user, &q.to_lowercase(), 200)`. Detail handler extracts `Path<String>`, lowercases, calls `admin_get_user`. Templates mirror `settings_*.html` structure (check one settings template for the `base.html` extension + nav_user usage pattern). Detail page must already contain the exact form actions C6 will serve (`/admin/users/alice/suspend`, `/unsuspend`, `/grant`, `/revoke`, `/delete`, `/reset-password`) with `_csrf` hidden inputs — the test above asserts the suspend action exists now.

- [ ] **Step 4: Run tests**

Run: `cargo test --test web_admin_users`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged-web/src/pages/admin.rs crates/starforged-web/src/lib.rs crates/starforged-web/templates/admin_users.html crates/starforged-web/templates/admin_user.html crates/starforged/tests/web_admin_users.rs
git commit -m "Add admin users list and detail pages"
```

---

### Task C6: User action POSTs — suspend, roles, delete, reset

**Files:**
- Modify: `crates/starforged-web/src/pages/admin.rs` (six POST handlers + re-render helper)
- Modify: `crates/starforged-web/src/lib.rs` (six POST routes)
- Modify: `templates/admin_user.html` (result/notice rendering — already has forms from C5)
- Test: extend `crates/starforged/tests/web_admin_users.rs`

**Interfaces:**
- Consumes: `Core::{suspend_user, unsuspend_user, grant_admin, revoke_admin, admin_delete_user, admin_password_reset, user_by_handle}` (C1 + existing), `AdminReset::{Emailed, Link}` (exists), `verify_csrf`, `WebError::BadRequest`.
- Produces:
  - `POST /admin/users/{handle}/suspend` → suspend; success 303 to `/admin/users/{handle}`. Suspended user's sessions end: assert in test that `s.try_login("bob", PASSWORD)` still 303? No — suspended users cannot sign in at all (`authenticate_password` rejects suspended → `Unauthenticated` → 401). Assert 401 after suspend, 303 after unsuspend.
  - `POST /unsuspend`, `/grant` (303 to detail), `/revoke`, `/delete` (303 to `/admin/users` on success — detail page is gone), `/reset-password` (re-renders detail with 200 showing either "A reset link was emailed to …" or the one-time link `/reset/<token>`; without mail and without address → still a Link, since `admin_password_reset` falls back to Link).
  - Failure shape: `Invalid`/`Conflict`/`NotFound` from core re-renders `admin_user.html` with `error: Option<String>` and status 422 (mirror `repo_settings::finish` post-redirect-get semantics from Plan B). `Forbidden` cannot happen (RequireAdmin already gated).
  - Guard tests: last admin cannot be demoted/suspended/deleted (`Invalid` → detail re-rendered 422 with "only site administrator"); self-suspend/self-delete refused; deleting a user who owns a live repo refused; deleting removes the account (`user_by_handle` → `NotFound`, sign-in 401).

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspend_unsuspend_ends_sessions_and_blocks_sign_in() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    s.user("bob").await;
    let before = post_form(&admin, &s.url("/admin/users/bob/suspend"), &[("_csrf", csrf.as_str())]).await;
    assert_eq!(before.status(), 303);
    assert_eq!(s.try_login("bob", PASSWORD).await.1.status(), 401);
    let (admin2, csrf2) = s.login("root").await;
    let back = post_form(&admin2, &s.url("/admin/users/bob/unsuspend"), &[("_csrf", csrf2.as_str())]).await;
    assert_eq!(back.status(), 303);
    assert_eq!(s.try_login("bob", PASSWORD).await.1.status(), 303);
}
```

Verify `post_form`'s exact signature/return in `common/mod.rs` before use (it returns `reqwest::Response`; existing tests call `post_form(&client, &url, &[...])` then check `.status()`). Add tests: `grant_and_revoke_admin` (bob becomes admin: his browser can GET /admin → 200; revoked → 404), `last_admin_guards` (single-admin instance: revoke/suspend/delete self → 422 + message; make bob second admin, then root can demote self), `delete_user_rules` (owns repo → 422; after deleting repo… repos deleted by owner are soft-deleted — rule is "owns non-deleted repositories", so deleting the repo first allows admin delete; assert deleted repos purged + sign-in 401), `reset_password_shows_link_without_mail` (detail shows `/reset/` link; submitting it via `submit_reset`-style POST works — copy the helper from `web_password_reset.rs` or reuse flow: GET link → 200 form → POST new password → 200 → login 303).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test web_admin_users`
Expected: FAIL — POST routes missing (404, not 303).

- [ ] **Step 3: Implement the six handlers**

Shared helper (modeled on `repo_settings::finish`):

```rust
async fn user_action(
    state: &AppState,
    session: &WebSession,
    handle: &str,
    result: CoreResult<()>,
    success_to: String,
) -> Result<Response, WebError> { ... }
```

Simpler and explicit: each handler calls `verify_csrf` first, lowercases the handle, matches on the core result: `Ok(_) => Ok(Redirect::to(...).into_response())`, `Err(CoreError::NotFound) => Err(WebError::NotFound)`, `Err(CoreError::Invalid(m)) | Err(CoreError::Conflict(m)) => Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_page_with_error(...).await?).into_response())`. Detail page rendering shared via `fn detail_page(state, session, handle, error: Option<String>, notice: Option<String>)`. Reset-password success renders detail 200 with `notice` = link or emailed message (the link must be shown once — it is, since it only appears in this response). Delete success → 303 to `/admin/users`.

Check imports: `axum::http::StatusCode`, `axum::response::{IntoResponse, Redirect, Response}`.

- [ ] **Step 4: Run tests**

Run: `cargo test --test web_admin_users`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged-web/src/pages/admin.rs crates/starforged-web/src/lib.rs crates/starforged-web/templates/admin_user.html crates/starforged/tests/web_admin_users.rs
git commit -m "Add admin user actions with last-admin guards"
```

---

### Task C7: Create-user-direct + invites page

**Files:**
- Modify: `crates/starforged-web/src/pages/admin.rs` (create-user GET form handling on `/admin/users` POST; invites handlers)
- Modify: `crates/starforged-web/src/lib.rs` (`POST /admin/users`, `GET/POST /admin/invites`, `POST /admin/invites/{id}/revoke`)
- Create: `templates/admin_invites.html`
- Modify: `templates/admin_users.html` (creation form at top, posts to `/admin/users`)
- Test: extend `crates/starforged/tests/web_admin_users.rs` (create-user) + extend `web_admin.rs`? No — create `crates/starforged/tests/web_admin_invites.rs`? Cheaper: put invite tests in `web_admin_users.rs`? Wrong file. Create `web_admin_invites.rs` — small file, fine. Actually to limit file sprawl, put create-user tests in `web_admin_users.rs` and invites tests in the same new `web_admin_invites.rs`.

**Interfaces:**
- Consumes: `Core::{admin_create_user, create_invite, list_invites, revoke_invite}` (C1 + existing), `InviteInfo { id, email, created_at, expires_at, status… }` (verify exact `InviteInfo` fields + `InviteStatus` variants `Pending/Used/Expired/Revoked` in `invites.rs` lines 12–47 before rendering status), `CreatedInvite { id, link, emailed }` (exists).
- Produces:
  - `POST /admin/users` (create): fields `handle, display_name, email, password, admin checkbox ("on"/missing), _csrf`. Success → 303 to `/admin/users/{handle}`. Failures (`Invalid`/`Conflict`) re-render `admin_users.html` 422 with the message; the spec's "or invite them instead" is a link to `/admin/invites` next to the form.
  - `GET /admin/invites`: creation form (optional `email`) + table id/email/status/created/expiry + revoke button per pending row + a "shown once" area. Status text exactly `pending`/`used`/`expired`/`revoked` (lowercase, from `InviteStatus`).
  - `POST /admin/invites`: creates; re-renders 200 with the one-time link (`CreatedInvite.link`) plus "emailed" note when `emailed`. The full link is shown (path on this server) — copy how `join.rs` or existing invite display works; simplest: render `link` string as-is in a `<code>` block.
  - `POST /admin/invites/{id}/revoke`: 303 to `/admin/invites`; unknown/used/revoked → 404 (core returns `NotFound`).

- [ ] **Step 1: Write the failing tests**

Create-user (append to `web_admin_users.rs`):

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admins_create_users_directly_with_verified_addresses() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let created = post_form(&admin, &s.url("/admin/users"), &[("_csrf", csrf.as_str()), ("handle", "carol"), ("display_name", "Carol"), ("email", "carol@example.com"), ("password", "correct horse battery staple extra"), ("admin", "on")]).await;
    assert_eq!(created.status(), 303);
    assert_eq!(created.headers().get("location").unwrap(), "/admin/users/carol");
    let carol = s.core.user_by_handle("carol").await.unwrap();
    assert!(carol.email_verified && carol.is_admin);
    let dup = post_form(&admin, &s.url("/admin/users"), &[/* same handle */]).await;
    assert_eq!(dup.status(), 422);
}
```

Verify `user_by_handle` return shape (`CoreResult<Option<User>>` vs `User`) before asserting. Invites (`web_admin_invites.rs`): create without email → link shown once containing `/join?invite=`; create with email → row shows address + `pending`; revoke → row shows `revoked`, second revoke → 404; non-admin GET → 404.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test web_admin_users --test web_admin_invites`
Expected: FAIL — routes missing.

- [ ] **Step 3: Implement handlers + template + routes**

Create form struct:

```rust
#[derive(serde::Deserialize)]
struct CreateUserForm {
    #[serde(rename = "_csrf")] csrf: String,
    handle: String,
    display_name: String,
    email: String,
    password: String,
    admin: Option<String>, // checkbox: Some("on") when ticked
}
```

Empty email string → `None`. `admin: form.admin.is_some()`. Invites list needs `InviteStatus` → display string: verify whether `InviteStatus` has a `Display`/helper or match variants in the handler (`Pending => "pending"` …). Check `invites.rs` before writing.

- [ ] **Step 4: Run tests**

Run: `cargo test --test web_admin_users --test web_admin_invites`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged-web/src/pages/admin.rs crates/starforged-web/src/lib.rs crates/starforged-web/templates/admin_users.html crates/starforged-web/templates/admin_invites.html crates/starforged/tests/web_admin_users.rs crates/starforged/tests/web_admin_invites.rs
git commit -m "Add admin user creation and invites pages"
```

---

### Task C8: Repositories page — restore + purge-now

**Files:**
- Modify: `crates/starforged-web/src/pages/admin.rs` (repos handlers)
- Modify: `crates/starforged-web/src/lib.rs` (`GET /admin/repositories`, `POST /admin/repositories/{id}/restore`, `POST /…/purge`)
- Create: `templates/admin_repos.html`
- Test: Create `crates/starforged/tests/web_admin_repos.rs`

**Interfaces:**
- Consumes: `Core::{admin_deleted_repos→Vec<AdminRepo> (C3 decision), restore_repo, purge_repo_now}` (C3 + existing), plus a live-repo listing for the "every repository" requirement: spec says the page shows *every* repository including private and deleted ones. `admin_deleted_repos` covers deleted; for live ones there is no site-wide list query. Add to this task (not C3): `starforged_db::repos::list_all_live(db, limit)` — `WHERE r.deleted_at IS NULL ORDER BY r.owner… ` wait, need owner handle ordering: check `select_repo!` columns (`owner_handle` exists per scout's `RepoRow { owner_handle, … }`). Order `ORDER BY o.handle ASC, r.name ASC`? Verify the owner-table alias in `select_repo!` first. Hmm — alternative without new query: none exists. So Produces adds:
  - `starforged_db::repos::list_all_live(db: &Db, limit: i64) -> DbResult<Vec<RepoRow>>`
  - `Core::admin_all_repos(admin) -> CoreResult<Vec<AdminRepo>>` (live, owner/name ordered) — page concatenates live + deleted sections.
- Produces (web):
  - `GET /admin/repositories`: two sections — every live repo (owner/name link, visibility, archived badge) and deleted section (owner/name, deleted date via `format_time`, restore + purge-now forms). Non-deleted rows have no buttons.
  - `POST /admin/repositories/{id}/restore` → 303 to `/admin/repositories`; past-window/missing → 404.
  - `POST /admin/repositories/{id}/purge` → 303 to `/admin/repositories`; live/missing → 404. Purge removes the directory: test asserts the repo dir is gone from `s.data`? `TestServer.data` is the tempdir; repos live under `<data>/repos/<id>.git` (verify layout via `repos_dir` in `Config`/common setup before asserting). Simpler robust assertion: `admin_deleted_repos` no longer lists it + page no longer lists it + git clone 404s. Use those; skip filesystem assertions.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleted_repos_restore_and_purge_now() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    // Private repos are visible to admins.
    let page = get_text(&admin, &s.url("/admin/repositories")).await;
    assert!(page.contains("alice/pro j".replace(' ', "").as_str()) ...);
```

Write plainly: `assert!(page.contains("alice/proj"), "{page}")`. Then `POST /admin/repositories/{id}/delete`? No — deletion happens as the owner via existing `/{owner}/{repo}/settings` delete (Plan B). Steps: owner deletes via existing settings POST (copy the confirm form usage from `web_repo_delete.rs`/`web_account_delete.rs` — read one to copy exact field names), assert repo 404s publicly; admin page shows it in deleted section with restore + purge forms; restore → 303 → repo page 200 again; delete again → purge → 303 → gone from admin list; purge of live repo → 404; non-admin GET → 404.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test web_admin_repos`
Expected: FAIL.

- [ ] **Step 3: Implement db query + core method + handlers + template**

`list_all_live`, `admin_all_repos`, handlers mirroring C6's 303/404 shape (restore/purge have no `Invalid` path — only `NotFound` → 404; CSRF failures → 403 via `verify_csrf`? check `verify_csrf` error mapping: returns `Err(WebError)` — which variant? auth.rs line 65: `verify_csrf(...) -> Result<(), WebError>`; check what it returns on mismatch (likely `Forbidden`). Fine — mismatched CSRF is 403, consistent with the rest of the app.)

- [ ] **Step 4: Run tests**

Run: `cargo test --test web_admin_repos`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged-db/src/repos.rs crates/starforged-core/src/admin.rs crates/starforged-web/src/pages/admin.rs crates/starforged-web/src/lib.rs crates/starforged-web/templates/admin_repos.html crates/starforged/tests/web_admin_repos.rs
git commit -m "Add admin repositories page with restore and purge-now"
```

---

### Task C9: Jobs page — retry + delete

**Files:**
- Modify: `crates/starforged-web/src/pages/admin.rs` (jobs handlers)
- Modify: `crates/starforged-web/src/lib.rs` (`GET /admin/jobs`, `POST /admin/jobs/{id}/retry`, `POST /admin/jobs/{id}/delete`)
- Create: `templates/admin_jobs.html`
- Test: Create `crates/starforged/tests/web_admin_jobs.rs`

**Interfaces:**
- Consumes: `Core::{admin_list_jobs, retry_job, delete_job}` + `JobInfo` (C2), `format_time` for `run_at`/`created_at`.
- Produces:
  - `GET /admin/jobs`: table kind / state / attempts / last error (truncated to 200 chars in the template — do the truncation in the handler into a display field to keep template logic trivial) / run-at + retry/delete buttons only on `failed` rows.
  - `POST /admin/jobs/{id}/retry` → 303 to `/admin/jobs`; non-failed/missing → 404. `POST /…/delete` same.
  - Payloads are never rendered (mail bodies hold secrets; `payload` is excluded from `JobInfo` by design).

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_jobs_retry_and_delete_from_the_page() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    // Seed a failed job (same mechanism as C2 core test), capture its id via admin_list_jobs.
    let jobs = s.core.admin_list_jobs(&root_user).await.unwrap();
    ...
    // Retry → 303 → row shows queued; delete a failed one → 303 → row gone;
    // retry of a queued job → 404; non-admin GET → 404.
}
```

To seed from the integration test: enqueue via `s.core.enqueue(Job::SendEmail{…})` then fail it — how? If C2's mechanism needs db access, integration tests can use `starforged_db::jobs::fail(s.core.db(), …)`? Check `Core::db()` visibility (`self.db()` used inside core — is there a public accessor? `test_core` fixture may expose it; otherwise seed through the public path the C2 test uses). Resolve during implementation; the test must use only public APIs. Fallback public path: enqueue a `SendEmail` with mail unconfigured? `execute` of SendEmail without mailer — does it fail or succeed? Read `jobs.rs execute` before writing; if unconfigured mail fails the job, then `run_due_jobs` 5 times produces a `failed` row with attempts exhausted — slow but public. Prefer whatever C2's core test does; if it calls a crate-private helper, expose the seeding differently: e.g. core test helper `#[cfg(test)]` vs integration — integration cannot use it. Safest: check `execute(SendEmail)` behavior with `mailer: None`; if it errors, loop `run_due_jobs` until `failed` (5 attempts, fast in-process). Confirm by reading `jobs.rs` first.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test web_admin_jobs`
Expected: FAIL.

- [ ] **Step 3: Implement handlers + template + routes**

Mirror C6/C8 shapes. Last-error truncation in handler:

```rust
fn short_error(info: &JobInfo) -> String {
    const MAX: usize = 200;
    if info.last_error.len() > MAX { format!("{}…", &info.last_error[..MAX]) } else { info.last_error.clone() }
}
```

Careful with char boundaries: use `info.last_error.chars().take(200).collect()`. (Never slice mid-char.)

- [ ] **Step 4: Run tests**

Run: `cargo test --test web_admin_jobs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged-web/src/pages/admin.rs crates/starforged-web/src/lib.rs crates/starforged-web/templates/admin_jobs.html crates/starforged/tests/web_admin_jobs.rs
git commit -m "Add admin jobs page with retry and delete"
```

---

### Task C10: 404 sweep, CSRF test, README

**Files:**
- Modify: `crates/starforged/tests/web_admin.rs` (full POST-action 404 sweep + forged-CSRF test)
- Modify: `README.md` (site-administration section)
- Test: the sweep itself

**Interfaces:**
- Consumes: all `/admin*` routes (C4–C9), `WebError::NotFound` page text.
- Produces:
  - Every POST action returns 404 for anonymous and for signed-in non-admin clients: `/admin/users` (create), `/admin/users/bob/suspend`, `/unsuspend`, `/grant`, `/revoke`, `/delete`, `/reset-password`, `/admin/invites`, `/admin/invites/1/revoke`, `/admin/repositories/1/restore`, `/…/purge`, `/admin/jobs/1/retry`, `/admin/jobs/1/delete`. One parameterized test loops the paths (POST with empty form; anonymous browser + bob's browser; assert 404 each). Note: for actions needing valid CSRF, non-admins are rejected by `RequireAdmin` before CSRF is checked — 404 regardless.
  - Forged CSRF: admin POST with `_csrf=forged` to `/admin/users/bob/suspend` → 403 (or whatever `verify_csrf` failure maps to — verify the mapping first and assert exactly that).
  - README gains a "Site administration" section: `/admin` overview/users/invites/repositories/jobs, admin-only 404, last-admin/self guards, audit. Keep to ~15 lines; check README's existing structure first and match its voice.

- [ ] **Step 1: Write the failing sweep test**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_admin_action_404s_to_non_admins() {
    let s = TestServer::start().await;
    let anon = s.browser();
    s.user("bob").await;
    let (bob, _) = s.login("bob").await;
    let posts = [
        "/admin/users",
        "/admin/users/bob/suspend", "/admin/users/bob/unsuspend",
        "/admin/users/bob/grant", "/admin/users/bob/revoke",
        "/admin/users/bob/delete", "/admin/users/bob/reset-password",
        "/admin/invites", "/admin/invites/1/revoke",
        "/admin/repositories/1/restore", "/admin/repositories/1/purge",
        "/admin/jobs/1/retry", "/admin/jobs/1/delete",
    ];
    for path in posts {
        for client in [&anon, &bob] {
            let response = client.post(s.url(path)).form(&[("_csrf", "x")]).send().await.unwrap();
            assert_eq!(response.status(), 404, "{path}");
        }
    }
}
```

- [ ] **Step 2: Run to verify it passes already (it should)**

Run: `cargo test --test web_admin`
Expected: PASS — `RequireAdmin` was correct from C4. If any path is not 404, fix `admin.rs`/`lib.rs` now (that is the point of the sweep).

- [ ] **Step 3: Add the forged-CSRF test + README section**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_forms_reject_forged_csrf() {
    let s = TestServer::start().await;
    let (admin, _) = root_client(&s).await;
    s.user("bob").await;
    let forged = admin.post(s.url("/admin/users/bob/suspend")).form(&[("_csrf", "forged")]).send().await.unwrap();
    assert_eq!(forged.status(), 403);
}
```

Confirm 403 vs actual `verify_csrf` mapping before finalizing (read `auth.rs` `verify_csrf` error return). README section after reading its layout.

- [ ] **Step 4: Full verification on both engines**

Run: `STARFORGE_TEST_PG=1 scripts/check.sh`
Expected: PASS (fmt, clippy, all tests, SQLite + Postgres).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged/tests/web_admin.rs README.md
git commit -m "Cover admin 404 sweep and document site administration"
```

---

## Self-Review

**1. Spec coverage.** §7 table rows: Overview → C3 (counts) + C4 (page). Users (searchable list → C5; suspend/unsuspend ending sessions → C1 + C6; grant/revoke → C1 + C6; reset by email or shown link → passwords reuse + C6; delete per §4.6 → C1 + C6; create verified or invite → C7). Invites (create optional-email, list w/ four statuses, revoke → C7 on reused core). Repositories (all incl. private+deleted → C8; restore → existing `restore_repo` + C8; purge-now → C3 + C8). Jobs (queued/running/failed + attempts + last error → C2 + C9; retry/delete failed → C2 + C9). Guards (last admin, self, audit, CSRF, 404) → C1 + C4 + C6 + C10. §10 admin routes → C4 (overview route) + C5–C9 (one route task each). §11: no new tables (no migration — verified latest is `0007`). §12: 404 to non-admins (C4 + C10 sweep), CSRF on every form (C5–C9 forms + C10 forged test), suspension ends sessions (C1 + C6 test), secrets never rendered (payload excluded from `JobInfo`, C9). §13 admin bullets: 404s (C4 + C10) and last-admin guards (C1 + C6). §14: plan saved here; execution is the orchestrator's next step.

**2. Placeholder scan.** No TBD/TODO; every step names exact files, function signatures, SQL, template fields, commands, and expected outcomes. Two deliberate read-first points are flagged inline (C2 Step 5's failure mechanism, C9 Step 1's seeding path) with instructions to reuse the exact existing mechanism rather than invent one.

**3. Type consistency.** `User`/`CreateUser`/`CoreError`/`InviteInfo`/`CreatedInvite`/`AdminReset`/`DeletedRepo`/`JobRow`/`RepoRow`/`RequireUser`/`MaybeUser`/`verify_csrf`/`WebError::NotFound`/`check_version`/`audit`/`delete_for_user`/`count_active_admins_except`/`list_deleted_by_owner`/`purge_repo(pub(crate))` all verified against the tree on 2026-11-03. New names (`admin.rs` items, `list_users`, `set_is_admin`, `count`, `list_recent`, `retry_failed`, `delete_job`, `count_by_state`, `list_all_deleted`, `count_all`, `list_all_live`, `RequireAdmin`, `AdminRepo`, `JobInfo`, `AdminOverview`, `UserSummary`) are introduced exactly once, in the task that creates them, and consumed with identical spellings downstream.

| Spec requirement | Task |
|---|---|
| §7 Overview (user/repo/queued+failed counts; registration mode + mail read-only; git version) | C3, C4 |
| §7 Users list (searchable) + detail | C1, C5 |
| §7 Suspend/unsuspend (ends web sessions; tokens already stop) | C1, C6 |
| §7 Grant/revoke admin | C1, C6 |
| §7 Password reset (emailed vs shown 24h link) | C6 (reuses `admin_password_reset`) |
| §7 Delete user (§4.6 rules) | C1, C6 |
| §7 Create-user-direct (verified) or invite | C7 |
| §7 Invites (create optional-email; pending/used/expired/revoked; revoke) | C7 (reuses invite core) |
| §7 Repositories (all incl. private+deleted; restore; purge-now) | C3, C8 |
| §7 Jobs (queued/running/failed + attempts + last error; retry/delete failed) | C2, C9 |
| §7 Guards (last admin; no self suspend/delete; audit; CSRF; 404) | C1, C4, C6, C10 |
| §10 Admin routes (`/admin`, `/users`, `/users/{handle}`, `/invites`, `/repositories`, `/jobs` + POST actions) | C4, C5, C6, C7, C8, C9 |
| §13 Admin tests (404s; last-admin guards) | C4, C6, C10 |
| README/docs touch-up | C10 |
