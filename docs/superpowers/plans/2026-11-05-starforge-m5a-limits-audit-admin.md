# Starforge M5a (Abuse controls, audit log UI, site-admin completeness) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- **§11.6 abuse controls,** all configurable:
  - login attempts: 10 per minute per IP and 20 per hour per account;
  - API requests: 5,000 per hour per token;
  - `refs/for`: 30 new changes per hour per user.
  The session upload volume and storage quotas already exist; this milestone verifies them against §11.6 and documents them.
- **§6.5 audit log UI** for site admins, with filters, plus an admin API.
- **§10.1 site-admin pages** still missing: the quarantine queue, health, and job-queue statistics (§12).
- **An audit completeness sweep** proving every §6.5 action class writes a record.

**Architecture:** No new crates and no new dependencies.
- **`starforged-core`** gains `limits.rs`:
  - in-memory fixed-window counters for per-IP login and per-token API limits;
  - database counts for the per-account login limit (from the audit log) and for `refs/for` (from `changes`).
- **The API auth extractor** consults the token limiter and sets rate-limit headers.
- **The git RPC snapshot** (`git_rpc_env`) carries the `refs/for` budget and the pusher's existing open agit topics, so the hook can refuse NEW changes over the limit with a sideband message.
- **`starforged-web`** gains `/admin/audit`, `/admin/quarantine`, and `/admin/health`.
- **`starforged-api`** gains `GET /api/v1/admin/audit`.
- **`starforged-db`** gains `0028_audit_indexes.sql`: indexes for the audit filters and the per-account count.

**Spec:** §11.6 (controls and defaults), §6.5 (audit contents), §10.1 (site admin: users, orgs, repositories, quarantine queue, audit log, jobs, health), §12 (job-queue statistics in the admin UI), §9 (login).

**Deferred (not built here):** distributed rate limiting (single process, §2 non-goal), CAPTCHA, and per-repository API limits.

## Global Constraints

- **Configuration:** `[limits]` with these keys (`0` disables a limit; all overridable by `STARFORGE__LIMITS__*`):
  - `login_per_ip_per_minute = 10`
  - `login_per_account_per_hour = 20`
  - `api_per_token_per_hour = 5000`
  - `refs_for_new_changes_per_hour = 30`

  The existing `[sessions]` quota keys keep their names and defaults (500 MiB/hour, 5 GiB per user, 20 GiB per repository).
- **Client IP:** use the same client-IP extraction the audit writer uses. When it honors `X-Forwarded-For`, it does so only as configured today; verify, and document the trust setting in the README.
- **Responses:**
  - API over limit: `429` with the error envelope (`code: "rate_limited"`), `Retry-After`, and `X-RateLimit-Limit`/`-Remaining`/`-Reset` on every token-authenticated API response.
  - Login over limit: the login page re-renders with `429` and a generic message. Failed attempts while limited are still audited.
  - `refs/for` over limit: `remote: starforge: …` naming the limit, and the push of that ref is refused.
- **No timing oracle:** the per-account limit counts failures for existing AND non-existing accounts identically: count by the normalized login name, not by user id. Every failed login writes its `auth.login_failed` audit row with the normalized login name as the target, including unknown names; verify the writer does this today and fix it if not, or the limiter silently misses probes of unknown names.
- **Audit:** limit hits write `auth.login_rate_limited` (one row per refused attempt) and nothing for API 429s (too noisy). They are logged at `info` with the token id, never the token.
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. Counters.**
  - Per-IP login and per-token API limits use in-memory fixed windows: a `HashMap` behind a mutex, keyed by IP or token id, pruned on access and at most every 60 s. A restart resets them, which a single-process deployment accepts.
  - Per-account login limits count `auth.login_failed` audit rows for the normalized login name in the last 3600 s, so they survive restarts. Index: `0028` adds `(action, target, created_at)` or the equivalent columns the audit table uses.
  - `refs/for` counts the user's `agit` changes created in ALL repositories in the last hour (per user, per §11.6).
- **D2. `refs/for` enforcement.**
  - The RPC snapshot includes `STARFORGE_REFS_FOR_BUDGET` (remaining new changes) and `STARFORGE_REFS_FOR_TOPICS` (the PUSHER's own open agit changes in this repository as `base/topic` lines; §8.2: only the same user pushing the same `<base>/<topic>` updates a change, so another user's identical topic is a new change and counts against the budget).
  - The hook counts the pushed `refs/for` refs whose `base/topic` is not in the list, and refuses the excess with a message.
  - The post-receive ingest re-checks the budget and skips creating changes beyond it, logging a warning (defense in depth for racing pushes).
- **D3. Audit UI.**
  - `/admin/audit` (site admins; others get 404 like other admin pages) lists entries newest first with keyset pagination (50 per page).
  - Filters: actor handle, action (exact or prefix like `session.`), target (free text match on the stored target), and from/to dates.
  - Columns: time, actor, action, target, IP, user agent, all escaped.
  - `GET /api/v1/admin/audit?actor=&action=&target=&from=&to=&after=&limit=` needs a site admin with an `admin`-scoped token.
- **D4. Quarantine queue.** `/admin/quarantine` lists quarantined sessions across all repositories: repo, ULID, uploader, reason (not detail content), and time. It has release and purge actions (CSRF) calling the existing `Core` release and purge, which already permit site admins.
- **D5. Health and jobs.** `/admin/health` shows:
  - version, database engine and schema version, and git version;
  - data dir free space;
  - job queue aggregates (count by kind × state: pending, running, failed, and the oldest pending age), which the jobs page also shows;
  - search index document counts (M4a `stats()`);
  - SSH listener status.

## File Structure

```
crates/starforged-db/migrations/{sqlite,postgres}/0028_audit_indexes.sql
crates/starforged-db/src/{audit.rs,jobs.rs,changes.rs}
crates/starforged-core/src/{limits.rs (new),sessions.rs,changes.rs,audit.rs,admin.rs,lib.rs}
crates/starforged/src/{config.rs,hook.rs}, crates/starforged-git/src/refpolicy.rs
crates/starforged-api/src/{auth.rs,admin.rs (new),lib.rs,error.rs}
crates/starforged-web/src/pages/admin.rs, templates/admin_audit.html, admin_quarantine.html, admin_health.html
crates/starforged/tests/{limits.rs,admin_audit.rs,admin_pages.rs,audit_completeness.rs}
README.md
```

---

### Task L1: Rate limits

**Files:**
- Create:
  - `crates/starforged-core/src/limits.rs`;
  - `crates/starforged/tests/limits.rs`.
- Modify:
  - `crates/starforged-core/src/{sessions.rs,changes.rs,lib.rs}`;
  - `crates/starforged-api/src/{auth.rs,error.rs}`;
  - `crates/starforged/src/{config.rs,hook.rs}`;
  - `crates/starforged-git/src/refpolicy.rs`;
  - `git_rpc_env`;
  - the 0028 migrations (audit index).

**Interfaces:** D1 and D2, plus `Core::check_api_rate(token_id) -> RateDecision { allowed, limit, remaining, reset_at }`.

- [ ] **Step 1: Write the failing tests.** Configure low limits in tests:
  - **Login per IP:** the 3rd attempt within a minute gets 429.
  - **Login per account:** 3 failures, then even the correct password gets 429 until the window passes (simulated through an injectable clock or by aging the audit rows). A non-existent login name is limited identically.
  - **API:** the 4th request gets 429 with `Retry-After` and the headers; another token is unaffected.
  - **`refs/for`:**
    - the 3rd NEW change in an hour is refused with the message;
    - an update push to an existing topic is still accepted;
    - two refs in one push that exceed the budget are refused.
  - **Disable:** `0` disables each limit.
  - **Existing quotas:** the upload volume and storage quotas still give their existing errors (regression).
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test limits`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test web_login --test api_tokens --test push_changes --test hook_cli` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add login, API, and refs/for rate limits`.

---

### Task L2: Audit log UI and API

**Files:**
- Create:
  - `templates/admin_audit.html`;
  - `crates/starforged-api/src/admin.rs`;
  - `crates/starforged/tests/admin_audit.rs`.
- Modify:
  - `crates/starforged-db/src/audit.rs`;
  - `crates/starforged-core/src/{audit.rs,admin.rs}`;
  - the web and API route registration.

**Interfaces:** D3.

- [ ] **Step 1: Write the failing tests.**
  - Filters by actor, action prefix, target, and date each narrow correctly.
  - Pagination is stable while new rows arrive.
  - The API matches the page.
  - **Access:** non-admins get 404 on the page; the API needs a site admin and the `admin` scope.
  - **XSS:** hostile user agents and targets render escaped.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test admin_audit`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add the audit log page and API`.

---

### Task L3: Quarantine queue, health, and job statistics

**Files:**
- Create:
  - `templates/admin_quarantine.html` and `admin_health.html`;
  - `crates/starforged/tests/admin_pages.rs`.
- Modify:
  - `crates/starforged-web/src/pages/admin.rs` and the admin navigation;
  - `crates/starforged-core/src/admin.rs`;
  - `crates/starforged-db/src/{jobs.rs,sessions.rs}`.

**Interfaces:** D4 and D5.

- [ ] **Step 1: Write the failing tests.**
  - **Quarantine queue:** lists a quarantined session from two repositories; release and purge work from it (CSRF); the session content never appears on the page.
  - **Health:** shows the version, engine, git version, and job aggregates. A failed job shows in the counts.
  - **Access:** non-admins get 404.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test admin_pages`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test web_admin` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add the quarantine queue and health pages`.

---

### Task L4: Audit completeness sweep and docs

**Files:**
- Create: `crates/starforged/tests/audit_completeness.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep.** One test per §6.5 class performs the action and asserts exactly one audit row with actor, action, target, IP, user agent, and timestamp. The classes:
  - login success and failure;
  - password change and 2FA changes (M3d);
  - token creation and revocation;
  - permission and membership changes: collaborators, org members, teams, team repositories, transfer;
  - visibility changes;
  - session publish, unpublish, quarantine, release, purge, and delete;
  - site-admin actions (suspend, grant, 2FA reset, job retry).

  A grep-style assertion confirms no audit row contains session transcript content: upload a session with a unique marker string and scan all audit rows. Fix any missing audit write in its owning `Core` method and report it.
- [ ] **Step 2: Run the sweep** 3 times; all green.
- [ ] **Step 3: README:** an "Abuse controls" section (every limit, its config key, the response shapes, client IP trust) and an "Audit log" section.
- [ ] **Step 4: Commit** (PG gate first): `Add the audit completeness sweep and docs`.
