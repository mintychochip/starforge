# Starforge M2a (Trail Core) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Trail-as-issue foundation of spec §6.2: dual-engine schema (`trails`, `trail_labels`, `trail_assignees`, `trail_comments`, `timeline_events`) via migration `0010_trails.sql`, per-repo numbering starting at 1, a `starforged-core` service layer (create/get/list/filter/update/state/ready/comment/labels/assignees, one timeline row per mutation), triage-aware permissions (§6.1) with 404-for-non-readers, REST JSON under `/api/v1/repos/{owner}/{repo}/trails`, and the web list/new/detail pages with sanitized Markdown. No changes/revisions, no `refs/for`, no reviews/checks/gates/merge, no webhooks, no CLI `trail` commands — those are M2b–M2d.

**Architecture:** No new crates, no new services. `starforged-db` gains `trails.rs` (row types + query fns) plus dual migration `0010_trails.sql`. `starforged-core` gains `trails.rs` (all permission, validation, numbering-retry, and timeline logic behind `Core` methods; API and web both delegate). `starforged-api` gains `trails.rs` (Bearer auth + scope check + `require_repo` leak-guard, then `Core` delegation). `starforged-web` gains `pages/trails.rs` + three askama templates reusing `RepoHead`, `markdown::render`, and the `_csrf` form pattern. Timeline is a plain table, not a service: every mutating `Core` method writes its `timeline_events` row in the same call.

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8 (existing), sqlx `Any` (SQLite + Postgres, `$N` placeholders), askama + comrak/ammonia via the existing `starforged-web/src/markdown.rs`, reqwest (dev/test HTTP client, already workspace).

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` §6.1 (permission levels; capability matrix: `read` opens/comments, `triage` labels/assignees + close/reopen, `write` pushes/approves/merges), §6.2 (Trail model: repo, per-repo number, title, intent Markdown, state `open|merged|closed`, ready flag, author, labels, assignees, timestamps; comments + timeline events), §6.5 (audit log), §6.6 (per-repo Trail sequence numbers starting at 1), §10.1 (Trail list filters; Trail page header + timeline), §10.4 (REST JSON under `/api/v1`, error envelope, bearer auth), §11.1 (comrak with raw HTML off → ammonia sanitize; escaped text), §13 (unit + server integration on both engines; access matrix identical for web/API; XSS corpus; CSRF; per-route auth). Later milestones consume this (changes/revisions M2b, checks/gates/merge M2c, CLI M2d); they are out of scope here.

**§6.2 gaps this plan deliberately cannot express yet (deferred, not built):** `merged` state has no writer (the `state` CHECK admits it so M2c needs no migration rewrite, but `set_trail_state` rejects it — see D3); changes/revisions/review threads/checks/gate panel/merge button/Sessions tab do not exist; list filters `has-changes`, `has-sessions`, `review-requested` have nothing to query yet (the list supports `state`, `label`, `assignee`, `author` only); `refs/trails/<n>/changes/<k>/head` refs are M2b; webhook `trail` events are M2c.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** every touched crate stays `AGPL-3.0-or-later` (`license.workspace = true`). No new crates in M2a, so no new license headers to get wrong.
- **Dependencies:** NO new `[workspace.dependencies]` entries and no new crate deps. Everything needed (axum, sqlx Any, askama, comrak/ammonia via `markdown.rs`, reqwest dev) already exists.
- **Migrations:** schema lands as `0010_trails.sql` in BOTH `crates/starforged-db/migrations/sqlite/` and `.../postgres/`, kept in lockstep. Only types/SQL valid on both engines (`$N` placeholders numbered by first appearance, `BIGINT`/`INTEGER` → `i64`, booleans as `0`/`1`, timestamps as unix seconds via `Db::now()`). Forward-only per spec §12; 0010 is purely additive (new tables only), so upgrade is a restart. Verify with `scripts/check.sh` AND the `STARFORGE_TEST_PG=1` gate for every SQL-touching task.
- **No route bypasses `starforged-core`:** API and web handlers authenticate (scope/`require_repo` checks) and delegate; all permission, validation, numbering, and timeline logic lives on `Core`. Web handlers never touch `Db` directly and render Markdown only through `markdown::render`.
- **Test tmpdirs:** run suites with `TMPDIR=/dev/shm` where available (all fixtures are `tempfile::tempdir()`-based `TestServer`/`TestDb`; tmpfs keeps them fast and off disk). Fall back to the system temp dir when `/dev/shm` is absent — never `$HOME`, never the repo.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green; SQL touched → also the `STARFORGE_TEST_PG=1` gate before committing.
- **Out of scope (do not build):** changes, revisions, `refs/for` push flow, reviews/threads, checks, gate rules, server-side merge, webhooks (not even outbox enqueue), CLI `trail` commands, `merged` transitions, trail deletion (no spec mandate; close covers M2a), comment deletion/history.
- **Decisions this plan makes where the spec is silent:**
  - Number allocation is `INSERT … SELECT COALESCE(MAX(number),0)+1 … WHERE repo_id=$1` retried on unique violation (≤5 attempts, then `Conflict`). Justification: no sequence object exists that works identically on both engines; the `UNIQUE(repo_id, number)` constraint makes the race safe, and Trail creation is far too infrequent for contention to matter.
  - Label charset is `[a-z0-9-_.]`, max 50 chars, stored lowercased and trimmed; anything else → `Invalid`. Justification: labels appear in query params (`?label=`) and CSS classes, so they must be URL- and selector-safe without encoding tricks; lowercase + trim makes `Bug` and `bug` the same label instead of two.
  - Pagination is keyset on the API (`?after=<number>&limit=`, default 30, max 100, `ORDER BY number ASC`, response carries `next_after`) and page-numbered on the web (`?page=N`, same ordering, 30 per page). Justification: keyset is stable under concurrent inserts (offset would skip) and the last-seen number is a natural opaque-ish cursor for an integer namespace; page numbers stay human-bookmarkable in HTML.
  - `merged` is rejected by `set_trail_state` with an explicit `Invalid("merged is set by the merge path")`. Justification: spec §6.2 derives `merged` from change states, which do not exist until M2b/M2c — letting anyone set it now would forge history the merge path must own.
  - API scope mapping: `GET` needs `repo:read` (via the existing `auth.reader()`; anonymous reads of visible repos keep working, non-readers 404), every mutation needs `trail:write` (via `auth.require(Scope::TrailWrite)`) PLUS the repo-permission check. A `trail:write`-only token therefore also needs `repo:read` to list/get (compose scopes as `"repo:read trail:write"`). Justification: `trail:write` is the spec-named PAT scope (§6.1); `repo:write` implies code push, not issue curation, so the two stay orthogonal and a CI push token cannot spam Trails. `admin` scope bypasses per the existing `grants` rule.
  - Title/intent/ready edits: the author (with ≥ `read`) may edit their own Trail; anyone with ≥ `triage` may edit anyone's (admins included via ordering). Justification: spec gives `triage` the whole issue-curation portfolio (labels, assignees, close/reopen) while `write` powers are code-centric (push, approvals, merge) — title/intent curation belongs with triage, and authors keep control of their own wording.
  - Comment edits have no time window: author or repo/site admin, unlimited, bumping `edited_at`. Justification: the spec never windows comment edits; a window would be review policy, which belongs to M2b if ever.
  - Audit vs timeline: `trail.open`, `trail.close`, `trail.reopen` are audited (target `trail:<owner>/<repo>#<n>`); comments, labels, assignees, title/intent/ready edits are timeline-only. Justification: §6.5 audits lifecycle/security events (cf. `session.publish|unpublish|quarantine`), and open/close/reopen are the Trail lifecycle analogues — while every other mutation already records actor + timestamp + payload in `timeline_events`, so auditing them too would duplicate the record.

---

## File Structure

```
crates/starforged-db/
  migrations/sqlite/0010_trails.sql      new tables: trails, trail_labels, trail_assignees, trail_comments, timeline_events (F1)
  migrations/postgres/0010_trails.sql    lockstep twin (F1)
  src/trails.rs                          TrailRow/Label/Assignee/CommentRow/TimelineEventRow + query fns incl. atomic number alloc (F1)
  src/lib.rs                             `pub mod trails;` (F1)
crates/starforged-core/
  src/trails.rs                          TrailView/Filter/inputs, normalize_label, Core trail methods + timeline writes + audits (F2)
  src/lib.rs                             `pub mod trails;` (F2)
crates/starforged-api/
  src/trails.rs                          list/create/get/patch/comments/labels/assignees handlers + DTOs (F3)
  src/lib.rs                             route table (F3)
crates/starforged-web/
  src/pages/trails.rs                    list/new/create/show/comment/state/label/assignee/edit handlers (F4)
  src/pages.rs (or pages/mod.rs — verify) module registration (F4)
  src/lib.rs                             route table (F4)
  templates/trails.html                  list with state/label/assignee filter form (F4)
  templates/trail_new.html               new-trail form (F4)
  templates/trail.html                   detail: header, labels, assignees, intent, timeline, comment form, triage-gated controls (F4)
  templates/repo_head.html               add Trails tab (F4)
crates/starforged/
  tests/api_trails.rs                    API status matrix + JSON shape + pagination (F3, extended F5)
  tests/web_trails.rs                    web 404/XSS/CSRF/pagination/visibility matrix (F4, extended F5)
  tests/common/mod.rs                    trail fixture helpers (F5)
README.md                                Trails (M2a) section (F5)
```

---

### Task F1: Schema + migrations + `starforged-db` repos

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0010_trails.sql`, `crates/starforged-db/migrations/postgres/0010_trails.sql`, `crates/starforged-db/src/trails.rs`
- Modify: `crates/starforged-db/src/lib.rs` (`pub mod trails;`)

**Interfaces:**
- Produces (all `pub`, cross-task contract — do not rename):
  ```rust
  // crates/starforged-db/src/trails.rs
  pub struct TrailRow { pub id: i64, pub repo_id: i64, pub number: i64, pub title: String,
      pub intent: String, pub state: String, pub ready: i64, pub author_id: i64,
      pub created_at: i64, pub updated_at: i64, pub closed_at: Option<i64>, pub merged_at: Option<i64> }
  pub struct TrailLabelRow { pub trail_id: i64, pub name: String }
  pub struct TrailAssigneeRow { pub trail_id: i64, pub user_id: i64 }
  pub struct TrailCommentRow { pub id: i64, pub trail_id: i64, pub author_id: i64,
      pub body: String, pub created_at: i64, pub edited_at: Option<i64> }
  pub struct TimelineEventRow { pub id: i64, pub repo_id: i64, pub trail_id: Option<i64>,
      pub kind: String, pub actor_id: Option<i64>, pub payload: String, pub created_at: i64 }
  pub struct NewTrail<'a> { pub repo_id: i64, pub title: &'a str, pub intent: &'a str, pub author_id: i64 }
  pub struct TrailFilter { pub state: Option<String>, pub label: Option<String>,
      pub assignee_id: Option<i64>, pub author_id: Option<i64>, pub after: Option<i64>, pub limit: i64 }
  pub async fn insert_trail(db: &Db, t: &NewTrail<'_>, now: i64) -> DbResult<TrailRow>;
  // Atomic number alloc: INSERT INTO trails (…) SELECT $1, COALESCE(MAX(number),0)+1, …
  //   FROM trails WHERE repo_id = $1 … RETURNING …; caller retries on unique violation (≤5, F2 owns the loop).
  pub async fn trail_by_number(db: &Db, repo_id: i64, number: i64) -> DbResult<Option<TrailRow>>;
  pub async fn trails_of_repo(db: &Db, repo_id: i64, f: &TrailFilter) -> DbResult<Vec<TrailRow>>;
  // Keyset: WHERE number > $after (when set) ORDER BY number ASC LIMIT $n; label/assignee via
  // EXISTS subqueries on trail_labels/trail_assignees; state/author direct predicates.
  pub async fn set_title_intent(db: &Db, id: i64, title: &str, intent: &str, now: i64) -> DbResult<()>;
  pub async fn set_state(db: &Db, id: i64, state: &str, now: i64, closed_at: Option<i64>) -> DbResult<()>;
  pub async fn set_ready(db: &Db, id: i64, ready: i64, now: i64) -> DbResult<()>;
  pub async fn touch(db: &Db, id: i64, now: i64) -> DbResult<()>; // updated_at bump for label/assignee/comment-only mutations
  pub async fn add_label(db: &Db, trail_id: i64, name: &str) -> DbResult<bool>; // insert-or-ignore; false when present
  pub async fn remove_label(db: &Db, trail_id: i64, name: &str) -> DbResult<bool>;
  pub async fn labels_of(db: &Db, trail_id: i64) -> DbResult<Vec<String>>;
  pub async fn add_assignee(db: &Db, trail_id: i64, user_id: i64) -> DbResult<bool>;
  pub async fn remove_assignee(db: &Db, trail_id: i64, user_id: i64) -> DbResult<bool>;
  pub async fn assignees_of(db: &Db, trail_id: i64) -> DbResult<Vec<i64>>;
  pub async fn insert_comment(db: &Db, trail_id: i64, author_id: i64, body: &str, now: i64) -> DbResult<TrailCommentRow>;
  pub async fn comment_by_id(db: &Db, id: i64) -> DbResult<Option<TrailCommentRow>>;
  pub async fn update_comment(db: &Db, id: i64, body: &str, now: i64) -> DbResult<()>;
  pub async fn comments_of(db: &Db, trail_id: i64) -> DbResult<Vec<TrailCommentRow>>;
  pub async fn insert_timeline(db: &Db, repo_id: i64, trail_id: Option<i64>, kind: &str, actor_id: Option<i64>, payload: &str, now: i64) -> DbResult<i64>;
  pub async fn timeline_of_trail(db: &Db, trail_id: i64) -> DbResult<Vec<TimelineEventRow>>;
  ```
- Every statement: `$N` placeholders in first-appearance order, `i64` integers, `0`/`1` bools, unix-second timestamps — the `lib.rs` rules, enforced by the PG gate.

- [ ] **Step 1: Write the failing db tests.** New `#[cfg(test)] mod tests` in `src/trails.rs` using `crate::testing::TestDb`: insert two trails in one repo → numbers `1, 2`; a second repo starts at `1` again; duplicate `(repo_id, number)` insert is a unique violation; `trails_of_repo` filters by state/label/assignee/author and keyset (`after` excludes, `ORDER BY number ASC`); label add twice → `false` the second time + `labels_of` deduped; comment insert → update bumps `edited_at`; timeline insert with `trail_id = NULL` (repo-level shape) round-trips.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-db trails` — Expected: FAIL (module/table do not exist).
- [ ] **Step 3: Write both migrations + `trails.rs`.** Tables per assignment §1: `trails` (`UNIQUE(repo_id, number)`, `state TEXT NOT NULL CHECK (state IN ('open','merged','closed'))` — `merged` admitted by the CHECK now so M2c writes it with no migration rewrite, `ready INTEGER NOT NULL DEFAULT 0`, `author_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE` matching the 0008 uploader precedent, `closed_at`/`merged_at` nullable, `merged_at` always NULL in M2a); `trail_labels` (`trail_id … REFERENCES trails (id) ON DELETE CASCADE`, `UNIQUE(trail_id, name)`); `trail_assignees` (`UNIQUE(trail_id, user_id)`, both FKs `ON DELETE CASCADE`); `trail_comments` (`trail_id` CASCADE, `author_id` CASCADE, `edited_at` nullable); `timeline_events` (`repo_id` CASCADE, `trail_id … REFERENCES trails (id) ON DELETE CASCADE` nullable for repo-level events, `actor_id INTEGER REFERENCES users (id) ON DELETE SET NULL` per the 0001 audit precedent, `payload TEXT NOT NULL` holding JSON). FK style is inline `REFERENCES … ON DELETE CASCADE` exactly like 0008; sqlite/postgres twins differ only in integer types + identity syntax. `insert_trail` uses the single-statement `SELECT COALESCE(MAX(number),0)+1` form with `RETURNING`.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-db` then the PG gate for the package — Expected: PASS on both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-db
  git commit -m "Add Trail core schema with dual migrations and db repos"
  ```

---

### Task F2: Core service + permissions + numbering + timeline

**Files:**
- Create: `crates/starforged-core/src/trails.rs`
- Modify: `crates/starforged-core/src/lib.rs` (`pub mod trails;`)
- Create (tests): core unit tests live in-module (`trails.rs #[cfg(test)]` with `crate::testing::test_core`, following the `ingest.rs` convention).

**Interfaces:**
- Consumes: F1 (all row types + query fns), `permission_on`/`require_repo`, `Permission::{Read, Triage, Admin}`, `Core::audit`, `CoreError::{NotFound, Forbidden, Invalid, Conflict}`, `Db::now()`.
- Produces:
  ```rust
  // crates/starforged-core/src/trails.rs
  pub struct TrailView { pub number: i64, pub title: String, pub intent: String, pub state: String,
      pub ready: bool, pub author_id: i64, pub author_handle: String, pub labels: Vec<String>,
      pub assignees: Vec<String>, pub created_at: i64, pub updated_at: i64,
      pub closed_at: Option<i64>, pub merged_at: Option<i64> }
  pub struct TrailFilterInput { pub state: Option<String>, pub label: Option<String>,
      pub assignee: Option<String>, pub author: Option<String>, pub after: Option<i64>, pub limit: Option<i64> }
  pub struct ListPage { pub trails: Vec<TrailView>, pub next_after: Option<i64> }
  pub struct CommentView { pub id: i64, pub author_handle: String, pub body: String,
      pub created_at: i64, pub edited_at: Option<i64> }
  pub struct TrailDetail { pub trail: TrailView, pub comments: Vec<CommentView>,
      pub timeline: Vec<TimelineEventRow> } // re-exported from starforged_db::trails
  impl Core {
      pub async fn create_trail(&self, user: &User, owner: &str, repo: &str, title: &str, intent: &str) -> CoreResult<TrailView>;
      pub async fn trail_by_number(&self, user: Option<&User>, owner: &str, repo: &str, number: i64) -> CoreResult<TrailDetail>;
      pub async fn list_trails(&self, user: Option<&User>, owner: &str, repo: &str, f: &TrailFilterInput) -> CoreResult<ListPage>;
      pub async fn update_trail(&self, user: &User, owner: &str, repo: &str, number: i64, title: Option<&str>, intent: Option<&str>, ready: Option<bool>) -> CoreResult<TrailView>;
      /// Only "open"|"closed". "merged" → Invalid (M2c merge path owns it); anything else → Invalid.
      pub async fn set_trail_state(&self, user: &User, owner: &str, repo: &str, number: i64, state: &str) -> CoreResult<TrailView>;
      pub async fn add_comment(&self, user: &User, owner: &str, repo: &str, number: i64, body: &str) -> CoreResult<CommentView>;
      /// Comment author or effective ≥ Admin; else Forbidden. Bumps edited_at; timeline-only.
      pub async fn edit_comment(&self, user: &User, owner: &str, repo: &str, number: i64, comment_id: i64, body: &str) -> CoreResult<CommentView>;
      pub async fn add_label(&self, user: &User, owner: &str, repo: &str, number: i64, name: &str) -> CoreResult<TrailView>;
      pub async fn remove_label(&self, user: &User, owner: &str, repo: &str, number: i64, name: &str) -> CoreResult<TrailView>;
      pub async fn add_assignee(&self, user: &User, owner: &str, repo: &str, number: i64, handle: &str) -> CoreResult<TrailView>;
      pub async fn remove_assignee(&self, user: &User, owner: &str, repo: &str, number: i64, handle: &str) -> CoreResult<TrailView>;
      /// trim + lowercase; empty after trim, len > 50, or [^a-z0-9-_.] → Invalid.
      pub fn normalize_label(name: &str) -> CoreResult<String>;
  }
  ```
- Permission rule (binding, §6.1): every method first resolves the repo and effective permission; below `Read` (or invisible repo) → `NotFound` (no existence leak). `create_trail`/`add_comment`/read paths need ≥ `Read`. `add/remove_label`, `add/remove_assignee`, `set_trail_state` need ≥ `Triage`. `update_trail` needs author-with-≥-`Read` or ≥ `Triage`. `edit_comment` needs comment-author or effective ≥ `Admin`. `write` gains no extra Trail powers in M2a (its powers are code-centric per the §6.1 matrix). Assignees must be repo members (≥1 explicit grant — implicit public/internal read is NOT membership) else `Invalid`.
- Validation (binding): title non-empty after trim (max 200 chars), intent max 100_000 chars; comment body non-empty (max 100_000); `state` filter/label/author/assignee filters validated (`state` must be `open|merged|closed` — `merged` lists empty in M2a, never 422); `limit` clamped to 1..=100.
- Numbering: `create_trail` loops `insert_trail` ≤5 times, retrying only on unique violation, else `Conflict`. `updated_at` (`Db::now()`) bumps on every mutation; close sets `closed_at`, reopen clears it; `merged_at` is never written in M2a. Audits `trail.open` on create, `trail.close`/`trail.reopen` on state change (target `trail:<owner>/<repo>#<n>`); all other mutations are timeline-only.
- Timeline kinds (binding — every mutation writes exactly one, `payload` is JSON):
  - `trail.open` → `{"number": <n>}`
  - `trail.comment` → `{"comment_id": <id>}`
  - `trail.state` → `{"from": "<open|closed>", "to": "<open|closed>"}`
  - `trail.label` → `{"action": "add"|"remove", "name": "<normalized>"}`
  - `trail.assignee` → `{"action": "add"|"remove", "user": "<handle>"}`
  - `trail.edit` → `{"fields": ["title"|"intent"|"ready", …]}` (only actually-changed fields; `update_trail` with no changes writes no row)

- [ ] **Step 1: Write failing core tests.** In-module tests with `test_core()`: create → view round-trips number `1`, author, labels/assignees empty; get-missing → `NotFound`; `set_trail_state` to `merged` → `Invalid` with a merge-path message, to `bogus` → `Invalid`; close sets `closed_at`, reopen clears it; label `Bug` normalizes to `bug`, `BAD LABEL!` → `Invalid`, 51-char name → `Invalid`, re-add dedupes; assignee non-member → `Invalid`, member → ok; comment edit by stranger → `Forbidden`, by author → ok with `edited_at` set; every mutation appends exactly one `timeline_events` row with the documented kind + payload shape; `updated_at` strictly increases across mutations; audit rows exist for open/close/reopen and NOT for comment/label edits.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-core trails` — Expected: FAIL (module does not exist).
- [ ] **Step 3: Implement `trails.rs`.** Follow `repos.rs`/`ingest.rs` conventions: resolve via `require_repo(Some(user), owner, repo, Permission::Read)` for the leak-guard 404, then compare `access.permission` against the action threshold; member check for assignees via the collaborators path (explicit grant, not implicit read). Number-retry loop on `is_unique_violation`. Timeline insert + audit inside each method after the row write. `list_trails` resolves filter handles → ids (unknown assignee/author handle → empty list, not 404), clamps limit, returns `next_after` = last number iff the page was full.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-core` then the PG gate for the package — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-core
  git commit -m "Add Trail core service with permissions, numbering, and timeline"
  ```

---

### Task F3: REST API

**Files:**
- Create: `crates/starforged-api/src/trails.rs`, `crates/starforged/tests/api_trails.rs`
- Modify: `crates/starforged-api/src/lib.rs` (route table)

**Interfaces:**
- Consumes: F2 (`Core` trail methods, `TrailFilterInput`, views), `ApiAuth::require/reader`, `Scope::TrailWrite`, `require_repo` + `Permission::Read`, `ApiError` envelope mapping.
- Produces:
  ```rust
  // crates/starforged-api/src/trails.rs — routes (exact shapes; {owner}/{repo} reuse the existing repo path params):
  // GET    /repos/{owner}/{repo}/trails[?state=&label=&assignee=&author=&after=&limit=] → 200 {"trails": [TrailJson], "next_after": N|null}
  // POST   /repos/{owner}/{repo}/trails                                                 → 201 TrailJson
  // GET    /repos/{owner}/{repo}/trails/{n}                                             → 200 TrailDetailJson
  // PATCH  /repos/{owner}/{repo}/trails/{n}                                             → 200 TrailJson
  // GET    /repos/{owner}/{repo}/trails/{n}/comments                                    → 200 {"comments": [CommentJson]}
  // POST   /repos/{owner}/{repo}/trails/{n}/comments                                    → 201 CommentJson
  // PATCH  /repos/{owner}/{repo}/trails/{n}/comments/{id}                               → 200 CommentJson
  // POST   /repos/{owner}/{repo}/trails/{n}/labels      ({"name": "…"})                 → 200 TrailJson
  // DELETE /repos/{owner}/{repo}/trails/{n}/labels      ({"name": "…"})                 → 200 TrailJson
  // POST   /repos/{owner}/{repo}/trails/{n}/assignees   ({"user": "<handle>"})          → 200 TrailJson
  // DELETE /repos/{owner}/{repo}/trails/{n}/assignees   ({"user": "<handle>"})          → 200 TrailJson
  pub struct TrailJson { pub number: i64, pub title: String, pub intent: String, pub state: String,
      pub ready: bool, pub author: String, pub labels: Vec<String>, pub assignees: Vec<String>,
      pub created_at: i64, pub updated_at: i64, pub closed_at: Option<i64>, pub merged_at: Option<i64> }
  pub struct TrailDetailJson { pub trail: TrailJson, pub comments: Vec<CommentJson>, pub timeline: Vec<TimelineJson> }
  pub struct CommentJson { pub id: i64, pub author: String, pub body: String, pub created_at: i64, pub edited_at: Option<i64> }
  pub struct TimelineJson { pub id: i64, pub kind: String, pub actor: Option<String>, pub payload: serde_json::Value, pub created_at: i64 }
  pub async fn list_trails(State(state): State<ApiState>, auth: ApiAuth, Path((owner, repo)): Path<(String, String)>, Query(q): Query<ListQuery>) -> Result<impl IntoResponse, ApiError>;
  pub async fn create_trail(/* + Json<CreateTrailBody{title, intent}> */) -> Result<impl IntoResponse, ApiError>;
  // …get_trail, patch_trail(Json<PatchTrailBody{title?, intent?, ready?, state?}>), comments, labels, assignees — same extractor shape
  ```
- Auth mapping (binding): reads call `auth.reader()?` (bad token → `401`; missing token → anonymous, visibility decides; non-reader → `404` via `Core::NotFound`, never `403`). Mutations call `auth.require(Scope::TrailWrite)?` (missing/bad → `401`, wrong scope → `403` “…lacks the trail:write scope”) then `Core` enforces the repo-permission threshold (`Forbidden` → `403`). `CoreError::Invalid` → `422`, `Conflict` → `409`, all in the `{error:{code,message}}` envelope. `PATCH {state:"merged"}` surfaces the `422` merge-path message verbatim.
- `TimelineJson.payload` is parsed JSON (never a double-encoded string); `actor` is the handle looked up from `actor_id` (NULL → null). `ready` serializes as bool (stored `0`/`1`).

- [ ] **Step 1: Write failing API tests.** New `crates/starforged/tests/api_trails.rs` with `TestServer`: create user + private repo + tokens (`repo:read`, `trail:write`-only, `repo:read trail:write` composed, bogus): no token on private repo → `404`; bogus → `401`; `repo:read` token POST → `403` with `forbidden` scope message; composed token POST → `201` with the full `TrailJson` shape (every field asserted); `GET` list with `?state=open&label=bug&assignee=…&author=…&after=&limit=` filters + `next_after` pagination over 35 trails; `PATCH` title + `ready` → `200` and reflected; `PATCH {state:"merged"}` → `422`; label add/remove round-trip; assignee add of a stranger → `422`; comment POST → `201`, PATCH by another user → `403`, by author → `200`; timeline array contains `trail.open` with `{"number":1}` payload as real JSON.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test api_trails` — Expected: FAIL (routes do not exist → 404s).
- [ ] **Step 3: Implement handlers + route table.** Canonical shape per `sessions.rs`: extract `auth`, `Path`, `Query`/`Json`; reads `auth.reader()?` → `core.list_trails/trail_by_number(user, …)`; mutations `auth.require(Scope::TrailWrite)?` + `core.<verb>(&token.user, …)` (the `Read` leak-guard lives inside `Core`, so handlers pass through `NotFound` untouched). `POST` create returns `201`; label/assignee `DELETE` reads `{name}`/`{user}` from a JSON body (symmetric with POST, no URL-encoding pitfalls) and returns `200` with the updated trail. Register every route in `router()` next to the session routes.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test api_trails` — Expected: PASS. Then `TMPDIR=/dev/shm cargo test --workspace`.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-api crates/starforged/tests/api_trails.rs
  git commit -m "Add Trail REST API with scope mapping and keyset pagination"
  ```

---

### Task F4: Web UI + templates

**Files:**
- Create: `crates/starforged-web/src/pages/trails.rs`, `templates/trails.html`, `templates/trail_new.html`, `templates/trail.html`, `crates/starforged/tests/web_trails.rs`
- Modify: `crates/starforged-web/src/pages.rs` (or `pages/mod.rs` — verify exact module file), `crates/starforged-web/src/lib.rs` (route table), `templates/repo_head.html` (Trails tab)

**Interfaces:**
- Consumes: F2 (`Core` trail methods, `TrailFilterInput`), `MaybeUser`/`RequireUser`, `repo_for` (invisible → `404`), `verify_csrf` + `_csrf` hidden-input pattern, `markdown::render` (comrak → ammonia; titles never pass through it — askama escaping only), `RepoHead::new(&access, "trails", …)`, `NavUser::from_session`.
- Produces (routes, all HTML):
  ```
  GET  /{owner}/{repo}/trails[?state=&label=&assignee=]  list (MaybeUser; non-reader → 404)
  GET  /{owner}/{repo}/trails/new                        new form (RequireUser + ≥ Read, else 404/302)
  POST /{owner}/{repo}/trails/new                        create (CSRF; Invalid → re-render 422 with message)
  GET  /{owner}/{repo}/trails/{n}                        detail: header, state badge, author, labels, assignees,
                                                         intent (rendered Markdown), timeline, comments (rendered
                                                         Markdown) + comment form; triage-gated controls (F4)
  POST /{owner}/{repo}/trails/{n}/comment                add comment (CSRF; ≥ Read)
  POST /{owner}/{repo}/trails/{n}/state                  close/reopen (CSRF; ≥ Triage)
  POST /{owner}/{repo}/trails/{n}/labels                 add/remove via `action=` field (CSRF; ≥ Triage)
  POST /{owner}/{repo}/trails/{n}/assignees              add/remove via `action=` field (CSRF; ≥ Triage)
  POST /{owner}/{repo}/trails/{n}/edit                   title/intent/ready (CSRF; author-or-triage)
  POST /{owner}/{repo}/trails/{n}/comments/{id}/edit     edit comment (CSRF; author-or-admin)
  ```
- Template contract: `trails.html` extends `base.html`, includes `repo_head.html`, filter form preserves `state`/`label`/`assignee` values, rows link `/{owner}/{repo}/trails/{n}` with state badge + labels + assignee handles + relative age; `trail.html` renders `intent_html`/`comment.html` via `|safe` (already sanitized by `markdown::render`), shows raw title ONLY through askama escaping, hides every mutation form behind `{% if can_triage %}` / `{% if can_edit %}` / `{% if can_admin %}` flags computed in the handler (never in-template permission logic), and carries `_csrf` in every form. `repo_head.html` gains a `Trails` tab alongside Code/Commits/Branches/Tags (same `{% if %}` active-tab convention). Like the session pages, detail responses send `X-Robots-Tag: noindex`.
- Error mapping: `Core::NotFound` → 404 page (covers invisible repos AND out-of-range numbers — identical bodies so numbers are not enumerable); `Forbidden` on POST → 403 page; `Invalid` → re-render with `400`/`422` + inline message (never a redirect that drops the form).

- [ ] **Step 1: Write failing web tests.** New `crates/starforged/tests/web_trails.rs` with `TestServer` + `browser()`/`try_login`/`login` helpers: anonymous on public repo sees the list + detail but no forms; anonymous on private repo → `404` on list, new, and detail; signed-in `read` user sees the comment form but no close/label controls; `triage` user sees all controls; POST comment without `_csrf` → `403`; POST with another user's `_csrf` → `403`; XSS payload (`<script>alert(1)</script>` + `<img onerror=…>`) in title/intent/comment renders escaped/stripped (assert response bytes contain NO `<script`, and the escaped title text IS present); `?state=closed&label=bug&assignee=…` filters the list; `?page=2` paginates 35 trails; `/{n}` for `n=9999` → `404` with the same body as a missing repo trail page.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_trails` — Expected: FAIL (routes/templates do not exist → 404s).
- [ ] **Step 3: Implement pages + templates + tab.** Handlers follow `pages/session.rs` show/mutation shape: `MaybeUser` for reads with manual `require_repo`-level check surfacing `NotFound`; `RequireUser` for mutations (anon → `302 /login?next=…`), `verify_csrf(&session.csrf_token, &form.csrf)?`, then `Core` verbs, then `Redirect` (PRG). `can_triage`/`can_edit`/`can_admin` computed from `access.permission` + authorship and passed as plain bools to askama. Intent + comment bodies rendered once in the handler via `markdown::render`; titles/handles/labels left for askama escaping (assert by review: no `|safe` on unsanitized strings).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_trails` — Expected: PASS. Then `TMPDIR=/dev/shm cargo test --workspace`.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-web crates/starforged/tests/web_trails.rs
  git commit -m "Add Trail web list, new, and detail pages with triage-gated controls"
  ```

---

### Task F5: Security/permission sweep + numbering concurrency + README

**Files:**
- Modify: `crates/starforged/tests/api_trails.rs`, `crates/starforged/tests/web_trails.rs` (matrix extensions), `crates/starforged/tests/common/mod.rs` (fixture helpers), `README.md` (Trails section)
- Create: none (core/db tests extended in place where a gap is found)

**Interfaces:**
- Consumes: F1–F4; `TestServer::{user, token, repo, browser, login}` + `Scope::{RepoRead, TrailWrite}`, collaborator grants to build the full matrix.
- Produces:
  ```rust
  // crates/starforged/tests/common/mod.rs
  pub async fn trail_user(s: &TestServer, handle: &str) -> User;
  pub async fn trail_repo(s: &TestServer, owner: &User, name: &str, visibility: Visibility) -> Repo;
  pub fn trail_token(s: &TestServer, user: &User, scopes: &[Scope]) -> String;
  pub async fn open_trail_api(client: &reqwest::Client, s: &TestServer, token: &str, owner: &str, repo: &str, title: &str) -> serde_json::Value;
  ```
- The sweep asserts REAL behavior (rows, status codes, rendered bytes — never tautologies): the full permission matrix per action (create/read/list/update/state/ready/comment/edit-comment/label/assignee) × (read/triage/write/maintain/admin/non-member/anonymous) × (public/internal/private), identical expectations for web and API; state machine (`open→closed→open`, `merged` rejected both layers, `closed_at` set/cleared, `merged_at` always null); label normalization table + dedupe + `UNIQUE` enforcement; assignee-must-be-member (including: grant revoked → add fails); comment edit by author/admin ok, by triage non-author → `403`; one timeline row per mutation with exact kind + JSON payload (parsed, not string-compared); API envelope codes + `next_after` chain covering all 35 rows with no gaps/dupes; web 404-parity (missing repo ≡ missing number ≡ no-access); XSS corpus (`<script>`, `<img onerror>`, `<svg onload>`, `javascript:` links) through title/intent/comment/label-rendered paths; CSRF rejection on every POST; pagination stability (insert mid-listing, keyset does not skip).
- Numbering concurrency (binding): N=16 concurrent `create_trail` tasks (core-level, single `TestServer`) yield exactly numbers `1..=16` with no gaps or dupes; repeated on both engines in the PG gate.

- [ ] **Step 1: Write the failing sweep tests.** Extend `api_trails.rs`/`web_trails.rs` with the matrix + concurrency + XSS-corpus tests; add `common/mod.rs` helpers. Tests that need collaborators use the existing collaborator API routes (`PUT …/collaborators/{handle}`) exactly like `api.rs` does.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test api_trails --test web_trails` — Expected: FAIL (matrix cases the F2–F4 code gets wrong, or the concurrency/XSS cases).
- [ ] **Step 3: Fix what the matrix finds + write README.** Fix in the owning layer only (permission logic in `Core`, never in handlers). `README.md` gains a "Trails (M2a)" subsection (~40 lines, matching README voice): issue-like Trails with per-repo numbers, states + `ready`, labels/assignees/comments/timeline, the API table with the `repo:read`/`trail:write` scope mapping, web routes, the deferred list (changes/revisions in M2b, checks/gates/merge in M2c, CLI in M2d).
- [ ] **Step 4: Run the full sweep.** Run: `TMPDIR=/dev/shm cargo test --workspace` then `STARFORGE_TEST_PG=1 scripts/check.sh` — Expected: PASS everything (all prior suites + the sweep on both engines).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged/tests crates/starforged/Cargo.toml README.md
  git commit -m "Add Trail permission sweep, numbering concurrency test, and docs"
  ```
