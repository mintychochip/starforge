# Starforge M2b (Changes, Revisions, refs/for, Reviews) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the change-and-review layer of spec §6.2 on top of the M2a Trail core: dual-engine schema (`changes`, `revisions`, `reviews`, `review_threads`, `review_comments`, `repos.refs_for_access`) via migration `0012_changes.sql`; ref policy accepting `refs/for/<base>[/<topic>]` with `-o trail=<n>` / `-o title=<text>` push options while rejecting `refs/trails/*` from clients; a post-receive scan that creates/updates `agit` changes and revisions, maintains `refs/trails/<n>/changes/<k>/head` + `rev/<r>`, computes mergeability with `git merge-tree --write-tree`, records timeline events, and enqueues a recompute job; a `starforged-core` service plus REST JSON for branch-change creation, change/revision reads, reviews, threads, and close/reopen; and web Trail-changes sections plus a change page with revision picker, diff, review form, outdated threads, and a merge button disabled with the literal M2c reason. No checks, gate rules, merge execution, webhooks, CLI commands, notifications, mirrors/import.

**Architecture:** No new crates, no new services. `starforged-db` gains `changes.rs` (row types + query fns including per-trail/per-change sequence allocators, mirroring the M2a `trail_sequences` precedent) plus dual migration `0012_changes.sql` and a `refs_for_access` getter/setter on `repos.rs`. `starforged-git` gains the `refs/for` grammar + push-option parsing in `refpolicy.rs`, `update-ref` ref helpers in `write.rs`, and the `receive.advertisePushOptions`/`transfer.hideRefs` env helper in `http.rs`. `starforged`'s `hook.rs` pre-receive enforces the per-user ref policy from server-passed env and writes per-push option sidecars. `starforged-web`'s `githttp.rs` relaxes receive-pack auth to `Read`, advertises push options, and extends the post-RPC scan into change/revision ingestion. `starforged-core` gains `changes.rs`: push-ingestion internals (G3) plus the user-facing service (G4); API and web delegate to it. Mergeability runs in a new `Job::ChangeMergeability` worker arm (sync fallback in the scan is forbidden — one path only).

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8 (existing), sqlx `Any` (SQLite + Postgres, `$N` placeholders), askama + comrak/ammonia via the existing `starforged-web/src/markdown.rs`, git subprocesses only through `starforged-git` (`command::git()` hermetic env, blocking pool, timeouts), reqwest + real `git` CLI in tests (in-process `TestServer`, temp repos; mocked receive-pack forbidden).

**Spec:** §6.2 (Change, Revision, Review, Review thread/comment incl. outdated display; timeline kinds for revisions/reviews), §8.2 (ref policy table incl. the `refs/for` row, `refs_for_access` default `anyone_with_read`, `-o trail=<n>` / `-o title=<text>`, same-user same-base/topic updates the same change, the `refs/for` ref itself is not stored, `refs/trails/*` server-only), §8.3 (fetching trail refs; `refs/trails/*` excluded from default clones), §8.4 step 1 (`git merge-tree --write-tree` mergeability; recompute after every new revision and every base-branch movement), §10.1 (Trail page Changes tab with diff + inline threads + revision picker; repo settings `refs/for` control), §10.4 (REST JSON under `/api/v1`, error envelope, bearer auth), §13 (real push/pull over HTTP in integration tests, `refs/for` flow, access matrix, XSS corpus, CSRF, both engines).

**§6.2/§8.2 gaps this plan deliberately cannot express yet (deferred, not built):** checks + commit-status API, gate rules (approvals counting, dismiss-on-revision, required contexts, up-to-date, resolved-threads, session evidence), merge execution + method selector (button renders disabled), webhooks (no outbox enqueue), CLI `trail push|checkout|review|merge`, notifications, pull/push mirrors, GitHub/`imported` creation (`imported` is admitted by the `kind` CHECK so M4 needs no rewrite, but nothing writes it), per-user `refs/for` rate limits (§11.6 → M5 hardening), review-requested/has-changes list filters (M2c search state).

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** every touched crate stays `AGPL-3.0-or-later` (`license.workspace = true`). No new crates, so no new license headers to get wrong.
- **Dependencies:** NO new `[workspace.dependencies]` entries and no new crate deps. Everything needed (axum, sqlx Any, askama, `markdown.rs`, reqwest dev, `tokio::task::spawn_blocking`, `git` on `PATH`) already exists.
- **Migrations:** schema lands as `0012_changes.sql` in BOTH `crates/starforged-db/migrations/sqlite/` and `.../postgres/`, kept in lockstep. Only types/SQL valid on both engines (`$N` placeholders numbered by first appearance, `BIGINT`/`INTEGER` → `i64`, booleans as `0`/`1`, timestamps as unix seconds via `now()`). Same PK idiom as the 0010/0011 twins. Forward-only per spec §12; 0012 is purely additive (new tables + one nullable-with-default column), so upgrade is a restart. Verify with `scripts/check.sh` AND the `STARFORGE_TEST_PG=1` gate for every SQL-touching task.
- **No route bypasses `starforged-core`:** API and web handlers authenticate (scope/`require_repo` checks) and delegate; ALL change/review/thread/mergeability logic lives on `Core`. The githttp scan task calls `Core` ingestion methods, never `Db` directly. Web handlers never touch `Db` and render Markdown only through `markdown::render`.
- **Every mutation timeline-audited where §6.2 says so:** `change.open`, `change.revision`, `change.mergeability`, `change.state`, `review.submitted`, `review.dismissed`, `thread.open`, `thread.resolved`, `thread.comment` — exactly one row per mutation, JSON payloads, written in the same `Core` method as the row write.
- **git-subprocess safety (binding):** every git invocation goes through `command::git()` (hermetic env, no system/global config, prompts off); argv arrays only, never a shell string; SHAs validated as 40/64 lowercase hex (`refpolicy::is_oid`, unifying the two existing private copies) and refnames validated by prefix + charset before use; branch/base/topic names resolved through the existing `read::` helpers (never string-interpolated into rev specs); ALL blocking git work on `tokio::task::spawn_blocking` following the `content.rs` precedent; every merge-tree/diff call has a 60s timeout and output caps (conflict list ≤ 100 paths / 4 KiB; diffs reuse the existing `commit_diff`/`range_diff` line+byte caps, same call shape as the compare page).
- **Test tmpdirs:** run suites with `TMPDIR=/dev/shm` where available (all fixtures are `tempfile`-based `TestServer`/temp repos). Fall back to the system temp dir when absent — never `$HOME`, never the repo.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green; SQL touched → also the `STARFORGE_TEST_PG=1` gate before committing.
- **Out of scope (do not build):** checks, gate rules, merge execution, webhooks (not even outbox enqueue), CLI `trail` commands, notifications, mirrors/import writers, `refs/for` rate limiting, per-file viewed state, review-requested filters.
- **Decisions this plan makes where the spec is silent:**
  - Topic/base split is deterministic and existence-dependent (§8.2 never defines it): strip `refs/for/`; if the whole remainder names an existing branch it is the base and the topic defaults; else with `a/b/…/t` the base is `a/b/…` (must exist as `refs/heads/<base>`) and the topic is the last segment; a single non-branch segment is rejected (`unknown base branch`). Justification: bases may contain slashes (`release/1.x`) so position alone is ambiguous — longest-existing-branch-match is the only rule that accepts both `refs/for/main/foo` and `refs/for/release/1.x/foo` without a second flag.
  - Default topic (no `/<topic>` given) is the pusher's handle lowercased with every char outside `[a-z0-9-_.]` replaced by `-`, truncated to 63 chars. Justification: stable per user (re-pushes update the same change), URL/ref safe, no randomness to communicate.
  - "Same user's change" for an update is `(repo_id, creator_user_id, base_branch, topic)` with state `open`; a closed/merged change with that key is never resurrected — the push creates a fresh change (fresh `k`). With `-o trail=<n>` the lookup is additionally scoped to that trail. Justification: matches "pushing again with the same `<base>/<topic>` from the same user updates the same change" exactly, and closed state stays a deliberate human decision.
  - A new revision is created on every accepted `refs/for` push and every head-branch move of a `branch` change, EXCEPT when the new head SHA equals the current revision's head SHA (idempotent re-push: no row, no timeline). There is no "amend the same revision" path — revisions are append-only. Justification: the glossary calls a revision an immutable snapshot created on each push; dedupe on identical SHA keeps retries side-effect free.
  - Mergeability recompute triggers: every new revision AND every movement of the base branch (§8.4). It is stored on the `changes` row (current status vs current base tip) and snapshotted once onto the revision row when first computed; the revision is otherwise never mutated. Base moves never create revisions. Justification: recompute-in-place on the revision would violate revision immutability; the change row is the only mutable "current status" the gate panel (M2c) can read.
  - No merge base (unrelated histories) → `conflict` with an empty `conflict_paths` and payload `{"unrelated": true}`. Justification: a merge with no common ancestor cannot be clean, and an empty path list plus the flag distinguishes it from a computed file list.
  - Session reference validation: `session_ulid` NULL is fine; non-NULL must name a session row in the SAME repo (any lifecycle/quarantine state — quarantine governs transcript reads, not review authorship); existence is checked, content never is. Anything else → `Invalid`. Justification: §6.2 ties the review to "the agent session that produced the review" — repo-scoped existence is the checkable half without leaking cross-repo sessions.
  - Thread anchoring: `side: base` resolves blobs against the anchor revision's `merge_base_sha`, `side: head` against its `head_sha`. A thread is outdated iff its anchor revision is not the change's current revision AND (file missing on that side, or `end_line` exceeds the file's line count, or the blob is binary). Content-equality is NOT checked. Justification: this is exactly "anchor lines no longer exist in the current revision", computable from one `blob_bytes` call with no diffing.
  - Diff caps: reuse the existing `range_diff(merge_base, head, max_lines, max_bytes)` call shape from the compare page (same constants, verify in-task); files beyond the caps and binary files (existing `classify` NUL sniff) are listed with name + status and NO hunks, plus a `truncated: true` flag. Justification: one cap policy for every diff surface, and binary content never reaches the renderer.
  - **Pipeline gap the current code cannot express (§8.2 `-o` options):** `GIT_PUSH_OPTION_*` env exists ONLY in the `pre-receive` hook process; the in-process post-RPC scan task never sees it, and the RPC body is an opaque byte stream the web layer must not parse. Carry mechanism: pre-receive writes one JSON sidecar per accepted `refs/for` line to `<gitdir>/starforge-push-options/<new-sha>.json` (`{repo_id, user_id, base, topic, trail, title}`); the scan consumes (deletes) sidecars for SHAs it ingests, falls back to no-options semantics when missing, and reaps files older than 1h. Justification: sidecars are crash-safe (orphans are inert JSON), need no DB in the hook process, and survive the pre/post-receive process boundary that env cannot cross.
  - The accepted `refs/for/<base>/<topic>` ref IS physically created by receive-pack, then deleted by the scan (`update-ref -d`) after ingestion; `transfer.hideRefs` hides `refs/for` and `refs/trails` from advertisements so default clones never fetch them (§8.3). Justification: git has no "accept but don't store" switch — delete-after-record is the only honest implementation of "the `refs/for` ref itself is not stored".
  - Push-options capability: the server must send `receive.advertisePushOptions=true` (else clients never transmit `-o`), injected via `GIT_CONFIG_*` env through the existing `spawn_rpc` `env` param — no signature change. Justification: stateless-RPC spawns share one builder; env injection is the seam the codebase already documents ("`env` reaches the repository's hooks").
  - Duplicate `-o` keys, unknown `-o` keys, `trail=0`/non-numeric, empty/overlong `title=`, or options on a push with no `refs/for` line all REJECT the whole push. Justification: silently ignoring addressing (`trail=`) misfiles human intent; fail-closed is the only safe default.
  - Anonymous `refs/for` pushes are rejected even on `anyone_with_read` repos (authentication required; identity defines update-scoping). A `read` collaborator IS a member (explicit grant). Justification: "same user" update matching is meaningless without a user, and member means explicit grant per the glossary.
  - Numbering uses `change_sequences(trail_id, next_k)` and `revision_sequences(change_id, next_r)` tables with the M2a 0011 row-lock pattern. Justification: same race-free, both-engine allocator the codebase already proves; `k`/`r` start at 1 per parent.
  - Review authorship: any ≥ `Read` user may submit any verdict; gate counting (write+ only) is M2c's problem. Dismiss needs triage+. Resolve needs thread author or triage+. `branch`-change creation needs triage+ (curation, like labels). Change close/reopen needs creator-with-≥-`Read` or triage+ (mirrors the M2a trail-edit rule). `merged`/`open→merged` transitions are rejected everywhere (M2c owns them). `refs_for_access` changes need maintain+ via the existing repo-settings power. Justification: each threshold mirrors its M2a analogue (read = discuss, triage = curate, maintain = configure, merge path owns `merged`).

---

## File Structure

```
crates/starforged-db/
  migrations/sqlite/0012_changes.sql      new tables + change/revision sequences + repos.refs_for_access (G1)
  migrations/postgres/0012_changes.sql    lockstep twin (G1)
  src/changes.rs                          ChangeRow/RevisionRow/ReviewRow/ThreadRow/ThreadCommentRow + query fns + sequence alloc (G1)
  src/repos.rs                            refs_for_access get/set (G1)
  src/lib.rs                              `pub mod changes;` (G1)
crates/starforged-git/
  src/refpolicy.rs                        ForRef/PushOptions parsing, refs/for policy check, is_oid (G2)
  src/write.rs                            set_ref/delete_ref under refs/trails + refs/for delete (G2)
  src/http.rs                             receive_pack_env() GIT_CONFIG_* helper (G2)
  src/lib.rs                              re-exports if needed (G2)
crates/starforged/
  src/hook.rs                             env identity, option parsing, sidecar write (G2)
crates/starforged-core/
  src/changes.rs                          push ingestion record_agit_push/record_branch_move + mergeability worker (G3), user-facing service (G4)
  src/jobs.rs                             Job::ChangeMergeability + worker arm (G3)
  src/lib.rs                              `pub mod changes;` (G3)
crates/starforged-web/
  src/githttp.rs                          receive-pack auth relax, advertisement env, post-RPC change ingestion scan (G3)
  src/pages/changes.rs                    change page, revision picker, review/thread handlers (G5)
  src/pages/trails.rs                     changes section on trail page + branch-change form (G5)
  src/lib.rs                              route table (G5)
  templates/change.html                   header, revision selector, diff, review form, threads, disabled merge button (G5)
  templates/trail.html                    changes section (G5)
crates/starforged-api/
  src/changes.rs                          list/create/get/diff/reviews/threads/state handlers + DTOs (G4)
  src/repos.rs                            PATCH refs_for_access (G4)
  src/lib.rs                              route table (G4)
crates/starforged/
  tests/push_changes.rs                   real push→change→revision→recompute incl. -o options (G3, extended G6)
  tests/api_changes.rs                    API status matrix + JSON shape + pagination (G4, extended G6)
  tests/web_changes.rs                    web 404/XSS/CSRF/outdated/disabled-merge matrix (G5, extended G6)
  tests/common/mod.rs                     change/review/thread fixture helpers (G6)
README.md                                 Changes/reviews/refs/for subsection (G6)
```

---

### Task G1: Schema + migrations + `starforged-db` repos

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0012_changes.sql`, `crates/starforged-db/migrations/postgres/0012_changes.sql`, `crates/starforged-db/src/changes.rs`
- Modify: `crates/starforged-db/src/repos.rs` (`refs_for_access` get/set), `crates/starforged-db/src/lib.rs` (`pub mod changes;`)

**Interfaces:**
- Produces (all `pub`, cross-task contract — do not rename):
  ```rust
  // crates/starforged-db/src/changes.rs
  pub struct ChangeRow { pub id: i64, pub trail_id: i64, pub number: i64, pub kind: String,
      pub head_branch: Option<String>, pub base_branch: String, pub current_revision_id: Option<i64>,
      pub state: String, pub merge_method: Option<String>, pub merge_commit: Option<String>,
      pub creator_id: i64, pub created_at: i64, pub updated_at: i64,
      pub mergeability: String, pub conflict_paths: String } // conflict_paths: "\n"-joined, "" when clean/unknown
  pub struct RevisionRow { pub id: i64, pub change_id: i64, pub number: i64, pub head_sha: String,
      pub base_sha: String, pub merge_base_sha: Option<String>, pub pusher_id: Option<i64>,
      pub created_at: i64, pub mergeability: String, pub conflict_paths: String }
  pub struct ReviewRow { pub id: i64, pub change_id: i64, pub revision_id: i64, pub author_id: i64,
      pub verdict: String, pub body: String, pub session_ulid: Option<String>,
      pub state: String, pub created_at: i64 }
  pub struct ThreadRow { pub id: i64, pub change_id: i64, pub anchor_revision_id: i64, pub path: String,
      pub side: String, pub start_line: i64, pub end_line: i64, pub resolved: i64, pub created_at: i64 }
  pub struct ThreadCommentRow { pub id: i64, pub thread_id: i64, pub review_id: Option<i64>,
      pub author_id: i64, pub body: String, pub created_at: i64 }
  pub async fn insert_change(db: &Db, trail_id: i64, kind: &str, head_branch: Option<&str>, base_branch: &str, creator_id: i64, now: i64) -> DbResult<ChangeRow>;
  // Allocates k from change_sequences inside the insert transaction (M2a 0011 pattern); UNIQUE(trail_id, number) is the defensive fallback.
  pub async fn change_by_trail_number(db: &Db, trail_id: i64, k: i64) -> DbResult<Option<ChangeRow>>;
  pub async fn changes_of_trail(db: &Db, trail_id: i64) -> DbResult<Vec<ChangeRow>>; // ORDER BY number ASC
  pub async fn open_agit_change(db: &Db, repo_id: i64, user_id: i64, base: &str, topic: &str, trail_id: Option<i64>) -> DbResult<Option<ChangeRow>>;
  // Joins trails for the repo scope; state = 'open', kind = 'agit'.
  pub async fn set_current_revision(db: &Db, change_id: i64, revision_id: i64, now: i64) -> DbResult<()>;
  pub async fn set_change_state(db: &Db, change_id: i64, state: &str, now: i64) -> DbResult<()>;
  pub async fn set_mergeability(db: &Db, change_id: i64, status: &str, paths: &str) -> DbResult<()>;
  pub async fn insert_revision(db: &Db, change_id: i64, head_sha: &str, base_sha: &str, pusher: Option<i64>, now: i64) -> DbResult<RevisionRow>;
  // Allocates r from revision_sequences; merge_base_sha/mergeability snapshot start NULL/'unknown', filled once by the G3 worker.
  pub async fn revisions_of_change(db: &Db, change_id: i64) -> DbResult<Vec<RevisionRow>>;
  pub async fn revision_by_number(db: &Db, change_id: i64, r: i64) -> DbResult<Option<RevisionRow>>;
  pub async fn set_revision_snapshot(db: &Db, revision_id: i64, merge_base: Option<&str>, status: &str, paths: &str) -> DbResult<()>;
  pub async fn insert_review(db: &Db, change_id: i64, revision_id: i64, author_id: i64, verdict: &str, body: &str, session_ulid: Option<&str>, now: i64) -> DbResult<ReviewRow>;
  pub async fn reviews_of_change(db: &Db, change_id: i64) -> DbResult<Vec<ReviewRow>>;
  pub async fn set_review_state(db: &Db, review_id: i64, state: &str) -> DbResult<()>;
  pub async fn insert_thread(db: &Db, change_id: i64, anchor_revision_id: i64, path: &str, side: &str, start_line: i64, end_line: i64, now: i64) -> DbResult<ThreadRow>;
  pub async fn threads_of_change(db: &Db, change_id: i64) -> DbResult<Vec<ThreadRow>>;
  pub async fn set_thread_resolved(db: &Db, thread_id: i64, resolved: i64) -> DbResult<()>;
  pub async fn insert_thread_comment(db: &Db, thread_id: i64, review_id: Option<i64>, author_id: i64, body: &str, now: i64) -> DbResult<ThreadCommentRow>;
  pub async fn comments_of_thread(db: &Db, thread_id: i64) -> DbResult<Vec<ThreadCommentRow>>;
  // repos.rs additions:
  pub async fn refs_for_access(db: &Db, repo_id: i64) -> DbResult<String>;
  pub async fn set_refs_for_access(db: &Db, repo_id: i64, value: &str) -> DbResult<()>;
  ```
- Schema (both twins): `changes` (`UNIQUE(trail_id, number)`; `kind CHECK IN ('branch','agit','imported')` — `imported` admitted now, never written until M4; `state CHECK IN ('open','merged','closed')` — `merged` admitted now, never written until M2c; `head_branch NULL` for `agit`, `merge_method`/`merge_commit` always NULL in M2b); `revisions` (`UNIQUE(change_id, number)`); `reviews` (`verdict CHECK`, `state CHECK IN ('pending','submitted','dismissed') DEFAULT 'submitted'`, `session_ulid` plain TEXT, no FK — sessions live partly outside the DB-portable core); `review_threads` (`side CHECK IN ('base','head')`, `resolved INTEGER DEFAULT 0`); `review_comments` (`review_id … REFERENCES reviews(id) ON DELETE SET NULL`); `change_sequences(trail_id … PRIMARY KEY … ON DELETE CASCADE, next_k)` / `revision_sequences(change_id … PRIMARY KEY … ON DELETE CASCADE, next_r)` seeded empty (no backfill: no prior rows can exist); `ALTER TABLE repos ADD COLUMN refs_for_access TEXT NOT NULL DEFAULT 'anyone_with_read' CHECK (refs_for_access IN ('anyone_with_read','members'))`; indexes on `(trail_id)`, `(change_id)`, `(trail_id, number)`, `(change_id, number)`.

- [ ] **Step 1: Write the failing db tests.** New `#[cfg(test)] mod tests` in `src/changes.rs` using `crate::testing::TestDb`: two changes in one trail → `k = 1, 2`; a second trail restarts at `1`; two revisions → `r = 1, 2`; duplicate `(trail_id, number)` is a unique violation; `open_agit_change` finds only the matching open row (closed twin ignored, other-user twin ignored, `trail_id`-scoped variant respected); review/thread/comment round-trips; `refs_for_access` defaults to `anyone_with_read` on repo insert and round-trips `members`.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-db changes` — Expected: FAIL (module/table do not exist).
- [ ] **Step 3: Write both migrations + `changes.rs` + `repos.rs` additions.** Follow the 0010/0011 twin style and the `trails.rs` query conventions (`$N` first-appearance order, `i64`, unix seconds).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-db` then the PG gate for the package — Expected: PASS on both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-db
  git commit -m "Add change/review schema with dual migrations and db repos"
  ```

---

### Task G2: Ref policy + pre-receive push options

**Files:**
- Modify: `crates/starforged-git/src/refpolicy.rs`, `crates/starforged-git/src/write.rs`, `crates/starforged-git/src/http.rs`, `crates/starforged-git/src/lib.rs` (re-exports if needed), `crates/starforged/src/hook.rs`

**Interfaces:**
- Produces:
  ```rust
  // crates/starforged-git/src/refpolicy.rs
  pub struct ForRef { pub base: String, pub topic: String }
  /// None when name is not under refs/for/. Syntax-checked only (charset, no empty
  /// segments, no "..", len ≤ 255); base existence is resolved by the caller against refs/heads/.
  pub fn parse_for_ref(name: &str) -> Option<ForRef>; // Some even when base/topic split is ambiguous — see split_for()
  /// Deterministic base/topic split needing the branch list: whole remainder names a branch → (all, default);
  /// else all-but-last must name a branch → (base, last). Returns Err("unknown base branch …") otherwise.
  pub fn split_for(remainder: &str, branches: &[String], default_topic: &str) -> Result<(String, String), String>;
  pub fn default_topic(handle: &str) -> String; // lowercase, [^a-z0-9-_.] → '-', truncate 63, never empty ("topic")
  pub struct PushOptions { pub trail: Option<i64>, pub title: Option<String> }
  /// Reads GIT_PUSH_OPTION_COUNT / GIT_PUSH_OPTION_<i> via get(); rejects unknown keys,
  /// duplicates, trail=0/non-digits, empty or >200-char/multiline title=. Missing count → Ok(default).
  pub fn parse_push_options(count: Option<&str>, get: impl Fn(usize) -> Option<String>) -> Result<PushOptions, String>;
  /// hex SHA (40 or 64 chars) — unifies the two existing private copies.
  pub fn is_oid(s: &str) -> bool;
  pub enum RefKind { Branch, Tag, For(ForRef) }
  /// Pure policy: refs/heads|tags need ≥ Write; refs/for needs ≥ Read AND (anyone_with_read OR member);
  /// refs/trails/* and everything else → Err. Anonymous (user None) → Err for refs/for.
  pub fn check_allowed(name: &str, permission: Option<&str>, is_member: bool, refs_for: &str) -> Result<RefKind, String>;
  // crates/starforged-git/src/write.rs additions (argv-only, blocking-pool callers, validated names):
  pub async fn set_ref(repo: &Path, name: &str, sha: &str) -> Result<(), GitError>; // name must start with "refs/trails/"
  pub async fn delete_ref(repo: &Path, name: &str) -> Result<(), GitError>;        // name must start with "refs/for/" or "refs/trails/"
  // crates/starforged-git/src/http.rs addition:
  pub fn receive_pack_env() -> Vec<(&'static str, String)>; // GIT_CONFIG_COUNT/KEY_n/VALUE_n: receive.advertisePushOptions=true + hideRefs refs/for + refs/trails
  ```
- The exact push-line grammar accepted by pre-receive (binding):
  ```
  pre-receive line ::= <old> SP <new> SP <refname>        (existing parse_line; old/new are 40/64-hex or all-zero)
  refname        ::= "refs/heads/" branch | "refs/tags/" tag | "refs/for/" for-target
  for-target     ::= <base> [ "/" <topic> ]               (base may contain "/")
  base           ::= existing refs/heads/<base> (checked via git; charset: no empty segments, no "..", ≤255)
  topic          ::= 1*63 [A-Za-z0-9-_.], no leading/trailing "." (validated in split_for)
  option         ::= "trail=" 1*19DIGIT (≥1) | "title=" 1*200CHAR (trimmed non-empty, no \n \r)
  ```
  `-o` parsing: read `GIT_PUSH_OPTION_COUNT` (absent = no options); for `i` in `0..count` read `GIT_PUSH_OPTION_<i>`; split each at the first `=`; unknown key / missing `=` / duplicate key / bad value → reject the WHOLE push with `starforge: bad push option …`. Options on a push containing zero `refs/for` lines → reject. Deletion lines (`new` = all-zero) targeting `refs/for/*` → reject (`cannot delete a refs/for pseudo-ref`).
- `hook.rs` pre-receive: reads `STARFORGE_REPO_ID`, `STARFORGE_USER_ID` (empty = anonymous), `STARFORGE_PERMISSION` (`read|triage|write|maintain|admin`), `STARFORGE_IS_MEMBER` (`0|1`), `STARFORGE_REFS_FOR` from env (server snapshot at RPC start; hook never opens the DB); enforces `check_allowed` per line (branch/tag keep the M0 accept — write already enforced by the RPC layer, M3 owns protection); for accepted `refs/for` lines additionally resolves base/topic via `split_for` against the repo's branch list and writes the sidecar `<gitdir>/starforge-push-options/<new-sha>.json` (mode 600; `<new-sha>` must pass `is_oid`). Malformed input, unknown base, or bad options → exit nonzero with `remote: starforge: …` lines (existing stderr convention).

- [ ] **Step 1: Write failing git + hook tests.** `refpolicy.rs` tests: grammar table (valid `refs/for/main`, `refs/for/release/1.x/feat`, default-topic derivation, `split_for` ambiguity cases, option parsing incl. duplicates/unknowns/`trail=0`/multiline title, `check_allowed` matrix incl. anonymous/member/`members`-mode/`refs/trails/*` rejection); `hook.rs` tests extended with env-driven cases (reader pushing `refs/heads/*` still accepted at hook level — RPC layer owns the write gate; reader pushing `refs/for/main/t` accepted + sidecar written; anonymous `refs/for` rejected; bad option rejects). Property test: `default_topic` output always matches the topic charset.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-git -p starforged hook` — Expected: FAIL (new fns/env handling do not exist).
- [ ] **Step 3: Implement.** Keep M0 branch/tag behavior byte-identical; `check()` stays as the no-identity fallback and delegates for non-`refs/for` names.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-git -p starforged` — Expected: PASS. No SQL touched → no PG gate.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  git add crates/starforged-git crates/starforged/src/hook.rs
  git commit -m "Accept refs/for with push options in ref policy and pre-receive"
  ```

---

### Task G3: Post-receive change/revision ingestion + refs + mergeability job

**Files:**
- Create: `crates/starforged/tests/push_changes.rs`
- Modify: `crates/starforged-core/src/changes.rs` (new file: ingestion half), `crates/starforged-core/src/jobs.rs` (`Job::ChangeMergeability` + worker arm), `crates/starforged-core/src/lib.rs`, `crates/starforged-web/src/githttp.rs` (auth relax + advertisement env + scan rewrite)

**Interfaces:**
- Consumes: G1 (all row types + query fns), G2 (`ForRef`, `PushOptions`, `set_ref`/`delete_ref`, `receive_pack_env`, `is_oid`), `read::merge_base`, `diff` helpers (not yet — G4), `Core::enqueue`, timeline insert, existing `list_refs`/`changed_refs`/`new_commits` scan scaffolding.
- Produces:
  ```rust
  // crates/starforged-core/src/changes.rs (G3 half)
  pub struct IngestSidecar { pub base: String, pub topic: String, pub trail: Option<i64>, pub title: Option<String> }
  impl Core {
      /// Agit push: resolve/create trail (opts.trail → must be open in this repo else fall back to new
      /// with timeline note; new trail title = opts.title or tip subject, intent ""), find-or-create the
      /// open (repo, user, base, topic[, trail]) agit change, skip when head SHA is unchanged (returns None),
      /// else insert revision (r = next), point refs/trails/<n>/changes/<k>/{head,rev/<r>}, delete the
      /// refs/for pseudo-ref, write change.open/change.revision timeline rows, enqueue ChangeMergeability.
      /// All git writes on the blocking pool; ref-write failure is logged and replayed by the job, never fatal.
      pub async fn record_agit_push(&self, repo_id: i64, user_id: i64, sc: &IngestSidecar, head_sha: &str, base_tip: &str) -> CoreResult<Option<(i64, i64)>>;
      /// Branch move: for every OPEN branch change with (repo, head_branch), insert a revision when the tip
      /// moved; base moves enqueue ChangeMergeability for open changes targeting the base. No revision on base moves.
      pub async fn record_branch_move(&self, repo_id: i64, branch: &str, old: Option<&str>, new: &str) -> CoreResult<()>;
      /// Worker: merge_base(head, base_tip) → None means unrelated → conflict(empty, unrelated=true);
      /// else `git merge-tree --write-tree <base_tip> <head_sha> <merge_base>` (argv verified in-task against
      /// real git; exit 0 = clean, nonzero = conflict with --name-only paths, capped) → set changes.mergeability
      /// + revision snapshot once + change.mergeability timeline row on transitions.
      pub async fn recompute_mergeability(&self, change_id: i64) -> CoreResult<()>;
  }
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  // jobs.rs addition: Job::ChangeMergeability { change_id: i64 } // kind "change_mergeability", dedupe key per change
  ```
- `githttp.rs` changes: `authorize()` for `ReceivePack` now requires `Permission::Read` + `Scope::RepoRead` (per-ref write power moves into pre-receive via env; branch/tag pushes by non-writers are rejected there, never here). `spawn_rpc` AND `advertisement` for receive-pack pass `receive_pack_env()`. `rpc()` passes hook env `STARFORGE_REPO_ID/USER_ID/PERMISSION/IS_MEMBER/REFS_FOR` (snapshotted from `access`). The post-RPC task becomes `scan_push_changes`: diffs before/after (existing `changed_refs`), ingests each new `refs/for/*` tip via `record_agit_push` (sidecar `<new-sha>.json` if present, else optionless fallback), calls `record_branch_move` for `refs/heads/*` changes, deletes consumed `refs/for` refs, reaps sidecars older than 1h, keeps the trailer scan + maintenance enqueue untouched.
- Quarantine note (binding): unreachable-until-accepted objects are handled by git itself; readers may now upload pack data but cannot make it reachable — pre-receive rejects their branch/tag writes and the scan only creates `refs/trails/*` from accepted pushes.

- [ ] **Step 1: Write the failing push-flow test.** New `crates/starforged/tests/push_changes.rs` with `TestServer` + temp clone (follow `smart_http.rs` push conventions — REAL `git push` over HTTP, never a mocked receive-pack): reader pushes `HEAD:refs/for/main/feat` → change `k=1` + revision `r=1` exist, `refs/trails/<n>/changes/1/{head,rev/1}` resolve to the pushed SHA, `refs/for/main/feat` is gone; second push same base/topic → `r=2`; `-o trail=<n>` targets the trail; `-o title=` names a new trail; member-mode repo rejects a non-member reader push; `refs/trails/…` direct push rejected; anonymous push rejected. Mergeability starts `unknown`, then run the worker entrypoint (same helper the `jobs.rs` tests use) → `clean` with empty paths on a fast-forward fixture.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test push_changes` — Expected: FAIL (scan creates nothing; refs/for rejected).
- [ ] **Step 3: Implement ingestion + job + githttp wiring.** `Core` owns every DB write and timeline row; git ref writes via the G2 helpers on the blocking pool; merge-tree only in the worker (never inline in the scan).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test push_changes` then the PG gate (ingestion writes SQL on both engines) — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-core crates/starforged-web/src/githttp.rs crates/starforged/tests/push_changes.rs
  git commit -m "Ingest refs/for pushes into agit changes with mergeability job"
  ```

---

### Task G4: Service + REST API

**Files:**
- Create: `crates/starforged-api/src/changes.rs`, `crates/starforged/tests/api_changes.rs`
- Modify: `crates/starforged-core/src/changes.rs` (user-facing half), `crates/starforged-api/src/repos.rs` (PATCH `refs_for_access`), `crates/starforged-api/src/lib.rs` (route table)

**Interfaces:**
- Consumes: G1–G3, `Core` permission/`require_repo`/`is_repo_member`, `ApiAuth::require/reader`, `Scope::{RepoRead, TrailWrite, RepoWrite}`, `range_diff` + `merge_base` + `blob_bytes` (thread checks), sessions table (session-ulid existence).
- Produces:
  ```rust
  // crates/starforged-core/src/changes.rs (G4 half)
  pub struct ChangeView { pub trail_number: i64, pub k: i64, pub kind: String, pub head_branch: Option<String>,
      pub base_branch: String, pub current_revision: i64, pub state: String, pub creator_handle: String,
      pub mergeability: String, pub conflict_paths: Vec<String>, pub created_at: i64, pub updated_at: i64 }
  pub struct RevisionView { pub r: i64, pub head_sha: String, pub base_sha: String, pub merge_base_sha: Option<String>,
      pub pusher_handle: Option<String>, pub created_at: i64, pub mergeability: String, pub conflict_paths: Vec<String> }
  pub struct ReviewView { pub id: i64, pub revision: i64, pub author_handle: String, pub verdict: String,
      pub body: String, pub session_ulid: Option<String>, pub state: String, pub created_at: i64 }
  pub struct ThreadView { pub id: i64, pub revision: i64, pub path: String, pub side: String,
      pub start_line: i64, pub end_line: i64, pub resolved: bool, pub outdated: bool, pub comments: Vec<ThreadCommentView> }
  pub struct ThreadCommentView { pub id: i64, pub review_id: Option<i64>, pub author_handle: String, pub body: String, pub created_at: i64 }
  pub struct ChangeDetail { pub change: ChangeView, pub revisions: Vec<RevisionView>, pub selected: RevisionView,
      pub files_truncated: bool, pub reviews: Vec<ReviewView>, pub threads: Vec<ThreadView>,
      pub can_review: bool, pub can_triage: bool, pub can_close: bool }
  impl Core {
      pub async fn create_branch_change(&self, user: &User, owner: &str, repo: &str, trail_n: i64, head: &str, base: &str) -> CoreResult<ChangeView>;
      // triage+; head/base must exist as branches, head != base; writes change.open timeline.
      pub async fn list_changes(&self, viewer: Option<&User>, owner: &str, repo: &str, trail_n: i64) -> CoreResult<Vec<ChangeView>>;
      pub async fn get_change(&self, viewer: Option<&User>, owner: &str, repo: &str, trail_n: i64, k: i64, rev: Option<i64>) -> CoreResult<ChangeDetail>;
      // rev None = current; outdated flags computed per thread (one blob_bytes per distinct side-SHA, capped).
      pub async fn change_diff_files(&self, viewer: Option<&User>, owner: &str, repo: &str, trail_n: i64, k: i64, rev: Option<i64>) -> CoreResult<CommitDiff>; // range_diff(merge_base, head), existing caps
      pub async fn submit_review(&self, user: &User, owner: &str, repo: &str, trail_n: i64, k: i64, r: i64, verdict: &str, body: &str, session: Option<&str>) -> CoreResult<ReviewView>;
      // ≥ Read; verdict ∈ comment|approve|request_changes; body ≤ 64 KiB Markdown; session must exist in repo.
      pub async fn dismiss_review(&self, user: &User, owner: &str, repo: &str, trail_n: i64, k: i64, review_id: i64) -> CoreResult<ReviewView>; // triage+
      pub async fn create_thread(&self, user: &User, owner: &str, repo: &str, trail_n: i64, k: i64, r: i64, path: &str, side: &str, start: i64, end: i64, body: &str) -> CoreResult<ThreadView>;
      // ≥ Read; path ≤ 1024 chars; side ∈ base|head; 1 ≤ start ≤ end, span ≤ 1000; first comment = body.
      pub async fn resolve_thread(&self, user: &User, owner: &str, repo: &str, trail_n: i64, k: i64, thread_id: i64, resolved: bool) -> CoreResult<ThreadView>;
      // thread author or triage+.
      pub async fn add_thread_comment(&self, user: &User, owner: &str, repo: &str, trail_n: i64, k: i64, thread_id: i64, body: &str, review_id: Option<i64>) -> CoreResult<ThreadCommentView>; // ≥ Read
      pub async fn set_change_state(&self, user: &User, owner: &str, repo: &str, trail_n: i64, k: i64, state: &str) -> CoreResult<ChangeView>;
      // open|closed only (merged → Invalid, M2c owns it); creator-with-≥-Read or triage+.
      pub async fn set_refs_for_access(&self, user: &User, owner: &str, repo: &str, value: &str) -> CoreResult<String>; // maintain+
  }
  // crates/starforged-api/src/changes.rs — routes (exact shapes; {owner}/{repo} reuse existing repo path params):
  // GET    /repos/{owner}/{repo}/trails/{n}/changes                              → 200 {"changes": [ChangeJson]}
  // POST   /repos/{owner}/{repo}/trails/{n}/changes                             → 201 ChangeJson   {"kind":"branch","head_branch","base_branch"}
  // GET    /repos/{owner}/{repo}/trails/{n}/changes/{k}[?rev=]                   → 200 ChangeDetailJson
  // GET    /repos/{owner}/{repo}/trails/{n}/changes/{k}/diff[?rev=]              → 200 {"files":[…],"truncated":bool}
  // POST   /repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews                  → 201 ReviewJson   {"revision","verdict","body","session"?}
  // POST   /repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews/{id}/dismiss    → 200 ReviewJson
  // POST   /repos/{owner}/{repo}/trails/{n}/changes/{k}/threads                  → 201 ThreadJson
  // POST   /repos/{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/resolve     → 200 ThreadJson   {"resolved":bool}
  // POST   /repos/{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/comments    → 201 ThreadCommentJson
  // POST   /repos/{owner}/{repo}/trails/{n}/changes/{k}/state                   → 200 ChangeJson   {"state":"open"|"closed"}
  // PATCH  /repos/{owner}/{repo}  (extended body: {"refs_for_access": "anyone_with_read"|"members"})
  ```
- Auth mapping (binding): reads call `auth.reader()?` (bad token → `401`; missing token → anonymous, visibility decides; non-reader → `404` via `Core::NotFound`). Mutations call `auth.require(Scope::TrailWrite)?` (settings change: `Scope::RepoWrite`) then `Core` enforces the repo-permission threshold. `CoreError::Invalid` → `422`, `Conflict` → `409`, all in the `{error:{code,message}}` envelope. Diff `files` entries carry `{path, status, binary, hunks[], truncated}` — binary/capped files ship metadata with empty hunks, never raw bytes.

- [ ] **Step 1: Write failing API tests.** New `crates/starforged/tests/api_changes.rs` with `TestServer`: branch-change create by triage → `201` full shape; by read user → `403`; unknown head branch → `422`; list/get round-trips incl. `?rev=1` after a second push; review submit (all three verdicts) → `201`, bad verdict → `422`, unknown session → `422`; dismiss by triage → `200`, by author → `403`; thread create/resolve/comment round-trip; state close/reopen → `200`, `merged` → `422`; `refs_for_access` PATCH by maintainer → `200`, by writer → `403`; auth matrix (no token private → `404`, bogus → `401`, `repo:read`-only POST → `403`).
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test api_changes` — Expected: FAIL (routes do not exist).
- [ ] **Step 3: Implement service half + handlers + route table.** Canonical shape per `trails.rs`/`sessions.rs`: extract `auth`, `Path`, `Query`/`Json`; reads via `auth.reader()?`, mutations via `auth.require(…)?` + `core.<verb>(&token.user, …)`; leak-guard `NotFound` passes through untouched.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test api_changes` then the PG gate — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-core/src/changes.rs crates/starforged-api crates/starforged/tests/api_changes.rs
  git commit -m "Add change/review/thread service with REST API"
  ```

---

### Task G5: Web change page + reviews/threads

**Files:**
- Create: `crates/starforged-web/src/pages/changes.rs`, `templates/change.html`, `crates/starforged/tests/web_changes.rs`
- Modify: `crates/starforged-web/src/pages/trails.rs` (changes section data), `crates/starforged-web/src/lib.rs` (route table), `templates/trail.html` (changes section + branch-change form)

**Interfaces:**
- Consumes: G4 (`Core` change/review/thread verbs, `ChangeDetail`), `MaybeUser`/`RequireUser`, `verify_csrf` + `_csrf` pattern, `markdown::render` (review/thread bodies only; titles/handles/paths askama-escaped, never `|safe`), `range_diff` rendering via the existing compare diff partial (extract to a shared partial if the compare page does not already expose one — no second renderer), `RepoHead::new(&access, "trails", …)`.
- Produces (routes, all HTML):
  ```
  GET  /{owner}/{repo}/trails/{n}                         trail page gains Changes section (list + triage-gated branch-change form)
  POST /{owner}/{repo}/trails/{n}/changes/new             create branch change (CSRF; triage+)
  GET  /{owner}/{repo}/trails/{n}/changes/{k}[?rev=]      change page: header, revision selector, diff, reviews, threads, gated forms
  POST /{owner}/{repo}/trails/{n}/changes/{k}/reviews    submit review (CSRF; ≥ Read; verdict radio + Markdown body + optional session ULID)
  POST /{owner}/{repo}/trails/{n}/changes/{k}/reviews/{id}/dismiss   (CSRF; triage+)
  POST /{owner}/{repo}/trails/{n}/changes/{k}/threads     new thread + first comment (CSRF; ≥ Read)
  POST /{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/resolve    (CSRF; author-or-triage)
  POST /{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/comment     (CSRF; ≥ Read)
  POST /{owner}/{repo}/trails/{n}/changes/{k}/state       close/reopen (CSRF; creator-or-triage)
  ```
- Template contract: `change.html` extends `base.html`; revision selector is a `<select>` GET form (`?rev=`) listing `r` + short SHAs + timestamps; diff reuses the compare partial ( capped/binary files render as name + status lines, no hunks); threads render under their file with an `Outdated` badge when `outdated` (anchor revision ≠ current AND lines gone) plus the anchor `r`; review form has three verdict radios defaulting to `comment`; the merge button renders as `<button disabled title="Merging lands in M2c — gates and merge execution are not implemented yet.">Merge</button>` — the LITERAL disabled reason, always disabled, no method selector. `trail.html` gains a Changes section (state + kind + base/topic or head branch + current `r` + mergeability badge per change, linking `…/changes/{k}`). Every mutation form carries `_csrf`; `can_review`/`can_triage`/`can_close` arrive as plain bools from the handler.

- [ ] **Step 1: Write failing web tests.** New `crates/starforged/tests/web_changes.rs` with `TestServer` + `browser()`/`login` helpers: anonymous on private repo → `404` on change page; signed-in reader sees review/thread forms but no dismiss/close controls; triage sees all; POST without `_csrf` → `403`, cross-user token → `403`; XSS corpus (`<script>`, `<img onerror>`, `javascript:`) in review body/thread comment/change title renders escaped-or-stripped (assert bytes contain NO `<script`); `?rev=1` shows the old diff after `r=2` lands; outdated badge appears on a thread anchored to `r=1` whose lines vanished in `r=2`; merge button present, `disabled`, with the literal title text.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_changes` — Expected: FAIL (routes/templates do not exist).
- [ ] **Step 3: Implement pages + templates.** Handlers follow the `trails.rs` page shape (`MaybeUser` reads, `RequireUser` mutations, `verify_csrf`, `Core` verbs, PRG redirects; `Invalid` re-renders `422` with the message).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_changes` — Expected: PASS. Then `TMPDIR=/dev/shm cargo test --workspace`.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-web crates/starforged/tests/web_changes.rs
  git commit -m "Add change page with reviews, threads, and disabled merge button"
  ```

---

### Task G6: Security/e2e sweep incl. real push flow + docs

**Files:**
- Modify: `crates/starforged/tests/push_changes.rs`, `crates/starforged/tests/api_changes.rs`, `crates/starforged/tests/web_changes.rs` (matrix extensions), `crates/starforged/tests/common/mod.rs` (fixture helpers), `README.md` (Changes subsection)
- Create: none (core/db tests extended in place where a gap is found)

**Interfaces:**
- Consumes: G1–G5; `TestServer::{user, token, repo, browser, login, git_url}` + `Scope::{RepoRead, RepoWrite, TrailWrite}`, collaborator grants for the matrix, real `git` CLI pushes (the ONLY push path in tests).
- Produces:
  ```rust
  // crates/starforged/tests/common/mod.rs
  pub async fn change_user(s: &TestServer, handle: &str) -> User;
  pub async fn push_for_ref(work: &StdPath, url: &str, base: &str, topic: Option<&str>, opts: &[(&str, &str)]) -> Output;
  // wraps `git push [-o k=v …] <url> HEAD:refs/for/<base>[/<topic>]`, returning the push output for remote: line assertions
  pub async fn change_fixture(s: &TestServer, owner: &User, repo: &str, trail_n: i64) -> (i64, i64); // (k, r) of a pushed agit change
  ```
- The sweep asserts REAL behavior (rows, refs, status codes, rendered bytes — never tautologies): the full permission matrix per action (push refs/for, create branch change, list/get, review incl. each verdict, dismiss, thread create/resolve/comment, close/reopen, refs_for_access change) × (read/triage/write/maintain/admin/non-member/anonymous) × (public/internal/private) × (`anyone_with_read`/`members`), identical expectations for web and API; state machine (`open→closed→open`, `merged` rejected both layers with the M2c message); option edge cases (`trail=` missing trail → new trail + timeline note, duplicate/unknown options → whole push rejected, optionless push titled from tip subject); update-scoping (same user/base/topic → same `k`; different user or topic → new `k`; closed change → new `k`); idempotent re-push (same SHA → no new `r`); branch-move revision (move head branch → `r+1`; move base → mergeability recomputed, no new `r`); mergeability `clean → conflict` transition on a real conflicting fixture (two branches, overlapping edit, recompute after base moves); outdated-thread lifecycle; disabled-merge literal; XSS corpus + CSRF + cross-token on every new route; one timeline row per mutation with exact kind + parsed JSON payload.
- Docs: `README.md` gains a "Changes, revisions, and reviews (M2b)" subsection (~40 lines, README voice): `refs/for` push flow with `-o` examples, change page, reviews/threads, the merge-button placeholder, the deferred list (checks/gates/merge in M2c, CLI in M2d).

- [ ] **Step 1: Write the failing sweep tests.** Extend the three suites with the matrix + e2e transitions + XSS corpus; add `common/mod.rs` helpers. Push tests use `git push` against the in-process server over HTTP only.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test push_changes --test api_changes --test web_changes` — Expected: FAIL (matrix cases the G2–G5 code gets wrong, or the conflict/outdated transitions).
- [ ] **Step 3: Fix what the matrix finds + write README.** Fix in the owning layer only (policy in `Core`/`refpolicy`, never in handlers). No new features while sweeping — gaps that need design go back to the plan, not into the code.
- [ ] **Step 4: Run the full sweep.** Run: `TMPDIR=/dev/shm cargo test --workspace` then `STARFORGE_TEST_PG=1 scripts/check.sh` — Expected: PASS everything (all prior suites + the sweep on both engines).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged/tests README.md
  git commit -m "Add change push-flow e2e, permission sweep, and docs"
  ```
