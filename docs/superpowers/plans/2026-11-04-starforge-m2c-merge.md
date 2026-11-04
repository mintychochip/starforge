# Starforge M2c (Commit statuses, gates, merge, webhooks) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the merge layer of spec §6.2 on top of the M2b change/review core: dual-engine schema (`checks`, `gate_rules`, `webhooks`, `webhook_deliveries`) via migration `0013_checks_gates.sql`; a commit-status API with combined status; pure-ish gate evaluation over approvals, required contexts, up-to-date, resolved threads, session evidence, and allowed methods; server-side merge execution (`merge-tree --write-tree` + `commit-tree` + `update-ref` CAS, all three methods) with trail-state transitions and recompute triggers; and HMAC-signed webhook delivery with retries. Plus web: gate panel, merge form, statuses docs, hooks settings page.

**Architecture:** No new crates, no new services. `starforged-db` gains `checks.rs` (check/gate/webhook row types + query fns) plus dual migration `0013_checks_gates.sql`. `starforged-git` gains the merge-execution helpers in `write.rs` (`commit_tree`, `update_ref_cas`) and a `contains`/`is_ancestor` helper in `read.rs`, reusing the existing `merge.rs` probe for the up-to-date/clean inputs. `starforged-core` gains `gates.rs` (pure evaluation over loaded rows) and `merge.rs` (method dispatch, message construction, CAS retry, trail transitions), plus `Job::WebhookDelivery` (+ enriching `SessionWebhookOutbox` is out of scope) and recompute-trigger call sites in `changes.rs`. `starforged-api` gains `statuses.rs` (status + combined-status), merge/gate endpoints on `changes.rs`, and `webhooks.rs` (CRUD). `starforged-web` gains the gate panel + merge form on the change page (`pages/changes.rs` + `templates/change.html`), a hooks settings page (`pages/repo_settings.rs` or new `pages/webhooks.rs`), and a statuses doc section.

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8 (existing), sqlx `Any` (SQLite + Postgres, `$N` placeholders), askama + comrak/ammonia via the existing `starforged-web/src/markdown.rs`, git subprocesses only through `starforged-git` (`command::git()` hermetic env, blocking pool, timeouts), `reqwest` (existing dep — verify in-task; delivery worker only) + HMAC-SHA256 via existing crypto deps (verify in-task, add only if absent), real `git` CLI in tests (in-process `TestServer`, temp repos).

**Spec:** §6.2 (Check, Gate rules, GateReport, merge methods, Trail `merged` transitions, timeline kinds for checks/gates/merge), §6.5 (audit: every status change, gate-rule change, merge, webhook change audited), §8.4 (server-side merge: `merge-tree --write-tree`, `commit-tree`, `update-ref` CAS, trailers, recompute triggers), §10.1 (change page gate panel + merge form; repo hooks settings), §10.4 (statuses API, combined status, webhooks API), §13 (real-git merge tests incl. conflict + fast-forward-only, security sweep).

**§6.2/§8.4 gaps this plan deliberately cannot express yet (deferred, not built):** CLI `trail merge` (M2d owns it; API + web only here), search (`merged`-state list filters beyond the trail-page badge), pull/push mirrors, OIDC, SSH, per-context `required: false` soft gates, check-run retries/re-requested events, deployment/status environments, webhook event filtering per hook beyond all-events, signature rotation.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** every touched crate stays `AGPL-3.0-or-later` (`license.workspace = true`). No new crates.
- **Dependencies:** prefer existing deps only. `reqwest` for delivery and an HMAC-SHA256 primitive must be verified in-task (`cargo tree`); add a crate only if no workspace dep can sign/deliver, and then one minimal crate with justification in the commit message.
- **Migrations:** schema lands as `0013_checks_gates.sql` in BOTH `crates/starforged-db/migrations/sqlite/` and `.../postgres/`, kept in lockstep. Only types/SQL valid on both engines (`$N` placeholders numbered by first appearance, `BIGINT`/`INTEGER` → `i64`, booleans as `0`/`1`, timestamps as unix seconds via `now()`). Same PK idiom as 0010–0012. Forward-only per spec §12; 0013 is purely additive (four new tables, no column changes), so upgrade is a restart. Verify with `scripts/check.sh` AND the `STARFORGE_TEST_PG=1` gate for every SQL-touching task.
- **No route bypasses `starforged-core`:** API and web handlers authenticate (scope/`require_repo` checks) and delegate; ALL check/gate/merge/webhook logic lives on `Core`. Web handlers never touch `Db`. Gate evaluation at merge time is server-side in `Core::merge_change` — the client-supplied `GateReport` (if any) is never trusted, and a stale report cannot authorize a merge (re-evaluate inside the merge transaction path).
- **Every mutation timeline-audited where §6.2/§6.5 says so:** `check.submitted` (one row per status POST), `change.gate_evaluated` (only on explicit re-evaluate calls, not on every page view), `change.merge` (+ `trail.merged` when the last open change merges), `gate_rule.created/updated/deleted`, `webhook.created/deleted` (+ `webhook.failed` on terminal delivery failure) — exactly one row per mutation, JSON payloads, written in the same `Core` method as the row write. Reads (gate panel render, combined-status GET) write nothing.
- **git-subprocess safety (binding):** every git invocation goes through `command::git()` (hermetic env, no system/global config, prompts off); argv arrays only, never a shell string; SHAs validated as 40/64 lowercase hex (`refpolicy::is_oid`) and refnames validated by prefix + charset before use; branch names resolved through the existing `read::` helpers (never string-interpolated into rev specs); ALL blocking git work on `tokio::task::spawn_blocking` following the `content.rs` precedent; every merge/commit/update-ref call has a 60s timeout and output caps (conflict list ≤ 100 paths / 4 KiB; delivery bodies ≤ 64 KiB).
- **Test tmpdirs:** run suites with `TMPDIR=/dev/shm` where available (all fixtures are `tempfile`-based `TestServer`/temp repos). Fall back to the system temp dir when absent — never `$HOME`, never the repo.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green; SQL touched → also the `STARFORGE_TEST_PG=1` gate before committing.
- **Out of scope (do not build):** CLI `trail merge` (M2d), search, mirrors, OIDC, SSH, per-context soft gates, check retries, deployments, per-event hook subscriptions.
- **Decisions this plan makes where the spec is silent:**
  - Gate-rule matching: `gate_rules.pattern` is a gitignore-style glob over the BASE branch name; NULL/empty pattern matches all branches; when several rules match, ALL matching rules must pass (AND semantics); zero matching rules → gates pass (only mergeability + open/archived checks apply). Justification: AND-of-matching is the only fail-closed composition, and empty-means-all keeps single-rule repos trivial.
  - Required-contexts JSON shape: `required_contexts` TEXT stores a JSON array of exact context-name strings (`["ci/unit","ci/lint"]`); comparison is exact, case-sensitive; `[]`/NULL means no required contexts. `allowed_methods` TEXT stores a JSON array subset of `["merge","squash","fast_forward"]`; NULL/empty means all three allowed. Justification: exact-match arrays are portable across both engines with no JSON operators, and NULL-means-default keeps the settings form simple.
  - Secret encryption for webhooks: reuse the existing `secret_key` pattern — `webhooks.secret_encrypted` stores `v1:<base64(nonce‖ciphertext)>` from the same AEAD/seal helper the mail/oauth secrets use (verify helper name in-task; if none exists, HMAC-store `sha256_hex(secret)` + return-once plaintext is rejected — a recoverable secret is required for signing, so symmetric encryption under the server `secret_key` is the only option). The plaintext secret is shown ONCE at creation, never again; list/get return `has_secret: bool` only. Justification: delivery must re-sign every attempt, so a one-way hash cannot work; server-key AEAD is the codebase's existing recoverable-secret story.
  - Delivery retry policy: reuse `jobs.rs::retry_delay` (1m/5m/30m/2h, max 5 attempts) with per-attempt timeout 10s, then mark the delivery `failed` + write `webhook.failed` timeline. Backoff is attempt-indexed, not event-priority. Justification: one retry schedule for the whole queue — no second policy to tune, and `MAX_ATTEMPTS` already bounds queue growth.
  - Merge CAS retry policy: `update-ref <ref> <new> <expected-old>`; on `old-value-mismatch` re-resolve the base tip ONCE, re-evaluate gates + recompute the merge commit, retry once; second mismatch → `409` with fresh `{base_sha, head_sha, mergeability}`. Only `update-ref` races retry — never the whole gate evaluation loop. Justification: two writers racing the same base converge on the second attempt in the common case; unbounded retries let a hot branch starve the merger.
  - Who may merge: write+ (≥ `Write` repo permission) on non-archived repos; change must be `open`, gates must pass on the CURRENT revision at merge time. Dismissed reviews never count; `comment` verdicts never count. Justification: merge mutates the base branch — same threshold as a direct branch push — and archived repos refuse all mutations per the M2a precedent.

---

## File Structure

```
crates/starforged-db/
  migrations/sqlite/0013_checks_gates.sql     new checks/gate_rules/webhooks/webhook_deliveries (H1)
  migrations/postgres/0013_checks_gates.sql   lockstep twin (H1)
  src/checks.rs                               CheckRow/GateRuleRow/WebhookRow/DeliveryRow + query fns (H1)
  src/lib.rs                                  `pub mod checks;` (H1)
crates/starforged-git/
  src/write.rs                                commit_tree + update_ref_cas helpers (H4)
  src/read.rs                                 is_ancestor/contains helper (H4)
  src/merge.rs                                no change (probe reused; H4 consumes)
crates/starforged-core/
  src/gates.rs                                GateReport/GateResult evaluation (H3)
  src/merge.rs                                MergeRequest/dispatch/trail transitions (H4)
  src/checks.rs                               status CRUD + combined + rules CRUD + webhooks CRUD + enqueue fan-out (H2/H5)
  src/jobs.rs                                 Job::WebhookDelivery + worker arm (H5)
  src/changes.rs                              recompute-trigger call sites (new revision, base move, post-merge) (H4)
  src/lib.rs                                  `pub mod gates; pub mod merge; pub mod checks;` (H2)
crates/starforged-api/
  src/statuses.rs                             status POST/GET + combined-status (H2)
  src/changes.rs                              merge POST + gate GET endpoints (H3/H4)
  src/webhooks.rs                             webhook CRUD (H5)
  src/lib.rs                                  route table (H2/H5)
crates/starforged-web/
  src/pages/changes.rs                        gate panel data + merge handler (H3/H4)
  src/pages/webhooks.rs                       hooks settings page (new) (H5)
  src/lib.rs                                  route table (H4/H5)
  templates/change.html                       gate panel + merge form (H3/H4)
  templates/webhooks.html                     hooks list/create/delete, secret-once banner (H5)
  templates/doc_statuses.html (or docs partial) statuses API doc section (H2)
crates/starforged/
  tests/status_merge.rs                       status→gate→merge e2e, all 3 methods, conflict + ff-only (H6, extends H2–H4)
  tests/webhooks.rs                           delivery HMAC/retry/matrix (H6, extends H5)
  tests/common/mod.rs                         status/gate/merge/webhook fixture helpers (H6)
README.md                                     statuses/gates/merge/webhooks subsection (H6)
```

---

### Task H1: Schema + migrations + `starforged-db` repos

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0013_checks_gates.sql`, `crates/starforged-db/migrations/postgres/0013_checks_gates.sql`, `crates/starforged-db/src/checks.rs`
- Modify: `crates/starforged-db/src/lib.rs` (`pub mod checks;`)

**Interfaces:**
- Produces (all `pub`, cross-task contract — do not rename):
  ```rust
  // crates/starforged-db/src/checks.rs
  pub struct CheckRow { pub id: i64, pub repo_id: i64, pub sha: String, pub context: String,
      pub state: String, pub target_url: Option<String>, pub description: Option<String>,
      pub creator_id: Option<i64>, pub created_at: i64, pub updated_at: i64 }
  pub struct GateRuleRow { pub id: i64, pub repo_id: i64, pub pattern: Option<String>,
      pub required_approvals: i64, pub dismiss_on_push: i64, pub block_on_request_changes: i64,
      pub required_contexts: String, pub require_up_to_date: i64, pub require_threads_resolved: i64,
      pub require_session_evidence: i64, pub allowed_methods: String,
      pub created_at: i64, pub updated_at: i64 }
  pub struct WebhookRow { pub id: i64, pub repo_id: i64, pub url: String, pub secret_encrypted: String,
      pub events: String, pub active: i64, pub last_status: Option<i64>, pub last_error: Option<String>,
      pub created_at: i64 }
  pub struct WebhookDeliveryRow { pub id: i64, pub webhook_id: i64, pub event: String, pub payload: String,
      pub status_code: Option<i64>, pub error: Option<String>, pub delivered_at: i64 }
  pub async fn insert_check(db: &Db, repo_id: i64, sha: &str, context: &str, state: &str, target_url: Option<&str>, description: Option<&str>, creator: Option<i64>, now: i64) -> DbResult<CheckRow>;
  // Upsert on UNIQUE(repo_id, sha, context): insert-or-update state/fields + updated_at.
  pub async fn latest_checks_for_sha(db: &Db, repo_id: i64, sha: &str) -> DbResult<Vec<CheckRow>>; // latest row per context
  pub async fn combined_state(checks: &[CheckRow]) -> &'static str; // error > failure > pending > success (empty → "pending")
  pub async fn insert_gate_rule(db: &Db, repo_id: i64, pattern: Option<&str>, approvals: i64, dismiss_on_push: bool, block_rc: bool, contexts: &str, up_to_date: bool, threads: bool, session_ev: bool, methods: &str, now: i64) -> DbResult<GateRuleRow>;
  pub async fn gate_rules_for_repo(db: &Db, repo_id: i64) -> DbResult<Vec<GateRuleRow>>;
  pub async fn delete_gate_rule(db: &Db, id: i64, repo_id: i64) -> DbResult<bool>;
  pub async fn insert_webhook(db: &Db, repo_id: i64, url: &str, secret_enc: &str, events: &str, now: i64) -> DbResult<WebhookRow>;
  pub async fn webhooks_for_repo(db: &Db, repo_id: i64) -> DbResult<Vec<WebhookRow>>;
  pub async fn delete_webhook(db: &Db, id: i64, repo_id: i64) -> DbResult<bool>;
  pub async fn set_webhook_result(db: &Db, id: i64, status: Option<i64>, error: Option<&str>) -> DbResult<()>;
  pub async fn insert_delivery(db: &Db, webhook_id: i64, event: &str, payload: &str, status: Option<i64>, error: Option<&str>, now: i64) -> DbResult<WebhookDeliveryRow>;
  ```
- Schema (both twins): `checks` (`state CHECK IN ('pending','success','failure','error')`, `UNIQUE(repo_id, sha, context)`, `creator_id … REFERENCES users(id) ON DELETE SET NULL`); `gate_rules` (`required_approvals INTEGER ≥ 0`, flags `0/1`, `required_contexts`/`allowed_methods` TEXT JSON arrays default `'[]'`); `webhooks` (`active INTEGER DEFAULT 1`, `events` TEXT JSON array); `webhook_deliveries` (`webhook_id … REFERENCES webhooks(id) ON DELETE CASCADE`).

- [ ] **Step 1: Write the failing db tests.** New `#[cfg(test)] mod tests` in `src/checks.rs` using `crate::testing::TestDb`: check upsert same `(repo, sha, context)` updates state; `latest_checks_for_sha` returns one row per context; `combined_state` truth table (any error → error, else any failure → failure, else any pending/empty → pending, else success); gate-rule insert/list/delete round-trip; webhook insert/list/delete + delivery insert + `set_webhook_result`.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-db checks` — Expected: FAIL (module/tables do not exist).
- [ ] **Step 3: Write both migrations + `checks.rs`.** Follow the 0012 twin style (`$N` first-appearance order, `i64`, unix seconds).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-db` then the PG gate for the package — Expected: PASS on both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-db
  git commit -m "Add checks, gate rules, and webhooks schema with dual migrations"
  ```

---

### Task H2: Commit status API + combined status

**Files:**
- Create: `crates/starforged-api/src/statuses.rs`, `crates/starforged/tests/status_merge.rs` (skeleton extended in H6)
- Modify: `crates/starforged-core/src/checks.rs` (new file: status half), `crates/starforged-core/src/lib.rs`, `crates/starforged-api/src/lib.rs` (route table)

**Interfaces:**
- Consumes: H1 (all row types + query fns), `Core` permission/`require_repo`, `ApiAuth::require/reader`, `Scope::{RepoRead, RepoWrite}`, audit insert, `refpolicy::is_oid`.
- Produces:
  ```rust
  // crates/starforged-core/src/checks.rs (H2 half)
  pub struct StatusDto { pub sha: String, pub context: String, pub state: String,
      pub target_url: Option<String>, pub description: Option<String>,
      pub creator_handle: Option<String>, pub created_at: i64, pub updated_at: i64 }
  pub struct CombinedDto { pub sha: String, pub state: String, pub statuses: Vec<StatusDto> }
  impl Core {
      /// repo:write + ≥ Write permission; sha must be lowercase-hex; context non-empty ≤ 255;
      /// state ∈ pending|success|failure|error; target_url http(s) ≤ 2048; description ≤ 1024.
      /// Upserts + writes check.submitted timeline + audit + enqueues status fan-out. Archived repo → Refused.
      pub async fn submit_status(&self, user: &User, owner: &str, repo: &str, sha: &str, state: &str, context: &str, target_url: Option<&str>, description: Option<&str>) -> CoreResult<StatusDto>;
      pub async fn list_statuses(&self, viewer: Option<&User>, owner: &str, repo: &str, sha: &str) -> CoreResult<Vec<StatusDto>>;
      pub async fn combined_status(&self, viewer: Option<&User>, owner: &str, repo: &str, sha: &str) -> CoreResult<CombinedDto>;
  }
  // crates/starforged-api/src/statuses.rs — routes:
  // POST /repos/{owner}/{repo}/statuses/{sha}   → 201 StatusJson   {"state","context","target_url"?,"description"?}
  // GET  /repos/{owner}/{repo}/statuses/{sha}   → 200 {"statuses":[…]}
  // GET  /repos/{owner}/{repo}/commits/{sha}/combined-status → 200 {"sha","state","statuses":[…]}
  ```
- Auth mapping (binding): POST calls `auth.require(Scope::RepoWrite)?` then `Core` enforces ≥ `Write`; GETs call `auth.reader()?` (bad token → `401`; missing token → anonymous, visibility decides). `Invalid` → `422` in the `{error:{code,message}}` envelope. Every POST writes one audit row (§6.5).

- [ ] **Step 1: Write the failing API tests.** Extend `status_merge.rs`: submit → `201` full shape; second POST same context overwrites; GET lists latest-per-context; combined aggregates (pending + success → pending; + failure → failure; error dominates); bad sha → `422`; read-user POST → `403`; anonymous GET on private → `404`; audit row exists per POST.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test status_merge` — Expected: FAIL (routes do not exist).
- [ ] **Step 3: Implement service half + handlers + route table.** Canonical shape per `changes.rs`: extract `auth`, `Path`, `Json`; leak-guard `NotFound` passes through untouched.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test status_merge` then the PG gate — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-core/src/checks.rs crates/starforged-api crates/starforged/tests/status_merge.rs
  git commit -m "Add commit status API with combined status"
  ```

---

### Task H3: Gate evaluation + change-page panel

**Files:**
- Create: `crates/starforged-core/src/gates.rs`
- Modify: `crates/starforged-core/src/lib.rs`, `crates/starforged-api/src/changes.rs` (gate GET), `crates/starforged-web/src/pages/changes.rs` (panel data), `templates/change.html` (panel)

**Interfaces:**
- Consumes: H1–H2, M2b `ChangeView`/`RevisionView`/`ReviewView`/`ThreadView`, `read::merge_base`, sessions table (upload existence), `range_diff` mergeability.
- Produces:
  ```rust
  // crates/starforged-core/src/gates.rs
  pub struct GateResult { pub rule_id: Option<i64>, pub pattern: Option<String>, pub passed: bool, pub reasons: Vec<String> }
  pub struct GateReport { pub passed: bool, pub mergeable: bool, pub results: Vec<GateResult>, pub reasons: Vec<String> }
  impl Core {
      /// Pure-ish evaluation (reads DB + git, writes nothing except an optional
      /// change.gate_evaluated timeline row when `record` is true).
      /// Rules: zero matching rules → pass. Per matching rule (ALL must pass):
      /// approvals = submitted approve reviews by write+ authors on the current
      ///   revision (dismiss_on_push=false counts approvals on ANY revision of this
      ///   change; true counts only current-revision approvals) ≥ required_approvals;
      /// block_on_request_changes → no non-dismissed request_changes by write+ on the
      ///   counted scope; required contexts all `success` on head SHA (H2 latest-per-context);
      /// require_up_to_date → merge_base(head, base_tip) == base_tip;
      /// require_threads_resolved → zero unresolved threads on current revision;
      /// require_session_evidence → every commit in merge_base..head carrying a
      ///   Starforge-Session trailer names a session row uploaded to THIS repo
      ///   (any lifecycle state, not quarantined); method ∈ allowed_methods.
      /// Plus always: change open, repo not archived, mergeability == clean.
      pub async fn evaluate_gates(&self, viewer: Option<&User>, owner: &str, repo: &str, trail_n: i64, k: i64, method: Option<&str>, record: bool) -> CoreResult<GateReport>;
  }
  // API: GET /repos/{owner}/{repo}/trails/{n}/changes/{k}/gates[?method=] → 200 GateReportJson
  ```
- Panel contract: per-rule pass/fail badge + human reason strings (from `reasons`), overall banner, method-aware (re-render on method select change via query param). Reads write no timeline rows.

- [ ] **Step 1: Write the failing gate tests.** Core tests (no HTTP): approvals counting (write+ only, dismiss_on_push true/false scopes, dismissed excluded, request_changes blocks), contexts (missing → fail, failure → fail, success → pass), up-to-date (base moved → fail), threads (one open → fail), session evidence (commit without upload → fail; quarantined → fail), method allowlist, multi-rule AND, no-rules pass. API GET shape test.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-core gates` — Expected: FAIL (module does not exist).
- [ ] **Step 3: Implement `gates.rs` + API GET + panel data/template.** Glob matching via an existing workspace pattern dep (verify in-task) or a small `*`/`?` matcher written in-task — no new dep for a 20-line matcher. Session-evidence scan parses trailers from `read::log`/`commit` messages in `merge_base..head`.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-core gates` then `TMPDIR=/dev/shm cargo test -p starforged --test status_merge` — Expected: PASS. PG gate before commit.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-core/src/gates.rs crates/starforged-api/src/changes.rs crates/starforged-web/src/pages/changes.rs templates/change.html
  git commit -m "Add gate evaluation with change-page panel"
  ```

---

### Task H4: Server-side merge + trail state

**Files:**
- Modify: `crates/starforged-git/src/write.rs` (`commit_tree`, `update_ref_cas`), `crates/starforged-git/src/read.rs` (`is_ancestor`), `crates/starforged-core/src/merge.rs` (new file), `crates/starforged-core/src/changes.rs` (recompute triggers), `crates/starforged-core/src/lib.rs`, `crates/starforged-api/src/changes.rs` (merge POST), `crates/starforged-web/src/pages/changes.rs` (merge handler), `templates/change.html` (merge form)

**Interfaces:**
- Consumes: H1–H3, `merge::merge_tree`, M2b `record_branch_move`/`recompute_mergeability`, audit + timeline.
- Produces:
  ```rust
  // crates/starforged-git/src/write.rs additions
  pub async fn commit_tree(repo: &Path, tree: &str, parents: &[&str], message: &str, author: Identity<'_>) -> Result<String, GitError>;
  // argv-only `commit-tree <tree> (-p <parent>)* -m <msg>` with GIT_AUTHOR_* / GIT_COMMITTER_* env; all ids is_oid-checked.
  pub async fn update_ref_cas(repo: &Path, name: &str, new: &str, old: &str) -> Result<bool, GitError>;
  // argv-only `update-ref <name> <new> <old>`; Ok(false) on old-value-mismatch (stderr sniff, verified in-task); name must start with refs/heads/.
  // crates/starforged-git/src/read.rs addition
  pub fn is_ancestor(repo: &Path, ancestor: &str, head: &str) -> Result<bool, GitError>; // `merge-base --is-ancestor`, exit 0/1
  // crates/starforged-core/src/merge.rs
  pub struct MergeRequest { pub method: String } // merge|squash|fast_forward
  pub struct MergeOutcome { pub sha: String, pub method: String }
  impl Core {
      /// Server-side merge (binding): re-resolves base tip + head, re-evaluates gates
      /// AT MERGE TIME (never trusts a client report), refuses archived repos,
      /// closed/merged changes, failing gates, unknown methods. Writes timeline
      /// change.merge (+ trail.merged when the last non-closed change merges) + audit.
      pub async fn merge_change(&self, user: &User, owner: &str, repo: &str, trail_n: i64, k: i64, method: &str) -> CoreResult<MergeOutcome>;
  }
  // API: POST /repos/{owner}/{repo}/trails/{n}/changes/{k}/merge → 200 {"sha","method"} {"method":"merge"|"squash"|"fast_forward"}
  ```
- **Merge algorithm (binding, all git on the blocking pool, 60s timeouts):**
  1. Load change (must be `open`), repo (must not be archived), caller permission (≥ `Write`), current revision head `H`, base branch tip `B` (re-resolved now).
  2. `evaluate_gates(..., method)` fresh; any failure → `Refused` (no write). Unknown `method` → `Invalid`. Fast-forward requested but `is_ancestor(B, H)` false → `Refused` (not a fast-forward).
  3. Build the new commit: `merge` → `merge_tree(B, H)` must be clean → tree `T`; `commit_tree(T, [B, H], msg)` where `msg = "<trail title> (#<n>)\n\nChange: <owner>/<repo>#<n>/<k>\n"`; `squash` → squash tree = tree of `H` (`rev-parse H^{tree}`); `commit_tree(squash_tree, [B], msg)` where `msg = "<trail title> (#<n>)\n\n<squashed subjects, one per commit in merge_base..H, oldest-first>\n\n<distinct Starforge-Session trailers from those commits, one per line>\nChange: <owner>/<repo>#<n>/<k>\n"`; `fast_forward` → new = `H` (no new commit).
  4. Server identity for created commits: author/committer `Starforge <forge@local>` + `Starforge-Trail: <owner>/<repo>#<n>` trailer appended to `msg`. Every created commit carries the trailer.
  5. `update_ref_cas(refs/heads/<base>, new, B)`; on mismatch: re-resolve `B'`, re-evaluate gates once, rebuild the commit, retry once; second mismatch → `Conflict` 409 with `{base_sha: B', head_sha: H, mergeability}`.
  6. On success: set change `state='merged'`, `merge_commit=new`, `merge_method=method`; point `refs/trails/<n>/changes/<k>/head` at `new`; write `change.merge` timeline + audit; enqueue `ChangeMergeability` for every OTHER open change targeting the moved base; if all non-closed changes of the trail are now merged → set trail state `merged` + `trail.merged` timeline.
- Recompute triggers (binding): new revision, base-branch movement (existing M2b path), base-branch deletion (already), AND post-merge (step 6 fan-out). The merged change itself never recomputes.

- [ ] **Step 1: Write the failing merge tests.** Real-git e2e in `status_merge.rs`: approve → success status → gates pass → `merge` moves the branch, merge commit has two parents + `Starforge-Trail` trailer; `squash` single parent + title/number + subjects + distinct session trailers; `fast_forward` only when head contains base (else `422`/`409`); conflict case → gates fail, merge refused; CAS race (move base between gate read and update) retries once then 409s; archived repo refuses; unknown method → `422`; non-write user → `403`; stale-client-report test (gates broken after report, merge still refuses).
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test status_merge merge` — Expected: FAIL (no merge path).
- [ ] **Step 3: Implement git helpers + `merge.rs` + triggers + API/web merge.** Web merge form: method `<select>` limited to the matching rules' allowed methods, submit disabled unless the fresh `GateReport.passed` (server re-checks anyway).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test status_merge` then the PG gate — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-git/src/write.rs crates/starforged-git/src/read.rs crates/starforged-core/src/merge.rs crates/starforged-core/src/changes.rs crates/starforged-api/src/changes.rs crates/starforged-web
  git commit -m "Add server-side merge with CAS retry and trail transitions"
  ```

---

### Task H5: Webhooks (CRUD, fan-out, delivery worker, settings page)

**Files:**
- Create: `crates/starforged-api/src/webhooks.rs`, `crates/starforged-web/src/pages/webhooks.rs`, `templates/webhooks.html`, `crates/starforged/tests/webhooks.rs`
- Modify: `crates/starforged-core/src/checks.rs` (webhook half), `crates/starforged-core/src/jobs.rs` (`Job::WebhookDelivery` + arm), `crates/starforged-api/src/lib.rs`, `crates/starforged-web/src/lib.rs`

**Interfaces:**
- Consumes: H1 (`WebhookRow`/`DeliveryRow` + query fns), server `secret_key` for AEAD, `reqwest` client, `retry_delay`.
- Produces:
  ```rust
  // crates/starforged-core/src/checks.rs (H5 half)
  pub struct WebhookDto { pub id: i64, pub url: String, pub events: Vec<String>, pub active: bool,
      pub last_status: Option<i64>, pub last_error: Option<String>, pub created_at: i64 }
  // secret plaintext returned ONLY from create_webhook (CreateOutcome { dto, secret }); never stored.
  impl Core {
      pub async fn create_webhook(&self, user: &User, owner: &str, repo: &str, url: &str, events: &[String]) -> CoreResult<(WebhookDto, String)>;
      // maintain+; url https? (http only for localhost/test — verify policy in-task); events non-empty, known set.
      pub async fn list_webhooks(&self, viewer: Option<&User>, owner: &str, repo: &str) -> CoreResult<Vec<WebhookDto>>;
      pub async fn delete_webhook(&self, user: &User, owner: &str, repo: &str, id: i64) -> CoreResult<()>;
      /// Enqueues one WebhookDelivery job per active webhook on the repo. Never fails the caller: enqueue errors are logged.
      pub fn fan_out(&self, repo_id: i64, event: &str, payload: &serde_json::Value);
  }
  pub struct WebhookDelivery { pub webhook_id: i64, pub event: String, pub payload: serde_json::Value }
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  // jobs.rs addition: Job::WebhookDelivery { webhook_id: i64, event: String, payload: String }
  // Worker: decrypt secret → POST payload with X-Starforge-Event, X-Starforge-Signature: sha256=<hmac-hex>, 10s timeout → insert webhook_deliveries row + set_webhook_result; failure → retry_delay schedule; terminal → webhook.failed timeline.
  // crates/starforged-api/src/webhooks.rs — routes:
  // GET    /repos/{owner}/{repo}/webhooks          → 200 {"webhooks":[…]}
  // POST   /repos/{owner}/{repo}/webhooks          → 201 WebhookJson + {"secret": "…"} (once)
  // DELETE /repos/{owner}/{repo}/webhooks/{id}     → 204
  ```
- Events (binding): `trail.open`, `change.open`, `change.revision`, `check.submitted`, `change.merge`, `trail.merged`. Payload: `{event, repo, trail?, change?, sha?, at}`. Fan-out call sites: trail creation, agit/branch ingestion, status POST, merge success, trail-merged transition. No delivery blocks the request path (fire-and-forget enqueue after commit).
- Settings page: `GET/POST /{owner}/{repo}/settings/hooks` — list + create (URL + event checkboxes) + delete (CSRF); creation banner shows the secret ONCE; later renders show `has_secret` only.

- [ ] **Step 1: Write the failing webhook tests.** New `webhooks.rs` suite with a local-loopback HTTP sink: create → `201` + secret present once, GET never contains the secret; delete → `204`; event (status POST / merge) → sink receives POST with `X-Starforge-Signature` verifying against the shown secret; failing sink (500/timeout) retries per `retry_delay` then records `failed` delivery + `last_error`; non-maintainer create → `403`.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test webhooks` — Expected: FAIL (routes/jobs do not exist).
- [ ] **Step 3: Implement CRUD + fan-out + worker + settings page.** Secrets encrypted with the server-key AEAD before insert; HMAC-SHA256 over the exact payload bytes.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test webhooks` then the PG gate — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-core/src/checks.rs crates/starforged-core/src/jobs.rs crates/starforged-api/src/webhooks.rs crates/starforged-web
  git commit -m "Add webhooks with signed delivery and retries"
  ```

---

### Task H6: Security/e2e sweep — push → approve → status → gate → merge → webhooks + docs

**Files:**
- Modify: `crates/starforged/tests/status_merge.rs`, `crates/starforged/tests/webhooks.rs`, `crates/starforged/tests/common/mod.rs` (fixture helpers), `README.md` (statuses/gates/merge/webhooks subsection)
- Create: none (core/db tests extended in place where a gap is found)

**Interfaces:**
- Consumes: H1–H5; `TestServer::{user, token, repo, browser, login, git_url}` + `Scope::{RepoRead, RepoWrite, TrailWrite}`, collaborator grants for the matrix, real `git` CLI pushes/merges (the ONLY git path in tests), loopback sink for deliveries.
- Produces:
  ```rust
  // crates/starforged/tests/common/mod.rs
  pub async fn status_fixture(s: &TestServer, owner: &User, repo: &str, sha: &str, context: &str, state: &str);
  pub async fn gate_rule_fixture(s: &TestServer, owner: &User, repo: &str, pattern: Option<&str>) -> i64;
  pub async fn merge_fixture(s: &TestServer, owner: &User, repo: &str, trail_n: i64, k: i64, method: &str) -> String;
  // pushes a real branch, approves as writer, posts success contexts, merges; returns the merge SHA
  ```
- The sweep asserts REAL behavior (rows, refs, status codes, rendered bytes — never tautologies): full e2e per method (`merge` two-parent + trailer, `squash` message shape + distinct session trailers, `fast_forward` ref equality) ending in branch moved + trailers present + trail `merged`; conflict + ff-only-negative cases; permission matrix per action (status POST, gate read, merge, webhook CRUD) × (read/triage/write/maintain/admin/non-member/anonymous) × (public/internal/private); archived-repo refusals; stale-report merge refusal; signature verification on every delivery kind; retry-then-fail path; XSS corpus on gate reasons/status descriptions/webhook URLs renders escaped-or-stripped.
- Docs: `README.md` gains a "Commit statuses, gates, merge, and webhooks (M2c)" subsection (~40 lines, README voice): status POST/combined example, gate-rule semantics, merge methods + squash message shape, hooks settings + signature verification snippet, the deferred list (CLI merge in M2d, mirrors).

- [ ] **Step 1: Write the failing sweep tests.** Extend both suites with the matrix + all-methods e2e + trailer assertions + signature checks; add `common/mod.rs` helpers. Pushes/merges use real git against the in-process server over HTTP only.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test status_merge --test webhooks` — Expected: FAIL (matrix cases the H2–H5 code gets wrong, or the conflict/trailer transitions).
- [ ] **Step 3: Fix what the matrix finds + write README.** Fix in the owning layer only (policy in `Core`/gates/merge, never in handlers). No new features while sweeping — gaps that need design go back to the plan, not into the code.
- [ ] **Step 4: Run the full sweep.** Run: `TMPDIR=/dev/shm cargo test --workspace` then `STARFORGE_TEST_PG=1 scripts/check.sh` — Expected: PASS everything (all prior suites + the sweep on both engines).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged/tests README.md
  git commit -m "Add merge e2e, permission sweep, and docs"
  ```
