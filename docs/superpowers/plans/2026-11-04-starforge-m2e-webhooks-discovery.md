# Starforge M2e (Webhooks to spec, Trail discovery) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring webhooks to spec §10.4 and give users ways to find the Trails that need them (§10.1).
- **Webhook events:** the five event types `push`, `trail` (opened, updated, ready, merged, closed), `review`, `check`, and `session` (uploaded, quarantined, published), delivered in one documented envelope and signed in `X-Starforge-Signature-256`.
- **Webhook delivery:** a delivery log that records every attempt's request, response, and duration, and redelivery from the API and the repository settings page.
- **Trail discovery:** review requests on Trails; the has-changes and review-requested Trail list filters, plus the missing `merged` state in the web filter; and a dashboard that shows Trails assigned to you, Trails awaiting your review, and your recent sessions.

**Architecture:** No new crates and no new services.
- **`starforged-db`** gains three dual-engine migrations: `0014_webhook_events.sql` rewrites stored subscription names, `0015_webhook_delivery_log.sql` adds delivery-log columns, and `0016_review_requests.sql` adds a new table. It also gains the query fns these need.
- **`starforged-core`**:
  - `webhooks.rs` owns the event model, envelope, headers, the per-attempt log, and redelivery;
  - every emitting mutation calls one typed dispatch entry point;
  - `trails.rs` gains review requests, the new list filters, and the cross-repo dashboard queries;
  - `jobs.rs` hourly cleanup prunes old delivery rows.
- **`starforged-api`** gains delivery list, detail, and redeliver routes, review-request routes, and the new list query params.
- **`starforged-web`** gains a delivery list, delivery detail, and redeliver form on the hooks page; a Reviewers section on the Trail page; the new list filters; and the new dashboard sections.
- **`starforge-cli`** (`MIT OR Apache-2.0`) gains the two new `trail list` filter flags.

**Tech Stack:**
- Rust 1.99.1 (edition 2024).
- axum 0.8 and askama, with escaping by default.
- sqlx `Any` (SQLite plus Postgres, `$N` placeholders).
- The existing `reqwest` delivery client with the SSRF gate (resolve-then-pin, no redirects, 10 s timeout, 64 KiB cap) and the existing `ring` HMAC.
- The real `git` CLI in tests (the in-process `TestServer`, temp repos, and the loopback webhook sink).

**Spec:** §10.4 (webhook events, signature header, delivery log, redelivery), §10.1 (dashboard; Trail list filters for review-requested and has-changes; Trail page shows who is asked to review), §6.4 (session read rules bound the session event payload), §6.5 (audit), §6.2 (Trail, Change, Review).

**Gaps deferred (not built here):**
- **M2f:** the has-sessions list filter, together with the stored Trail↔session links it and the Sessions tab need; Sessions tab; timeline linked sessions and checks; the Trail-page header gate panel; revision-to-revision diffs; per-file viewed state; pending (draft) reviews.
- **Later:** webhook secret rotation, per-hook filtering by action, OpenAPI, mirrors.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide (tests never call `std::env::set_var`); workspace lints inherited.
- **Licenses:** server crates stay `AGPL-3.0-or-later`. `starforge-cli` stays `MIT OR Apache-2.0` and never depends on a `starforged-*` crate. No new third-party dependencies anywhere.
- **Migrations:** each lands in BOTH `crates/starforged-db/migrations/sqlite/` and `.../postgres/`, in lockstep, as `0014`, `0015`, and `0016`, one per task that needs it. Use only SQL valid on both engines: `$N` placeholders numbered by first appearance, `INTEGER`/`BIGINT` → `i64`, booleans as `0`/`1`, unix-second timestamps via `now()`, nullable `ALTER TABLE … ADD COLUMN` or `ADD COLUMN … NOT NULL DEFAULT …`. Migrations are forward-only and are never edited after their task commits.
- **No route bypasses `starforged-core`:** API and web handlers authenticate and delegate. Every permission, validation, and dispatch decision lives on `Core`. Web handlers never touch `Db`.
- **Every mutation is audited exactly once:** each new mutation writes exactly one timeline row, in the same `Core` method as its row write, with these kinds: `trail.review_requested`, `trail.review_request_removed`, `webhook.redelivered`. `webhook.redelivered` also writes an audit row (§6.5: webhook changes are audited). Reads write nothing. Webhook dispatch is fire-and-forget (enqueue only) and never fails the mutation that triggered it.
- **Visibility:** a user who cannot read a repo gets `404`, never `403`, on every new route. Dashboard sections show only Trails and sessions the viewer can read NOW (effective permission, §6.4 for sessions), so losing access hides them immediately.
- **SSRF and secrets (binding, unchanged from M2c):** every delivery, including a redelivery, goes through the existing resolve-then-pin SSRF gate, with no redirects, a 10 s timeout, and the 64 KiB response cap. Hook secrets stay AEAD-sealed and are never logged. Stored request headers include the signature, which is an HMAC of a body the receiver already has, never the secret.
- **Session payloads (binding, §6.4):** session events carry identifiers and state only, never titles, quarantine reasons, prompts, messages, file names, or token counts. A quarantined session is readable only by its uploader and repo admins, while webhooks are created by maintainers.
- **Escaping:** every stored webhook response body and header renders as escaped text. Nothing from a receiver is ever rendered as HTML.
- **Test tmpdirs:** `TMPDIR=/dev/shm`. One cargo build at a time on this machine.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green. Tasks touching SQL (K1, K3, K4, K5) also pass the `STARFORGE_TEST_PG=1` gate.
- **Out of scope (do not build):** everything in the deferred list; webhook event filtering beyond the five types; dual-sending the old signature header; review requests on individual changes; CLI commands for review requests or deliveries.
- **Decisions this plan makes where the spec is silent:**
  - **D1. Wire format.**
    - Every delivery is `POST` with these headers:
      - `Content-Type: application/json`
      - `User-Agent: starforged/<crate version>`
      - `X-Starforge-Event: <event>`
      - `X-Starforge-Delivery: <delivery id>` (stable across retries of one delivery; new on redelivery)
      - `X-Starforge-Signature-256: sha256=<lowercase hex HMAC-SHA256 of the exact body>`
    - The old `X-Starforge-Signature` header is removed: a clean cutover, since nothing has been released.
    - The body is one envelope:
      ```json
      {"event": "trail", "action": "opened", "cause": null, "at": "2026-11-05T10:00:00Z",
       "repository": {"owner": "alice", "name": "proj", "full_name": "alice/proj", "url": "<base>/alice/proj"},
       "sender": {"handle": "alice"},
       "trail": { … }}
      ```
      - `action` and `cause` are always present (string or `null`).
      - `sender` is `null` for system-originated events (auto-dismissal on push, quarantine found at ingest).
      - Exactly one subject key is present, matching `event`: `push`, `trail`, `review`, `check`, or `session`.
    - Justification: one envelope that receivers parse the same way, GitHub-like enough to be familiar, and headers that name the event before the body is parsed.
  - **D2. Subjects.** All timestamps are RFC 3339 UTC; `url`s are absolute web URLs.
    - `push`: `{ref, before, after, created, deleted, pusher}`. It covers `refs/heads/*` and `refs/tags/*` creates, updates, and deletes, one event per ref. `refs/for/*` (reported as `trail` updated) and `refs/trails/*` (server-internal) never emit.
    - `trail`: `{number, title, state, ready, author, url}`, plus `change: {k, revision}` when a change caused the event.
    - `review`: `{id, trail, change, revision, verdict, state, author, body}`.
    - `check`: `{sha, context, state, target_url, description, creator}`.
    - `session`: `{ulid, uploader, agent, lifecycle_state, quarantine_state, visibility}` only (see the session-payload constraint).
  - **D3. Action and cause mapping.**
    - `trail`:
      - created → `opened`; closed → `closed`.
      - The ready flag going false → true → `ready`.
      - The Trail flipping to `merged` → `merged`. The change merge that completes a Trail emits only `merged`, never also `updated`.
      - Everything else that changes a Trail emits `updated`, with `cause` one of `edited` (title/intent), `ready_cleared`, `reopened`, `labeled`, `unlabeled`, `assigned`, `unassigned`, `review_requested`, `review_request_removed`, `change_opened`, `revision_pushed`, `change_merged` (a change merged while others stay open), `change_closed`, `change_reopened`.
    - `review`: `submitted`, `dismissed` (explicit, or automatic on push with `sender: null`).
    - `check`: `action: null`.
    - `push`: `action: null`.
    - `session`: `uploaded` (lifecycle reaches `complete`), `quarantined`, `published`.
    - Justification: the spec fixes the event types and the `trail`/`session` action lists, and `cause` keeps `updated` useful without inventing new actions.
  - **D4. Subscriptions.**
    - A hook's `events` is a subset of `["push","trail","review","check","session"]`; empty means all.
    - Unknown names are a `422` on create.
    - Migration 0014 rewrites the legacy stored names with a portable `REPLACE` chain:
      - `trail.opened`, `trail.closed`, `change.opened`, `revision.pushed`, `change.merged` → `trail`;
      - `review.submitted` → `review`;
      - `status.updated` → `check`.
    - The read path de-duplicates.
    - Justification: existing subscribers keep receiving what they asked for, with no dual-name support in code.
  - **D5. Delivery log.**
    - Every attempt writes one `webhook_deliveries` row: success, HTTP error, transport error, and SSRF denial alike.
    - Each row stores the delivery id, attempt number, event, action, request headers (JSON object), request body, response status, response headers (JSON), and the response body (the first 16 KiB, UTF-8-lossy, read up to the existing 64 KiB cap for error bodies too). It also stores the error, duration in ms (from request start to response end or failure), the redelivery flag, and the time.
    - The hourly cleanup deletes rows older than 30 days.
    - Justification: the spec's "request, response, and duration", bounded storage, and receivers' bodies never trusted beyond a capped, escaped preview.
  - **D6. Redelivery.**
    - Maintain+ on a non-archived repo, and the hook must be active (else `422`).
    - It re-sends the stored request body of a logged attempt as a NEW delivery: a new delivery id, `redelivery = 1`, a signature recomputed with the hook's current secret, the same SSRF gate, and the normal job retries.
    - It writes `webhook.redelivered` timeline and audit rows.
    - Justification: redelivery exists to replay a missed event exactly; a new id lets receivers de-duplicate.
  - **D7. Review requests.**
    - They are per Trail. Triage+ may add or remove them.
    - The requested user must be a repo member (the assignee rule) and not the Trail's author. At most 10 per Trail. Adding is idempotent.
    - A request is cleared when that user submits any review on any change of the Trail. Clearing writes no extra timeline row; `review.submitted` records it.
    - Justification: the Trail is the collaboration object and the list/dashboard unit, and per-Trail requests mirror assignees exactly.
  - **D8. Filters and dashboard.**
    - The list adds `has_changes=true|false` and `review_requested=<handle>` (an unknown handle gives an empty page, like `assignee`). The web state select gains `merged`. The CLI gains `--has-changes <true|false>` and `--review-requested <handle>`.
    - The dashboard, for signed-in users, adds three sections above the repository list, each showing only items the viewer can read now:
      - "Assigned to you": open Trails, newest updated first, at most 20.
      - "Awaiting your review": open Trails with a pending request for you, at most 20.
      - "Your recent sessions": sessions you uploaded that pass §6.4 for you, newest first, at most 10.
    - The DB fetches up to 100 candidates per section and Core filters by permission, then truncates.
    - Justification: §10.1's dashboard; bounded queries; no cross-repo leak.

---

## File Structure

```
crates/starforged-db/
  migrations/{sqlite,postgres}/0014_webhook_events.sql        legacy subscription rewrite (K1)
  migrations/{sqlite,postgres}/0015_webhook_delivery_log.sql  delivery-log columns (K3)
  migrations/{sqlite,postgres}/0016_review_requests.sql       trail_review_requests (K4)
  src/checks.rs                     delivery-log insert/list/get + prune (K3)
  src/trails.rs                     review-request fns, list filters, dashboard queries (K4, K5)
  src/sessions.rs                   sessions_uploaded_by (K5)
crates/starforged-core/
  src/webhooks.rs                   event model, envelope, headers, per-attempt log, redelivery (K1, K3)
  src/trails.rs, src/changes.rs, src/merge.rs, src/checks.rs, src/ingest.rs, src/rescan.rs
                                    emitter call sites (K1, K2); review requests, filters, dashboard (K4, K5)
  src/jobs.rs                       hourly delivery-row prune (K3)
crates/starforged-web/src/githttp.rs push events for branch/tag creates, updates, deletes (K2)
crates/starforged-api/src/{webhooks,trails,lib}.rs   deliveries + redeliver routes (K3); review requests, filters (K4, K5)
crates/starforged-web/
  src/pages/webhooks.rs + templates/webhooks.html (+ webhook_delivery.html)   delivery log + redeliver (K3)
  src/pages/trails.rs + templates/trail.html, trails.html                      Reviewers section; filters (K4, K5)
  src/pages/dashboard.rs + templates/dashboard.html                            dashboard sections (K5)
crates/starforge-cli/src/{cli.rs, commands/trail/read.rs}                       list filter flags (K5)
crates/starforged/tests/
  webhooks.rs                       event model, emitters, delivery log, redelivery (K1–K3)
  api_trails.rs, web_trails.rs, web_dashboard.rs (new)                          review requests, filters, dashboard (K4, K5)
  web_discovery_security.rs (new)   sweep (K6)
README.md                           webhooks + discovery docs (K1, K3, K6)
```

---

### Task K1: Webhook event model, envelope, and headers

**Files:**
- Modify: `crates/starforged-core/src/webhooks.rs`, plus every existing dispatch call site (`trails.rs` create and close, `changes.rs` change opened, revision pushed, and review submitted, `merge.rs` `finish_merge`, `checks.rs` `submit_status`). Also `crates/starforged-api/src/webhooks.rs` (validation messages), the event list on `crates/starforged-web/src/pages/webhooks.rs` + `templates/webhooks.html`, and `README.md` (the webhooks paragraph).
- Create: `crates/starforged-db/migrations/{sqlite,postgres}/0014_webhook_events.sql`.
- Tests: `crates/starforged/tests/webhooks.rs`, `crates/starforged/tests/web_merge_security.rs` (header name), and a db test that applies the 0014 statement to legacy rows.

**Interfaces:**
- Produces:
  ```rust
  // crates/starforged-core/src/webhooks.rs
  pub const EVENT_TYPES: [&str; 5] = ["push", "trail", "review", "check", "session"];
  /// One webhook event (D1–D3). `subject` is the JSON for the key named by `event`.
  pub struct HookEvent {
      pub event: &'static str,           // one of EVENT_TYPES
      pub action: Option<&'static str>,  // D3
      pub cause: Option<&'static str>,   // D3, only with action "updated"
      pub sender: Option<String>,        // handle; None for system-originated
      pub subject: serde_json::Value,
  }
  impl Core {
      /// Builds the D1 envelope (at, repository, sender, the subject under its key)
      /// and enqueues one delivery per active hook of the repo subscribed to
      /// `ev.event` (empty subscription = all). Never fails the caller: errors warn-log.
      pub async fn dispatch_event(&self, repo_id: i64, ev: HookEvent);
  }
  ```
- The old string-named `dispatch(repo_id, "<legacy name>", payload)` entry point and every legacy event name are removed (clean cutover). All existing sites move to `dispatch_event` with the D3 mapping:
  - trail created → `trail`/`opened`;
  - closed → `trail`/`closed`;
  - change opened → `trail`/`updated` `change_opened`;
  - revision pushed → `trail`/`updated` `revision_pushed`;
  - review submitted → `review`/`submitted`;
  - status → `check`;
  - change merged → `trail`/`merged` if the Trail flipped to merged, else `trail`/`updated` `change_merged`.
- Delivery headers per D1. `X-Starforge-Delivery` keeps today's job-id value.

- [ ] **Step 1: Write the failing tests.**
  - Each existing emitter delivers the D1 envelope with the right event, action, cause, sender, and subject key, and its signature verifies under `X-Starforge-Signature-256` using `sha256=`.
  - The old `X-Starforge-Signature` header is absent.
  - `User-Agent` starts with `starforged/`.
  - Hook create with `events: ["trail.opened"]` is `422`; `["trail","check"]` is accepted.
  - A hook subscribed to `["check"]` receives a status event and not a Trail event.
  - The db test inserts a webhook whose `events` is `["trail.opened","change.merged","review.submitted","status.updated"]`, executes the 0014 SQL text, and reads the events back normalized to `["trail","review","check"]`. A second run is a no-op.
- [ ] **Step 2: Run them to verify failure.** Run `TMPDIR=/dev/shm cargo test -p starforged --test webhooks` and `TMPDIR=/dev/shm cargo test -p starforged-db checks`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the Step 2 commands plus `TMPDIR=/dev/shm cargo test -p starforged --test web_merge_security --test merge_changes` and `cargo clippy -p starforged-db -p starforged-core -p starforged-api -p starforged-web -p starforged --all-targets -- -D warnings`. Expected: PASS.
- [ ] **Step 5: Commit** (SQL touched, so the PG gate runs first).
  ```bash
  git commit -m "Deliver webhooks as spec event types with the signature-256 header"
  ```

---

### Task K2: The remaining webhook events (push, trail updates, review dismissed, session)

**Files:**
- Modify:
  - `crates/starforged-core/src/trails.rs` (edit, ready, state reopen, labels, assignees);
  - `crates/starforged-core/src/changes.rs` (change close/reopen; review dismissal, explicit and automatic);
  - `crates/starforged-core/src/ingest.rs` and `rescan.rs` (session uploaded, quarantined, published);
  - a new `Core` method recording a push, called from `crates/starforged-web/src/githttp.rs` post-receive for every `refs/heads/*` and `refs/tags/*` update (create, update, delete).
- Tests: `crates/starforged/tests/webhooks.rs`.

**Interfaces:**
- Consumes: K1's `dispatch_event` and `HookEvent`.
- Produces:
  ```rust
  // crates/starforged-core (location: next to record_branch_move)
  pub struct RefUpdate { pub name: String, pub old: String, pub new: String } // full refname; zero-oid for create/delete
  impl Core {
      /// Emits one `push` event per heads/tags update (D2). Skips refs/for/* and refs/trails/*.
      /// Does not replace record_branch_move's existing work; githttp calls both.
      pub async fn record_push(&self, repo_id: i64, pusher: Option<&User>, updates: &[RefUpdate]);
  }
  ```
- Every D3 `trail` cause listed in K1's interface but not yet emitted gets emitted, in the same Core method that writes its timeline row:
  - `edited`, `ready`, `ready_cleared`, `reopened`;
  - `labeled`, `unlabeled`, `assigned`, `unassigned`;
  - `change_closed`, `change_reopened`.

  `review_requested` and `review_request_removed` arrive with K4.
- **`review`/`dismissed`:** from explicit dismissal (sender = the dismisser) and from the automatic dismiss-on-push (sender `null`).
- **`session`:** each uses the D2 identifier-and-state subject:
  - `uploaded` when a session's lifecycle reaches `complete`;
  - `quarantined` when a quarantine hit is applied, whether at ingest or on rescan;
  - `published` when a session is published.

- [ ] **Step 1: Write the failing tests.** One test per new emitter asserts event, action, cause, sender, and subject:
  - **Push:** a branch create, update, and delete and a tag push each emit `push` with the correct `before`/`after`/`created`/`deleted`. A `refs/for` push emits `trail` (opened, or updated with `change_opened`) and never `push`. A server-side trail-ref update never emits `push`.
  - **Trail edits:** title and intent edits, the ready flag set then cleared, reopen, label add and remove, assignee add and remove, and change close and reopen.
  - **Review:** explicit dismissal and dismiss-on-push.
  - **Session:** upload to complete, quarantine at ingest (a fixture segment containing a high-confidence secret), and publish on a public repo. Each session payload contains none of the session's title, the quarantine reason, or any transcript text; assert by searching the raw body for the title and reason strings.
- [ ] **Step 2: Run them to verify failure.** Run `TMPDIR=/dev/shm cargo test -p starforged --test webhooks`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run `TMPDIR=/dev/shm cargo test -p starforged --test webhooks --test push_changes --test smart_http`, `TMPDIR=/dev/shm cargo test -p starforged-core`, and clippy for the touched crates. Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  git commit -m "Emit push, trail update, review dismissal, and session webhooks"
  ```

---

### Task K3: Delivery log and redelivery

**Files:**
- Create: `crates/starforged-db/migrations/{sqlite,postgres}/0015_webhook_delivery_log.sql` and `crates/starforged-web/templates/webhook_delivery.html`.
- Modify:
  - `crates/starforged-db/src/checks.rs`;
  - `crates/starforged-core/src/webhooks.rs` (per-attempt rows, redelivery) and `jobs.rs` (prune);
  - `crates/starforged-api/src/webhooks.rs` and `lib.rs`;
  - `crates/starforged-web/src/pages/webhooks.rs`, `templates/webhooks.html`, and `src/lib.rs`;
  - `README.md`.
- Tests: `crates/starforged/tests/webhooks.rs`, a db unit test, and a web test.

**Interfaces:**
- Produces:
  ```sql
  -- 0015 (both engines): ALTER TABLE webhook_deliveries ADD COLUMN …
  -- delivery_id TEXT, attempt INTEGER, action TEXT, request_headers TEXT, response_headers TEXT,
  -- response_body TEXT, duration_ms INTEGER, redelivery INTEGER NOT NULL DEFAULT 0
  -- (payload = the request body, status_code, error, delivered_at already exist)
  ```
  ```rust
  impl Core {
      /// Maintain+; newest first; at most `limit` (1–100, default 20).
      pub async fn list_deliveries(&self, user: &User, owner: &str, repo: &str, hook_id: i64, limit: Option<i64>) -> CoreResult<Vec<DeliverySummary>>;
      /// Maintain+; full request and response for one logged attempt of this hook (another hook's id → NotFound).
      pub async fn get_delivery(&self, user: &User, owner: &str, repo: &str, hook_id: i64, delivery_row: i64) -> CoreResult<DeliveryDetail>;
      /// D6. Returns the new delivery id.
      pub async fn redeliver(&self, user: &User, owner: &str, repo: &str, hook_id: i64, delivery_row: i64) -> CoreResult<String>;
  }
  ```
  ```
  GET  /api/v1/repos/{owner}/{repo}/hooks/{id}/deliveries[?limit=]                 → 200 {"deliveries":[summary…]}
  GET  /api/v1/repos/{owner}/{repo}/hooks/{id}/deliveries/{row}                    → 200 detail
  POST /api/v1/repos/{owner}/{repo}/hooks/{id}/deliveries/{row}/redeliver          → 202 {"delivery_id"}
  ```
  - Auth: `Scope::RepoWrite`, then Core ≥ Maintain, as for hook CRUD today. Non-readers get `404`.
  - `summary` = `{id, delivery_id, attempt, event, action, status_code, error, duration_ms, redelivery, delivered_at}`.
  - `detail` = summary + `{request_headers, request_body, response_headers, response_body}`.
- **Web:** under each hook, the last 20 attempts (time, event/action, status or error, duration, a redelivery marker). Each links to `/{owner}/{repo}/settings/hooks/{id}/deliveries/{row}`, which shows the request headers and body and the response status, headers, and body, all escaped, plus a Redeliver form (CSRF, maintain+, 303 back with a flash naming the new delivery id).

- [ ] **Step 1: Write the failing tests.**
  - A delivery that fails twice, then succeeds, writes 3 rows with attempts 1, 2, 3 and one delivery id. Each row has request headers (including `X-Starforge-Signature-256`), the request body, the response status, a response body (≤ 16 KiB stored; the sink returns 20 KiB), and `duration_ms` ≥ 0.
  - An SSRF-denied hook writes one row with an error and no status.
  - Redeliver gives a 202 with a new id; the sink receives the identical body under a new `X-Starforge-Delivery`, its signature verifies, and the row has `redelivery = 1`. An inactive hook gives 422, an archived repo 422, and a below-maintain user 403.
  - Exactly one `webhook.redelivered` timeline row and one audit row are written per redelivery.
  - The prune deletes rows older than 30 days and keeps newer ones.
  - The web detail page renders a `<script>` response body escaped.
  - The redeliver form without CSRF gives 403.
- [ ] **Step 2: Run them to verify failure.** Run `TMPDIR=/dev/shm cargo test -p starforged --test webhooks`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run `TMPDIR=/dev/shm cargo test -p starforged --test webhooks --test web_merge_security`, `TMPDIR=/dev/shm cargo test -p starforged-db checks`, and clippy for the touched crates. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first).
  ```bash
  git commit -m "Log every webhook attempt and allow redelivery"
  ```

---

### Task K4: Review requests

**Files:**
- Create: `crates/starforged-db/migrations/{sqlite,postgres}/0016_review_requests.sql`.
- Modify: `crates/starforged-db/src/trails.rs`, `crates/starforged-core/src/trails.rs` (requests and trail views) and `changes.rs` (clearing on review), `crates/starforged-api/src/trails.rs` and `lib.rs`, `crates/starforged-web/src/pages/trails.rs`, `templates/trail.html`, and `src/lib.rs`.
- Tests: `crates/starforged/tests/api_trails.rs`, `crates/starforged/tests/web_trails.rs`, and a db unit test.

**Interfaces:**
- Mirror the assignee implementation exactly (table shape, db fns, Core permission and members-only checks, idempotency, timeline, API route shape, web form). Read it first: `0010_trails.sql` assignees, `db/trails.rs` assignee fns, `core/trails.rs` `add_assignee`/`remove_assignee`, `api/trails.rs` assignee routes, and `templates/trail.html`'s assignees section.
- Produces:
  ```sql
  -- 0016: trail_review_requests (trail_id → trails ON DELETE CASCADE, user_id → users ON DELETE CASCADE,
  --       requested_by → users ON DELETE SET NULL, created_at, PRIMARY KEY (trail_id, user_id))
  ```
  ```rust
  impl Core {
      /// D7. Triage+; the requested user must be a member and not the Trail author; ≤ 10; idempotent.
      /// Writes `trail.review_requested`; dispatches trail/updated cause review_requested.
      pub async fn request_review(&self, user: &User, owner: &str, repo: &str, n: i64, handle: &str) -> CoreResult<TrailView>;
      /// Triage+; idempotent. Writes `trail.review_request_removed`; dispatches trail/updated cause review_request_removed.
      pub async fn remove_review_request(&self, user: &User, owner: &str, repo: &str, n: i64, handle: &str) -> CoreResult<TrailView>;
  }
  // TrailView gains `review_requests: Vec<String>` (handles); the trail JSON gains "review_requests": [...].
  // Core::submit_review deletes the reviewer's pending request on that Trail (D7).
  ```
- API: the same verbs and path shape as assignees, under `…/trails/{n}/review-requests/{handle}`.
- Web: a "Reviewers" section beside "Assignees" on the Trail page, with add and remove forms (triage+, CSRF).

- [ ] **Step 1: Write the failing tests.**
  - A triage user requests bob, and the trail JSON lists bob.
  - Requesting is idempotent.
  - Requesting a non-member, an unknown handle, or the author gives 422.
  - An 11th request gives 422.
  - A read user gets 403; a non-reader gets 404.
  - Bob submits a review on a change of the Trail → his request is gone; others remain.
  - Removing works.
  - Exactly one timeline row per add and per remove, and none for idempotent repeats.
  - With a `trail`-subscribed hook, add and remove each deliver `trail`/`updated` with the matching cause.
  - Web: the form round trip gives 303, a forged CSRF gives 403, and a read user sees no forms.
- [ ] **Step 2: Run them to verify failure.** Run `TMPDIR=/dev/shm cargo test -p starforged --test api_trails --test web_trails`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus `TMPDIR=/dev/shm cargo test -p starforged-db trails --test webhooks` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first).
  ```bash
  git commit -m "Add review requests to Trails"
  ```

---

### Task K5: Trail list filters and the dashboard

**Files:**
- Create: `crates/starforged/tests/web_dashboard.rs`.
- Modify:
  - `crates/starforged-db/src/trails.rs` and `sessions.rs`;
  - `crates/starforged-core/src/trails.rs` (filters, `dashboard_trails`), plus a session-listing fn beside the §6.4 read rules in `core/read.rs`;
  - `crates/starforged-api/src/trails.rs`;
  - `crates/starforged-web/src/pages/trails.rs`, `templates/trails.html`, `pages/dashboard.rs`, and `templates/dashboard.html`;
  - `crates/starforge-cli/src/cli.rs` and `commands/trail/read.rs`;
  - tests: `crates/starforged/tests/api_trails.rs`, `web_trails.rs`, and `crates/starforge-cli/tests/trail.rs`.

**Interfaces:**
- Produces:
  ```rust
  // TrailFilterInput gains: pub has_changes: Option<bool>, pub review_requested: Option<String>
  pub struct TrailSummary { pub owner: String, pub repo: String, pub number: i64, pub title: String, pub updated_at: i64 }
  pub struct SessionSummary { pub owner: String, pub repo: String, pub ulid: String, pub agent: String, pub title: String, pub started_at: i64 }
  impl Core {
      /// D8: open Trails in repos the user can read now; newest updated first; ≤ 20 each.
      pub async fn dashboard_trails(&self, user: &User) -> CoreResult<(Vec<TrailSummary>, Vec<TrailSummary>)>; // (assigned, awaiting review)
      /// D8: sessions the user uploaded that pass §6.4 for the user now; newest first; ≤ 10.
      pub async fn recent_sessions_for(&self, user: &User) -> CoreResult<Vec<SessionSummary>>;
  }
  ```
- **API:** `GET …/trails` accepts `has_changes=true|false` (anything else → 422) and `review_requested=<handle>`.
- **Web list:**
  - The filter form adds a has-changes select (any, yes, no) and a review-requested handle field.
  - The state select adds `merged`.
  - Filters persist across pager links.
- **CLI:** `starforge trail list --has-changes <true|false> --review-requested <handle>` passes them through.
- **Dashboard** (signed in), shown above the repository list:
  - "Assigned to you", "Awaiting your review", and "Your recent sessions" sections; each section is omitted when empty.
  - Every Trail links to its page, and every session to its viewer.
  - Anonymous visitors see no change.

- [ ] **Step 1: Write the failing tests.**
  - **API list:** `has_changes=true/false` splits correctly. `review_requested=bob` lists only Trails with a pending request for bob. An unknown handle gives an empty list; `has_changes=maybe` gives 422. `state=merged` from the web filter is reachable.
  - **Dashboard:**
    - Alice's assigned and requested Trails across two repos appear.
    - A closed Trail does not.
    - Removing alice from a private repo hides that repo's Trails and her sessions there.
    - Her quarantined session appears for her (she is the uploader), but not on another user's dashboard.
    - A session she uploaded as a non-member to a public repo while unpublished does not appear (rule 2).
    - An anonymous visitor's dashboard is unchanged.
  - **CLI:** the stub test sends exactly `has_changes=true&review_requested=bob`.
- [ ] **Step 2: Run them to verify failure.** Run `TMPDIR=/dev/shm cargo test -p starforged --test api_trails --test web_trails --test web_dashboard` and `TMPDIR=/dev/shm cargo test -p starforge-cli --test trail`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy for the touched crates. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first).
  ```bash
  git commit -m "Filter Trails by changes and review requests and show them on the dashboard"
  ```

---

### Task K6: Security sweep and docs

**Files:**
- Create: `crates/starforged/tests/web_discovery_security.rs`.
- Modify: `README.md`.

**Coverage:**
- **Permission matrix:** each new route and form (deliveries list, detail, redeliver; review requests add and remove; dashboard sections) × anonymous, non-member, read, triage, write, maintain, admin, and site admin × public, internal, and private repos. Non-readers get 404, never 403. Below-threshold readers get 403. Archived repos refuse every mutation.
- **XSS corpus:** applied to every newly rendered field: delivery response bodies and headers, request headers, reviewer handles, dashboard Trail titles, and session titles.
- **CSRF:** every new form refuses a forged token, and the state is unchanged afterwards.
- **One end-to-end webhook test:** a hook subscribed to all events receives exactly the five event types from one scripted flow: a branch push, Trail open and edit, a review request, a `refs/for` push, a review, a status, a merge, and a session upload. Every signature verifies, and one delivery is redelivered and verified.
- **README:**
  - "Webhooks": event types, actions and causes, the envelope, headers, a verification snippet using `X-Starforge-Signature-256`, the delivery log, and redelivery.
  - "Finding Trails": review requests, the new filters, and the dashboard.
  - The deferred list (M2f).

- [ ] **Step 1: Write the sweep tests.**
- [ ] **Step 2: Run them.** Run `TMPDIR=/dev/shm cargo test -p starforged --test web_discovery_security --test webhooks`. Expected: PASS, or failures that expose K1–K5 defects. Fix each in its owning module and report it.
- [ ] **Step 3: Write the README sections.**
- [ ] **Step 4: Commit.**
  ```bash
  git commit -m "Add discovery and webhook security sweep and docs"
  ```
