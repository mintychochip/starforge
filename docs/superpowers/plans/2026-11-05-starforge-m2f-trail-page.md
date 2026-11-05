# Starforge M2f (Trail-page completeness) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the Trail list and Trail page of spec §10.1, and close the revision-integrity defects that M2e carried over.
- **Revision integrity:** each pushed head becomes exactly one revision, the current revision always points at the branch tip, and a `push` webhook fires only after its revisions are recorded.
- **Trail↔session links (§6.3):** a session is linked to a Trail through commits in the Trail's changes, or explicitly by a user. Links feed the has-sessions list filter, the Sessions tab, and the timeline.
- **Trail page (§10.1):**
  - tabs: Conversation, Changes, and Sessions;
  - a header gate panel per open change, with the merge button and method selector;
  - a timeline that also shows linked sessions and checks;
  - a Changes tab with inline review threads, inter-revision diffs, and per-file viewed state;
  - pending (draft) reviews (§6.2 review state `pending`).
- **Commit view (§10.1):** the Sessions panel gains agent, model, token totals, prompt preview, and link confidence (an M1 gap).

**Architecture:** No new crates, no new services, no new third-party dependencies.
- **`starforged-db`** gains three dual-engine migrations:
  - `0018_trail_sessions.sql`: the `revision_commits` table, the `revisions.commits_recorded` flag, and the `trail_session_links` table;
  - `0019_change_file_views.sql`;
  - `0020_pending_reviews.sql`: one pending review per author per change.
- **`starforged-core`:**
  - `changes.rs` gains per-repo ingest serialization, the latest-row duplicate guard, revision-commit recording, inter-revision diffs, viewed state, and pending reviews;
  - `trails.rs` gains session links, the has-sessions filter, the Sessions view, and the derived timeline rows;
  - `read.rs` gains richer commit-panel rows.
- **`starforged-api`** gains the Trail sessions routes, `from`/`to` on the change diff, and the pending-review routes.
- **`starforged-web`** gains:
  - Trail tabs, the header gate panel, the Sessions tab, and the timeline rows;
  - the changes list page, inline threads, the revision compare picker, and viewed toggles;
  - the pending-review UI and the richer commit Sessions panel.
- **`starforge-cli`** (`MIT OR Apache-2.0`) gains `trail list --has-sessions`.

**Tech Stack:**
- Rust 1.99.1 (edition 2024).
- axum 0.8 and askama (escaping by default).
- sqlx `Any` (SQLite plus Postgres, `$N` placeholders).
- `git` subprocesses through `starforged-git` (rev-list, diff).
- The in-process `TestServer` with real `git` in tests.

**Spec:** §6.2 (Change, Revision, Review states, Review thread), §6.3 (Commit link, Trail link), §6.4 (session read rules bind every session surface), §10.1 (Trail list filter "has sessions"; Trail page header, timeline, Changes tab, Sessions tab; commit view Sessions panel), §8.2 (post-receive creates revisions), §10.4 (webhook causes).

**Deferred (not built here):** CLI commands for Trail session links, viewed state, and pending reviews; review-thread suggestions; timeline pagination.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide (tests never call `std::env::set_var`); workspace lints inherited.
- **Licenses:**
  - server crates stay `AGPL-3.0-or-later`;
  - `starforge-cli` stays `MIT OR Apache-2.0` and never depends on a `starforged-*` crate;
  - no new third-party dependencies anywhere.
- **Migrations:**
  - Each lands in BOTH `crates/starforged-db/migrations/sqlite/` and `.../postgres/` in lockstep, as `0018`, `0019`, and `0020`, in the task that needs it.
  - Use only SQL valid on both engines:
    - `$N` placeholders numbered by first appearance;
    - `INTEGER` (SQLite) / `BIGINT` (Postgres) ids, read as `i64`;
    - booleans as `0`/`1`, never boolean literals;
    - unix-second timestamps via `now()`;
    - `ALTER TABLE … ADD COLUMN … NOT NULL DEFAULT …`.
  - Partial unique indexes (`CREATE UNIQUE INDEX … WHERE state = 'pending'`) are valid on both engines.
  - Migrations are forward-only and never edited after their task commits.
- **No route bypasses `starforged-core`:** API and web handlers authenticate and delegate. Every permission, validation, and dispatch decision lives on `Core`. Web handlers never touch `Db`.
- **Timeline and audit:**
  - Each new mutation writes exactly one timeline row, in the same `Core` method as its row write. The new kinds are `trail.session_linked` and `trail.session_unlinked` (payload: the session ULID only).
  - Viewed state and pending-review drafts write no timeline rows. Reads write nothing.
  - Webhook dispatch stays fire-and-forget.
- **Visibility:**
  - A user who cannot read the repo gets `404`, never `403`, on every new route; below-threshold readers get `403`; archived repositories refuse every new mutation.
  - **Every session surface applies §6.4 for the CURRENT viewer at read time:** has-sessions, the Sessions tab and its API, timeline session rows, and the commit panel. No count, title, ULID, or token total of an unreadable session ever reaches the viewer. Use the existing §6.4 predicate in `core/read.rs`; where SQL must filter (has-sessions), express the same three rules with bound viewer facts and pin it with tests.
- **Escaping:** session titles, commit subjects, file paths, check contexts, descriptions, and target URLs render escaped. Target URLs become links only when they are `http`/`https`.
- **Determinism:** after a real `git push`, tests wait on observable state (a revision pointer, a delivered webhook) with bounded polls. No sleeps are used as synchronization.
- **Test tmpdirs:** `TMPDIR=/dev/shm`. One cargo build at a time on this machine.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` are green on SQLite and on `STARFORGE_TEST_PG=1`.
- **Out of scope (do not build):** everything in the deferred list; multi-node locking; changes to gate semantics; new webhook event types.

## Decisions this plan makes where the spec is silent

- **D1. Revision integrity.**
  - Post-receive processing for one repository is serialized. `Core` owns a per-repo async lock (`Core::repo_ingest_lock(repo_id)`), and the githttp post-receive scan holds it for its whole run: `refs/for` ingest, branch moves, and push events. A single process is the deployment model (§2 non-goals), so an in-memory lock is sufficient.
  - Under the lock, the scan ingests each moved branch's CURRENT tip, not the push line's `new` value, and skips a branch that no longer exists. Two racing pushes therefore converge on the real tip.
  - `record_branch_move` compares against the head of the change's LATEST revision row (highest number), not the current-revision pointer.
  - `append_revision` itself refuses to append a head equal to the latest row's head. It returns that row, with no dismissals, no timeline, and no webhook, so every caller is covered.
  - Branch-change creation writes the change, its first revision, and the current-revision pointer in one database transaction.
  - `record_push` (the `push` webhooks) runs after the branch moves and `refs/for` ingest, so a delivered `push` event implies the push's revisions exist.
  - Justification: these fix the M2e-deferred duplicate revision, the pointer that could land on an older head, and the push-before-revision ordering.
- **D2. Trail commits.**
  - Table `revision_commits (revision_id, sha, subject, position)`, written when a revision is recorded. It holds the commits reachable from the revision head and not from its merge base (from its base SHA when no merge base is known). `position` is 0 for the head. At most 250 commits per revision; on hitting the cap, the newest 250 are kept and a warning is logged.
  - `revisions.commits_recorded` (0/1) marks recorded revisions. Existing revisions are backfilled by a job that the existing hourly maintenance pass enqueues for unrecorded revisions (bounded batch, idempotent). New revisions are recorded synchronously in `append_revision` and `insert_revision_and_point`; a git failure leaves the flag at 0 for the backfill.
  - Justification: the has-sessions filter must run in SQL, so the Trail's commits must be stored. Joining `commit_links` at read time means a link resolves whichever side, commit or upload, arrives first.
- **D3. Trail↔session links.**
  - **Through commits:** session S is linked to Trail T when a `commit_links` row with S's `session_id` (non-null) has a SHA in `revision_commits` of any revision of any change of T. This is computed by join and never stored.
  - **Explicit:** table `trail_session_links (trail_id, session_id, linked_by, created_at, UNIQUE (trail_id, session_id))`.
    - Who may link or unlink: triage+ on the repo, or the Trail's author for a session they uploaded. The session must be in the same repo and readable by the actor (§6.4); otherwise 404.
    - Cap: 50 explicit links per Trail (422 beyond it). Linking is idempotent, and a no-op writes nothing.
    - Each real link/unlink writes `trail.session_linked`/`trail.session_unlinked` (payload `{"session": "<ulid>"}`) and dispatches `trail`/`updated` with cause `session_linked`/`session_unlinked`.
  - **API:** `POST /api/v1/repos/{owner}/{repo}/trails/{n}/sessions` with body `{"session": "<ulid>"}`, `DELETE …/trails/{n}/sessions/{ulid}`, and `GET …/trails/{n}/sessions` (D5).
  - **Web:** link and unlink forms on the Sessions tab (CSRF).
- **D4. Has-sessions filter.**
  - `has_sessions=true|false` on the API, web, and CLI list. `true` keeps Trails with at least one linked session (D3, either way) that the VIEWER can read under §6.4; `false` keeps the rest. Any other value is 422.
  - Evaluated in SQL as an extra `AND` conjunct that composes with the existing filters and keyset paging. The viewer facts are bound parameters: repo public, viewer is a member, viewer is a repo admin, viewer id; anonymous viewers bind zero/false.
  - CLI: `starforge trail list --has-sessions <true|false>`.
- **D5. Sessions tab and API.**
  - **Page:** `GET /{owner}/{repo}/trails/{n}/sessions`, a readable Trail.
    - Groups, one per Trail commit that has at least one readable session, ordered newest first by first appearance (change number ascending, then revision number descending, then `position`). Each commit appears once.
    - Then a "Linked by hand" group for explicit links.
    - Each session row: agent name and version, models, title as the prompt preview (escaped, at most 120 characters), token totals (input, output, cache read, cache write, reasoning, total), link confidence (`exact`/`heuristic`; explicit links show `explicit`), uploader handle, start time.
    - Each row links to the viewer at `#turn-<seq_start>` when the commit link has a start sequence.
    - Per-group totals, and Trail-wide totals over distinct sessions.
  - **API:** `GET …/trails/{n}/sessions` returns `{"commits": [{"sha", "subject", "sessions": [row…]}], "linked": [row…], "totals": {…}}`, using the same rows and the same §6.4 filtering.
  - **Commit page:** the Sessions panel renders the same row component (agent, models, token totals, prompt preview, link confidence).
- **D6. Trail page structure.**
  - **Tabs** on every Trail page:
    - Conversation: `/trails/{n}`, unchanged URL;
    - Changes (count): `/trails/{n}/changes`, a new list page. It shows each change's number, state, kind, head or base, current revision, mergeability, and a gate summary; each change links to the existing `/trails/{n}/changes/{k}` page, which also shows the tabs;
    - Sessions (count of readable sessions): `/trails/{n}/sessions`.
  - **Header** (every tab): intent, labels, assignees, reviewers, and a **gate panel per open change**.
    - The panel shows approvals (have/need), required checks with their states, conflicts (mergeability and conflict paths), and session evidence.
    - For viewers allowed to merge, it also shows the merge button with the method selector limited to allowed methods. It posts to the existing merge route; CSRF.
    - It reuses `Core::evaluate_gates`; there is no new gate logic.
- **D7. Timeline.** The Conversation timeline merges stored events with derived rows, all in time order (the timeline is unpaginated today):
  - **Linked sessions:** one row per readable session linked through commits, timed at the later of the session's `created_at` and the first revision containing its commit. Explicit links already have stored rows.
  - **Checks:** one row per check status posted on a head SHA of any revision of the Trail's changes: context, state, description, target link, and change/revision label.
  - **Stored `change.*` and `review.*` kinds** render as readable sentences (verdict, change and revision numbers), never as the raw fallback.
  - Derived rows are computed per request and filtered for the viewer.
- **D8. Changes tab.**
  - **Inter-revision diff:**
    - The change page and `GET …/changes/{k}/diff` accept `from=<r1>&to=<r2>` (two distinct revisions of the change). The result is the tree diff between their head commits, labeled as such, with a note that it includes base changes when the change was rebased.
    - An unknown revision is 404; `from == to` is 422.
    - The page gains a compare picker.
  - **Inline threads:**
    - In the default view of a revision, a thread anchored on that revision renders directly under its `(path, side, end_line)` diff line.
    - Threads anchored elsewhere, or whose line is absent from the displayed hunks, render in the existing list below, marked outdated where they are.
    - The inter-revision view lists threads below only.
  - **Viewed state:**
    - Table `change_file_views (user_id, change_id, path, blob_sha, created_at, UNIQUE (user_id, change_id, path))`.
    - A file counts as viewed for a signed-in reader when the stored `blob_sha` equals the file's blob at the displayed head, so a later revision that changes the file resets it.
    - Toggle: CSRF form POST `/trails/{n}/changes/{k}/viewed` (`path`, `viewed=0|1`). Viewed files render collapsed.
    - Readers only; archived repos refuse. Anonymous viewers see no toggles.
- **D9. Pending reviews.**
  - **Drafts:**
    - A signed-in reader holds at most one `pending` review per change (migration 0020: a partial unique index).
    - `POST …/changes/{k}/threads` and `POST …/threads/{t}/comments` accept `"pending": true`. The comment then attaches to the actor's pending review, which is created on demand on the change's current revision.
    - Pending comments, and threads whose only comments are pending, are visible only to their author: web, API, and therefore the CLI.
    - Pending reviews never count toward gates, never appear in the timeline, and dispatch nothing.
  - **Submit:**
    - `POST …/changes/{k}/reviews` (the existing submit) converts the actor's pending review, if any. It sets state `submitted`, the verdict, the body, and the change's current revision at submit time, and attaches the pending comments plus any comments sent in the call.
    - Effects: exactly one `review.submitted` timeline row and one `review`/`submitted` webhook, clearing the actor's review request, and normal gate effects.
    - Without a pending review, behavior is unchanged.
  - **Discard and read:**
    - `DELETE …/changes/{k}/reviews/pending` discards the draft: its comments, plus threads left without comments. It writes no timeline row.
    - `GET …/changes/{k}/reviews/pending` returns the actor's draft or 404.
  - **Restrictions:** dismissing a pending review is 422. Others' pending reviews never appear in review lists.
  - **Web:** the inline comment form offers "Comment" and "Add to review". A "Finish your review" panel shows the draft comment count, with verdict, body, Submit, and Discard.
- **D10. Carried minors.**
  - `response_headers_json` truncates each joined header value to 1 KiB after joining repeated names.
  - `jobs::enqueue_returning` shares one insert-and-notify helper with `enqueue`/`enqueue_at`.
  - The approval de-duplication in `gates.rs` uses a map keyed by author instead of the nested scan.

## File Structure

```
crates/starforged-db/
  migrations/{sqlite,postgres}/0018_trail_sessions.sql      revision_commits, commits_recorded, trail_session_links (F2)
  migrations/{sqlite,postgres}/0019_change_file_views.sql   change_file_views (F5)
  migrations/{sqlite,postgres}/0020_pending_reviews.sql     partial unique pending index (F6)
  src/changes.rs, src/trails.rs, src/sessions.rs            query fns
crates/starforged-git/src/                                  rev-list with subjects; diff between two commits (if missing)
crates/starforged-core/src/changes.rs                       D1, D2 recording, D8, D9
crates/starforged-core/src/trails.rs                        D3, D4, D5, D7
crates/starforged-core/src/read.rs                          D5 commit-panel rows
crates/starforged-core/src/{gates.rs,jobs.rs,webhooks.rs}   D10
crates/starforged-api/src/{trails.rs,changes.rs,lib.rs}     routes
crates/starforged-web/src/githttp.rs                        D1 scan ordering + lock
crates/starforged-web/src/pages/{trails.rs,changes.rs,history.rs}, templates/*.html
crates/starforge-cli/src/{cli.rs,commands/trail/read.rs}    --has-sessions
crates/starforged/tests/*.rs                                tests
README.md                                                   Trail page, sessions, pending reviews
```

---

### Task F1: Revision integrity and carried fixes

**Files:**
- Modify:
  - `crates/starforged-core/src/changes.rs` and `crates/starforged-db/src/changes.rs`;
  - `crates/starforged-web/src/githttp.rs`;
  - `crates/starforged-core/src/{webhooks.rs,jobs.rs,gates.rs}`;
  - tests in `crates/starforged/tests/` (push_changes.rs, webhooks.rs, api_changes.rs as fitting) and core unit tests.

**Interfaces:**
- Produces: `Core::repo_ingest_lock(&self, repo_id: i64) -> tokio::sync::OwnedMutexGuard<()>`. The map of per-repo mutexes must not grow without bound: drop entries whose mutex is unused. D1 and D10 behavior as specified.

- [ ] **Step 1: Write the failing tests.**
  - **Core: stale pointer.** Insert a revision row WITHOUT moving the pointer (db fn), then call `record_branch_move` with that same head → no new revision, no `revision_pushed` dispatch.
  - **Core:** `append_revision` with the latest row's head is a no-op; it returns the existing revision and dismisses nothing.
  - **Concurrent scans.** Run the scan entry point twice concurrently for one repo. The second push line carries a stale `new` (an older commit) while the branch tip is newer. Afterwards the change's current revision head equals the branch tip, and no two consecutive revisions share a head.
  - **Push ordering.** In a web test, push a commit to a change's head branch. Wait for the `push` webhook delivery (`delivered_until`). Then IMMEDIATELY, with no polling, assert the change's current revision is the new head.
  - **Branch-change creation** leaves no observable state with a change and no current revision: creation is one transaction. Assert the change and revision exist together after creation, plus a unit test of the db fn if one is added.
  - **D10:**
    - a repeated response header whose joined value exceeds 1 KiB is stored truncated to 1 KiB;
    - enqueue behavior is unchanged (existing tests cover it);
    - approval de-duplication is unchanged (existing gate tests cover it), with an added test for one author's two approvals counting once.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core changes`, `cargo test -p starforged --test push_changes --test webhooks`. Expected: FAIL on the new tests.
- [ ] **Step 3: Implement** D1 and D10.
- [ ] **Step 4: Run tests.** Run the Step 2 commands, then `cargo test -p starforged --test api_changes --test web_changes --test web_merge_security`, then clippy on the touched crates. Expected: PASS, with the new webhook and push tests stable over 5 consecutive runs.
- [ ] **Step 5: Commit** (PG gate first): `Serialize push ingest and record each pushed head once`.

---

### Task F2: Trail commits, Trail↔session links, and the has-sessions filter

**Files:**
- Create:
  - `crates/starforged-db/migrations/{sqlite,postgres}/0018_trail_sessions.sql`;
  - `crates/starforged/tests/trail_sessions.rs`.
- Modify:
  - `crates/starforged-git/src/` (rev-list with subjects, if no wrapper exists);
  - `crates/starforged-db/src/{changes.rs,trails.rs,sessions.rs}`;
  - `crates/starforged-core/src/{changes.rs,trails.rs,jobs.rs}`;
  - `crates/starforged-api/src/{trails.rs,lib.rs}`;
  - `crates/starforged-web/src/pages/trails.rs`, `templates/trails.html`, and `src/lib.rs`;
  - `crates/starforge-cli/src/{cli.rs,commands/trail/read.rs}`;
  - tests: api_trails.rs, web_trails.rs, cli_trail.rs, and `crates/starforge-cli/tests/trail.rs`.

**Interfaces:**
- Produces:
  ```rust
  // TrailFilterInput gains: pub has_sessions: Option<bool>
  impl Core {
      /// D3 explicit link. Triage+, or the Trail author for own sessions; same repo; actor can read the session.
      pub async fn link_trail_session(&self, user: &User, owner: &str, repo: &str, n: i64, ulid: &str) -> CoreResult<()>;
      pub async fn unlink_trail_session(&self, user: &User, owner: &str, repo: &str, n: i64, ulid: &str) -> CoreResult<()>;
      /// D5 data: the viewer's readable linked sessions, grouped. Used by F3 and F4.
      pub async fn trail_sessions(&self, viewer: Option<&User>, owner: &str, repo: &str, n: i64) -> CoreResult<TrailSessions>;
  }
  pub struct TrailSessions { pub commits: Vec<CommitSessions>, pub linked: Vec<SessionLinkRow>, pub totals: TokenTotals }
  pub struct CommitSessions { pub sha: String, pub subject: String, pub change: i64, pub revision: i64, pub first_seen_at: i64, pub sessions: Vec<SessionLinkRow> }
  pub struct SessionLinkRow { pub ulid: String, pub agent: String, pub agent_version: String, pub models: String, pub title: String,
                              pub uploader: String, pub started_at: i64, pub created_at: i64, pub confidence: String /* exact|heuristic|explicit */,
                              pub seq_start: Option<i64>, pub totals: TokenTotals }
  pub struct TokenTotals { pub input: i64, pub output: i64, pub cache_read: i64, pub cache_write: i64, pub reasoning: i64, pub total: i64 }
  ```
- API:
  - `POST/DELETE` link routes (D3) return the Trail sessions JSON;
  - `GET …/trails/{n}/sessions` (D5 JSON);
  - list param `has_sessions`.
- Web: the Trail list gains a has-sessions select (any/yes/no), persisted across pager links. The Sessions tab page itself is built in F3.

- [ ] **Step 1: Write the failing tests.**
  - **Recording:** a revision's commits are recorded with subjects; the cap holds; the backfill job records an unrecorded revision and sets the flag.
  - **Linking through commits:** a session uploaded with a commit link to a commit in a change → listed under that commit. This holds when the upload arrives before the push, and when it arrives after.
  - **Explicit links:**
    - triage user links → listed in `linked`, with exactly one timeline row and one `trail`/`updated` `session_linked` webhook;
    - idempotent repeat → no new row;
    - unlink works;
    - the Trail author links their own upload;
    - a read user linking someone else's session gets 403;
    - a session from another repo or an unknown ULID gets 404;
    - the 51st link gets 422;
    - an archived repo refuses.
  - **§6.4 matrix** on the API GET and on `has_sessions`:
    - on a public repo, an unpublished session is invisible to non-members, and has_sessions=true excludes that Trail for them while including it for members;
    - a quarantined session is visible only to the uploader and repo admins;
    - a published session is visible to anonymous readers.
  - **Filter:** `has_sessions` composes with state/label filters and keyset paging; `has_sessions=maybe` gives 422; the CLI flag maps to the param.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test trail_sessions --test api_trails --test web_trails --test cli_trail` and `cargo test -p starforge-cli --test trail`. Expected: FAIL.
- [ ] **Step 3: Implement** D2, D3, and D4, plus the `trail_sessions` data fn.
- [ ] **Step 4: Run tests.** Run the Step 2 commands plus `cargo test -p starforged-db` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Link sessions to Trails through commits and by hand`.

---

### Task F3: Trail tabs, the header gate panel, the Sessions tab, and the commit Sessions panel

**Files:**
- Create: `templates/trail_header.html`, `templates/trail_sessions.html`, `templates/trail_changes.html`, and a shared session-row partial.
- Modify:
  - `crates/starforged-web/src/pages/{trails.rs,changes.rs,history.rs}`, `templates/{trail.html,change.html,commit.html,sessions_panel.html}`, and `src/lib.rs`;
  - `crates/starforged-core/src/read.rs`;
  - tests in web_trails.rs, web_changes.rs, and a commit-page test file (web_session_security.rs or the existing commit-panel test).

**Interfaces:**
- Consumes: `Core::trail_sessions` (F2) and `Core::evaluate_gates`.
- Produces: the D6 tabs, header gate panel, and changes list page; the D5 Sessions tab page with link/unlink forms; the D5 commit Sessions panel rows (`readable_links_for_commit` gains the row fields, or a sibling fn returns `SessionLinkRow`s).

- [ ] **Step 1: Write the failing tests.**
  - **Tabs:** each Trail page shows the three tabs with counts.
  - **Changes list page:** lists each change with its state and gate summary.
  - **Gate panel** for an open change:
    - shows approvals have/need, required checks with states, conflicts, and session evidence;
    - shows the merge form with only the allowed methods to a write user, and none to a read user;
    - a merge posted from the panel works (303) and refuses a forged CSRF token (403).
  - **Sessions tab:**
    - renders commit groups, totals, and the `#turn-` link;
    - link and unlink forms work with CSRF;
    - §6.4: an unreadable session never appears, by title, ULID, or totals.
  - **Commit page panel:** shows agent, models, token totals, preview, and confidence.
  - **XSS:** a hostile session title and commit subject render escaped on both pages.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test web_trails --test web_changes` plus the commit-panel test file. Expected: FAIL.
- [ ] **Step 3: Implement** D5 (pages and panel) and D6.
- [ ] **Step 4: Run tests.** Run the Step 2 commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add Trail tabs, the gate panel, and the Sessions tab`.

---

### Task F4: Timeline completeness

**Files:**
- Modify:
  - `crates/starforged-core/src/trails.rs` (the timeline view: stored rows plus derived rows);
  - `crates/starforged-db/src/checks.rs` (checks on a SHA set, if missing);
  - `crates/starforged-web/src/pages/trails.rs` and `templates/trail.html`;
  - the API Trail detail if it exposes the timeline: keep the API timeline stored-only unless it already merges, and record which in the report;
  - tests in web_trails.rs.

**Interfaces:**
- Produces: `Core` returns the timeline as typed entries: `Stored(TimelineEventRow)`, `Session(SessionLinkRow + commit)`, `Check(CheckRow + change/revision)`, in time order. The web renders readable sentences for every stored `change.*`, `review.*`, and `trail.session_*` kind (D7).

- [ ] **Step 1: Write the failing tests.**
  - After a push and a session upload linked to the change's commit, the timeline shows one session row, filtered by §6.4: absent for a non-member on a public repo while the session is unpublished.
  - A status posted on a revision head shows as a check row with context and state.
  - A submitted review shows as "<user> approved change 1 (revision 1)" (wording free), not raw JSON.
  - Rows are in time order.
  - XSS: a hostile check description, context, and target URL (`javascript:`) render escaped; the URL is not a link.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test web_trails`. Expected: FAIL.
- [ ] **Step 3: Implement** D7.
- [ ] **Step 4: Run tests.** Run the same command plus `--test web_changes` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Show linked sessions and checks in the Trail timeline`.

---

### Task F5: Changes tab: inline threads, inter-revision diffs, viewed state

**Files:**
- Create: `crates/starforged-db/migrations/{sqlite,postgres}/0019_change_file_views.sql`.
- Modify:
  - `crates/starforged-git/src/diff.rs` (diff between two commits, if missing);
  - `crates/starforged-core/src/changes.rs`;
  - `crates/starforged-db/src/changes.rs`;
  - `crates/starforged-api/src/changes.rs`;
  - `crates/starforged-web/src/pages/changes.rs`, `templates/change.html`, and `src/lib.rs`;
  - tests in web_changes.rs and api_changes.rs.

**Interfaces:**
- Produces:
  - `Core::change_diff_files` gains an optional `(from, to)` revision pair;
  - `Core::set_file_viewed(user, owner, repo, n, k, path, viewed: bool)`;
  - viewed flags on the diff view model (D8).

- [ ] **Step 1: Write the failing tests.**
  - **Inter-revision diff:**
    - after two pushes, `from=1&to=2` shows only the second push's file changes;
    - an unknown revision gives 404; `from == to` gives 422;
    - the API diff gives the same.
  - **Inline threads:** a thread on revision 1, line L, renders inside the diff under line L for revision 1. Viewing revision 2 where the line changed lists it below as outdated.
  - **Viewed state:**
    - marking a file viewed collapses it;
    - a new revision that changes the file un-views it; one that leaves the file unchanged keeps it viewed;
    - CSRF is enforced;
    - anonymous viewers see no toggles;
    - an archived repo refuses;
    - a non-reader gets 404.
  - **XSS:** a hostile file path renders escaped in the viewed form.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test web_changes --test api_changes`. Expected: FAIL.
- [ ] **Step 3: Implement** D8.
- [ ] **Step 4: Run tests.** Run the same commands plus `cargo test -p starforged-db` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add inline threads, inter-revision diffs, and viewed files`.

---

### Task F6: Pending reviews

**Files:**
- Create: `crates/starforged-db/migrations/{sqlite,postgres}/0020_pending_reviews.sql`.
- Modify:
  - `crates/starforged-core/src/changes.rs` (and `gates.rs` only to prove pending reviews are ignored);
  - `crates/starforged-db/src/changes.rs`;
  - `crates/starforged-api/src/{changes.rs,lib.rs}`;
  - `crates/starforged-web/src/pages/changes.rs` and `templates/change.html`;
  - tests in api_changes.rs, web_changes.rs, and webhooks.rs.

**Interfaces:**
- Produces:
  - `Core::pending_review(user, …) -> CoreResult<Option<PendingReviewView>>`;
  - `Core::discard_pending_review(user, …)`;
  - a `pending: bool` input on thread and comment creation;
  - `submit_review` converts the draft (D9).

- [ ] **Step 1: Write the failing tests.**
  - **Draft visibility:** two "Add to review" comments → visible to their author via web and API; invisible to another reader and to anonymous viewers (no thread, no count).
  - **Draft side effects:** no timeline row, no webhook, and no gate effect while the review is pending.
  - **Submit with an approval:**
    - one review, state submitted, with both comments attached;
    - one `review.submitted` row and one `review`/`submitted` webhook;
    - the actor's review request is cleared;
    - the approval counts toward gates.
  - **Discard** removes the draft comments and the threads left empty, and writes no timeline row.
  - **Concurrency:** a second draft for the same author and change reuses the first; the unique index holds.
  - **Restrictions:** dismissing a pending review gives 422. GET pending gives 404 when there is none.
  - **CLI `trail show`:** shows no foreign drafts (through the API).
  - **Web:** "Add to review", then "Finish your review" (Submit and Discard), with CSRF.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test api_changes --test web_changes --test webhooks`. Expected: FAIL.
- [ ] **Step 3: Implement** D9.
- [ ] **Step 4: Run tests.** Run the same commands plus `--test cli_trail`, `cargo test -p starforged-core gates`, and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add pending reviews`.

---

### Task F7: Security sweep and docs

**Files:**
- Create: `crates/starforged/tests/web_trail_page_security.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep.**
  - **Permission matrix** over every new route and form:
    - Trail sessions GET, link, and unlink (API and web);
    - the changes list page;
    - the inter-revision diff (API and web);
    - the viewed toggle;
    - pending review GET and DELETE, and pending thread/comment creation;
    - the gate panel merge form.
  - **Matrix shape:**
    - roles: anonymous, non-member reader, read, triage, write, maintain, admin, site admin;
    - visibilities: public, internal, private;
    - non-readers get 404, never 403; below-threshold users get 403;
    - archived repos refuse every mutation.
  - **§6.4 matrix:**
    - sessions: quarantined, unpublished on a public repo, and published;
    - surfaces: Sessions tab, Sessions API, has_sessions, timeline rows, and the commit panel;
    - no unreadable session's title, ULID, or totals in any response body.
  - **XSS corpus**, reusing the existing helpers and asserting both escaped-present and raw-absent per payload: session titles, commit subjects, file paths, check context/description/target URL, and pending comment bodies.
  - **CSRF** on every new form, with state unchanged after a forged post.
- [ ] **Step 2: Run the sweep** 3 times; all green. Fix any production defect found in its owning module and report it.
- [ ] **Step 3: README:**
  - a "Trail page" section: tabs, gate panel, timeline rows, Changes tab (compare, inline threads, viewed files), Sessions tab, and how sessions link (commits and by hand), with the API routes;
  - "Pending reviews";
  - the `has_sessions` filter and the CLI flag;
  - the new webhook causes `session_linked`/`session_unlinked` in the Webhooks section.

  Check every example against the code.
- [ ] **Step 4: Commit** (PG gate first): `Add Trail page security sweep and docs`.
