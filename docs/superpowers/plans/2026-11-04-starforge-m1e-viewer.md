# Starforge M1e (Session Viewer + Read Rules) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close milestone M1 (§14) on the read side: one reusable §6.4 session read-rule helper enforced identically by the session web page, the session JSON API, and (by contract) future search results; a server-rendered session viewer at the repo page convention with safe rendering of every Trace Format v1 kind; a Commit Sessions panel on commit/history pages backed by a new links-by-SHA query; a blame page whose blocks link line → commit → linked sessions; publish/unpublish endpoints + UI for public repos; the two recorded M1d gaps (admin `POST …/sessions/{ulid}/rescan` over HTTP and the links-by-SHA lookup); and uploader/admin session delete with blob decref. No search indexing, no webhooks delivery, no export/import CLI, no raw-transcript upload, no S3 backend, no SSH, no orgs (all out of scope below).

**Architecture:** No new service layer: everything continues through `starforged-core` (the only path to stored state). `starforged-db/src/sessions.rs` gains read-path queries only (`links_for_sha`, session listing for a repo, visibility update — no schema change). `starforged-core` gains `read.rs` (the single `can_read_session`/`authorize_session_read` helper every read path calls) plus `publish_session`/`unpublish_session`/`delete_session` on the existing session domain and a `blame` path that shells out to `git blame --porcelain` through `starforged-git`. `starforged-web` gains a `pages/sessions.rs` (viewer + publish/unpublish/delete/rescan forms), a `pages/blame.rs` (new blame page; none exists yet), viewer templates plus one ES-module enhancement script, and Sessions-panel wiring in the existing commit/history pages. `starforged-api` gains read endpoints (`GET` session, `GET` events/segments) plus `POST` publish/unpublish/delete/rescan beside the existing release/purge routes. The search-results leg of the §13 matrix is a contract in E1 (helper + test shape), enforced for real by M4 tantivy filtering.

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8 (existing), askama templates (existing, auto-escape on), htmx for tool-detail expansion only (pagination and all state changes are full-page forms so the viewer works without JavaScript per §10.2), comrak (raw HTML off) + ammonia (existing `markdown.rs`), `starforge-format` (`Event`, `parse_event`, `kind_name`, `wrap_untrusted`, `blake3_hex`, `decompress`), `starforge-redact` replacement markers (`[redacted:<id>]`), sqlx `Any` (SQLite + Postgres, `$N` placeholders). Playwright for the one browser test (§13); everything else is `reqwest` against `TestServer`.

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` §6.4 (session access rules — authoritative matrix), §7.8 (Trace Format v1: kinds, evolution rules), §7.9 (export/import — deferred, see Constraints), §10.1 (Commit Sessions panel, blame with sessions), §10.2 (session viewer), §11.1 (rendering safety), §11.2 (untrusted delimiters), §13 (access-matrix + XSS + browser tests), §14 M1. M1d (`docs/superpowers/plans/2026-11-04-starforge-m1d-ingest.md`) is the baseline: ingest, quarantine, links, rescan-Core, and blob plumbing already exist.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** every touched/created server crate stays `AGPL-3.0-or-later` (`license.workspace = true`, `publish.workspace = true`). MIT crates (`starforge-format`, `starforge-redact`) are consumed as path dependencies only — never copied, never re-licensed.
- **Dependencies:** NO new `[workspace.dependencies]` entries. `starforged-web` adopts existing `comrak`/`ammonia` via the shared `markdown.rs` helper (no direct crate use in page modules); the viewer script is dependency-free vanilla ES. Anything else must be named in its task and justified in one sentence.
- **Migrations:** prefer NONE. M1e needs no schema change: `visibility` (`inherit`/`published`), `quarantine` + reason/detail, commit-link rows, and blob refcounts all exist from 0008. If a task discovers a missing column/index, it lands as `0010_*.sql` in BOTH `crates/starforged-db/migrations/sqlite/` and `.../postgres/`, kept in lockstep (types/SQL valid on both engines, `$N` placeholders, forward-only), verified with `scripts/check.sh` AND `STARFORGE_TEST_PG=1 scripts/check.sh`.
- **No route bypasses `starforged-core`:** web and API handlers authenticate, call exactly one `Core` read/mutation method, and render. Web handlers never touch `Db` or the blob store directly; the read helper lives in core, not in `starforged-web/src/auth.rs`.
- **Determinism:** same session bytes → same rendered page. No wall-clock in verdicts; event paging is a pure function of `(segments, page, PER_PAGE)`; redaction markers render byte-identically to storage.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green; SQL touched → also `STARFORGE_TEST_PG=1` gate for the affected package before committing.
- **`TMPDIR=/dev/shm` note for this sandbox:** integration and browser tests that boot `TestServer` or write temp repos/blobs MUST run with `TMPDIR=/dev/shm` (e.g. `TMPDIR=/dev/shm cargo test -p starforged --test web_sessions_viewer`); the default `/tmp` mount in this sandbox is slow/full and causes spurious failures. CI is unaffected.
- **Out of scope (do not build):** search indexing/tantivy (M4 — E1 only defines the filter contract the index must honor); webhook delivery (outbox enqueue already exists); export/import CLI bundles (§7.9 — deferred, see ruling below); raw-transcript upload wire (M1f); S3 backend; SSH; orgs/teams; Trail pages (M2); refresh-token rotation (M3); per-token rate limiting (M5).
- **Ruling R1 (§7.9 export/import is deferred, not built).** Reason: export is `starforge export`/`import` CLI surface over bundles plus a stable bundle schema both sides pin; the server already exposes every primitive M1e adds (GET session meta, GET event pages, GET full JSONL, links). Building half of it (server download without the CLI round-trip) would freeze a bundle format with no consumer. The viewer ships a "Download JSONL" link (the normalized transcript bytes the bundle will contain) so no M1e work is thrown away; the bundle envelope + CLI land together after M1.
- **Decisions this plan makes where the spec is silent:**
  - Route names: viewer `GET /{owner}/{repo}/sessions/{ulid}` (repo page convention, alongside `/commit/{id}`); JSON API `GET /api/v1/repos/{owner}/{repo}/sessions/{ulid}` (meta + links) and `GET …/sessions/{ulid}/events?page=N` (200-event JSON page); publish/unpublish `POST …/sessions/{ulid}/publish|unpublish` on both API and web; delete `DELETE` on API + `POST …/sessions/{ulid}/delete` on web (forms cannot DELETE); rescan `POST …/sessions/{ulid}/rescan` on both (fills the M1d gap: `Core::rescan_session` exists with no HTTP route). Blame `GET /{owner}/{repo}/blame/{*rest}?at=<ref>&page=N` beside tree/blob.
  - Template structure: `session.html` (header + quarantine banner + admin forms + turn list + pager), `session_event.html` (single-turn partial shared by the page and the htmx tool-expand fragment), `session_list.html`? No — no session index page in M1e (commit panel + direct ULID links are the discovery paths; a repo session index is M4 search UI). Commit panel is a `sessions_panel.html` include in `commit.html` + a sessions column in `commits.html` rows. Blame is `blame.html`.
  - Pagination size: 200 events per page (`VIEWER_PER_PAGE = 200`, spec §10.2 binding), sliced over the concatenated segment event stream in stored order; `?page=N` (1-based, default 1); out-of-range → 404; `#turn-<seq>` deep links resolve to the page containing `seq` (server computes it; unknown `seq` renders page 1 with no anchor).
  - Unknown event kinds: rendered as a collapsed `<details>` block titled `unknown event kind "<kind>"` with seq/ts and the escaped raw JSON line — never dropped (evidence), never interpreted (evolution rule §7.8). Unknown top-level fields on KNOWN kinds are ignored for display (the `Event::extra` round-trips in downloads but is not rendered, except inside the unknown-kind raw block).
  - Redaction markers: `[redacted:<id>]` substrings render verbatim — askama-escaped like all other text, wrapped in `<span class="redacted">` for styling only. Rationale: markers are forensic evidence; restyling must not alter bytes, and wrapping keeps `view-source` diffable against downloads.
  - Quarantine visibility: quarantine NEVER hides content from the uploader or a repo admin — §6.4 rule 3 grants them read, and the point of the M1d queue is review. The viewer shows them the full transcript under a quarantine banner (reason + detail + release/purge/rescan forms). Everyone else gets 404 (not 403, so ULIDs stay undiscoverable — same convention as `require_repo` for invisible repos).
  - HTMX vs full pages: pagination, publish/unpublish/delete/rescan/release/purge are full-page GETs/POSTs (work without JavaScript; state changes carry `_csrf` like every other web form). htmx is used ONLY for tool-call input/result expansion (`hx-get` event fragment) as progressive enhancement; without JS the input/result render inline collapsed `<details>`.
  - Blame rendering is server-side: `git blame --porcelain` runs in `Core::blame` (blocking pool), grouped into blocks in the handler; the template renders blocks + session chips as plain links. No htmx on the blame page (one request, fully indexed HTML, consistent with history/diff pages).

---

## Read Contract (Binding — §6.4; every later task consumes it verbatim)

```rust
// crates/starforged-core/src/read.rs
use crate::{Core, CoreError, CoreResult};
use crate::accounts::User;
use crate::repos::RepoAccess;

/// The single enforcement point for spec §6.4 rule "Read". Every read path —
/// web viewer, session JSON API, commit panel, blame chips, and (M4) search
/// filtering — calls this and nothing else.
pub fn can_read_session(
    access: &RepoAccess,       // repo already resolved via repo_for (None permission = invisible)
    session: &starforged_db::sessions::SessionRow,
    viewer: Option<&User>,     // None = anonymous
) -> bool;

impl Core {
    /// `repo_for` (read) + `session_by_ulid` + `can_read_session`.
    /// Invisible repo or unreadable session → `NotFound` (never `Forbidden`,
    /// so session ULIDs stay undiscoverable). Returns the access + row for rendering.
    pub async fn authorize_session_read(
        &self,
        viewer: Option<&User>,
        owner: &str,
        name: &str,
        ulid: &str,
    ) -> CoreResult<(RepoAccess, starforged_db::sessions::SessionRow)>;
}
```

Truth table (`can_read_session`; repo readability is a precondition — `repo_for` already returned `None` permission → invisible → `false` before this table):

| # | Repo visibility | Viewer | Session `visibility` | Quarantine | Uploader? | Repo admin? | May read |
|---|---|---|---|---|---|---|---|
| 1 | private/internal, no read grant | anyone | * | * | * | * | NO (precondition) |
| 2 | any readable | anonymous | * | * | — | — | repo readable only if public; then NO unless published (rows 6–7) |
| 3 | private/internal + read grant | signed-in non-member | inherit | none | no | no | YES |
| 4 | private/internal + read grant | signed-in non-member | inherit | quarantined | no | no | NO |
| 5 | private/internal + read grant | uploader | inherit | quarantined | YES | no | YES (+ banner) |
| 6 | public | anonymous | published | none | * | * | YES |
| 7 | public | anonymous | inherit | * | * | * | NO |
| 8 | public | signed-in non-member | inherit | none | no | no | NO (not a member) |
| 9 | public | member (any grant) | inherit | none | no | no | YES |
| 10 | public | member | inherit | quarantined | no | no | NO |
| 11 | public | uploader (non-member) | inherit | quarantined | YES | no | YES (+ banner) |
| 12 | any readable | repo admin | * | quarantined | no | YES | YES (+ banner) |
| 13 | any readable | site admin, no grant | * | * | no | no | YES iff repo readable (site admin is admin everywhere readable); quarantine banner iff not uploader? NO — site admin reads as admin: YES (+ banner when quarantined) |
| 14 | internal | signed-in, no grant | inherit | none | no | no | YES (implicit read; member check only gates public+unpublished) |
| 15 | any readable | anyone allowed above | released | * | * | * | same as `none` (release clears the gate; evidence columns stay) |

Notes: "member" = at least one explicit grant (collaborator/team/org-base/org-ownership), per §6.1 — implicit public/internal read does NOT make a member; `Core::is_repo_member` (E1 defines it on the collaborator + org tables as they exist) answers it. Publish has no effect on non-public repos (rows 3–5 ignore `published`). Anonymous on internal/private fails the precondition (row 2).

---

## File Structure

```
crates/starforged-db/src/sessions.rs     links_for_sha + sessions_of_repo listing + set_visibility (E1/E3; no migration)
crates/starforged-core/src/read.rs       NEW: can_read_session + authorize_session_read + is_repo_member (E1)
crates/starforged-core/src/lib.rs        pub mod read; (E1)
crates/starforged-core/src/sessions_view.rs  NEW? No — viewer assembly lives in read.rs? No:
crates/starforged-core/src/read.rs       + session_events paging helper: read_session_page (decompress+parse+slice) (E2)
crates/starforged-core/src/ingest.rs     publish_session/unpublish_session/delete_session (E5; audit session.publish/unpublish/deleted)
crates/starforged-core/src/blame.rs      NEW: Core::blame via git blame --porcelain + block grouping (E4)
crates/starforged-core/src/lib.rs        pub mod blame; (E4)
crates/starforged-git/src/blame.rs       NEW: porcelain parser (porcelain structs, no color) (E4)
crates/starforged-git/src/lib.rs         pub mod blame; (E4)
crates/starforged-api/src/sessions.rs    GET session, GET events, POST publish/unpublish, DELETE session, POST rescan (E2/E5)
crates/starforged-api/src/lib.rs         route table (E2/E5)
crates/starforged-web/src/pages/sessions.rs  NEW: viewer + publish/unpublish/delete/rescan/release/purge forms (E2/E5)
crates/starforged-web/src/pages/blame.rs      NEW: blame page (E4)
crates/starforged-web/src/pages/history.rs    commit panel wiring + sessions column (E3)
crates/starforged-web/src/pages.rs       module list (verify exact file) (E2/E4)
crates/starforged-web/src/lib.rs         route table: sessions viewer, blame, web POST actions (E2/E4/E5)
crates/starforged-web/src/session_render.rs   NEW: Event→HTML renderer (all kinds, XSS corpus target) (E2)
crates/starforged-web/templates/session.html NEW viewer page (E2)
crates/starforged-web/templates/session_event.html NEW single-turn partial + htmx fragment (E2)
crates/starforged-web/templates/sessions_panel.html NEW commit-page include (E3)
crates/starforged-web/templates/blame.html NEW (E4)
crates/starforged-web/templates/commit.html  include panel (E3)
crates/starforged-web/templates/commits.html sessions column (E3)
crates/starforged-web/assets/session.js  NEW plain ES module: htmx-independent expand + search-within + split-view stub? No:
crates/starforged-web/assets/session.js  NEW plain ES module: search-within + #turn deep-link scroll only (E2; transcript/diff split view deferred — see E2)
crates/starforged/tests/web_sessions_viewer.rs NEW (E2/E5, extended E6)
crates/starforged/tests/web_history_sessions.rs NEW commit panel + blame (E3/E4, extended E6)
crates/starforged/tests/api_sessions_read.rs NEW matrix over HTTP (E1/E5)
README.md                                  session viewer + publish rules section (E6)
```

What M1d's data model cannot express (called out explicitly so no task is blocked mid-flight):
- `commit_links` has no per-link event-range index beyond `seq_start/seq_end` (nullable; trailer rows leave them NULL) — the viewer "open at the commit's event range" (§10.1) therefore scrolls to `seq_start` when present and to the session top when absent. No migration: backfilling trailer ranges is unknowable server-side.
- `sessions.visibility` has only `inherit`/`published` — there is no per-user or per-team share scope. Publish is all-or-nothing on public repos, per §6.4.
- There is no session listing table/column for "recent sessions" ordering beyond `created_at/updated_at` — E3's commit panel never needs it (lookup is by SHA), and no repo session index page ships in M1e, so no query is added for it.
- `segments` carry no per-event full-text index — "Search within the session" (§10.2) is client-side find over the rendered 200-event page plus `?page=` navigation, not a server search endpoint. Server-side session search is M4.

---

### Task E1: §6.4 read-rule helper + access-matrix tests

**Files:**
- Create: `crates/starforged-core/src/read.rs`
- Modify: `crates/starforged-core/src/lib.rs` (`pub mod read;`), `crates/starforged-db/src/sessions.rs` (new queries only)

**Interfaces:**
- Consumes: M1d rows (`SessionRow`, `quarantined_of_repo`, visibility columns), `permission::effective` + `Viewer`, `require_repo`/`repo_for`/`permission_on` conventions, collaborator/org grant tables as they exist.
- Produces (exact signatures from the Read Contract above, plus):
  ```rust
  // crates/starforged-core/src/read.rs
  pub async fn is_repo_member(&self, repo_id: i64, user_id: i64) -> CoreResult<bool>;
  // true when any explicit grant exists (collaborator row, team grant, org base/ownership).
  // Implicit public/internal read returns false.
  // crates/starforged-db/src/sessions.rs
  pub async fn links_for_sha(db: &Db, repo_id: i64, sha: &str) -> DbResult<Vec<CommitLinkRow>>;
  pub async fn sessions_of_repo(db: &Db, repo_id: i64, limit: i64) -> DbResult<Vec<SessionRow>>;
  pub async fn set_visibility(db: &Db, id: i64, visibility: &str) -> DbResult<()>;
  ```
- `can_read_session` is pure (no I/O): `(access.repo.visibility, viewer, session.visibility, session.quarantine, uploader?, admin?) → bool` per the truth table. "Repo admin" = `access.permission >= Admin`; site admin is admin on every repo it can read (follows existing `effective()` owner/admin rule — E1 does not change `permission.rs`).

- [ ] **Step 1: Write failing matrix tests.** Core in-module tests (`read.rs #[cfg(test)]`, `test_core()` + users/collaborators/visibility fixtures following `repos.rs` conventions): one case per truth-table row 3–15 (parametrized vec of `(visibility, member?, published?, quarantine?, uploader?, admin?, expect)`), asserting `can_read_session` directly AND `authorize_session_read` end-to-end (private repo invisible → `NotFound`; public+inherit+anonymous → `NotFound`; quarantined+stranger → `NotFound`; quarantined+uploader → `Ok`; published+anonymous → `Ok`). DB tests: `links_for_sha` returns both trailer-first (NULL session_id) and claimed rows for one SHA and nothing for an unknown SHA; `set_visibility` round-trips `inherit`→`published`→`inherit`.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-core read::` and `TMPDIR=/dev/shm cargo test -p starforged-db sessions::` — Expected: FAIL (module/functions do not exist).
- [ ] **Step 3: Implement `read.rs` + queries.** `can_read_session` matches the table row-for-row (comment each arm with its row numbers, e.g. `// rows 4, 10: quarantined gate`). `authorize_session_read`: `repo_for(viewer, owner, name)` (read precondition — invisible repos 404 here) → `session_by_ulid` (unknown ULID → `NotFound`) → `can_read_session` with `is_repo_member` evaluated ONLY on the public+inherit path and the quarantine path (private/internal readable needs no membership check — rows 3–5). Queries use `$N` placeholders, `i64`/`0`/`1` conventions; `links_for_sha` is `WHERE repo_id = $1 AND sha = $2 ORDER BY session_ulid`.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-core -p starforged-db` then the PG gate `STARFORGE_TEST_PG=1 TMPDIR=/dev/shm cargo test -p starforged-core -p starforged-db` — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  TMPDIR=/dev/shm cargo test -p starforged-core -p starforged-db
  git add crates/starforged-core/src/read.rs crates/starforged-core/src/lib.rs crates/starforged-db/src/sessions.rs
  git commit -m "Add session read-rule helper with access-matrix tests"
  ```

---

### Task E2: Session viewer page + templates + safe rendering

**Files:**
- Create: `crates/starforged-web/src/session_render.rs`, `crates/starforged-web/src/pages/sessions.rs`, `templates/session.html`, `templates/session_event.html`, `templates/sessions_panel.html`? No — panel is E3. E2 creates `session.html` + `session_event.html`, `assets/session.js`, `crates/starforged/tests/web_sessions_viewer.rs`
- Modify: `crates/starforged-core/src/read.rs` (add `read_session_page`), `crates/starforged-web/src/lib.rs` (routes), `pages.rs` (module list), `crates/starforged-api/src/sessions.rs` + `lib.rs` (GET session, GET events JSON)

**Interfaces:**
- Consumes: E1 (`authorize_session_read`, `can_read_session`), M1d blob reads (`blob_store.get_by_hash` via `BlobStore`, `decompress_segment_text` semantics), `starforge_format::{parse_event, kind_name, EventKind}`, `markdown::render`/`markdown::plain`, `wrap_untrusted` (agent-output framing — see rendering rules), `RequireUser`/`MaybeUser` + `verify_csrf` conventions, `format_time`/`format_age`, `X-Robots-Tag: noindex` on every session response (spec §11.1).
- Produces:
  ```rust
  // crates/starforged-core/src/read.rs
  pub const VIEWER_PER_PAGE: i64 = 200;
  pub struct SessionPage { pub events: Vec<starforge_format::Event>, pub page: i64, pub pages: i64, pub total: i64, pub page_for_seq: Box<dyn Fn(i64) -> i64> }
  // actually: page_for_seq as a free fn page_containing_seq(total_events: i64, seq: i64) -> i64
  impl Core {
      /// Decompresses segments in stored order, parses lines with parse_event
      /// (unparseable lines are skipped with a warn, never fail the page),
      /// and returns the 1-based page slice. Runs on the blocking pool.
      pub async fn read_session_page(&self, session_id: i64, page: i64) -> CoreResult<SessionPage>;
      /// Full normalized transcript (all segments concatenated) for "Download JSONL".
      pub async fn read_session_jsonl(&self, session_id: i64) -> CoreResult<Vec<u8>>;
  }
  // crates/starforged-web/src/session_render.rs
  /// Render one parsed Event to trusted HTML (askama-escaped args only; markdown.rs for prose).
  pub fn render_event(event: &starforge_format::Event, repo: &RepoHead-ish, owner/repo strings) -> String;
  // routes:
  // GET /{owner}/{repo}/sessions/{ulid}?page=N[&focus=seq] → session.html (+ X-Robots-Tag: noindex)
  // GET /{owner}/{repo}/sessions/{ulid}/events/{seq} (hx-get fragment → session_event.html, tool input/result expanded)
  // GET /{owner}/{repo}/sessions/{ulid}/download → full JSONL (Content-Type: application/jsonl? No: text/plain + attachment, §11.1 sandbox headers)
  // GET /api/v1/repos/{owner}/{repo}/sessions/{ulid} → {"meta": SessionMeta-ish, "links": [...], "visibility": ..., "quarantine": ...}
  // GET /api/v1/repos/{owner}/{repo}/sessions/{ulid}/events?page=N → {"events": [...raw Event JSON...], "page": N, "pages": P, "total": T}
  ```
- Rendering rules (binding for the XSS corpus in E6): assistant/user/system/reasoning `text` → `wrap_untrusted` THEN `markdown::render` for assistant + user (spec §10.2 "sanitized Markdown"), `markdown::plain` for reasoning/system/tool I/O? No — reasoning renders collapsed as plain escaped text (`plain`); tool `input`/`result.output` render as escaped `<pre>` (never Markdown — tool output is data, §11.1); `file_change.diff` renders as escaped diff text (reuse `file_views`? No — unified diff string only; escaped `<pre class="diff">`); `compaction.summary` plain collapsed; `subagent_start/end` as tree markers with `subagent_id` linking `#turn-<first-seq-of-child>`? No — subagent sessions are separate ULIDs (`parent_id` in meta); render `subagent_id` as plain code text (no link unless it parses as a ULID with a session row in this repo — E2 checks `session_by_ulid` and links only then). Commit markers: the viewer shows one marker per linked commit (from `links_of_session`) at its `seq_start` position ("commit `<sha7>` · <confidence>" with the SHA linked to `/commit/<sha>` — the E11 commit links). Redaction markers verbatim per Constraints. Every renderer output passes through askama escaping (no `|safe` except the already-sanitized `markdown::render`/`plain` strings — the same two-call pattern as `blob.html`).

- [ ] **Step 1: Write failing viewer tests.** New `crates/starforged/tests/web_sessions_viewer.rs` (`TestServer`, multi-thread like `api.rs`): seed user + private repo + session with a 3-segment, 5-event fixture (user prompt, assistant message with `[redacted:known_token]` marker already in stored text, tool_call + tool_result with `<script>alert(1)</script>` in output, file_change with diff, compaction, subagent boundary, one unknown-kind line `{"v":1,"seq":9,…,"kind":"future_kind","extra":"<img src=x onerror=…>"}`): (a) anonymous on private repo → 404; stranger (no grant) → 404; uploader → 200 with header meta (agent, models, usage totals), all kind blocks present, NO raw `<script>`/`<img onerror>` bytes in the HTML, marker text `[redacted:known_token]` present verbatim; (b) `?page=99` → 404; `?focus=<seq>` jumps (assert canonical page + anchor); (c) API GET session as stranger → 404, as reader → 200 with links array; API events `?page=1` shape; (d) quarantine banner cases (deferred to E5's quarantine tests? No — banner markup asserted here with a quarantined fixture: uploader sees banner + content; stranger 404s).
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_sessions_viewer` — Expected: FAIL (routes/templates do not exist).
- [ ] **Step 3: Implement `read_session_page` + renderer + pages + API GETs.** Page handler: `repo_for` is inside `authorize_session_read` (one call — never duplicate the check); quarantined sessions render the same template with `banner` set (uploader/admin only — guaranteed by the helper); every response sets `X-Robots-Tag: noindex` (web middleware or per-handler header — per-handler, same file, so the API JSON gets it too). `session.js` (vanilla ES, no deps): search-within-page highlight + `#turn-<seq>` scroll; loaded with the per-response CSP nonce (follow the existing nonce pattern — verify exact helper; no inline scripts per §11.1). Split view (transcript left, diff right, §10.2) is explicitly deferred inside E2's scope: the file_change diff renders inline; the split-view toggle lands only if E2 stays green without it — default: NOT built, recorded as M1-known-gap in E6 docs.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_sessions_viewer` then `TMPDIR=/dev/shm cargo test --workspace` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-core/src/read.rs crates/starforged-web/src/session_render.rs crates/starforged-web/src/pages/sessions.rs crates/starforged-web/templates/session.html crates/starforged-web/templates/session_event.html crates/starforged-web/assets/session.js crates/starforged-api crates/starforged/tests/web_sessions_viewer.rs
  git commit -m "Add session viewer with safe event rendering and read-rule enforcement"
  ```

---

### Task E3: Commit Sessions panel + links-by-SHA

**Files:**
- Create: `templates/sessions_panel.html`, `crates/starforged/tests/web_history_sessions.rs` (panel half; blame half lands in E4, same file)
- Modify: `crates/starforged-web/src/pages/history.rs` (commit + commits list wiring), `templates/commit.html` (include), `templates/commits.html` (sessions column), `crates/starforged-web/src/views.rs` (`SessionChip` view model)

**Interfaces:**
- Consumes: E1 (`links_for_sha`, `authorize_session_read` per linked session — the panel NEVER shows a session the viewer cannot read: filter `can_read_session` per row, so a public commit page does not leak private-session titles), E2 viewer routes (chip hrefs).
- Produces:
  ```rust
  // crates/starforged-web/src/views.rs
  pub struct SessionChip { pub ulid: String, pub agent: String, pub models: String,
      pub confidence: String, pub source: String, pub seq_start: Option<i64>, pub seq_end: Option<i64>,
      pub href: String /* viewer URL, with #turn-<seq> when seq_start known */ }
  impl Core {
      /// Links for one SHA, filtered to sessions `viewer` may read, oldest first.
      /// Trailer-only rows (NULL session_id) resolve via session_by_ulid when the
      /// upload has since arrived; rows with no session row are skipped (panel
      /// shows uploaded sessions only — upload-pending trailers show nothing).
      pub async fn readable_links_for_commit(&self, access: &RepoAccess, viewer: Option<&User>, sha: &str) -> CoreResult<Vec<SessionChip>>;
  }
  ```
- Panel content per linked session (§10.1): agent + version, models, token totals (input/output from the session row), prompt preview (first `user_message` text, truncated to 160 chars, escaped — fetched from page 1 of `read_session_page`? No: prompt preview comes from the session row? M1d rows have no prompt column — E3 reads the first segment's first `user_message` via `read_session_page(session_id, 1)` and scans for the first user_message; bounded (one segment decompress per chip, cached per request in a `HashMap<ulid, preview>`). Link confidence + source (`trailer`/`cli_claim` → display "trailer"/"claim", `exact`/`heuristic`), opening the viewer at the commit's event range (`#turn-<seq_start>` when known, else session top).

- [ ] **Step 1: Write failing panel tests.** In `web_history_sessions.rs`: real repo via TestServer + `git` (follow `web_history.rs` fixture conventions): commit carrying `Starforge-Session: <ULID>` trailer + uploaded session (exact-claim link with seq range) → `GET /commit/<sha>` contains panel with agent, confidence `exact`, and `href` with `#turn-<seq>`; trailer-only (no upload) → panel shows "linked session not yet uploaded" placeholder? No — rows with no session row are SKIPPED (decision above): assert panel absent/empty. Stranger on public repo with unpublished session → panel absent (no leak of agent/title/totals); uploader sees it. `commits.html` list shows a session-count chip per commit (`1 session` link to commit page anchor).
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_history_sessions` — Expected: FAIL.
- [ ] **Step 3: Implement chip query + panel wiring.** `readable_links_for_commit` lives in `read.rs` (it IS a read rule — same file, so the filter cannot drift from the viewer). `commits` list path: N+1 risk (one `links_for_sha` per commit × 50 rows) — bounded by batching: single `WHERE repo_id = $1 AND sha IN (…)`? E3 adds `links_for_shas(db, repo_id, &[sha])` to the db layer up front (one query for the page) and per-chip `can_read_session` filtering in core. History page caps at `PER_PAGE` commits, so the IN-list is ≤ 50.
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_history_sessions` then `TMPDIR=/dev/shm cargo test -p starforged-web -p starforged-core` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-db/src/sessions.rs crates/starforged-core/src/read.rs crates/starforged-web/src/pages/history.rs crates/starforged-web/src/views.rs crates/starforged-web/templates/sessions_panel.html crates/starforged-web/templates/commit.html crates/starforged-web/templates/commits.html crates/starforged/tests/web_history_sessions.rs
  git commit -m "Add commit Sessions panel with links-by-SHA lookup"
  ```

---

### Task E4: Blame with sessions

**Files:**
- Create: `crates/starforged-git/src/blame.rs`, `crates/starforged-core/src/blame.rs`, `crates/starforged-web/src/pages/blame.rs`, `templates/blame.html`
- Modify: `crates/starforged-git/src/lib.rs`, `crates/starforged-core/src/lib.rs`, `crates/starforged-web/src/lib.rs` (route), `pages.rs` (module list)

**Interfaces:**
- Consumes: E1 (`links_for_sha` batch + `readable_links_for_commit`), `Core::commit`/`repo_for` conventions, `content_href`/`crumbs` helpers.
- Produces:
  ```rust
  // crates/starforged-git/src/blame.rs
  pub struct BlameBlock { pub sha: String, pub author: String, pub author_time: i64,
      pub start: usize, pub count: usize, pub lines: Vec<String> }
  /// `git blame --porcelain -l <rev> -- <path>` in the repo dir; binary/huge
  /// files refuse with a typed error (page shows "blame unavailable").
  pub fn blame(repo_dir: &std::path::Path, rev: &str, path: &str) -> Result<Vec<BlameBlock>, BlameError>;
  // crates/starforged-core/src/blame.rs
  pub struct BlameLine-grouped view: Vec<BlameBlockView { sha, author, when, lines, sessions: Vec<SessionChip> }>
  impl Core {
      pub async fn blame_with_sessions(&self, access: &RepoAccess, viewer: Option<&User>,
          rev: &str, path: &str) -> CoreResult<BlameView>;
  }
  // route: GET /{owner}/{repo}/blame/{*rest}?at=<ref, default branch>
  ```
- Blame runs on the blocking pool (`spawn_blocking` — `git blame` on large files is slow; cap with `--max-stats`? No: rely on existing raw/blob size conventions — refuse files over the blob inline limit with "blame unavailable for large files"). Each DISTINCT sha in the blame issues one batched `links_for_shas` lookup (E3's batch fn — one query total), then per-session `can_read_session` filtering: blocks whose commit has no readable sessions render the commit link only. Session chips reuse E3's `SessionChip` (same href convention, `#turn-<seq>`).

- [ ] **Step 1: Write failing blame tests.** Extend `web_history_sessions.rs` (blame half): fixture repo with two commits touching different line ranges (commit A by uploader with linked+uploaded session, commit B without) + `?at=main`: 200 with both blocks, block A carrying a session chip href with the ULID, block B commit-only; stranger on public repo + unpublished session → block renders, chip absent; unknown path → 404; binary file → 200 "blame unavailable" (not 500). Git-level unit tests for the porcelain parser (multi-block, boundary commit `^sha` lines skipped, filenames with spaces) live in `blame.rs #[cfg(test)]`.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged-git blame` and `TMPDIR=/dev/shm cargo test -p starforged --test web_history_sessions blame` — Expected: FAIL.
- [ ] **Step 3: Implement porcelain parser + `blame_with_sessions` + page.** Parser is strict: lines starting with SHA-40 + 3 ints open a block; `author`/`author-time` headers captured; `filename` line ends headers; tab-prefixed lines are content until the next SHA line. `Core::blame_with_sessions` resolves `rev` through the existing commit-resolution path (`core.commit(&access, rev)` shape — verify exact name; fall back to default branch like `tree` does). Template escapes every line (no highlighting in M1e — plain escaped text; highlighting blame lines is deferred, recorded in E6).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged-git -p starforged-core -p starforged-web` then `TMPDIR=/dev/shm cargo test -p starforged --test web_history_sessions` + PG gate for db-touching packages — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-git/src/blame.rs crates/starforged-git/src/lib.rs crates/starforged-core/src/blame.rs crates/starforged-core/src/lib.rs crates/starforged-web/src/pages/blame.rs crates/starforged-web/templates/blame.html crates/starforged/tests/web_history_sessions.rs
  git commit -m "Add blame page with session chips"
  ```

---

### Task E5: Publish/unpublish + delete + admin rescan route

**Files:**
- Modify: `crates/starforged-core/src/ingest.rs` (publish/unpublish/delete methods) — or `read.rs`? Mutations stay with the session domain: `ingest.rs`. `crates/starforged-db/src/sessions.rs` (`set_visibility` from E1 reused; no new queries), `crates/starforged-api/src/sessions.rs` + `lib.rs` (4 routes), `crates/starforged-web/src/pages/sessions.rs` (4 forms on the viewer: publish/unpublish for maintain+, delete for uploader/admin, rescan for admin, release/purge buttons moved beside them from the M1d API-only queue), `templates/session.html` (banner actions)

**Interfaces:**
- Consumes: E1 read helper (post-mutation re-check for the redirect target), M1d `purge_session`/`release_session`/`rescan_session` (rescan route THIN-wraps `Core::rescan_session` — no new verdict logic), `delete_session` + `blob_decref` + `delete_session_links` rows.
- Produces:
  ```rust
  impl Core {
      /// Public repos only (else Invalid "publishing has no effect on non-public repos");
      /// require_repo(maintain) or site admin; sets visibility=published + audit session.publish.
      pub async fn publish_session(&self, actor: &User, access: &RepoAccess, ulid: &str) -> CoreResult<SessionRow>;
      /// Mirror with visibility=inherit + audit session.unpublish. Unpublishing a never-published session is Ok no-op.
      pub async fn unpublish_session(&self, actor: &User, access: &RepoAccess, ulid: &str) -> CoreResult<SessionRow>;
      /// Uploader, repo admin, or site admin (via access); deletes session + segments
      /// (decref blobs; zero-ref swept by HourlyCleanup) + all links under the ULID
      /// + audit session.deleted. Quarantined sessions delete the same way (purge stays
      /// the admin-queue path with its session.purged audit; delete is the user path).
      pub async fn delete_session(&self, actor: &User, access: &RepoAccess, ulid: &str) -> CoreResult<()>;
  }
  // API (scope: session-bearing PAT/OAuth; API auth follows the existing ApiAuth convention):
  // POST   /api/v1/repos/{owner}/{repo}/sessions/{ulid}/publish   → 200 session JSON (maintain+; 403 else; 422 on non-public repo)
  // POST   .../unpublish → 200 (same auth)
  // DELETE .../sessions/{ulid} → 204 (uploader/admin; unknown → 404)
  // POST   .../sessions/{ulid}/rescan → 200 {"quarantine": ..., "reason": ..., "detail": ...} (admin only; re-runs rule scan on stored segments)
  // Web (RequireUser + _csrf, same pattern as tokens page):
  // POST /{owner}/{repo}/sessions/{ulid}/publish|unpublish|delete + POST .../rescan (admin) + existing release/purge as web forms
  ```
- Why delete is cheap (justification for building it now): every primitive exists — `db_sessions::delete_session` returns removed segments, the caller decrefs, `delete_session_links` covers trailer-first rows, HourlyCleanup sweeps zero-ref files. The ONLY new code is the auth check (uploader-or-admin) + audit. Not building it would leave M1 without §11.5's user-delete path while the viewer makes sessions visible for the first time.

- [ ] **Step 1: Write failing mutation tests.** API tests in `api_sessions_read.rs` (with `TestServer`): maintain user publishes on public repo → 200 + anonymous can now GET; write-only user → 403; publish on private repo → 422; unpublish → anonymous 404 again; uploader DELETE → 204 + blob refcount decremented + links gone + anonymous 404; stranger DELETE → 404 (undiscoverable, not 403); admin rescan on clean session → 200 `{"quarantine":"none"}`; admin rescan with a planted secret → `quarantined` with reason. Web tests in `web_sessions_viewer.rs`: publish form without `_csrf` → 403 (CSRF enforced); with token → redirect to viewer showing "Published" badge; delete form as uploader → redirect + session gone. Audit rows asserted for all five actions (`session.publish/unpublish/deleted/purged/quarantine*`).
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test api_sessions_read` and `TMPDIR=/dev/shm cargo test -p starforged --test web_sessions_viewer publish` — Expected: FAIL (methods/routes do not exist).
- [ ] **Step 3: Implement mutations + routes + banner forms.** Publish/unpublish/delete/rescan each: handler resolves `access` via `require_repo` at the documented level (publish/unpublish: `Maintain`; delete: `Read` + in-Core uploader-or-admin check so the auth reads naturally; rescan/release/purge: `Admin`), calls `Core`, audits inside `Core` (never in handlers). Web forms POST back to the viewer URL and re-render with a success banner (same created/error pattern as `tokens.html`); session JSON API errors keep the `{error:{...}}` envelope (no CLI-shaped exceptions here — the CLI never calls these).
- [ ] **Step 4: Run tests.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test api_sessions_read --test web_sessions_viewer` then `STARFORGE_TEST_PG=1 TMPDIR=/dev/shm cargo test -p starforged-core -p starforged-db -p starforged --test api_sessions_read` — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-core/src/ingest.rs crates/starforged-api crates/starforged-web/src/pages/sessions.rs crates/starforged-web/templates/session.html crates/starforged/tests/api_sessions_read.rs
  git commit -m "Add session publish, delete, and admin rescan endpoints with UI"
  ```

---

### Task E6: Browser/e2e test + XSS corpus + docs close-out

**Files:**
- Create: `crates/starforged/tests/browser_sessions.rs`? No — Playwright lives outside cargo (verify exact harness location; if none exists, E6 adds `e2e/sessions.spec.ts` + the minimal Playwright config following the repo's existing browser-test convention — if no convention exists, E6 uses `reqwest` + HTML assertions instead and records why). Prefer: extend `web_history_sessions.rs`/`web_sessions_viewer.rs` where possible; truly new file only for the XSS corpus if it fits neither.
- Modify: `README.md` (session viewer + publish rules section), `docs/superpowers/specs/2026-11-03-starforge-design.md`? No — spec is frozen; record deltas in the plan files only. `crates/starforged-web/src/session_render.rs` (only if the corpus finds holes — otherwise no change).

**Interfaces:**
- Consumes: every prior task; the E2 rendering rules as the oracle.
- Produces: (a) XSS payload corpus test through EVERY renderer (each `EventKind`, commit panel chip/preview, blame block/chip, quarantine banner reason/detail, session title/models): payloads include `<script>`, `<img src=x onerror>`, `javascript:` links, `"><svg onload>`, markdown image/exfiltration `[x](https://evil)`, nested quotes breaking out of attributes, and a fake `<<<STARFORGE-UNTRUSTED-ENDS>>>` injection line — asserting escaped-or-sanitized output and byte-absence of the raw payload; (b) CSRF matrix: every web POST from E2/E5 without `_csrf` → 403; (c) quarantine-content test: quarantined session body bytes (a planted canary token string) present for uploader/admin HTML, absent (404, no bytes) for stranger/anonymous; (d) browser test: viewer loads, tool-expand works via htmx, `#turn-<seq>` deep link scrolls, publish flow clicks through (Playwright; fallback recorded if harness missing); (e) README "Sessions (M1e)" subsection (~40 lines, README voice): viewer URL + paging, publish rules table, delete rules, quarantine banner, download JSONL, deferred list (split view, export/import with Ruling R1 pointer, server-side session search → M4).

- [ ] **Step 1: Write the failing corpus + e2e tests.** Corpus test constructs one hostile session (every kind carries two payloads) and asserts per-renderer; e2e boots TestServer, uploads via the M1d wire (reuse `ingest.rs` D7 helpers — `ingest_meta`/`ingest_segment`), then walks viewer → commit panel → blame → publish → anonymous-read → delete as separate HTTP principals. If any assertion fails on correct code (e.g. ammonia allows an attribute the test forbids), FIX THE TEST to match the documented sanitizer contract (`markdown.rs` behavior), never loosen the renderer to pass.
- [ ] **Step 2: Run to verify failure.** Run: `TMPDIR=/dev/shm cargo test -p starforged --test web_sessions_viewer xss` (or the new corpus file) — Expected: FAIL (corpus file does not exist; renderer holes, if any, show as failures after writing).
- [ ] **Step 3: Fix renderer holes (if any) + README.** Renderer fixes stay inside `session_render.rs` + templates (no new escaping helpers — reuse `markdown::render`/`plain` + askama). README section per (e). Record known gaps in the README as deferred (split-view toggle, blame syntax highlighting, repo session index → M4).
- [ ] **Step 4: Run the full sweep.** Run: `TMPDIR=/dev/shm cargo test --workspace` then `STARFORGE_TEST_PG=1 scripts/check.sh` — Expected: PASS everything (all M1d suites + all M1e suites on both engines).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged/tests README.md crates/starforged-web/src/session_render.rs crates/starforged-web/templates e2e
  git commit -m "Add session viewer XSS corpus, browser test, and documentation"
  ```
