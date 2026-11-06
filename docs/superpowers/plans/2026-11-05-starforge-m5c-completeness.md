# Starforge M5c (v0.1 completeness: CLI, session viewer, deletion, OpenAPI, property tests) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the spec gaps that M0–M2 left before the v0.1.0 release (program ledger, `maps/spec-gaps.md`):
- **CLI (§10.3, §7.9):**
  - `starforge sessions publish`, `unpublish`, and `delete` (they are stubs today);
  - `starforge export` and `starforge import` session bundles.
- **Session viewer (§10.2):**
  - commit markers;
  - per-turn token usage;
  - search within the session;
  - split view (transcript left, the resulting diff right).
- **Deletion (§11.5):** deleting an account deletes the sessions it uploaded through the same path as a session delete (blob reference counts and index documents), not by a database cascade alone.
- **REST API (§10.4, §5.1):** an OpenAPI 3.1 document generated from code with utoipa, served at `/api/v1/openapi.json`.
- **Property tests (§13):** proptests for the §6.4 rules and the ref policy (M3a added permission resolution).

**Architecture:** `starforge-cli` (MIT OR Apache-2.0) gains commands through its existing API client. The server gains:
- any missing read endpoint the export needs: raw segment download and links listing;
- viewer features in `starforged-web` (server-rendered, with the plain ES-module enhancement);
- a Core account-deletion fix;
- utoipa annotations on every API route.

**Tech Stack:** as before, plus **utoipa** (new dependency, D1) in `starforged-api` only.

**Spec:** §10.3 (CLI command table), §7.9 (export and import bundles), §10.2 (viewer), §11.5 (deletion), §10.4 (OpenAPI 3.1), §5.1 (`starforged-api`: OpenAPI 3.1 via utoipa), §13 (property tests), §6.4 (session rules).

**Explicit non-goals for v0.1.0** (program rulings; reported in the final summary):
- **Fluent message catalog (§10.6):** English strings stay in templates. Moving every template string into Fluent is a large retrofit with no user-visible change for an English-only release. Cost: translation later needs the retrofit.
- **htmx (§3 D12):** pages work as plain server-rendered forms with the one JS module. Nothing in the spec's behavior requires htmx. Cost: none functional.
- **Per-response CSP nonce (§11.1):** the CSP forbids inline scripts entirely and serves scripts only from the origin, which is stricter than a nonce allowance. Cost: none.

## Global Constraints

- **New dependency (D1):** `utoipa` with the `axum_extras` feature only if needed by the router, in `starforged-api` only. Use the latest stable version; record it in the report.
- **Licensing:** `starforge-cli` stays MIT OR Apache-2.0 and never depends on `starforged-*`. It talks only HTTP to the API.
- **CLI session content handling (§11.2):** `export` writes exactly what the API returns to that user. Raw segments appear in the export only when the server returns them (raw storage enabled and the user permitted). `import` never re-uploads to a server without confirming the target repository (`--repo` is required).
- **§6.4 everywhere:** export, viewer search, and split view expose only what the viewer can read. A session's commit diff in the split view requires repository read access, which §6.4 already implies.
- **The viewer works without JS** (§10.2): search is a GET form with server-side results; the split view is a server-rendered two-column layout chosen by `?split=<sha>`. The JS module only enhances: in-page highlight and switching commits without a reload. Keyboard navigable (§10.6): every control is a link, button, or input with visible focus.
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. utoipa.** The spec names it (§5.1). Every route registered in `starforged-api`'s router appears in the generated document, with request and response schemas for JSON bodies and the shared error envelope. The document is generated at startup (cached) and served unauthenticated (it reveals no data). A test enumerates the router's routes and asserts each method+path is in the document.
- **D2. Bundles (§7.9).** `<dir>/<owner>__<repo>/<ulid>/`:
  - `session.json`: the API metadata as returned;
  - `events.jsonl`: the normalized transcript (via `/events`);
  - `segments/<n>.raw.zst`: only when the API serves raw;
  - `links.json`: commit links;
  - a top-level `bundle.json` (format version 1, server URL, exported_at).

  `starforge import <dir> --repo <owner>/<repo>` uploads each session through the normal upload API (meta, segments, complete), preserving ULIDs, with the CLI re-segmenting the normalized events by the format crate's rules, and re-creating `cli_claim` links from `links.json`. Re-importing an existing ULID reports "exists" and skips it.
- **D3. Viewer.**
  - **Commit markers:** a marker after the event at each commit link's `seq_end`, showing the short SHA, linked to the commit page.
  - **Per-turn usage:** assistant events with usage show input, output, cache, and reasoning counts.
  - **Search:** `?q=` (case-insensitive substring over message text, tool names, and file paths; at most 200 hits) lists `seq` links that jump to the right page and `#turn-<seq>`.
  - **Split view:** `?split=<sha>` (the sha must be one of the session's linked commits in this repository) renders the commit's diff beside the transcript. Commit markers link to it.
- **D4. Account deletion.** `Core::delete_account` deletes each uploaded session through `Core::delete_session`'s internals (blob decref, index docs, links) before deleting the user row, in bounded batches. It is idempotent if interrupted: rerunning finishes the job.

## File Structure

```
crates/starforge-cli/src/{cli.rs,commands/sessions/*.rs,commands/export.rs (new),commands/import.rs (new),api/*.rs}
crates/starforge-cli/tests/{sessions_admin.rs,export_import.rs}
crates/starforged-api/src/{sessions.rs (raw segment GET, links GET if missing),openapi.rs (new),lib.rs, every route module (annotations)}
crates/starforged-core/src/{read.rs (search, markers),account.rs}
crates/starforged-web/src/{pages/session.rs,session_render.rs}, templates/session.html, static/session-viewer.js
crates/starforged-core/src/{read.rs or permission.rs} (§6.4 pure predicate proptest), crates/starforged-git/src/refpolicy.rs (proptest)
crates/starforged/tests/{web_session_viewer.rs,account_deletion.rs,openapi.rs,e2e_export_import.rs}
README.md
```

---

### Task V1: CLI session administration and export/import

**Files:**
- Create: the CLI command modules and tests; `crates/starforged/tests/e2e_export_import.rs`.
- Modify: the CLI `cli.rs` stubs; the API read endpoints, if missing.

**Interfaces:**
- `starforge sessions publish <ulid> [--repo]`, `unpublish <ulid> [--repo]`, `delete <ulid> [--repo] [--yes]`;
- `starforge export --repo <o>/<r> [--session <ulid>…] <dir>`;
- `starforge import <dir> --repo <o>/<r>`.

- [ ] **Step 1: Write the failing tests.**
  - **CLI unit tests against a mock server:** argument parsing and error messages (401, 403, 404).
  - **End to end with the real server:**
    - upload a session via the CLI flow;
    - export it;
    - delete it with `starforge sessions delete` (it is gone, with blob refs decremented);
    - import the bundle into another repository (the session is visible, with links recreated);
    - publish and unpublish toggle visibility as seen by an anonymous reader on a public repository.
  - **Export permissions:** a user who cannot read a session cannot export it (404 surfaces as a clear CLI error).
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforge-cli` and `cargo test -p starforged --test e2e_export_import`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add CLI session publish, unpublish, delete, export, and import`.

---

### Task V2: Session viewer completeness

**Files:**
- Modify:
  - `crates/starforged-core/src/read.rs`;
  - `crates/starforged-web/src/{pages/session.rs,session_render.rs}`, `templates/session.html`, and the viewer JS module;
  - `crates/starforged/tests/web_session_viewer.rs` (new or existing).

**Interfaces:** D3.

- [ ] **Step 1: Write the failing tests.**
  - **Markers:** commit markers appear after the right event and link to the commit page.
  - **Per-turn usage** renders.
  - **Search:**
    - finds text on page 2 and links to it;
    - is limited to 200 hits;
    - is escaped;
    - tool inputs are not searched (matches spec §10.5's scope).
  - **Split view:**
    - renders the diff for a linked commit;
    - refuses a sha that is not linked (404);
    - is unreadable for users without repository read.
  - **Without JS:** the page content is complete. A test fetches the HTML and checks that the search results and the split columns exist server-side.
  - **XSS:** hostile message text and file paths render escaped in markers, search, and split view.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test web_session_viewer`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test web_session_security` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add commit markers, per-turn usage, search, and split view to the session viewer`.

---

### Task V3: Account deletion and property tests

**Files:**
- Modify:
  - `crates/starforged-core/src/{account.rs,ingest.rs or read.rs}`;
  - `crates/starforged-git/src/refpolicy.rs`;
  - test files `account_deletion.rs` (new) and the proptest modules.

**Interfaces:**
- D4;
- `read::can_read_session` exposed as a pure fn over facts, if it is not pure already (no behavior change);
- proptests.

- [ ] **Step 1: Write the failing tests.**
  - **Account deletion:** delete an account that uploaded sessions to two repositories; afterwards the sessions are gone, blob refcounts are decremented, the blob GC removes the zero-ref blobs, and the index has no docs for them. An interrupted deletion (fail midway via a test hook) completes on rerun.
  - **§6.4 proptest:** the predicate equals a reference implementation written directly from the three spec rules, over all fact combinations (exhaustive is fine; there are few booleans).
  - **Ref-policy proptest:** generated ref names (valid and hostile: `..`, control chars, `@{`, trailing `.lock`, leading `-`) never panic; non-allowed namespaces are refused unless allow-listed; `refs/trails/*` are always refused for clients.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test account_deletion`, `cargo test -p starforged-core read`, and `cargo test -p starforged-git refpolicy`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Delete accounts' sessions through Core and add §6.4 and ref-policy property tests`.

---

### Task V4: OpenAPI 3.1

**Files:**
- Create:
  - `crates/starforged-api/src/openapi.rs`;
  - `crates/starforged/tests/openapi.rs`.
- Modify:
  - `Cargo.toml` (workspace dependency);
  - every route module in `starforged-api` (path annotations and DTO schemas).

**Interfaces:** D1.

- [ ] **Step 1: Write the failing tests.**
  - `GET /api/v1/openapi.json` returns `openapi: 3.1.x`.
  - Every method+path in the router is in `paths`, by router enumeration or a maintained list checked against the router's registration code.
  - Error responses reference the shared error schema.
  - Bearer auth is declared.
  - The document validates as JSON and is stable across two requests.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test openapi`. Expected: FAIL.
- [ ] **Step 3: Implement.** This is mechanical across many modules; keep DTOs unchanged.
- [ ] **Step 4: Run tests.** Run the same command plus `cargo test -p starforged-api` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Serve an OpenAPI 3.1 document generated from the API code`.

---

### Task V5: Docs

**Files:** `README.md`.

- [ ] **Step 1: README:**
  - the CLI command table updated, with export/import bundle format;
  - viewer features;
  - account deletion semantics;
  - an OpenAPI note;
  - the explicit v0.1.0 non-goals (Fluent, htmx, CSP nonce) in a "Known gaps" section.

  Check every example against the code.
- [ ] **Step 2: Commit** (gate first): `Document CLI, viewer, and API completeness`.
