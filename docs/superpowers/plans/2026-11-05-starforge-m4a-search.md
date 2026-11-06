# Starforge M4a (Search and code search) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec §10.5.
- **Index:** a tantivy index of Trails (title, intent, comments) and session events (prompt and message text, tool names, file paths, linked commit SHAs).
- **Filters:** repository, agent, model, author or uploader, date range, and linked commit.
- **Permissions:** enforced in the query and re-checked against the database for every hit before rendering.
- **Code search:** `git grep` on one repository's default branch.
- **Rebuild:** `starforged index rebuild`.
- **Purge:** purging or deleting a session removes its index documents (§11.3).

**Architecture:**
- **New crate `starforged-index`** (AGPL), the only crate depending on tantivy. It owns the schema, document building from plain inputs, the writer and reader, and query building with the permission filter. It has no database access: `Core` feeds it.
- **Data:** `data/index/` (config `storage.index_dir`), rebuildable and skipped by backups (M5).
- **`starforged-core`:**
  - holds an `Arc<SearchIndex>`;
  - indexing runs in jobs. `IndexSessionEvents` becomes real, and `IndexTrail`, `IndexRepo`, and `DropSessionDocs` are added, de-duplicated by key and enqueued at every mutation point;
  - search fns apply permissions and re-checks.
- **`starforged-web`:** `/search` (Trails and Sessions tabs) and `/{owner}/{repo}/search` (code).
- **`starforged-api`:** `GET /api/v1/search/trails`, `GET /api/v1/search/sessions`, and `GET /api/v1/repos/{owner}/{repo}/search/code`.
- **`starforged`:** the `index rebuild` subcommand; opens the index at startup.

**Tech Stack:** as before, plus **tantivy 0.27.0** (new dependency, D1) in `starforged-index` only.

**Spec:** §10.5 (search, filters, permissions, re-check, code search, rebuild), §6.4 (session read rules), §11.1 (session search results send `X-Robots-Tag: noindex`), §11.3 (purge removes index docs), §5.3 (`data/index/`), §13 (access matrix includes search results).

**Deferred (not built here):** semantic search (non-goal); indexed code search (non-goal: `git grep` only); search over review comments; cross-repo code search.

## Global Constraints

- **New dependency (D1):** `tantivy = { version = "0.27.0" }` in `[workspace.dependencies]`, used ONLY by `starforged-index`. Default features are acceptable if they build on musl (pure-Rust compression only; no C dependencies). The implementer verifies with `cargo tree -p starforged-index -e features`, removes any feature that needs a C toolchain, and records the final feature set in the report.
- **The index is never the source of truth.** Every hit is re-read from the database and re-checked (repo read permission, plus §6.4 for sessions) before it is returned. A stale document can only ever hide a result, never leak one.
- **Session document content** comes from the same reader the session viewer uses (`load_session_items`, with redaction applied), so the index never holds text the viewer would redact. Quarantined sessions ARE indexed, with their quarantine state, so the uploader and admins can find them; the query filter and re-check hide them from everyone else.
- **Indexing never blocks or fails a mutation.** Mutations only enqueue jobs. Jobs retry on the existing ladder. The writer commits in batches.
- **Startup:** a missing or corrupt index is recreated empty and a full rebuild job is enqueued. The server never refuses to start because of the index.
- **No route bypasses `starforged-core`.** Search pages and the API call `Core`.
- **Escaping:** snippets and highlights are built as text plus highlight ranges and rendered through askama escaping. Never render HTML produced by tantivy.
- **Code search** runs `git grep` through `starforged-git`'s hermetic helper with these limits:
  - fixed-string by default, with an optional case-insensitive switch;
  - a timeout of 10 s;
  - at most 200 matches over at most 50 files, and lines truncated to 500 characters;
  - the query is never interpreted as options: pass it with `-e` after `--fixed-strings`, and refuse an empty query or one longer than 256 characters.
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. tantivy 0.27.0.** The spec names tantivy (D6, §10.5). The cost if wrong is a large dependency, isolated to one crate.
- **D2. Schema.** One index; field `doc_kind` ∈ {`trail`, `event`}.
  - **Common fields:** `repo_id` (i64, indexed, fast), `repo_visibility` (`public|internal|private`, string), `ts` (i64 date, fast).
  - **Trail docs** (one per Trail, keyed `trail_id`):
    - `title` and `body` (text): the intent plus all comment bodies;
    - `author_id`;
    - `state`.
  - **Event docs** (one per session event that has searchable content, keyed `session_id` + `seq`):
    - `text`: user and assistant message text, reasoning excluded; tool names; file paths;
    - `agent` and `models` (strings);
    - `uploader_id`;
    - `published` (0/1);
    - `quarantined` (0/1);
    - `commits`: the session's linked commit SHAs, from `commit_links`.
  - Tool call inputs and outputs are NOT indexed. They can be large and secret-prone; spec §10.5 lists only tool names.
- **D3. Permission filter in the query.** For viewer V:
  - **Repo readability:**
    - `repo_visibility = public`, OR
    - `repo_visibility = internal AND V signed in`, OR
    - `repo_id ∈ R(V)`, where `R(V)` is the private and internal repositories V can read: explicit grants, org and team grants, or all repositories for site admins.
  - **Event docs additionally get the §6.4 clauses:**
    - (`repo_visibility != public` OR `published = 1` OR `repo_id ∈ M(V)`, where M(V) is the repositories where V is a member), AND
    - (`quarantined = 0` OR `uploader_id = V` OR `repo_id ∈ A(V)`, where A(V) is V's repo-admin repositories).
  - The re-check after retrieval uses `Core::permission_on` and the §6.4 predicate. A result that fails the re-check is dropped and the next one fetched, so a page is filled from up to 3× the page size of candidates.
- **D4. Filters.**
  - `repo` (`owner/name`); `agent`; `model` (term in `models`); `author` (handle → `author_id` for Trails, `uploader_id` for events);
  - `from`/`to` (RFC 3339 date or date-time, inclusive, applied to `ts`; a Trail's `ts` is its `updated_at`, an event's is its own timestamp);
  - `commit` (a full or ≥7-character SHA prefix, matched against `commits`; prefixes go through a prefix query).
  - Pagination: `page` (1-based) and `per_page` (≤ 50, default 20).
  - Session results group events by session: each result shows the session and its best-matching events (at most 3 snippets), and links to the viewer at `#turn-<seq>`.
- **D5. Index lifecycle.**
  - **Mutation → job:**
    - Trail create, edit, comment, comment edit, or state change → `IndexTrail{trail_id}`;
    - session complete or segment append after complete → `IndexSessionEvents{session_id}` (replace all docs of the session);
    - publish, unpublish, quarantine, release, link changes, rescan → `IndexSessionEvents`;
    - session delete or purge → `DropSessionDocs{session_id}`;
    - repo visibility change → `IndexRepo{repo_id}`, which rewrites `repo_visibility` on every doc of the repository by re-indexing it;
    - repo delete or purge → drop the repository's docs;
    - rename and transfer change no docs (ids are stable).
  - **De-duplication:** jobs dedupe by kind and id.
  - **Rebuild:** `starforged index rebuild` (server stopped) wipes and rebuilds from the database and blobs, printing counts. While the server runs, the tantivy writer lock makes it fail with a clear "stop the server or use the admin rebuild" message. The site-admin jobs page gains a "Rebuild search index" action that enqueues `RebuildIndex`.
- **D6. API shapes.**
  - `GET /api/v1/search/trails?q=&repo=&author=&from=&to=&page=&per_page=` → `{"results": [{"repo", "number", "title", "state", "updated_at", "snippet": {"text", "highlights": [[start, end]…]}}], "page", "per_page", "has_more"}`.
  - `GET /api/v1/search/sessions?q=&repo=&agent=&model=&author=&from=&to=&commit=&page=&per_page=` → sessions with matched events (`seq`, `kind`, `snippet`).
  - `GET /api/v1/repos/{owner}/{repo}/search/code?q=&case=sensitive|insensitive` → `{"ref", "commit", "matches": [{"path", "line", "text"}], "truncated": bool}`.
  - Responses for session search send `X-Robots-Tag: noindex`, both web and API.

## File Structure

```
Cargo.toml                                              tantivy workspace dep
crates/starforged-index/{Cargo.toml,src/lib.rs,src/schema.rs,src/docs.rs,src/query.rs}   new crate
crates/starforged-core/src/{search.rs (new),jobs.rs,trails.rs,ingest.rs,rescan.rs,repos.rs,lib.rs}
crates/starforged-git/src/grep.rs                       new
crates/starforged/src/{main.rs,config.rs,serve.rs,admin.rs,index_cmd.rs (new)}
crates/starforged-api/src/search.rs                     new
crates/starforged-web/src/pages/search.rs               new, templates/search.html, code_search.html
crates/starforged/tests/{search_index.rs,api_search.rs,web_search.rs,code_search.rs,search_security.rs}
README.md
```

---

### Task S1: The index crate and the rebuild command

**Files:**
- Create:
  - the `starforged-index` crate;
  - `crates/starforged/src/index_cmd.rs`;
  - `crates/starforged/tests/search_index.rs`.
- Modify:
  - `Cargo.toml`;
  - `crates/starforged/src/{main.rs,config.rs,admin.rs}`;
  - `crates/starforged-core/src/{lib.rs,search.rs}` (open the index and build docs from rows).

**Interfaces:**
```rust
// starforged-index
pub struct SearchIndex;   // open_or_create(dir) -> Result<Self>; writer is internal (Mutex<IndexWriter>), reader reloads on commit
pub struct TrailDoc { pub trail_id: i64, pub repo_id: i64, pub repo_visibility: &'static str, pub title: String, pub body: String, pub author_id: Option<i64>, pub state: String, pub ts: i64 }
pub struct EventDoc { pub session_id: i64, pub seq: i64, pub repo_id: i64, pub repo_visibility: &'static str, pub text: String, pub agent: String,
                      pub models: Vec<String>, pub uploader_id: i64, pub published: bool, pub quarantined: bool, pub commits: Vec<String>, pub ts: i64 }
pub struct Scope { pub signed_in: bool, pub readable: Vec<i64>, pub member: Vec<i64>, pub admin: Vec<i64>, pub viewer_id: Option<i64> }
impl SearchIndex {
    pub fn replace_trail(&self, doc: TrailDoc) -> Result<()>;
    pub fn replace_session(&self, session_id: i64, docs: Vec<EventDoc>) -> Result<()>;
    pub fn drop_session(&self, session_id: i64) -> Result<()>;
    pub fn drop_repo(&self, repo_id: i64) -> Result<()>;
    pub fn commit(&self) -> Result<()>;
    pub fn search_trails(&self, q: &TrailQuery, scope: &Scope, offset: usize, limit: usize) -> Result<Vec<TrailHit>>;
    pub fn search_events(&self, q: &EventQuery, scope: &Scope, offset: usize, limit: usize) -> Result<Vec<EventHit>>;
    pub fn stats(&self) -> Result<IndexStats>;   // doc counts per kind (doctor in M5 uses it)
}
```

- [ ] **Step 1: Write the failing tests.**
  - **Unit (in-crate, temp dir):**
    - documents are found by title, body, and event text, and by tool name and file path;
    - each filter narrows the results;
    - **the permission filter**, given a hand-built `Scope`:
      - a private repository's docs are absent unless its id is in `readable`;
      - a public unpublished event is absent for a non-member;
      - a quarantined event is absent unless the viewer is the uploader or an admin;
    - `replace_session` replaces the session's docs; `drop_session` and `drop_repo` remove them.
  - **Integration:** `starforged index rebuild` on a data dir with Trails and a completed session produces the expected counts. Run against a running server's dir, it fails with the lock message.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-index` and `cargo test -p starforged --test search_index`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy and `cargo tree -p starforged-index -e features` (record the feature set in the report). Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add the search index crate and index rebuild`.

---

### Task S2: The indexing pipeline

**Files:**
- Modify:
  - `crates/starforged-core/src/{jobs.rs,search.rs,trails.rs,changes.rs (comments are Trail comments only),ingest.rs,rescan.rs,repos.rs,admin.rs}`;
  - `crates/starforged/src/serve.rs` (startup recovery);
  - `crates/starforged-web/src/pages/admin.rs` (the rebuild action);
  - `crates/starforged/tests/search_index.rs`.

**Interfaces:** D5. `IndexSessionEvents` stops being a stub.

- [ ] **Step 1: Write the failing tests.**
  - After each mutation in D5, running the due jobs updates the index observably through `SearchIndex::search_*` with an admin scope:
    - create, edit, and comment on a Trail;
    - upload and complete a session;
    - publish and unpublish;
    - quarantine and release;
    - delete and purge (the docs are gone);
    - a repository visibility change (the `repo_visibility` field changes, so an anonymous scope sees or loses the docs);
    - repository deletion.
  - A corrupt index directory at startup is recreated and a rebuild job is enqueued.
  - The admin rebuild action enqueues `RebuildIndex` (CSRF, site admin only).
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test search_index`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test api_sessions --test api_trails --test web_admin` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Index Trails and session events as they change`.

---

### Task S3: Search API and pages

**Files:**
- Create:
  - `crates/starforged-api/src/search.rs`;
  - `crates/starforged-web/src/pages/search.rs` and `templates/search.html`;
  - tests `api_search.rs` and `web_search.rs`.
- Modify:
  - `crates/starforged-core/src/search.rs` (scope building, re-check, pagination fill);
  - `crates/starforged-api/src/lib.rs`, `crates/starforged-web/src/lib.rs`;
  - the base layout (a search box in the header).

**Interfaces:**
- `Core::search_trails(viewer, query) -> CoreResult<Page<TrailResult>>`;
- `Core::search_sessions(viewer, query) -> CoreResult<Page<SessionResult>>`;
- D3, D4, D6.

- [ ] **Step 1: Write the failing tests.**
  - The web page with Trails and Sessions tabs:
    - filters apply;
    - pagination works;
    - highlights render;
    - session results link to `#turn-<seq>`.
  - API shapes as in D6.
  - The `noindex` header on session search.
  - **Validation:** an invalid date or SHA, or a `per_page` above 50, gives 422.
  - **Re-check:**
    - a doc whose repository became private after indexing, with the index job not yet run, is NOT returned to a former reader;
    - a session quarantined in the database but not yet re-indexed is NOT returned.
  - **XSS:** hostile Trail titles, comment text, and session text render escaped, with highlights intact.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test api_search --test web_search`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add Trail and session search`.

---

### Task S4: Code search

**Files:**
- Create:
  - `crates/starforged-git/src/grep.rs`;
  - `crates/starforged-web/templates/code_search.html`;
  - `crates/starforged/tests/code_search.rs`.
- Modify:
  - `crates/starforged-core/src/search.rs`;
  - `crates/starforged-api/src/{search.rs,lib.rs}`;
  - `crates/starforged-web/src/{lib.rs,pages/search.rs}`;
  - the repository navigation template (a search field on code pages).

**Interfaces:**
- `starforged_git::grep::grep(repo_dir, commit, query, case_insensitive, limits) -> Result<GrepResult>`;
- `Core::code_search(viewer, owner, repo, query) -> CoreResult<GrepResult>` (repository read access).

- [ ] **Step 1: Write the failing tests.**
  - Matches on the default branch only: a match that exists only on another branch is absent.
  - Case sensitivity works.
  - Regex metacharacters are literal.
  - A query starting with `-` is searched literally, not treated as an option.
  - Binary files are skipped.
  - The limits mark `truncated`.
  - Each result links to the file and line.
  - An empty repository gives an empty result.
  - Non-readers get 404.
  - XSS: hostile file content renders escaped.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-git grep` and `cargo test -p starforged --test code_search`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add code search over the default branch`.

---

### Task S5: Search access matrix and docs

**Files:**
- Create: `crates/starforged/tests/search_security.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep (§13 access matrix for search).** Combine:
  - permission levels: anonymous, signed-in non-member, read, triage, write, maintain, admin, site admin, an org base grant, a team grant;
  - repository visibility: public, internal, private;
  - session quarantine state: none, quarantined, released;
  - published flag.

  For each combination, the session search result set equals the set of sessions the session API lets that user read, and the Trail search equals the Trail list access. Revocation is immediate through the re-check (no job run needed). Code search follows repository read access.
- [ ] **Step 2: Run the sweep** 3 times; all green. Fix defects found and report them.
- [ ] **Step 3: README:** a "Search" section (what is indexed and what is not, filters, permissions, code search limits, `index rebuild`, the admin rebuild action, and the API). Check examples against the code.
- [ ] **Step 4: Commit** (PG gate first): `Add search access matrix and docs`.
