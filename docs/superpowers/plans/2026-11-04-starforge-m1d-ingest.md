# Starforge M1d (Server Session Ingest) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the server half of spec §7: session upload endpoints with the exact wire contract the `starforge` CLI (M1c) already speaks, validation (format version, numbering, BLAKE3, 16 MiB cap, idempotency, `complete` semantics), device-flow OAuth (`POST /api/v1/oauth/device/code` + `/token` plus a web approval page) so `starforge auth login` works against a real server, server-side re-scan with `starforge-redact` plus quarantine + audit + an in-app admin quarantine queue, the content-addressed blob store, commit-link resolution from both ends (push trailers and CLI claims, either arriving first), and the ingest follow-up jobs on the existing queue. No session viewer UI, no blame integration, no search indexing, no webhook delivery, no S3 backend (all later milestones).

**Architecture:** No new service layer: everything goes through `starforged-core` (the only path to stored state). One new leaf crate `starforged-blob` (AGPL, filesystem backend + `BlobStore` trait boundary; S3 is a future implementor). `starforged-db` gains `sessions.rs` (session/segment/commit-link/blob rows) plus dual migrations `0008_sessions.sql`, and `oauth.rs` (device-code rows) plus dual migrations `0009_device_oauth.sql`. `starforged-core` gains `ingest.rs` (authorize → validate → store → re-scan/quarantine → jobs, all behind `Core` methods), `oauth.rs` (device-code issue/approve/poll/token-grant, behind `Core` methods), `quota.rs` (storage + volume enforcement, rate-limit hook), and `Job` variants whose heavy bodies (index, webhooks) stay stubs owned by later milestones. `starforged-api` gains `sessions.rs` (the four upload routes + three admin quarantine routes, all thin over `Core`) and `oauth.rs` (device-code + token endpoints with RFC 8628 error bodies). `starforged-web` gains a device approval page (`GET`/`POST /oauth/device`, `RequireUser` + CSRF, modeled on the tokens settings page) — the smallest approval surface consistent with the existing pages. `starforged` gains a `[sessions]` config section mapped into `CoreConfig`, and the post-push task in `starforged-web/src/githttp.rs` snapshots refs to feed trailer scanning. Tests assert HTTP status, DB rows, and blob bytes — never tautologies.

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8 (existing), sqlx `Any` (SQLite + Postgres, `$N` placeholders), tokio fs, `starforge-format` (SessionMeta parse, decompress, blake3), `starforge-redact` (server re-scan), `zstd` + `ulid` + `blake3` (all already in `[workspace.dependencies]`), reqwest (dev/test HTTP client, already workspace).

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` §6.1 (credentials: CLI OAuth tokens, 1 h access / 90 d refresh), §6.3 (session/segment/commit-link/blob model), §6.4 (session access rules), §7.5 (upload protocol), §7.6 (discovery + CLI auth), §7.7 (server ingest), §7.8 (Trace Format v1), §9 (authentication: device grant for the first-party CLI), §11.3 (secrets/quarantine), §11.5 (deletion), §11.6 (quotas), §10.4 (webhooks, outbox only), §13 (server tests), §14 M1. Later milestones consume this (viewer M1e, raw-slice follow-up M1f, Trails M2, search M4, rate limits M5); they are out of scope here.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** every touched/created server crate stays `AGPL-3.0-or-later` (`license.workspace = true`, `publish.workspace = true`). The new `starforged-blob` crate is AGPL the same way. MIT crates (`starforge-format`, `starforge-redact`) are consumed as path dependencies only — never copied, never re-licensed.
- **Dependencies:** NO new `[workspace.dependencies]` entries. `starforged-core` adds path deps on `starforge-format`, `starforge-redact`, `starforged-blob` (named + justified in D2) and adopts existing workspace `zstd` and `ulid`. `starforged` integration tests add dev-deps on `starforge-format` + `starforge-redact` (named + justified in D7). Anything else must be named in its task and justified in one sentence.
- **Migrations:** every schema change lands as `0008_sessions.sql` (or the next free number) in BOTH `crates/starforged-db/migrations/sqlite/` and `.../postgres/`, kept in lockstep. Only types/SQL valid on both engines (`$N` placeholders numbered by first appearance, `BIGINT`/`INTEGER` → `i64`, booleans as `0`/`1`, timestamps as unix seconds). Forward-only per spec §12; 0008 is additive-only (new tables + one `DEFAULT ''` column), so upgrade is a restart. Verify with `scripts/check.sh` AND `STARFORGE_TEST_PG=1 scripts/check.sh`.
- **No route bypasses `starforged-core`:** axum handlers authenticate (scope check) and delegate; all permission, validation, quota, and state logic lives on `Core`. Web handlers never touch `Db` or the blob store directly.
- **Determinism:** same request bytes → same stored bytes, same BLAKE3, same quarantine verdict. Re-scan uses fixed rule order (`BUILT_IN_ORDER` + repo + site); no wall-clock in verdicts (timestamps only on rows).
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green; SQL touched → also `STARFORGE_TEST_PG=1` gate for the affected package before committing.
- **Out of scope (do not build):** session viewer UI/pages, blame integration, §6.4 read-path UI (M1e), raw-slice upload wire (M1f follow-up — see Ruling R1), search indexing, webhook delivery (outbox enqueue only), S3 backend, export/import, refresh-token rotation (device flow issues a refresh token; the rotation grant lands in M3 with OIDC — see D3b), per-token rate limiting (hook only; M5 owns it per the milestone table).
- **Decisions this plan makes where the spec is silent:**
  - Blob layout is `data/blobs/<hash[0..2]>/<hash>` (spec §5.3), atomic write via temp file + rename on the same filesystem. Content addressing uses lowercase BLAKE3 hex of the exact stored bytes.
  - Refcounts live in the `blobs` row; a segment referencing an existing hash increments the refcount without rewriting bytes (cross-session dedup falls out: same ULID re-uploaded to two repos shares bytes). Zero-ref blob files + rows are swept by the existing `HourlyCleanup` job — no new job kind.
  - The admin quarantine queue is **API-only in M1d** (`GET` list + `POST` release/purge under the repo scope, repo-`admin` or site admin). No askama pages: M1e owns all session UI and would duplicate them. The API is sufficient for repo admins with a token and is fully testable over HTTP.
  - "Queues an in-app admin notification" (§7.7) is implemented as the quarantine flag on the session row (which populates the queue listing) plus an `session.quarantined` audit row. There is NO separate `notifications` table in M1d — the queue listing plus audit trail is the in-app surface. The uploader learns the verdict from the `quarantine` field in upload responses (see wire contract) and full uploader-facing visibility lands with the M1e read path.
  - Rule precedence for the server re-scan: `built_in.merge(&repo_rules).merge(&site_rules)` — site wins over repo, repo wins over built-ins. Justification: the operator's secret rules must be able to override a repo that weakened detection; mirrors the CLI's repo-wins-over-built-in convention one level up.
  - Repo rules source: a new `repos.redact_rules TEXT NOT NULL DEFAULT ''` column holding `.starforge/redact.toml` content (empty = built-ins only). There is no repo-settings UI in M1d; the column is written by tests/seeds and read by ingest. Site rules source: `[sessions] site_redact_toml` in `starforged.toml` (empty = none).
  - Non-`write` uploaders get `403` in M1d. The §6.4 "open change author" exception cannot be evaluated until Trails exist (M2); the `authorize_upload` signature takes the authenticated user so the exception plugs in without a route change.
  - **Ruling R1 (raw slices are NOT uploaded in M1d).** The CLI writes raw native slices to the spool but never sends them (the four-route wire has no raw body), and the server never asks for them. Consequence, stated explicitly: §7.5/§6.3 want the raw native slice stored when the repo enables raw storage (default ON per the user decision), and the spec's "re-normalize after adapter update" path (§7.1/§7.2) depends on it — so until the follow-up lands, repos have normalized events only, `sessions.raw_enabled` stays `0`, `segments.raw_blob_hash` stays `NULL`, and adapter re-normalization is impossible. The schema and blob plumbing already carry the follow-up with no migration rewrite (nullable `raw_blob_hash` on `segments`, key-agnostic `BlobStore` + `blobs` refcounts — see D1/D2). Follow-up is the named M1-series item **M1f (raw slice upload + re-normalize)**: `PUT …/segments/{n}/raw` body (raw zstd bytes + `X-Starforge-Blake3`, same idempotency/409 semantics as D4), the CLI change to send `raw/<n>.zst`, storage + refcount via the existing `blob_incref` path, and a re-normalize job that rebuilds normalized segments from stored raw bytes after an adapter update.
  - Segment-conflict `409` returns exactly `{"hash": "<stored hex>"}` (NOT the `{error:{...}}` envelope) — the CLI parses this shape to distinguish idempotent success from real conflict. All other errors keep the envelope.
  - `PUT` responses return `200`/`201` with `{"id": ulid, "lifecycle": "...", "quarantine": "none|quarantined|released"}` so the uploader can surface quarantine in-app later; the M1c CLI ignores bodies (status-only), so this is wire-safe.
  - `POST complete` requires a body that parses as an empty JSON object (`{}`); anything else is `422`. The server never auto-completes (the CLI owns the 24 h idle rule).
  - `PUT` segment on a `complete` session: identical hash → `200` no-op (re-sync safe); new content → `422` ("session is complete").
  - Trailer-only commit links default to confidence `heuristic`; a CLI claim overwrites confidence + seq range. `resolved = trailer_seen AND claim_seen`.
  - Hourly upload volume (500 MiB/user) and storage quotas (5 GiB/user, 20 GiB/repo) are enforced for real from `segments` sums (data already exists). Per-token request rate limiting (5 000/hr) is a `check_rate_limit` hook returning `Ok` — it needs a request-log table that belongs to M5, which owns rate limits per the milestone table.
  - Push-trailer scanning runs in the existing post-receive-pack spawned task in `starforged-web/src/githttp.rs` by snapshotting `git for-each-ref` before spawning `receive-pack` and diffing after success; new SHAs are read via `starforged_git::read` and fed to `Core::record_trailer_links`. Justification: the server has no `post-receive` hook process yet, and this is the only post-push seam that exists — reuses it instead of inventing a second pipeline.
  - Device-flow approval is a web page, not an API action: `GET /oauth/device` (login-required, `?user_code=` prefill from the CLI's `verification_uri`) + `POST /oauth/device/approve` carrying the `user_code`, an approve/deny choice, and `_csrf` verified against the web session (the same `RequireUser` + `verify_csrf` pattern as the tokens settings page). Justification: the CLI prints `verification_uri` for a browser the user is already logged into; an API-only approval would need a second Bearer-token UX the CLI cannot drive. Device codes: `expires_in = 900`, `interval = 5` (matching the M1c stub the CLI already polls against); `user_code` is `XXXX-XXXX` from 40 random bits (Crockford base32, no ambiguous chars); `device_code` is 256-bit random hex. Token grant issues an access row (scope `session:upload`, 1 h expiry per §6.1 — written via `db_tokens::insert` directly since `Core::create_token` floors at 1 day) plus a refresh row (same scope, 90 d expiry); the refresh-token rotation grant is M3, not M1d.

---

## Wire Contract (Binding — the CLI pins this; the server must accept it verbatim)

The M1c CLI implements exactly this (see `crates/starforge-cli/src/upload.rs`, `src/auth.rs`); M1d must not deviate:

- `PUT /api/v1/repos/{owner}/{repo}/sessions/{ulid}` body = `SessionMeta` JSON; `200`/`201` ok.
- `PUT …/sessions/{ulid}/segments/{n}` body = the exact compressed zstd bytes; request header `X-Starforge-Blake3: <lowercase hex of the request body>`; `200` ok; `409` body `{"hash": "<hex of stored compressed bytes>"}` — equal hash is idempotent success (CLI treats as uploaded), different hash is a terminal conflict; `413` above 16 MiB (server-configurable, default 16 MiB).
- `POST …/sessions/{ulid}/complete` body exactly `{}` (CLI owns the 24 h idle rule; server never auto-completes).
- `POST …/sessions/{ulid}/links` body exactly `{"links": [<links.jsonl objects>]}` where each object is `{"ulid":..,"commit":"..","source":"trailer|cli_claim","confidence":"exact|heuristic","seq_start":N,"seq_end":N}`; omitted when nothing unsent.
- Auth: `Authorization: Bearer <token>`; token must carry OAuth scope `session:upload`; `401` bad/missing token, `403` wrong scope. `401`/`403` aborts the CLI run.
- Status semantics: `2xx` ok; `401`/`403` abort; `5xx`/transport retried with backoff up to 4 per entry; other `4xx` terminal for the entry.

**Device flow + remaining CLI assumptions (documented, not bugs):** (a) Device flow IS implemented in M1d (task D3b): `POST /api/v1/oauth/device/code` with form `client_id=starforge-cli&scope=session:upload`, `POST /api/v1/oauth/token` for the `urn:ietf:params:oauth:grant-type:device_code` grant with RFC 8628 error bodies, and the `/oauth/device` web approval page. Personal access tokens carrying `session:upload` also authenticate (CI/headless path). (b) The spec (§7.5) never names the `X-Starforge-Blake3` header, the `{"hash"}` 409 body, the `{}` complete body, or the `{"links"}` wrapper — all four are M1c-chosen conventions the server adopts verbatim. (c) The CLI never uploads raw slices although §7.5 mentions them — accepted under Ruling R1 (raw wire is the M1f follow-up). (d) The spec's "open change author" upload exception (§6.4) is not yet evaluable — non-`write` uploaders get `403` until M2.

---

## File Structure

```
crates/starforged-db/
  migrations/sqlite/0008_sessions.sql      new tables: sessions, segments, commit_links, blobs; repos.redact_rules (D1)
  migrations/postgres/0008_sessions.sql    lockstep twin (D1)
  migrations/sqlite/0009_device_oauth.sql  new table: device_codes (D3b)
  migrations/postgres/0009_device_oauth.sql lockstep twin (D3b)
  src/sessions.rs                          SessionRow/SegmentRow/CommitLinkRow/BlobRow + query fns (D1)
  src/oauth.rs                             DeviceCodeRow + issue/approve/deny/poll query fns (D3b)
  src/lib.rs                               `pub mod sessions; pub mod oauth;` (D1, D3b)
crates/starforged-blob/                    NEW crate, AGPL (D2)
  Cargo.toml                               license/publish .workspace = true; deps: tokio, thiserror (workspace)
  src/lib.rs                               BlobStore trait (object-safe) + FsBlobStore + BlobError
crates/starforged-core/
  src/ingest.rs                            authorize_upload/upsert_session/put_segment/complete/post_links/record_trailer_links/quarantine release+purge/rescan (D3–D6)
  src/oauth.rs                             create/approve/deny/poll/grant device codes + token issue (D3b)
  src/quota.rs                             storage + volume checks (real) + check_rate_limit hook (D3)
  src/jobs.rs                              + Job::{IndexSessionEvents, ResolveCommitLinks, UpdateSessionStats, SessionWebhookOutbox} (D6)
  src/lib.rs                               `pub mod ingest; pub mod oauth; pub mod quota;` + CoreConfig { blobs_dir, max_segment_bytes, site_redact_toml, quota_* } (D2/D3)
  src/admin.rs                             quarantine list for site admin (reuse; D5)
crates/starforged-api/
  src/sessions.rs                          upload handlers + quarantine admin handlers (D3, D5)
  src/oauth.rs                             device-code + token handlers with RFC 8628 error bodies (D3b)
  src/error.rs                             + ApiError::PayloadTooLarge → 413 (D3)
  src/lib.rs                               route table + DefaultBodyLimit::disable on session PUTs (D3, D3b)
crates/starforged-web/
  src/githttp.rs                           ref snapshot/diff + record_trailer_links call in post-push task (D6)
  src/pages/device.rs                      GET /oauth/device + POST /oauth/device/approve (RequireUser + CSRF) (D3b)
  templates/device.html                    askama approval form (user_code prefill, approve/deny) (D3b)
crates/starforged/
  src/config.rs                            [sessions] section → CoreConfig mapping (D2)
  tests/ingest.rs                          full wire test: real push + four endpoints + quarantine + idempotency + 409 + 413 (D7)
  tests/api_oauth.rs                       device-flow tests: happy path, expired, denied, wrong-scope 403 (D3b)
  tests/common/mod.rs                      tiny helper: make_session_meta / make_segment (D7)
README.md                                  server ingest section (D7)
```

---

### Task D1: Schema + migrations + `starforged-db` repos

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0008_sessions.sql`, `crates/starforged-db/migrations/postgres/0008_sessions.sql`, `crates/starforged-db/src/sessions.rs`
- Modify: `crates/starforged-db/src/lib.rs` (`pub mod sessions;`)

**Interfaces:**
- Produces (all `pub`, cross-task contract — do not rename):
  ```rust
  // crates/starforged-db/src/sessions.rs
  pub struct SessionRow { pub id: i64, pub repo_id: i64, pub ulid: String, pub uploader_id: i64,
      pub agent_name: String, pub agent_version: String, pub models: String, pub title: String,
      pub branch: String, pub head_sha: String, pub started_at: i64, pub ended_at: Option<i64>,
      pub parent_ulid: Option<String>, pub usage_input: i64, pub usage_output: i64,
      pub usage_cache_read: i64, pub usage_cache_write: i64, pub usage_reasoning: i64,
      pub files_touched: String, pub turn_count: i64, pub tool_call_count: i64,
      pub lifecycle: String, pub quarantine: String, pub quarantine_reason: String,
      pub quarantine_detail: String, pub visibility: String, pub raw_enabled: i64,
      pub redaction_fingerprint: String, pub redaction_counts: String, pub capture_mode: String,
      pub cli_version: String, pub adapter_verified: i64, pub created_at: i64, pub updated_at: i64 }
  pub struct SegmentRow { pub id: i64, pub session_id: i64, pub n: i64, pub seq_start: i64,
      pub seq_end: i64, pub blob_hash: String, pub byte_size: i64, pub raw_blob_hash: Option<String>,
      pub uploaded_at: i64 } // raw_blob_hash stays NULL until the M1f raw wire (Ruling R1); nullable so no rewrite then
  pub struct CommitLinkRow { pub id: i64, pub repo_id: i64, pub session_ulid: String,
      pub session_id: Option<i64>, pub sha: String, pub source: String, pub confidence: String,
      pub seq_start: Option<i64>, pub seq_end: Option<i64>, pub trailer_seen: i64, pub claim_seen: i64 }
  pub struct BlobRow { pub hash: String, pub size: i64, pub refcount: i64, pub backend_key: String }
  pub struct NewSession<'a> { pub repo_id: i64, pub ulid: &'a str, pub uploader_id: i64, /* + every meta column */ }
  pub async fn insert_session(db: &Db, s: &NewSession<'_>) -> DbResult<i64>;
  pub async fn session_by_ulid(db: &Db, repo_id: i64, ulid: &str) -> DbResult<Option<SessionRow>>;
  pub async fn update_session_meta(db: &Db, id: i64, s: &NewSession<'_>) -> DbResult<()>;
  pub async fn set_lifecycle(db: &Db, id: i64, lifecycle: &str) -> DbResult<()>;
  pub async fn set_quarantine(db: &Db, id: i64, quarantine: &str, reason: &str, detail: &str) -> DbResult<()>;
  pub async fn segment_by_n(db: &Db, session_id: i64, n: i64) -> DbResult<Option<SegmentRow>>;
  pub async fn segment_count(db: &Db, session_id: i64) -> DbResult<i64>;
  pub async fn insert_segment(db: &Db, session_id: i64, n: i64, seq_start: i64, seq_end: i64, blob_hash: &str, byte_size: i64) -> DbResult<i64>;
  pub async fn segments_of(db: &Db, session_id: i64) -> DbResult<Vec<SegmentRow>>;
  pub async fn delete_session(db: &Db, id: i64) -> DbResult<Vec<SegmentRow>>; // deletes session + segments + links, returns removed segments for refcount Viking
  pub async fn upsert_trailer_link(db: &Db, repo_id: i64, ulid: &str, sha: &str) -> DbResult<i64>;
  pub async fn upsert_claim_link(db: &Db, repo_id: i64, session_id: i64, ulid: &str, sha: &str, confidence: &str, seq_start: Option<i64>, seq_end: Option<i64>) -> DbResult<i64>;
  pub async fn links_of_session(db: &Db, session_id: i64) -> DbResult<Vec<CommitLinkRow>>;
  pub async fn blob_by_hash(db: &Db, hash: &str) -> DbResult<Option<BlobRow>>;
  pub async fn blob_incref(db: &Db, hash: &str, size: i64, backend_key: &str) -> DbResult<i64>; // insert-or-ignore then +1; returns refcount
  pub async fn blob_decref(db: &Db, hash: &str) -> DbResult<i64>; // -1 floor 0; returns refcount
  pub async fn zero_ref_blobs(db: &Db, limit: i64) -> DbResult<Vec<BlobRow>>;
  pub async fn delete_blob(db: &Db, hash: &str) -> DbResult<()>;
  pub async fn repo_storage_bytes(db: &Db, repo_id: i64) -> DbResult<i64>; // SUM(segments.byte_size) for repo
  pub async fn user_storage_bytes(db: &Db, user_id: i64) -> DbResult<i64>;
  pub async fn user_volume_since(db: &Db, user_id: i64, since_unix: i64) -> DbResult<i64>;
  pub async fn quarantined_of_repo(db: &Db, repo_id: i64) -> DbResult<Vec<SessionRow>>;
  ```
- Every statement: `$N` placeholders in first-appearance order, `i64` integers, `0`/`1` bools, unix-second timestamps — the `lib.rs` rules, enforced by the PG gate.

- [ ] **Step 1: Write the failing db tests.** New `#[cfg(test)] mod tests` in `src/sessions.rs` using `crate::testing::TestDb`: insert session → `session_by_ulid` round-trips every column; duplicate `(repo_id, ulid)` insert is a unique violation; segment insert + `segment_by_n`/`segment_count`; `blob_incref` twice → refcount 2, `blob_decref` → 1; `upsert_trailer_link` then `upsert_claim_link` on the same (repo, ulid, sha) yields ONE row with `trailer_seen = 1 AND claim_seen = 1`; `delete_session` removes segments + links and returns the segment list.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged-db` — Expected: FAIL (module/files do not exist).
- [ ] **Step 3: Write both migrations + `sessions.rs`.** Tables per §6.3: `sessions` (`UNIQUE(repo_id, ulid)`, `lifecycle CHECK receiving|complete`, `quarantine CHECK none|quarantined|released`, `visibility CHECK inherit|published`, `raw_enabled INTEGER NOT NULL DEFAULT 0` — always 0 in M1d per Ruling R1); `segments` (`UNIQUE(session_id, n)`, `FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE`, `raw_blob_hash TEXT` nullable — always NULL in M1d per Ruling R1, so the M1f raw wire fills it with no migration rewrite); `commit_links` (`UNIQUE(repo_id, session_ulid, sha)`, nullable `session_id` FK for trailer-first arrival); `blobs` (`hash PRIMARY KEY`, `refcount INTEGER NOT NULL DEFAULT 0`); `ALTER TABLE repos ADD COLUMN redact_rules TEXT NOT NULL DEFAULT ''` on both engines. Postgres twin uses `BIGSERIAL`/`BIGINT` matching the `0001` twins' conventions line-for-line. Keep `sessions.rs` query fns thin (no domain logic — that is D3+).
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforged-db` then the PG gate `STARFORGE_TEST_PG_URL=… cargo test -p starforged-db` (via `scripts/check.sh` flow) — Expected: PASS on both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  STARFORGE_TEST_PG=1 scripts/check.sh
  git add crates/starforged-db
  git commit -m "Add session, segment, commit-link, and blob schema with dual migrations"
  ```

---

### Task D2: Blob store crate + server config wiring

**Files:**
- Create: `crates/starforged-blob/Cargo.toml`, `crates/starforged-blob/src/lib.rs`
- Modify: root `Cargo.toml` members (only if `crates/*` glob does not pick it up — verify), `crates/starforged/src/config.rs`, `crates/starforged-core/src/lib.rs` (`CoreConfig` fields), `crates/starforged/src/serve.rs` or `admin.rs::open_core` (map config → `CoreConfig`).

**Interfaces:**
- Consumes: D1 (`BlobRow`, refcount fns).
- Produces:
  ```rust
  // crates/starforged-blob/src/lib.rs (license.workspace = true AGPL, publish.workspace = true)
  #[derive(Debug, thiserror::Error)]
  pub enum BlobError { #[error("i/o: {0}")] Io(String), #[error("blob not found: {0}")] NotFound(String) }
  pub type BlobResult<T> = Result<T, BlobError>;
  /// Object-safe so `Core` holds `Arc<dyn BlobStore>` without generics rippling.
  pub trait BlobStore: Send + Sync + 'static {
      fn put(&self, key: &str, bytes: Vec<u8>) -> std::pin::Pin<Box<dyn Future<Output = BlobResult<()>> + Send + '_>>;
      fn get(&self, key: &str) -> std::pin::Pin<Box<dyn Future<Output = BlobResult<Vec<u8>>> + Send + '_>>;
      fn delete(&self, key: &str) -> std::pin::Pin<Box<dyn Future<Output = BlobResult<()>> + Send + '_>>;
      fn exists(&self, key: &str) -> std::pin::Pin<Box<dyn Future<Output = BlobResult<bool>> + Send + '_>>;
  }
  #[derive(Debug, Clone)]
  pub struct FsBlobStore { pub root: std::path::PathBuf }
  impl FsBlobStore {
      pub fn new(root: std::path::PathBuf) -> Self;
      /// `<root>/<hash[0..2]>/<hash>`; S3 backends implement `BlobStore` with the same key space later.
      pub fn path_for(&self, hash_hex: &str) -> std::path::PathBuf;
  }
  // crates/starforged/src/config.rs
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct SessionsConfig {
      #[serde(default = "default_segment_cap")] pub max_segment_bytes: usize, // default 16 MiB
      #[serde(default)] pub site_redact_toml: String,                          // default ""
      #[serde(default = "default_user_quota")] pub quota_user_bytes: i64,      // default 5 GiB
      #[serde(default = "default_repo_quota")] pub quota_repo_bytes: i64,      // default 20 GiB
      #[serde(default = "default_volume_quota")] pub quota_volume_bytes_per_hour: i64, // default 500 MiB
  }
  // crates/starforged-core/src/lib.rs — CoreConfig gains:
  // pub blobs_dir: PathBuf, pub max_segment_bytes: usize, pub site_redact_toml: String,
  // pub quota_user_bytes: i64, pub quota_repo_bytes: i64, pub quota_volume_bytes_per_hour: i64,
  // pub blob_store: Arc<dyn starforged_blob::BlobStore> (default: FsBlobStore on blobs_dir)
  ```
- New deps: `starforged-core` → path deps `starforge-format` (meta parse, `blake3_hex`, `decompress`), `starforge-redact` (server re-scan), `starforged-blob`; workspace deps `zstd`, `ulid` (both already in the workspace table — adoption, not addition). Justification in one sentence each: format = the server must validate the same `SessionMeta` the CLI sends; redact = §7.7 mandates a server re-scan with the same engine; blob = §5.1 mandates the content-addressed store behind `Core`; zstd/ulid = decompress + ULID validation without new crates.

- [ ] **Step 1: Write failing blob tests.** `crates/starforged-blob/src/lib.rs` unit tests on a tempdir: `put` then `get` round-trips bytes at the sharded path; `put` twice is idempotent; `get` missing → `NotFound`; `delete` removes the file; concurrent `put`s of the same key do not corrupt (atomic temp + rename asserted by reading back N times).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged-blob` — Expected: FAIL (crate does not exist).
- [ ] **Step 3: Implement `FsBlobStore` + config mapping.** `put` writes `<root>/<hh>/<rest>.tmp-<rand>` then renames (same filesystem — `blobs_dir` lives under `data_dir` per spec §5.3); creates shard dirs. Keys are opaque hex strings, so the M1f raw wire reuses this store and the `blobs` refcount path unchanged (Ruling R1). `SessionsConfig` with `#[serde(default)]` on the parent so old `starforged.toml` files keep working; `open_core` maps every field into `CoreConfig` and builds `Arc::new(FsBlobStore::new(data_dir/blobs))`.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforged-blob -p starforged-core` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-blob crates/starforged/src/config.rs crates/starforged-core/src/lib.rs Cargo.toml
  git commit -m "Add filesystem blob store crate and sessions server config"
  ```

---

### Task D3: Upload endpoints + authorization + quota hooks

**Files:**
- Create: `crates/starforged-api/src/sessions.rs`, `crates/starforged-core/src/quota.rs`
- Modify: `crates/starforged-api/src/lib.rs` (route table), `crates/starforged-api/src/error.rs` (`PayloadTooLarge`), `crates/starforged-core/src/lib.rs` (`pub mod quota;`).

**Interfaces:**
- Consumes: D1 (rows), D2 (config, blob store), `ApiAuth::require(Scope::SessionUpload)`, `Core::require_repo`.
- Produces:
  ```rust
  // crates/starforged-api/src/sessions.rs — routes (exact shapes; {owner}/{repo} reuse the existing repo path params):
  // PUT    /repos/{owner}/{repo}/sessions/{ulid}            (meta: SessionMeta JSON; 200/201 + {"id","lifecycle","quarantine"})
  // PUT    /repos/{owner}/{repo}/sessions/{ulid}/segments/{n} (body bytes + X-Starforge-Blake3; 200; 409 {"hash"}; 413)
  // POST   /repos/{owner}/{repo}/sessions/{ulid}/complete   (body must be {}; 200)
  // POST   /repos/{owner}/{repo}/sessions/{ulid}/links      ({"links": [...]}; 200 {"accepted": k})
  pub async fn put_meta(State(state): State<ApiState>, auth: ApiAuth, Path(path): Path<SessionPath>, body: Bytes) -> Result<impl IntoResponse, ApiError>;
  pub async fn put_segment(State(state): State<ApiState>, auth: ApiAuth, Path(path): Path<SegmentPath>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError>;
  pub async fn post_complete(/* same extractors; Path<SessionPath> */) -> Result<impl IntoResponse, ApiError>;
  pub async fn post_links(/* same extractors */) -> Result<impl IntoResponse, ApiError>;
  // crates/starforged-core/src/ingest.rs (declared D3, bodies land D3–D6):
  pub struct IngestAuth { pub user: crate::accounts::User, pub access: crate::repos::RepoAccess }
  impl Core {
      /// 401 when anonymous, 403 when the token lacks `session:upload`, 403 when effective
      /// permission < Write (open-change-author exception plugs in here at M2).
      pub async fn authorize_upload(&self, auth: &starforged_core::tokens::TokenAuth, owner: &str, name: &str) -> CoreResult<IngestAuth>;
  }
  // crates/starforged-core/src/quota.rs:
  pub async fn check_storage_quotas(core: &Core, user_id: i64, repo_id: i64, incoming_bytes: i64) -> CoreResult<()>;
  pub async fn check_hourly_volume(core: &Core, user_id: i64, incoming_bytes: i64) -> CoreResult<()>;
  pub fn check_rate_limit() -> CoreResult<()>; // hook only: Ok; M5 implements per-token limits (documented)
  ```
- Auth mapping (binding): missing/bad token → `401` (via `ApiAuth` rejection / `authenticate_token`); token without `session:upload` → `403`; authenticated but permission < `Write` → `403`. Anonymous can never reach `authorize_upload` (scope check fires first).

- [ ] **Step 1: Write failing route tests.** New `crates/starforged/tests/api_sessions_auth.rs` (or extend D7's file — D3 owns auth-only cases): with `TestServer`, user + private repo + three tokens (`session:upload`, `repo:read`-only, bogus): no token → `401` + `WWW-Authenticate: Bearer`; bogus → `401`; `repo:read` token → `403`; `session:upload` token on a repo where the user has only `read` (granted collaborator) → `403`; same token with `write` → `200`/`201` on meta PUT. Assert envelope codes (`unauthenticated`/`forbidden`).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged --test api_sessions_auth` — Expected: FAIL (routes do not exist → 404s).
- [ ] **Step 3: Implement routes + `authorize_upload` + quota hooks.** Handlers: `auth.require(Scope::SessionUpload)?` then `core.authorize_upload(&auth, owner, repo)` then delegate to `Core::upsert_session/...` (D4 bodies; D3 wires meta path end-to-end, segments/complete/links delegate to `todo!()`-free stubs returning `501`? No — D3 implements all four handlers' auth + body-limit plumbing; D4–D6 fill domain logic behind the same `Core` methods, so land D3 with real meta + segment-size-cap enforcement and thin complete/links that validate shape). `PUT` segment routes get `DefaultBodyLimit::disable()` + manual `body.len() > max_segment_bytes → 413` (`ApiError::PayloadTooLarge`, envelope code `payload_too_large`). Quota hooks called on segment PUT (storage + volume); `check_rate_limit` called and `Ok`.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforged --test api_sessions_auth` — Expected: PASS. Then `cargo test --workspace`.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-api crates/starforged-core/src/quota.rs crates/starforged-core/src/ingest.rs crates/starforged/tests
  git commit -m "Add session upload routes with scope and write-permission authorization"
  ```

---

### Task D3b: Device-flow OAuth (code + token + web approval)

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0009_device_oauth.sql`, `crates/starforged-db/migrations/postgres/0009_device_oauth.sql`, `crates/starforged-db/src/oauth.rs`, `crates/starforged-core/src/oauth.rs`, `crates/starforged-api/src/oauth.rs`, `crates/starforged-web/src/pages/device.rs`, `crates/starforged-web/templates/device.html`, `crates/starforged/tests/api_oauth.rs`
- Modify: `crates/starforged-db/src/lib.rs` (`pub mod oauth;`), `crates/starforged-core/src/lib.rs` (`pub mod oauth;`), `crates/starforged-api/src/lib.rs` (route table), `crates/starforged-web/src/lib.rs` + pages module (route table), `crates/starforged-web/src/pages.rs` (module list — verify exact file).

**Interfaces:**
- Consumes: D1 conventions (dual migrations, lockstep, PG gate), `Core::create_token` PAT machinery shape, `RequireUser` + `verify_csrf` web conventions, `parse_scopes`/`Scope::SessionUpload`.
- Produces:
  ```rust
  // crates/starforged-db/src/oauth.rs — table device_codes:
  //   device_code TEXT PRIMARY KEY, user_code TEXT UNIQUE NOT NULL, client_id TEXT NOT NULL,
  //   scopes TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','consumed')),
  //   user_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
  //   created_at, expires_at INTEGER NOT NULL, interval_secs INTEGER NOT NULL, last_polled_at INTEGER NULL
  pub struct DeviceCodeRow { /* every column above */ }
  pub struct NewDeviceCode<'a> { pub device_code: &'a str, pub user_code: &'a str, pub client_id: &'a str, pub scopes: &'a str, pub expires_at: i64, pub interval_secs: i64 }
  pub async fn insert_device_code(db: &Db, c: &NewDeviceCode<'_>) -> DbResult<()>;
  pub async fn device_code_by_device(db: &Db, device_code: &str) -> DbResult<Option<DeviceCodeRow>>;
  pub async fn device_code_by_user_code(db: &Db, user_code: &str) -> DbResult<Option<DeviceCodeRow>>;
  pub async fn approve_device_code(db: &Db, id_or_code: &str, user_id: i64, approved: bool) -> DbResult<bool>; // pending→approved|denied, returns false when not pending
  pub async fn consume_device_code(db: &Db, device_code: &str) -> DbResult<()>; // approved→consumed on grant
  pub async fn touch_device_poll(db: &Db, device_code: &str, now: i64) -> DbResult<()>;
  pub async fn delete_expired_device_codes(db: &Db, now: i64) -> DbResult<i64>;
  // crates/starforged-core/src/oauth.rs
  pub struct DeviceAuthRequest { pub device_code: String, pub user_code: String, pub verification_uri: String, pub verification_uri_complete: String, pub expires_in: i64, pub interval: i64 }
  pub enum PollOutcome { Pending, SlowDown, Expired, Denied, Granted { access_token: String, refresh_token: String, expires_in: i64 } }
  impl Core {
      /// Validates client_id == "starforge-cli" (else Invalid) and scope via parse_scopes (else Invalid).
      /// user_code = XXXX-XXXX from 40 random bits (Crockford base32); device_code = 256-bit random hex.
      /// expires_in = 900, interval = 5. No authentication (anonymous, like well-known).
      pub async fn create_device_code(&self, client_id: &str, scope: &str) -> CoreResult<DeviceAuthRequest>;
      /// Binds the signed-in web user to a pending code (approve) or marks it denied.
      /// Wrong/expired/consumed code → NotFound/Invalid; audits `oauth.device.approve|deny`.
      pub async fn approve_device_code(&self, user: &User, user_code: &str, approve: bool) -> CoreResult<()>;
      /// RFC 8628 §3.5 state machine: expired → Expired (row deleted); denied → Denied;
      /// polled faster than interval → SlowDown (and interval +5, persisted); approved →
      /// issues the token pair and consumes the code → Granted.
      pub async fn poll_device_code(&self, device_code: &str, client_id: &str) -> CoreResult<PollOutcome>;
  }
  // Token issue (inside poll_device_code, Granted path): access row via db_tokens::insert
  // directly (scope session:upload, expires now+3600 — create_token floors at 1 day, so it
  // cannot mint the 1 h access token); refresh row, same scope, expires now+90d. Both rows
  // audited as token.create. Refresh-token rotation grant is M3, not M1d.
  // crates/starforged-api/src/oauth.rs — routes (form bodies, NOT JSON):
  // POST /api/v1/oauth/device/code   (client_id, scope) → 200 {device_code, user_code, verification_uri,
  //   verification_uri_complete, expires_in: 900, interval: 5}; unknown client/scope → 400 envelope `invalid`
  // POST /api/v1/oauth/token         (grant_type, device_code, client_id) → 200 {access_token,
  //   token_type: "Bearer", expires_in: 3600, refresh_token, scope}; pending states → 400 with the
  //   RFC 8628 body {"error": "authorization_pending"|"slow_down"|"expired_token"|"access_denied"}
  //   (NOT the {error:{...}} envelope — the CLI matches this shape); any other grant_type → 400 {"error":"unsupported_grant_type"}
  // crates/starforged-web/src/pages/device.rs (RequireUser + CSRF, tokens-page pattern):
  // GET  /oauth/device[?user_code=] → askama device.html (prefilled form, _csrf from session.csrf_token)
  // POST /oauth/device/approve      (user_code, decision: approve|deny, _csrf) → verify_csrf, then
  //   Core::approve_device_code; re-renders the page with a success banner (same created/error pattern as tokens.html)
  ```

- [ ] **Step 1: Write failing device-flow tests.** New `crates/starforged/tests/api_oauth.rs` with `TestServer`: (a) happy path — `POST device/code` (form `client_id=starforge-cli&scope=session:upload`) → `200` with all six fields and a `verification_uri` pointing at `/oauth/device?user_code=…`; `POST token` before approval → `400 {"error":"authorization_pending"}`; log in via the existing `/login` form flow (same as `web_auth` tests), `GET` the `verification_uri` → `200` containing the user code, `POST /oauth/device/approve` with the page's `_csrf` + `decision=approve` → success; `POST token` again → `200` with `access_token`/`refresh_token`/`expires_in: 3600`; that access token `PUT`s session meta → `2xx` (proves the `session:upload` scope end to end). (b) Second `POST token` with the same device code → `400 {"error":"expired_token"}` (consumed codes are single-use). (c) A code inserted with a past `expires_at` (via the db fns directly) polls → `expired_token`. (d) Approval with `decision=deny` → poll gives `access_denied`. (e) Immediate double-poll of a pending code → second is `slow_down`. (f) A `repo:read`-scoped PAT `PUT`ting session meta → `403` (wrong-scope token rejected at the upload endpoints).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged --test api_oauth` — Expected: FAIL (routes/table do not exist).
- [ ] **Step 3: Implement migration 0009 + db fns + `Core` OAuth + API handlers + approval page.** `verification_uri` = `{base_url}/oauth/device?user_code={user_code}` (base_url from `CoreConfig`, no trailing slash — same convention as mail links). Scope stored verbatim (`session:upload` in M1d; `parse_scopes`-validated so future scopes need no schema change). Deny path sets `denied` (polls stay `access_denied`; rows swept by `delete_expired_device_codes` from `HourlyCleanup` — one line in the existing arm, no new job kind). Consumed/expired rows are deleted on read (single-use + no stale secret material). Never log device codes, user codes, or tokens (assert by review: only ids + states in logs).
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforged --test api_oauth` then `STARFORGE_TEST_PG_URL=… cargo test -p starforged --test api_oauth` — Expected: PASS both engines. Then `cargo test --workspace`.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-db crates/starforged-core/src/oauth.rs crates/starforged-api crates/starforged-web crates/starforged/tests/api_oauth.rs
  git commit -m "Add device-flow OAuth with web approval for CLI login"
  ```

---

### Task D4: Validation + idempotency + `complete`/links payloads

**Files:**
- Modify: `crates/starforged-core/src/ingest.rs` (validation + method bodies), `crates/starforged-db/src/sessions.rs` (only if a query is missing — prefer no change).
- Create: `crates/starforged-core/tests/` — no; core unit tests live in-module (`ingest.rs #[cfg(test)]` with `crate::testing::test_core`, following `repos.rs`/`jobs.rs` convention).

**Interfaces:**
- Consumes: D1–D3, `starforge_format::{SessionMeta, parse_event? decompress, blake3_hex}`, `ulid::Ulid`.
- Produces:
  ```rust
  impl Core {
      /// Creates the session on first PUT, or updates mutable meta on later PUTs.
      /// Path ULID must equal `meta.id`; `meta.format` must be "starforge.session/v1";
      /// `agent.name` must be a known agent. Returns the view for the response body.
      pub async fn upsert_session(&self, auth: &IngestAuth, ulid: &str, meta: serde_json::Value) -> CoreResult<SessionView>;
      /// Append-only numbering: n == count → store (after hash/size/quota checks);
      /// n < count + identical hash → Ok no-op; n < count + different → Conflict(stored_hash);
      /// n > count → Invalid. Body must decompress as zstd and every line must parse
      /// as an Event (unknown kinds tolerated, unknown versions rejected); header hash,
      /// when present, must equal the recomputed hash; missing header is accepted
      /// (server always recomputes). Records blob + refcount, updates totals, enqueues jobs.
      pub async fn put_segment(&self, auth: &IngestAuth, ulid: &str, n: i64, body: Vec<u8>, claimed_hex: Option<String>) -> CoreResult<SegmentView>;
      /// Body must be `{}`; sets lifecycle complete. Idempotent.
      pub async fn complete_session(&self, auth: &IngestAuth, ulid: &str, body: serde_json::Value) -> CoreResult<SessionView>;
      /// Validates every link object (40-hex sha, known source/confidence, sane seq range),
      /// upserts claim rows. Returns accepted count.
      pub async fn post_session_links(&self, auth: &IngestAuth, ulid: &str, links: serde_json::Value) -> CoreResult<usize>;
  }
  pub struct SessionView { pub ulid: String, pub lifecycle: String, pub quarantine: String }
  pub struct SegmentView { pub n: i64, pub hash: String, pub size: i64, pub idempotent: bool }
  ```
- Handler mapping: `CoreError::Conflict(hash_hex)` on segments → raw `409 {"hash": ...}` (NOT the envelope); `Invalid` → `422`; `Forbidden` → `403`; oversize → `413` (checked in handler before `Core`, D3).

- [ ] **Step 1: Write failing core tests.** In-module tests with `test_core()` + `test_core_with` (small `max_segment_bytes` for the 413 path): meta PUT with path/body ULID mismatch → `Invalid`; bad `format` tag → `Invalid`; unknown agent → `Invalid`; segment `n=1` on empty session → `Invalid` (gap); re-PUT same bytes → `Ok{idempotent: true}` with unchanged row count; different bytes same `n` → `Conflict(stored)`; body that is not zstd → `Invalid`; JSONL with an unknown event `v` → `Invalid`; unknown `kind` with `v: 1` → accepted (evolution rule); `complete` with `{"x":1}` → `Invalid`; segment after complete with new bytes → `Invalid`, with identical bytes → `Ok`; links with bad sha → `Invalid`, good batch → count + rows with `claim_seen = 1`.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged-core ingest` — Expected: FAIL (methods do not exist).
- [ ] **Step 3: Implement validation + storage.** `upsert_session`: `Ulid::from_string` both sides + equality, `SessionMeta::parse`-equivalent checks via `starforge_format::session` types (reject `BadFormatTag`/`BadAgent`/`BadUlid`/`BadTimestamp` as `Invalid`), insert-or-update mutable columns (uploader pinned to first uploader — later PUTs by another writer keep the original `uploader_id`). `put_segment`: order checks exactly as documented (quota → size → continuity → hash → decompress+parse → store blob bytes via `BlobStore::put` + `blob_incref` → insert row → recompute totals (turn/tool counts, usage sums) → enqueue `UpdateSessionStats` + `ResolveCommitLinks` + `IndexSessionEvents` + `SessionWebhookOutbox` jobs (D6 kinds; enqueue-only here). Event counting parses decompressed lines with `starforge_format::parse_event`; `seq_start`/`seq_end` from min/max `seq`.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforged-core` then `STARFORGE_TEST_PG_URL=… cargo test -p starforged-core` — Expected: PASS both engines.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-core/src/ingest.rs
  git commit -m "Add session validation, idempotent segment store, complete and links"
  ```

---

### Task D5: Re-scan + quarantine + audit + admin quarantine queue

**Files:**
- Modify: `crates/starforged-core/src/ingest.rs` (`rescan_session`, `release_session`, `purge_session`, `list_quarantined`), `crates/starforged-api/src/sessions.rs` (three admin routes), `crates/starforged-api/src/lib.rs` (route table).
- Create: none (tests live in `crates/starforged/tests/ingest.rs` scaffolding? No — D5 owns core-level tests in-module + API quarantine tests in a new `crates/starforged/tests/api_quarantine.rs`).

**Interfaces:**
- Consumes: D1–D4, `starforge_redact::{RuleSet, fingerprint? redact_jsonl}` + `Compiled::is_high_confidence`, `rule_ids`.
- Produces:
  ```rust
  impl Core {
      /// Decompresses every segment from the blob store and re-scans with
      /// built_in.merge(repo).merge(site). First high-confidence hit
      /// (per `Compiled::is_high_confidence`) sets quarantine=quarantined with
      /// reason=<detector id> + detail="segment {n} seq {s}", writes audit
      /// `session.quarantined`, and returns Quarantined. Runs synchronously
      /// inside `put_segment` (segments are small; no worker race on the flag).
      pub async fn rescan_session(&self, session_id: i64) -> CoreResult<QuarantineOutcome>;
      pub async fn list_quarantined(&self, admin_access: &crate::repos::RepoAccess) -> CoreResult<Vec<SessionView>>;
      /// quarantine: quarantined → released + audit `session.quarantine.released`. Else Invalid.
      pub async fn release_session(&self, admin_access: &crate::repos::RepoAccess, ulid: &str) -> CoreResult<SessionView>;
      /// Deletes segments (decref blobs), links, session row + audit `session.purged`.
      /// Zero-ref files are swept by HourlyCleanup, not here.
      pub async fn purge_session(&self, admin_access: &crate::repos::RepoAccess, ulid: &str) -> CoreResult<()>;
  }
  pub enum QuarantineOutcome { Clean, Quarantined { reason: String, detail: String } }
  // API routes (repo admin via require_repo(..., Permission::Admin) or site admin):
  // GET  /repos/{owner}/{repo}/sessions/quarantine            → {"sessions": [{id, agent, quarantine, reason, ...}]}
  // POST /repos/{owner}/{repo}/sessions/{ulid}/release        → 200 SessionView
  // POST /repos/{owner}/{repo}/sessions/{ulid}/purge          → 204
  ```
- Location attribution: the re-scan walks segments in order and lines within a segment; the first high-confidence detector hit records that segment `n` and the line's event `seq` when the line parses (else `seq -`). Quarantine reason is the detector id (e.g. `private_key`, `cloud_credential`, `known_token`); counts merge additively into `redaction_counts` (server-found hits only — never rewrites the client's fingerprint).

- [ ] **Step 1: Write failing quarantine tests.** Core in-module: session with a planted `ghp_…` token in one event → after `put_segment`, row shows `quarantined` with reason `known_token` (or the exact `BuiltInId`), `released` NOT set; clean session stays `none`. API tests (`api_quarantine.rs` with `TestServer`): non-admin uploader GETs the queue → `403`; repo admin GETs → lists the ULID with reason; admin `release` → `200` + audit row `session.quarantine.released`; second `purge` on a fresh quarantined session → `204`, session row gone, blob refcount decremented, audit `session.purged` present; purge of a clean session by a non-admin → `403`.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged-core quarantine` and `cargo test -p starforged --test api_quarantine` — Expected: FAIL.
- [ ] **Step 3: Implement re-scan + admin routes.** `rescan_session` loads `segments_of`, `blob.get` each hash, `decompress`, `redact_jsonl(&compiled, &text)` per segment — but `redact_jsonl` returns aggregate counts without locations; for location, re-check high-confidence via per-detector `is_high_confidence` index → find first matching line by re-running `redact_text` per line? Keep it exact and cheap: scan line-by-line with `redact_text(&compiled, line)`, attribute the first line whose counts include a high-confidence detector id. Rule compile once per call (built_in + repo `redact_rules` TOML + site TOML; empty strings = skip). Compromise documented: line-level attribution, first hit wins, deterministic.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforged-core -p starforged` then the PG gate for both — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-core/src/ingest.rs crates/starforged-api
  git commit -m "Add server re-scan, quarantine, audit, and admin quarantine queue"
  ```

---

### Task D6: Commit links + push trailer scan + ingest jobs

**Files:**
- Modify: `crates/starforged-core/src/jobs.rs` (four new `Job` variants + worker arms), `crates/starforged-core/src/ingest.rs` (`record_trailer_links`, stats recompute), `crates/starforged-web/src/githttp.rs` (ref snapshot/diff in the post-push task).
- Create: core in-module tests only (no new files).

**Interfaces:**
- Consumes: D1 (`upsert_trailer_link`), D4 (`post_session_links` claim path), `starforged_git::read::{commit, ...}` for message lookup, existing `Core::enqueue`/`run_due_jobs`.
- Produces:
  ```rust
  // crates/starforged-core/src/jobs.rs — appended to the existing Job enum (serde tag stays):
  IndexSessionEvents { session_id: i64 },    // M4 owns the body: M1d worker arm loads the session and Ok(())s (stub, documented)
  ResolveCommitLinks { repo_id: i64, session_ulid: String }, // M1d worker arm: no-op Ok(()) — links resolve synchronously at write time (stub, documented)
  UpdateSessionStats { session_id: i64 },    // M1d worker arm: REAL — recomputes turn/tool counts + usage sums from segments
  SessionWebhookOutbox { session_id: i64, event: String },  // M2/M5 own delivery: M1d arm Ok(())s (stub, documented)
  impl Core {
      /// Upserts one trailer row per `Starforge-Session: <ULID>` trailer found in
      /// each commit message. Invalid ULIDs are skipped (never fail a push).
      /// Trailer-first rows carry session_id NULL until the upload arrives, when
      /// `upsert_session` backfills session_id by (repo_id, ulid).
      pub async fn record_trailer_links(&self, repo_id: i64, commits: &[(String, String)]) -> CoreResult<usize>;
  }
  // crates/starforged-web/src/githttp.rs — in rpc(), before spawning receive-pack:
  // snapshot `git for-each-ref` (sha → ref map); in the post-push success task,
  // re-list refs, collect SHAs not present before, read each message via
  // starforged_git::read, call record_trailer_links. Failures only warn (a push never fails because of links).
  ```
- Trailer regex (binding with CLI `trailer_line`): `^Starforge-Session: ([0-9A-HJKMNP-TV-Z]{26})$` per line, `Ulid::from_string`-validated. `confidence` on trailer rows defaults to `heuristic`; CLI claims overwrite it with their own confidence + seq range and set `claim_seen = 1`.

- [ ] **Step 1: Write failing link/job tests.** Core in-module: `record_trailer_links` with two messages (one carrying two trailers incl. a garbage `Starforge-Session: nope` line) → two rows, `trailer_seen = 1`, `claim_seen = 0`, garbage skipped; then `post_session_links` claim for one → that row `claim_seen = 1` + confidence overwritten, other row untouched (either-arriving-first: also test claim-before-trailer order). Jobs: after `put_segment`, `jobs` table holds all four kinds with the right payloads; `run_due_jobs` → `UpdateSessionStats` recomputed counts equal the segment-derived values; the three stub arms return `Ok` and mark jobs `done`.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged-core links` — Expected: FAIL (methods/variants do not exist).
- [ ] **Step 3: Implement links + jobs + githttp wiring.** `upsert_session` backfills `session_id` on pre-existing trailer rows for its `(repo_id, ulid)` (matching `commit_links` with NULL `session_id`). `HourlyCleanup` gains the zero-ref blob sweep: `zero_ref_blobs(100)` → `BlobStore::delete` each key → `delete_blob` row; failures warn, never fail cleanup. githttp snapshot: `for-each-ref --format=%(objectname)` before, diff after; cap scanned SHAs at 1 000 per push (abuse bound, documented).
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforged-core -p starforged-web -p starforged` + PG gate — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged-core/src/jobs.rs crates/starforged-core/src/ingest.rs crates/starforged-web
  git commit -m "Add commit-link resolution from push trailers and CLI claims plus ingest jobs"
  ```

---

### Task D7: End-to-end ingest test (real push + CLI-shaped upload) + docs close-out

**Files:**
- Create: `crates/starforged/tests/ingest.rs`
- Modify: `crates/starforged/tests/common/mod.rs` (fixture helpers), `crates/starforged/Cargo.toml` (dev-deps `starforge-format`, `starforge-redact`), `README.md` (server ingest section).

**Interfaces:**
- Consumes: every prior task; `starforge_format::{SessionMeta, split_jsonl, compress, blake3_hex}` and `starforge_redact::{RuleSet, fingerprint}` to build fixtures exactly like the CLI does.
- Produces:
  ```rust
  // tests/common/mod.rs
  pub fn ingest_meta(ulid: &str, overrides: serde_json::Value) -> serde_json::Value; // valid SessionMeta JSON (format tag, pi agent, redaction fingerprint recomputed in-test)
  pub fn ingest_segment(events_jsonl: &str) -> Vec<u8>; // compress() — byte-identical to CLI spool bytes
  ```
- The test performs NO stubbing of the server: boots `TestServer` (SQLite; PG variant under `STARFORGE_TEST_PG_URL`), creates user + repo + `session:upload` token, and speaks the binding wire with `reqwest` using the same construction as `UploadClient` (header name, bodies, status handling).

- [ ] **Step 1: Write the failing end-to-end test.** `tests/ingest.rs` (`#[tokio::test]` multi-thread like `api.rs`): (a) build a 3-event fixture (user prompt, assistant message with a planted `ghp_…` token, tool call) via `starforge-redact` client-side redact + `split_jsonl` + `compress`, computing the expected BLAKE3 in-test; (b) `PUT meta` → `201` with `{"quarantine":"none"}`; (c) `PUT segments/0` with `X-Starforge-Blake3` → `200`; assert DB `segments` row (`n=0`, hash, size), blob file bytes on disk equal the sent bytes, `blob refcount = 1`; (d) session row now `quarantined` (server re-scan caught the planted token) with reason + `segment 0` detail; audit `session.quarantined` exists; (e) re-`PUT segments/0` identical → `200`, row count unchanged (idempotent); different bytes same `n` → `409` with `{"hash": <original>}`; (f) second session, clean events: `PUT meta` → `PUT segments/0` → `PUT segments/1` (numbering) → `POST complete {}` → `200 lifecycle complete`; new segment after complete → `422`; (g) `POST links` claim → `200 {"accepted": 1}`; (h) real push: `git init` temp repo, commit carrying a `Starforge-Session: <ULID>` trailer, push over smart HTTP with the token, then assert a `commit_links` row with `trailer_seen = 1` (and `claim_seen = 1` where the ULIDs overlap); (i) `413`: one `PUT` with 17 MiB of incompressible bytes → `413`; (j) repo-admin quarantine `GET` lists the quarantined ULID, `POST release` → `released`, `POST purge` on a second quarantined session → session + segments gone, refcount decremented, blob file swept after `run_due_jobs` (HourlyCleanup).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforged --test ingest` — Expected: FAIL (routes/methods missing until D3–D6 land; run incrementally per task).
- [ ] **Step 3: Implement helpers + README section.** `README.md` gains a "Session ingest (M1d)" subsection (~40 lines, matching README voice): device flow (`auth login` → browser approval at `/oauth/device`), the four endpoints + header, `session:upload` scope + write rule, 16 MiB cap + quotas table, quarantine queue endpoints, blob layout, what is deferred (viewer M1e, raw upload + re-normalize M1f per Ruling R1, refresh-token rotation M3, rate limits M5).
- [ ] **Step 4: Run the full sweep.** Run: `cargo test --workspace` then `STARFORGE_TEST_PG=1 scripts/check.sh` — Expected: PASS everything (device flow, auth, validation, quarantine, links, push scan, e2e + all pre-existing suites).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforged/tests crates/starforged/Cargo.toml README.md
  git commit -m "Add server ingest end-to-end test and documentation"
  ```
