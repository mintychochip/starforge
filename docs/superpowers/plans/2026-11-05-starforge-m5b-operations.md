# Starforge M5b (Operations: backup, restore, doctor, observability) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The §12 operations surface:
- `starforged backup <dir>`, a consistent snapshot:
  - the database: SQLite through `VACUUM INTO`, Postgres through `pg_dump` from `PATH`;
  - repositories, each copied under a per-repository lock;
  - blobs. The search index is skipped.
- `starforged restore <dir>` into an empty data directory and, for Postgres, an empty database.
- `starforged doctor`: git version, hooks in every repository, data directory permissions, orphaned blobs, index health.
- `/readyz` and token-protected Prometheus `/metrics`.
- JSON logs.
- SQLite in WAL mode with one writer connection and a pool of reader connections.

**Architecture:**
- **New `crates/starforged/src/{backup.rs,restore.rs,doctor.rs}`** subcommands.
- **`starforged-core`** gains:
  - `repolock.rs`: a cross-process per-repository lock file. Repository writers take it shared; backup takes it exclusive;
  - a blob-GC lock, so blob deletion pauses during a backup;
  - `metrics.rs`: counters and gauges with hand-written Prometheus text exposition (no dependency).
- **`starforged-db`:** `Db` gains a separate reader pool for SQLite; read-only query fns use it.
- **`serve.rs`:** `/readyz`, `/metrics`, and the log format switch.

**Tech Stack:** as before. Locks use `std::fs::File::lock`/`lock_shared` (stable since Rust 1.89; no `unsafe`, no new crate). JSON logs use the existing `tracing-subscriber` with its `json` feature enabled; the cost is the small `tracing-serde` crate (ruling D1).

**Spec:** §12 (backup and restore, upgrades, doctor, observability, database), §5.3 (data dir layout), §11.4 (storage).

**Deferred (not built here):**
- S3 blob backend backups (only the filesystem backend exists);
- incremental backups;
- online restore;
- OpenTelemetry.

## Global Constraints

- **No new crates.** One new feature on an existing dependency: `tracing-subscriber/json` (D1).
- **Backup consistency:**
  - the database snapshot is transactionally consistent;
  - every repository is copied while holding its EXCLUSIVE lock, which blocks repository writers for that repository only;
  - blob garbage collection is paused (the GC lock is held shared by backup, exclusive by GC) from just before the database snapshot until the blob copy ends, so every blob referenced by the snapshot is copied.
- **Repository writers:** every code path that writes inside a repository directory holds the repository lock SHARED for its duration:
  - receive-pack RPCs (HTTP and SSH);
  - server-side merges;
  - Trail ref writes;
  - imports and mirror fetches;
  - git maintenance;
  - repository purge (exclusive).
  Readers (upload-pack, browsing) never lock.
- **The backup directory** must be empty or absent. It gets:
  - `manifest.json` (format version 1, starforged version, created_at, engine, latest migration, repository count, blob count);
  - `database/`;
  - `repos/` (same sharded layout);
  - `blobs/`;
  - `config/starforged.toml`, a copy of the running config. The manifest warns that the backup contains `secret_key`; see D3.
- **Restore** refuses a non-empty data dir, or a Postgres database that has any tables. It refuses a manifest from a NEWER schema than the binary knows. It runs migrations after restoring an older schema.
- **Doctor:**
  - exits 0 when all checks pass, 1 on any FAIL, and 2 when only WARNs occur;
  - prints one line per check;
  - `--fix` repairs only hooks (reinstalls the hook script) and removes orphaned blob FILES (files with no DB row, older than 1 hour);
  - never deletes database rows.
- **Metrics:**
  - token-protected (`Authorization: Bearer <metrics.token>`; 404 when no token is configured, 401 on a wrong token);
  - no labels carrying user, repository, or token identifiers (cardinality and privacy).
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`. Postgres backup and restore tests need `pg_dump`/`pg_restore`: the test harness provides PATH shims that run them inside the test Postgres container (`podman exec`/`run --network host`), and the tests SKIP with a printed reason only when no container engine is present, never silently.

## Decisions this plan makes where the spec is silent

- **D1. JSON logs.** `log.format = "text" | "json"` (default text), overridable by `STARFORGE__LOG__FORMAT`, plus `log.level` (EnvFilter string, default `info`). The `json` feature of tracing-subscriber pulls in `tracing-serde`. Cost if wrong: one small crate.
- **D2. Lock files.**
  - Each repository has `<repo>.git/starforge.lock`, created on first use.
  - The blob GC lock is `<blob_dir>/.gc.lock`.
  - Locks are released on drop. A process crash releases them through the OS.
- **D3. Config in backups.**
  - The config is copied because restoring without `secret_key` would log out every user and make mirror credentials unreadable (§12).
  - The backup dir is created 0700 and the config file 0600. The README warns that a backup contains secrets.
  - `--no-config` omits it.
- **D4. Postgres.**
  - `pg_dump --format=custom --no-owner --file database/starforge.pgdump <url>`, and `pg_restore --no-owner --dbname <url>` for restore.
  - The URL comes from config. The password is passed through `PGPASSWORD` in the child environment, never argv.
  - A missing `pg_dump` fails with a clear error naming the requirement.
- **D5. Readiness.** `/readyz` returns 200 only when all of these hold; otherwise 503 with the failing items as a JSON list:
  - the database answers `SELECT 1` within 2 s;
  - the latest migration is applied;
  - job workers have a heartbeat newer than 30 s;
  - the search index is open;
  - the SSH listener is bound (when enabled).
- **D6. Metrics.**
  - **Counters:**
    - `starforged_http_requests_total{class=web|api|git, status=2xx|3xx|4xx|5xx}`;
    - `starforged_git_rpc_total{service=upload-pack|receive-pack, transport=http|ssh}`;
    - `starforged_jobs_processed_total{kind, outcome=ok|retry|failed}`;
    - `starforged_session_upload_bytes_total`;
    - `starforged_rate_limited_total{limit}`.
  - **Gauges:**
    - `starforged_jobs_pending{kind}`;
    - `starforged_index_documents{kind}`;
    - `starforged_ssh_connections`.
  - **Histogram:** `starforged_http_request_duration_seconds{class}`, with fixed buckets.
- **D7. Reader pool.**
  - SQLite gets a writer pool (max 1 connection) and a reader pool (max 4, `PRAGMA query_only = ON`).
  - Query fns that only read take the reader pool. Fns inside transactions, and any read-then-write fn, take the writer.
  - Postgres uses one pool for both.
  - A test proves a long read does not block a concurrent write on SQLite.

## File Structure

```
Cargo.toml                                         tracing-subscriber json feature
crates/starforged/src/{main.rs,backup.rs (new),restore.rs (new),doctor.rs (new),serve.rs,config.rs}
crates/starforged-core/src/{repolock.rs (new),metrics.rs (new),jobs.rs,merge.rs,changes.rs,repos.rs,remotes.rs,lib.rs}
crates/starforged-web/src/githttp.rs, crates/starforged-ssh/src/server.rs     shared repo lock around receive-pack; metrics
crates/starforged-db/src/lib.rs (+ read-only fns across modules)               reader pool
crates/starforged/tests/{backup_restore.rs,doctor.rs,observability.rs,db_pool.rs}, tests/common/pg_shims.rs
README.md
```

---

### Task O1: Repository locks and backup

**Files:**
- Create:
  - `crates/starforged-core/src/repolock.rs`;
  - `crates/starforged/src/backup.rs`;
  - `crates/starforged/tests/backup_restore.rs` (backup part);
  - `tests/common/pg_shims.rs`.
- Modify: every repository writer named in the Global Constraints; blob GC in `jobs.rs`; `main.rs`.

**Interfaces:**
- `RepoLock::shared(repo_dir) -> Guard` and `RepoLock::exclusive(repo_dir) -> Guard`, both blocking with a timeout, each with an async wrapper via `spawn_blocking`;
- `BlobGcLock`;
- `starforged backup <dir> [--no-config]`.

- [ ] **Step 1: Write the failing tests.**
  - **Lock semantics:** a shared lock blocks an exclusive one and vice versa (two threads, bounded waits).
  - **Consistency under load:** a backup taken while a push is in flight contains either the pre-push or the post-push state of that repository, never a torn one. Check with `git fsck` on the copied repository.
  - **Contents:** the backup contains the manifest, database, repos, blobs, and config, with modes 0700/0600.
  - **Empty dir:** a non-empty target directory is refused.
  - **Blob GC:** blobs referenced by the snapshot survive a GC that runs concurrently (GC waits on the lock).
  - **Postgres:** the backup writes `starforged.pgdump` through the shims.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core repolock` and `cargo test -p starforged --test backup_restore`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus `--test smart_http --test merge_changes --test ssh_git` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add repository locks and starforged backup`.

---

### Task O2: Restore

**Files:**
- Create: `crates/starforged/src/restore.rs`.
- Modify: `crates/starforged/src/main.rs` and `tests/backup_restore.rs`.

**Interfaces:** `starforged restore <dir> [--config <path>]`. It restores into the data dir and database named by the target config. When `--config` is absent, it uses the backup's config with `storage.data_dir` taken from `--data-dir`.

- [ ] **Step 1: Write the failing tests.**
  - **Round trip:** back up a populated server (repositories, Trails, a session with blobs, a webhook, an org); restore into a fresh dir; start a server on it.
    - git clone works;
    - the session viewer renders;
    - the Trail page renders;
    - login works with the same password;
    - sealed secrets (webhook secret, mirror credentials) open.
  - **Refusals:** a non-empty dir or a newer-schema manifest.
  - **Postgres:** a Postgres round trip through the shims.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test backup_restore`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add starforged restore`.

---

### Task O3: Doctor

**Files:**
- Create:
  - `crates/starforged/src/doctor.rs`;
  - `crates/starforged/tests/doctor.rs`.
- Modify: `main.rs`; `crates/starforged-git/src/init.rs` (expose the expected hook content).

**Interfaces:** `starforged doctor [--fix]`. The checks:
1. git version ≥ 2.38;
2. `ssh` present when any SSH remote exists;
3. `pg_dump` present when Postgres is configured (WARN);
4. data dir and subdirectories not world-writable, with `secret_key`-bearing config 0600 (WARN otherwise);
5. every repository directory present with the expected hooks;
6. no repository directory without a database row (WARN);
7. orphaned blob files (WARN) and zero-reference blob rows older than the GC window (WARN);
8. the search index opens, with document counts within 1% of the database counts, or a WARN suggesting `index rebuild`;
9. migrations up to date.

- [ ] **Step 1: Write the failing tests.**
  - A healthy data dir exits 0.
  - Each injected fault produces the expected line and exit code: a deleted hook, a stray repository dir, an orphan blob file, a world-writable dir, an index removed, an old git (simulated through a PATH shim `git` that reports 2.30).
  - `--fix` reinstalls the hook and removes the orphan file, leaving rows untouched.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test doctor`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add starforged doctor`.

---

### Task O4: Readiness, metrics, JSON logs

**Files:**
- Create:
  - `crates/starforged-core/src/metrics.rs`;
  - `crates/starforged/tests/observability.rs`.
- Modify: `serve.rs`, `config.rs`, `main.rs`, the job worker (heartbeat and counters), githttp/ssh (counters), and the API/web middleware (request counter and histogram).

**Interfaces:** D1, D5, D6. Config: `metrics.token`, `log.format`, `log.level`.

- [ ] **Step 1: Write the failing tests.**
  - **`/readyz`:** 200 on a healthy server; 503 naming `jobs` when the workers are stopped (a test hook to stop them).
  - **`/metrics`:**
    - 404 without a token configured; 401 with a wrong token;
    - with the right token, the text exposition parses (a line-format check) and the counters move after a web request, a git clone, and a job run;
    - no label contains a repository or user name.
  - **JSON logs:** with `log.format = "json"`, the server's startup log line is valid JSON.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test observability`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test smart_http` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add readiness, metrics, and JSON logs`.

---

### Task O5: SQLite reader pool and docs

**Files:**
- Create: `crates/starforged/tests/db_pool.rs`.
- Modify: `crates/starforged-db/src/lib.rs` and the read-only fns across `crates/starforged-db/src/*.rs`; `README.md`.

**Interfaces:**
- `Db::pool()` stays for writes;
- `Db::read_pool()` is new (it equals `pool()` on Postgres);
- every fn that only SELECTs outside a transaction uses `read_pool()`.

- [ ] **Step 1: Write the failing tests.**
  - On SQLite, a read held open in one task does not block a write in another.
  - The reader connection refuses writes (`query_only`).
  - A write, then an immediate read, sees the write (WAL visibility).
- [ ] **Step 2: Run them to verify failure,** then **implement,** then run the whole affected suites: `cargo test -p starforged-db` and `cargo test -p starforged --test api_trails --test web_trails --test api_sessions`. Expected: PASS.
- [ ] **Step 3: README:** an "Operations" section (backup and restore, with the secrets warning and Postgres requirements; doctor; readiness and metrics; log format; upgrades and migrations).
- [ ] **Step 4: Commit** (PG gate first): `Add the SQLite reader pool and operations docs`.
