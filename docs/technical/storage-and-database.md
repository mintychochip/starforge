# Storage and database

<!-- ste-sources
crates/starforged-db/src/lib.rs
crates/starforged-db/migrations
crates/starforged-blob/src/lib.rs
crates/starforged/src/backup.rs
crates/starforged/src/restore.rs
crates/starforged-db/src/ci.rs
crates/starforged-db/src/sandboxes.rs
crates/starforged-core/src/ci.rs
-->

## Purpose

This page defines storage for Starforge. One schema serves SQLite and Postgres. Blobs are content addressed on the filesystem.

## Scope

This page covers the data directory, engine, schema, blobs, and copies. Operator procedures live in [the administration backup and restore guide](../admin/backup-and-restore.md).

## How it works

The code in `crates/starforged-db/src/lib.rs` owns the schema. `Db` holds a writer pool and a reader pool. Every statement runs unchanged on both engines. Placeholders number from `$1` in ascending order. Integers decode as `i64` on both engines. The code stores booleans as `0` or `1`.

Timestamps are unix seconds. `Db::ping` runs `SELECT 1` on the reader pool. `Db::latest_migration` reads `_sqlx_migrations`. `Db::known_migration` returns the newest embedded version.

### Data directory layout

| Path | Content |
|---|---|
| `<data_dir>/starforge.db` | SQLite database file |
| `<data_dir>/repos/<two-digit shard>/<id>.git` | Bare repositories |
| `<data_dir>/data/blobs/<hash[0..2]>/<hash>` | Blob bytes by default |
| `<data_dir>/index/` | Search index data |
| `<data_dir>/run/` | Runtime files |
| `<data_dir>/tmp/` | Scratch files |

The default blob root is `<data_dir>/data/blobs`. Absolute `sessions.blob_dir` values stay verbatim. Absolute `storage.index_dir` values stay verbatim.

The SQLite file name is `starforge.db`. The repositories path joins `data_dir` with `repos`. The scratch path joins `data_dir` with `tmp`. The index default joins `data_dir` with `index`.

### Engine pools

| Engine | Writer pool | Reader pool | Pragmas |
|---|---|---|---|
| SQLite | 1 connection | 4 connections | Foreign keys on, WAL, busy timeout 5000 ms |
| Postgres | One 16 connection pool | Same pool | Read committed |

SQLite serializes writes by design. WAL lets readers run beside the writer. The busy timeout waits 5000 milliseconds for locks. Reader connections refuse writes with `query_only`. In-memory SQLite shares one pool across readers. Postgres uses one shared pool with `READ COMMITTED`.

Reads inside open transactions use the writer pool. The engine enforces foreign keys on both sides. The writer pool serves every write and transaction. The reader pool serves plain reads outside transactions.

### Migrations

Embedded migrators live in `crates/starforged-db/migrations`. The SQLite and Postgres sets share filenames. Versions run from `0001` to `0042`, so `0030` to `0033` are absent. `Db::migrate` runs versions in order. Bookkeeping lives in `_sqlx_migrations`. Rerun of `migrate` is safe and idempotent.

Migrations are forward only. A released migration must not change, because sqlx validates its checksum. `0034` rebuilds the SSH fingerprint table and drops orphan rows during the rebuild. `0035` adds the `jobs.rerun_at` column for rerun requests on deduplicated jobs. A request that arrives while a deduplicated job runs records its time in `rerun_at`, so the worker runs the job again after it finishes.

`0036` adds the CI tables. `runners` stores registered runners. `runner_registration_tokens` stores hashed registration tokens. `ci_jobs` stores CI jobs in a queue separate from the internal `jobs` table. `ci_job_logs` stores log chunk rows. `ci_artifacts` stores artifact rows.

`ci_job_sessions` links CI jobs to sessions. `ci_job_tokens` stores hashed per-job tokens. `0036` also adds `sessions.ci_job_id`.

`0037` adds `sandboxes` and `sandbox_usage`. `sandboxes` records one sandbox per API create. `sandbox_usage` meters sandbox seconds per owner and repository in hourly windows. `0038` adds `ci_secrets`, `ci_job_secrets`, and `ci_artifact_tokens`.

`ci_secrets` stores sealed CI secret values. `ci_job_secrets` records which secrets one job resolved. `ci_artifact_tokens` stores hashed one-time artifact upload tokens.

`0039` adds `ci_jobs.claimed_at`, `ci_usage`, and `ci_supplier_links`. `claimed_at` records when each claim happens. `ci_usage` records one row per ended attempt of a native runner job. `ci_supplier_links` links a repository to an external CI supplier. The supplier check allows `depot` only.

`0040` adds `repos.ci_allow_secrets_on_refs_for`, `repos.ci_env_secrets`, `ci_secrets.host`, and `ci_secrets.header`. `ci_allow_secrets_on_refs_for` defaults to off. `ci_env_secrets` defaults to off. `ci_secrets.host` defaults to empty. `ci_secrets.header` defaults to `Authorization`. The host and header bind egress-proxy injection.

`0041` adds `notifications`, `repo_watches`, and `trail_subscriptions`. It also adds `users.notify_email` with default `1`. `notifications` stores one row per recipient per event. `repo_watches` stores `watching` or `ignoring` per user and repository. `trail_subscriptions` stores a subscribed flag per user and Trail.

`0042` adds `releases` and `release_assets`. `releases` stores tag, title, notes, draft flag, prerelease flag, author, and publish times per repository. The pair of repository and tag is unique. `release_assets` stores name, size, blob hash, and content type per release. The pair of release and name is unique. An index covers `release_assets` by release.

Removal of a release cascades to its assets. Removal of a repository cascades to its releases.

`auto_migrate` runs migrations at start. `starforged migrate` runs them manually. `doctor` compares latest and known versions. A difference reports a migrate action.

### Schema groups

| Group | Important tables | Key constraints |
|---|---|---|
| Identity and access | `owners`, `users`, `access_tokens`, `web_sessions` | Shared handle space |
| Jobs | `jobs` | Dedupe keys and leases |
| Sessions and traces | `sessions`, `segments`, `blobs`, `commit_links` | Unique ULID per repository |
| Trails and changes | `trails`, `changes`, `revisions`, `reviews`, `change_sequences` | Numbers per repository |
| Checks and gates | `checks`, `gate_rules` | One check per SHA and context; gate patterns are not unique |
| Webhooks | `webhooks`, `webhook_deliveries` | Sealed secrets at rest |
| Organizations and teams | `orgs`, `org_members`, `teams`, `team_members`, `team_repos` | Membership uniqueness |
| SSH keys | `ssh_keys`, `deploy_keys`, `ssh_fingerprints` | Fingerprint uniqueness |
| Mirrors and imports | `repo_remotes`, `github_imports` | Sealed credentials at rest |
| Audit | `audit_log` | Append-only by API convention |

| CI runners and jobs | `runners`, `runner_registration_tokens`, `ci_jobs`, `ci_job_logs`, `ci_artifacts`, `ci_job_sessions`, `ci_job_tokens` | Hashed tokens only; one active job per commit and job name |
| Sandboxes | `sandboxes`, `sandbox_usage` | Idempotency key unique per owner |
| CI secrets | `ci_secrets`, `ci_job_secrets`, `ci_artifact_tokens` | Sealed values; secret name unique per repository |
| CI usage | `ci_usage`, `ci_supplier_links` | One usage row per ended native attempt |
| Releases | `releases`, `release_assets` | One release per tag; reference counted blobs |
| Notifications | `notifications`, `repo_watches`, `trail_subscriptions` | One row per recipient per event; watch mode per repository |
Users and organizations share the `owners` table. User rows cascade from owner rows. Segments cascade from session rows. Blobs track reference counts in rows. Trail numbers live in `trail_sequences`. Each group keeps its own data access module.

Modules live under `crates/starforged-db/src`. Each module owns rows for one group. Business rules live above this layer. The core crate enforces permissions.

### Blob store

`FsBlobStore` stores exact bytes under a root. The hash is the BLAKE3 digest in hex. The layout is `<root>/<hash[0..2]>/<hash>`. `put` skips work when bytes exist. Writes create shard directories as needed. Writes use a same-directory temporary file.

CI log chunks and CI artifacts use the same blob store. `put_log_chunk` writes log bytes through the blob store. Chunk rows record the blob BLAKE3 digest. `upload_ci_artifact` writes artifact bytes through the blob store. Artifact rows record the blob BLAKE3 digest.

Expired artifacts stay out of downloads and out of the artifact quota. The hourly cleanup calls `gc_expired_artifacts` under the blob-GC lock. The cleanup deletes expired artifact rows, up to 1000 per pass. The cleanup removes a CAS blob when its refcount reaches zero.

The temporary name carries the process identifier. The code writes the temporary file, then renames it. The code does not fsync the file, so a crash can lose the blob. Concurrent identical puts rename over each other. Readers rebuild the hash on every read. Hash mismatch returns a corrupt error.

Missing files return a not-found error. Invalid hashes return a not-found error. The code rejects hashes with separators. `delete` accepts missing files. Deletion tries to remove empty shards. Refcounts live in the `blobs` table.

Release assets use the same reference counted blobs. Upload increments the count. Delete decrements the count. The hourly zero reference sweep removes the files.

Increment and decrement update the count. GC deletes rows with zero references. Deletion and GC never race with backup. `delete_session` returns segments for refcount drops.

## Interfaces

`Db::connect` takes a database URL. `Db::migrate` runs embedded migrations. `Db::pool` returns the writer pool. `Db::read_pool` returns the reader pool. `Db::ping` checks database health. `Db::latest_migration` returns the highest applied version.

`Db::known_migration` returns the highest known version. `Db::vacuum_into_file` writes a SQLite copy. `Db::backend` returns the engine kind. `now` returns unix seconds.

`BlobStore::put` stores bytes and returns a reference. `BlobStore::get` reads bytes by reference. `BlobStore::get_by_hash` reads bytes by hash. `BlobStore::delete` removes bytes idempotently. `BlobStore::exists` reports presence.

`FsBlobStore::path_for` maps a hash to a path. `blob_file_path` shares that mapping with tests.

## Failure behavior

Unsupported database URLs return an error. The error names the expected schemes. Foreign key violations map to not-found at callers. Unique violations map to domain errors at callers. Blob reads report corruption on hash mismatch. Backup refuses non-empty target directories.

Restore refuses non-empty data directories. Restore refuses populated Postgres databases. Restore refuses newer schema manifests. Restore refuses unknown format versions. An invalid manifest stops before any write.

### Backup and restore

`backup::run` takes a config path and a target. The target must be absent or empty. The target directory has mode `0700`. The manifest has mode `0600`. The config copy has mode `0600`. The manifest records format version `1`.

The manifest records engine and migration version. The manifest records repository and blob counts. SQLite copies with `VACUUM INTO`. Postgres copies with `pg_dump`. `pg_dump` uses format custom without owners. Passwords travel through the environment.

Passwords never appear in command arguments. Each repository copies under an exclusive lock. The blob GC lock stays shared during copies. The lock blocks blob deletion until copies end. Each backup holds pre-push or post-push state. Backups never report success on symlinks.

`restore::run` takes a backup directory. Validation runs before the first write. Checks cover manifest counts and tree entries. Checks cover schema and engine compatibility. Checks cover target emptiness. A refused restore leaves the target untouched.

Restore copies the database snapshot. Restore copies repositories and blobs strictly. Restore runs migrations after the copy. Restore enqueues an index rebuild job. The search index is never part of a backup. Index rebuild restores search after restore.

## Verification

Tests run migrations on fresh databases. Tests rerun migrations cleanly. Tests check foreign key enforcement. Tests check unique violation detection. Tests reject unknown URL schemes. Tests check blob round trips and dedup.

Tests check concurrent blob puts. Tests check corrupt blob detection. Tests check backup contents and locks. Tests check restore round trips. Tests check symlink refusal in copies. Run the checker on this page before commit.

## Related

Read [configuration](configuration.md) for keys and paths. Read [operations](operations.md) for health and jobs. Read [security](security.md) for secrets and trust.
