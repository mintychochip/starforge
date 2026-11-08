# Storage and database

<!-- ste-sources
crates/starforged-db/src/lib.rs
crates/starforged-db/migrations
crates/starforged-blob/src/lib.rs
crates/starforged/src/backup.rs
crates/starforged/src/restore.rs
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

Embedded migrators live in `crates/starforged-db/migrations`. The SQLite and Postgres sets share filenames. Versions run from `0001` to `0029`, then `0034` and `0035`, so `0030` to `0033` are absent. `Db::migrate` runs versions in order. Bookkeeping lives in `_sqlx_migrations`. Rerun of `migrate` is safe and idempotent.

Migrations are forward only. A released migration must not change, because sqlx validates its checksum. `0034` rebuilds the SSH fingerprint table and drops orphan rows during the rebuild.

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

Users and organizations share the `owners` table. User rows cascade from owner rows. Segments cascade from session rows. Blobs track reference counts in rows. Trail numbers live in `trail_sequences`. Each group keeps its own data access module.

Modules live under `crates/starforged-db/src`. Each module owns rows for one group. Business rules live above this layer. The core crate enforces permissions.

### Blob store

`FsBlobStore` stores exact bytes under a root. The hash is the BLAKE3 digest in hex. The layout is `<root>/<hash[0..2]>/<hash>`. `put` skips work when bytes exist. Writes create shard directories as needed. Writes use a same-directory temporary file.

The temporary name carries the process identifier. The code writes the temporary file, then renames it. The code does not fsync the file, so a crash can lose the blob. Concurrent identical puts rename over each other. Readers rebuild the hash on every read. Hash mismatch returns a corrupt error.

Missing files return a not-found error. Invalid hashes return a not-found error. The code rejects hashes with separators. `delete` accepts missing files. Deletion tries to remove empty shards. Refcounts live in the `blobs` table.

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
