# Operations

## Purpose

> **Note:** This page describes operator behavior and runtime controls.
> For command procedures, read the administration guide in `docs/admin`.

This page describes how an operator runs Starforge in daily use.
It covers startup, shutdown, background jobs, health checks, and recovery.
The page addresses operators who manage the server after installation.

## Scope

This page covers startup and shutdown order.
It covers the background job queue and job workers.
It covers health checks, metrics, logs, and audit reads.
It covers limits, the doctor command, backup, restore, and upgrade rules.

## Design

### Startup sequence

- The process aborts before binding when git is absent or below version 2.38.
- The server loads configuration from the path in `STARFORGE_CONFIG` or from `starforged.toml`.
- The server validates configuration before it opens the database.
- Startup aborts on invalid configuration or a database error. A migration error aborts startup when `database.auto_migrate` is true. With it false, startup continues and readiness reports the migration item.
- The server opens the search index through `open_or_create_fresh`.
- Index failure uses a throwaway index and never stops startup.
- The server enqueues a rebuild when open recreates the index.
- Two job workers start beside the HTTP listener and the SSH listener.
- The SSH listener starts before the HTTP listener serves requests.

### Shutdown sequence

- The process handles Ctrl-C and SIGTERM for graceful shutdown.
- The HTTP path drains requests across shutdown.
- The runtime drops job workers at shutdown.
- In flight jobs rely on leases after the next start.

### Job queue

- `Job` uses a serde `kind` tag shaped `snake_case`.
- The `jobs` table stores payload JSON, kind, `dedupe_key`, `run_at`, attempts, and lease state.
- A colliding dedupe key inserts no row.
- Idle workers wake on a `Notify` signal or poll after 5 seconds.
- Lease length is 600 seconds and maximum attempts equal 5.
- Retry delays after attempts 1, 2, 3, and 4 equal 60, 300, 1800, and 7200 seconds.
- An unreadable payload counts as a failure without a retry.
- The recurring jobs reschedule after each finish.
- Pull mirrors reschedule after each run. Push mirrors reschedule only after a failure. A successful push mirror waits for the next accepted push or the hourly reconcile.
- A same key enqueue records a rerun for index and mergeability jobs while the job runs. A collision with a queued copy records nothing.
- The hourly pass deletes expired web sessions, email tokens, and OAuth codes. It deletes invites that expired more than 30 days ago.
- The hourly pass blanks failed mail bodies older than 7 days. It prunes webhook delivery rows older than 30 days. It reconciles mirror schedules.
- The hourly pass garbage collects zero reference blobs under the blob garbage collection lock. The hourly pass deletes expired CI artifact rows and collects zero-ref artifact blobs.
- The hourly pass enqueues at most 100 unrecorded revision commits.
- The hourly pass finalizes idle `receiving` sessions after 24 hours without activity.
- The hourly pass runs `prune_notifications`. It deletes read rows older than 90 days. It deletes every row older than 365 days.

Each job worker also runs the CI sweep. `run_ci_sweep_if_due` calls `sweep_ci_jobs` at most once every 30 seconds across all workers. A compare-exchange on the due time lets one worker sweep per interval. Sweep errors only log warnings. A sweep failure never stops job work.

A job sandbox create resolves the job secrets on the server side. The hourly pass runs artifact GC.

The sweep requeues claimed or running CI jobs with expired leases. A lease lasts 60 seconds. A reaped job returns to `queued`, or ends `failed` after 3 attempts. A cancel request ends the job as `canceled`. A requeued job writes no terminal check and emits no event.

The sweep also fails overdue CI jobs. A job fails when its deadline passed more than 60 seconds ago. The job ends `failed` with reason `the job exceeded its timeout`. Every job that ends in the sweep writes its terminal `ci/<job>` check and emits a `ci` event.

CI jobs use a separate queue from the internal `jobs` table. The internal `Job` enum gains no new kind for M6. The hourly cleanup now also kills expired sandboxes through `gc_expired_sandboxes`. It kills at most 100 expired sandboxes per pass. A failed provider kill only logs a warning, and the row still moves to `killed`.

| Kind | Dedupe key | Schedule |
|---|---|---|
| `hourly_cleanup` | kind | 1 hour |
| `daily_prune` | kind | 1 day |
| `purge_deleted_repos` | kind | 1 day |
| `send_email` | none | on enqueue |
| `webhook_delivery` | none | on enqueue |
| `git_maintenance` | `git_maintenance:<repo_id>` | on enqueue |
| `index_session_events` | `index_session_events:<session_id>` | on enqueue |
| `index_trail` | `index_trail:<trail_id>` | on enqueue |
| `index_repo` | `index_repo:<repo_id>` | on enqueue |
| `drop_session_docs` | `drop_session_docs:<session_id>` | on enqueue |
| `rebuild_index` | `rebuild_index` | on enqueue |
| `resolve_commit_links` | none | on enqueue |
| `update_session_stats` | none | on enqueue |
| `session_webhook_outbox` | none | on enqueue |
| `change_mergeability` | `change_mergeability:<change_id>` | on enqueue |
| `record_revision_commits` | `record_revision_commits:<revision_id>` | on enqueue |
| `import_repo` | `import_repo:<repo_id>` | on enqueue |
| `import_github` | `import_github:<repo_id>` | on enqueue |
| `pull_mirror` | `pull_mirror:<repo_id>` | self scheduled |
| `push_mirror` | `push_mirror:<remote_id>` | on push, or after failure |

### Health and metrics behavior

- The readiness probe uses a 2 second database ping.
- Readiness fails on items named `database`, `migration`, `jobs`, `search`, and `data_dir`. It also fails on `ssh` when the SSH listener runs.
- The worker heartbeat must lag at most 30 seconds.
- The migration item compares the latest migration with the known migration.
- Metrics labels use class, status, service, transport, kind, outcome, limit, and `le` on histogram buckets.
- Labels never contain a user, a repository, or a token.
- Gauges compute per request from database and index state.
- The duration histogram uses eleven fixed buckets from 0.005 to 10 seconds.
- Exposition format follows the Prometheus text format.

## Interfaces

| Method and path | Result |
|---|---|
| `GET /healthz` | Always answers `ok` |
| `GET /readyz` | Answers 200 with status `ok` or 503 with failing items |
| `GET /metrics` | Answers 404 without a token, 401 on mismatch, or exposition text |
| `GET /api/v1/admin/audit` | Answers filtered audit rows for an admin token |
| `/admin/audit` | Shows 50 audit rows per page through a keyset cursor |

| Command | Effect |
|---|---|
| `starforged doctor` | Prints one line per check |
| `starforged doctor --fix` | Repairs filesystem defects only |
| `starforged backup <dir>` | Writes a snapshot into an empty or absent directory |
| `starforged restore <dir> --data-dir <dir>` | Validates a backup and writes it to `<dir>` |
| `starforged index rebuild` | Rebuilds the search index from the database |

### Logs

- `log.format` selects `text` or `json`.
- JSON mode emits one JSON object per line.
- `log.level` holds an EnvFilter string with default `info`.
- `RUST_LOG` overrides `log.level`.
- ANSI color applies only to terminal output.

### Audit reads

- The table `audit_log` holds actor, action, target, detail, client address, user agent, and time.
- State-changing actions write audit rows. Logout, web session expiry, token last-used updates, and object reads write none.
- Refused actions write no row except sign in failures and rate limited sign ins.
- Rows never contain transcripts, tokens, or secrets.
- The read path resolves the actor handle through a left join.
- User deletion clears the actor but keeps the row.

### Limits and quotas

| Key | Default | Storage |
|---|---|---|
| `limits.login_per_ip_per_minute` | 10 | in memory window of 60 seconds |
| `ci.limits.minutes_per_month` | 0, disabled | native runner minutes per repository per month |
| `ci.limits.artifact_bytes` | 0, disabled | live CI artifact bytes per repository |
| `sandbox.limits.max_concurrent_per_user` | 0, disabled | running sandboxes per user |
| `sandbox.limits.max_concurrent_per_repo` | 0, disabled | running sandboxes per repository |
| `sandbox.limits.sandbox_seconds_per_hour` | 0, disabled | sandbox seconds per hour |
| `limits.login_per_account_per_hour` | 20 | database count over 3600 seconds |
| `limits.api_per_token_per_hour` | 5000 | in memory window of 3600 seconds |
| `limits.refs_for_new_changes_per_hour` | 30 | database count over 3600 seconds |
| `sessions.max_segment_bytes` | 16 MiB | per segment |
| `sessions.max_repo_bytes` | 20 GiB | per repository |
| `sessions.max_user_bytes` | 5 GiB | per user |
| `sessions.max_hourly_bytes` | 500 MiB | per user per hour |

| `sessions.max_decompressed_bytes` | 256 MiB | per decompressed segment |

CI minutes come from `ci_usage` rows for native runner attempts. A full minutes quota refuses new runs at queue time. The refusal writes an `error` check, so a gate shows why the run did not start. The server reads Depot usage from the Depot API only. Starforge never enforces Depot limits.

- A value of 0 disables one of the four `limits.*` controls. A zero session quota rejects every upload.
- API limit breaches answer 429 with an error envelope and `Retry-After`.
- Token responses gain `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers.
- Sign in limit breaches re render the sign in page with 429 and a generic message.
- Session volume and storage quotas use the `sessions` keys in the table above.
- Read the session quotas page at [sessions.md](sessions.md) for detail.

### Doctor

The doctor command prints one line per check.
Each line starts with `[OK]`, `[WARN]`, or `[FAIL]`.

| Check | Level | Meaning |
|---|---|---|
| git version | FAIL | git is at least 2.38 |
| SSH client | FAIL | an SSH client exists for SSH remotes |
| `pg_dump` presence | WARN | Postgres backups need `pg_dump` in `PATH` |
| permissions | WARN | no world writable directory and the configuration file has mode 0600 |
| repository hooks | FAIL | hooks have the expected shape and are executable |
| stray entries | WARN | no stray `repos/<shard>/<id>.git` entries, unless the database is unavailable |
| locks | WARN | lock state is healthy |
| orphan blobs | WARN | no orphan blobs or zero reference rows outside the garbage collection window |
| index counts | WARN | index document count stays within 1 percent of database count |
| migrations | FAIL | applied migration is at least the known version |

| Exit code | Meaning |
|---|---|
| 0 | all checks pass |
| 1 | any check fails |
| 2 | only warnings occur |

- `--fix` reinstalls missing hooks.
- `--fix` deletes orphan blob files older than one hour.
- `--fix` never deletes database rows.
- `--fix` never rebuilds the index.
- The orphan blob repair never follows symlinks.

### Backup, restore, and index rebuild

- Backup copies the database through a transactionally consistent snapshot.
- Backup pauses blob garbage collection for the full snapshot.
- Backup holds a shared `BlobGcLock` across the snapshot.
- Backup holds a per repository exclusive `RepoLock` during each copy.
- Backup skips the search index.
- Backup refuses symlinks and non regular files.
- Backup requires an empty or absent target directory.
- The target directory has mode 0700 after capture.
- The configuration copy and `manifest.json` have mode 0600.
- `manifest.json` carries format version 1 and the database engine name.
- Restore validates format version, engine, migration level, counts, and target emptiness.
- Restore rejects symlink, FIFO, and socket entries inside a backup.
- Restore writes files only after all checks pass.
- Restore enqueues `RebuildIndex` after a successful write.

> **Caution:** The backup contains `security.secret_key`.
> Treat the backup directory like a secret after capture.

- Index rebuild probes the Tantivy writer before any side effect.
- A locked writer fails with a stop server message.

### Upgrades

- Migrations are forward only.
- The server applies migrations at startup when `database.auto_migrate` is true.
- The CLI applies migrations through `starforged migrate`.
- Back up the data before each upgrade.
- Keep `server.base_url` an origin without path, query, or fragment.
- Read the upgrade procedure at [upgrades and migrations](../admin/upgrades-and-migrations.md).

## Failure behavior

- Invalid configuration stops startup before any listener binds.
- A database connect failure stops startup.
- A migration failure stops startup.
- An HTTP bind failure stops startup.
- A search index failure never stops startup.
- Readiness answers 503 and lists each failing item.
- Metrics answers 404 without a token and 401 on mismatch.
- A locked index writer fails `index rebuild` without side effects.
- Restore writes no file before all checks pass.

## Verification

- `crates/starforged/tests/observability.rs` covers readyz, metrics, health checks, and JSON logs.
- `crates/starforged-core/src/jobs.rs` covers retry delays, dedupe, and recurring jobs.
- `crates/starforged/tests/doctor.rs` covers the doctor check suites.
- `crates/starforged/tests/backup_restore.rs` covers backup layout, restore layout, and manifest checks.
- Run the checker in [maintenance.md](maintenance.md) after changes.

## Related

- Read the storage and database page at [storage-and-database.md](storage-and-database.md).
- Read the configuration page at [configuration.md](configuration.md).
- Read the security page at [security.md](security.md).
- Read monitoring procedure at [monitoring](../admin/monitoring.md).
- Read backup procedure at [backup and restore](../admin/backup-and-restore.md).

<!-- ste-sources
crates/starforged/src/serve.rs
crates/starforged/src/doctor.rs
crates/starforged/src/backup.rs
crates/starforged/src/restore.rs
crates/starforged/src/index_cmd.rs
crates/starforged-core/src/jobs.rs
crates/starforged-core/src/metrics.rs
crates/starforged-core/src/audit.rs
crates/starforged-core/src/ci.rs
crates/starforged-core/src/sandboxes.rs
crates/starforged-core/src/ci_usage.rs
-->
