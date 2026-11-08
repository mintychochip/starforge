# Agent sessions

<!-- ste-sources
crates/starforge-capture/src
crates/starforge-cli/src/ingest.rs
crates/starforge-cli/src/spool.rs
crates/starforge-cli/src/queue.rs
crates/starforge-cli/src/commands/sync.rs
crates/starforge-cli/src/upload.rs
crates/starforged-core/src/ingest.rs
crates/starforged-api/src/sessions.rs
crates/starforged-core/src/jobs.rs
-->

## Purpose

The CLI captures agent sessions and uploads them to the server. This page describes the full pipeline from capture to viewer. The format and the redaction rules have their own page.

## Scope

The pipeline covers capture, normalization, redaction, spool, queue, sync, upload, ingest, indexing, and the viewer. The pipeline excludes server-side raw transcript storage in v0.1. The server keeps `raw_enabled` at 0 and `raw_blob_hash` at NULL. Local raw slices sit under `raw/<n>.zst` and never leave the workstation.

## How it works

```mermaid
flowchart LR
  A[Agent store] --> B[Capture adapters]
  B --> C[Normalize to Trace Format v1]
  C --> D[Redact on the CLI]
  D --> E[Spool and queue]
  E --> F[Sync and upload]
  F --> G[Ingest and re-scan]
  G --> H[Blob store and database]
  H --> I[Index jobs]
  I --> J[Viewer and search]
```

### Adapters and the privacy rule

Five adapters produce Trace Format v1 sessions.

| Agent | Store | Covered version |
|---|---|---|
| Claude Code | `~/.claude/projects/<slug>/<session-id>.jsonl` | 1.2.3 |
| Codex | `sessions/YYYY/MM/DD/rollout-*.jsonl` | 0.42.0 |
| Pi and omp | `.pi/agent/sessions/**/*.jsonl` and `.omp/agent/sessions/**/*.jsonl` | 0.5.2 |
| OpenCode | `opencode.db` SQLite file | 2.0.29 |
| Gemini CLI | `tmp/<hash>/chats/*.json` | 0.12.0 |
| Antigravity | none | not captured |

Capture keeps only sessions with a workdir inside the worktree. The Gemini hash match is the one exception. Capture skips sessions with unknown or empty workdir. `workdir_inside` canonicalizes existing paths before comparison. A symlink out of the worktree never counts as inside.

Gemini sessions without workdir join only on a matching hash.

### Capture, normalization, and ingest

The caller builds `Roots` with `config_dir`, `data_dir`, and worktree. Adapters read native stores under `data_dir`. Adapters write agent hooks only under `config_dir`. The `Adapter` trait offers `id`, `COVERED`, `version_status`, `detect`, `install_hooks`, `remove_hooks`, `discover`, and `read`.

`ingest` runs every detected adapter and reads new records. Each adapter returns new events plus an advanced cursor. The cursor counts emitted events, and `seq` continues from that count. Resume never reuses a seq and never trusts mtime.

The 24 hour idle rule ends a session with an old last event. The idle sweep ends stopped sessions with stale cursors.

The server finalizer completes idle `receiving` sessions after 24 hours without activity. The hourly cleanup completes each `receiving` session with 24 hours of no activity. The finalizer sets `ended_at` only when the field stays empty. It sets `ended_at` to the last activity time in that case.

The last activity time equals the newer of the session row update time and the newest segment upload time. The finalizer sends the `uploaded` session webhook event. It queues the same index job that a client `complete` call queues.

Only `receiving` sessions change state. The CLI keeps its own 24-hour idle sweep for local capture.

### Spool and queue

The spool root sits at `<git common dir>/starforge`.

| Path | Holds |
|---|---|
| `sessions/<ULID>/meta.json` | Session metadata and redaction summary |
| `sessions/<ULID>/segments/<n>.jsonl.zst` | Compressed normalized events |
| `sessions/<ULID>/raw/<n>.zst` | Compressed native slices, local only |
| `sessions/<ULID>/upload.json` | Uploaded segment hashes and completion |
| `sessions/<ULID>/link-watermark.json` | Sequence watermark for heuristic links |
| `cursors.json` | One cursor record per native session |
| `links.jsonl` | Append-only commit link claims |
| `queue.jsonl` | Pending upload operations |

Directories use mode `0700` and files use mode `0600` on Unix. The spool fsyncs blobs before it writes `meta.json`. `meta.json` and queue files change through temp file plus rename. `links.jsonl` only appends and never rewrites.

The queue holds one entry per line with op, ULID, and repository. Backoff doubles per attempt and caps at 300 seconds. The queue skips corrupt lines with a warning and never panics. `spool prune` deletes segment blobs for uploaded, complete sessions.

Prune keeps `meta.json`, `upload.json`, and cursors.

### Sync and the upload protocol

`sync` reconciles the queue from spool state, then drains it. Order runs meta, segments in number order, complete, then links. Complete runs only when `ended_at` exists, else it stays queued. Each segment PUT carries the exact spool bytes and BLAKE3 header.

| Call | Result |
|---|---|
| `PUT .../sessions/{ulid}` | Creates or refreshes metadata |
| `PUT .../sessions/{ulid}/segments/{n}` | Stores one segment |
| `POST .../sessions/{ulid}/complete` | Marks the session complete |
| `POST .../sessions/{ulid}/links` | Records commit link claims |

The `X-Starforge-Blake3` header must match the body hash. Identical re-upload succeeds as a no-op and never breaks sync. Different bytes at one number answer 409 with the stored hash. A 409 with a foreign hash ends the run as a conflict.

Transport errors and 5xx responses get up to four retries. Exit 0 means the queue drained and exit 2 means leftovers remain. Exit 1 means an auth abort or another operational failure.

### Ingest, storage, and quotas

`authorize_upload` demands effective write on the repository. Invisible repositories answer 404 and stay undiscoverable. `authorize_session_write` allows uploader or repository admin. `upsert_session_meta` validates metadata with `SessionMeta::parse`.

Re-PUT keeps lifecycle, quarantine, and uploader identity. `put_segment` accepts only the next expected segment number. Gap numbers and complete sessions reject new segment bytes. Identical re-upload changes no quota, blob, or row state.

The server checks three quotas from segment byte sums.

| Quota | Key |
|---|---|
| Repository storage cap | `max_repo_bytes` |
| Uploader storage cap | `max_user_bytes` |
| Rolling hour volume cap | `max_hourly_bytes` |

`decompress_bounded` reads at most limit plus one byte. The server caps expansion through `max_decompressed_bytes`. `segment_seq_range` parses every line and rejects seq overlap. The server re-scans text before it commits the segment row.

`blob_incref` shares one blob file across same-byte sessions. A lost race decrements the extra refcount and reports the winner. Each accepted segment fires an index job for search. `update_session_stats` recomputes turn, tool, and usage totals.

Complete fires the index job once and emits one upload event.

### Lifecycle, quarantine, and visibility

| Group | Values |
|---|---|
| `lifecycle` | `receiving`, `complete` |
| `quarantine` | `none`, `quarantined`, `released` |
| `visibility` | `inherit`, `published` |

A high-confidence hit sets quarantine and keeps the segment. Release clears quarantine for repository admins and site admins. Purge deletes the session rows and decrements blob refcounts.

Publish moves `inherit` to `published` on public repositories. Delete allows uploader, repository admin, or site admin. Unknown ULIDs and forbidden deletes both answer 404.

### Commit links

Git hooks append `Starforge-Session: <ULID>` trailers. The claim source is `cli_claim` with `exact` confidence. `claim_links` validates each SHA and confidence up front. Duplicate SHAs in one payload collapse to one row.

Trailer rows and claim rows merge in one transaction. Backfill matches commits inside session bounds and touched files. Backfill adds 30 minutes after the last event too. `--dry-run` prints backfill pairs and writes nothing.

### Viewer, search, and bundle export

Page handlers call `authorize_session_read_by_ulid` once. `read_session_page` returns one page of items in seq order. `page_for_seq` finds the page that holds one seq. `search_session` lowercases the query and matches message text, tool names, and file paths. It never searches tool inputs. It reads server-redacted items.

The Tantivy path indexes session text in background jobs. Export writes metadata, events, segments, and links. Import re-uploads each session and keeps its ULID. Existing ULIDs on import report `exists` and skip.

## Interfaces

Entry points live in `starforge` CLI and session API routes. The CLI exposes `ingest`, `sync`, `sessions link`, and `spool prune`. The API exposes meta, segment, complete, links, release, and purge.

Route and scope detail lives in [http-api.md](http-api.md). Bundle layout detail lives in the [format README](../format/README.md). User procedures live in the [user sessions guide](../user/sessions.md).

## Failure behavior

Bad native transcripts fail capture with `CaptureError::BadNative`. Cursors past the transcript end fail with `CursorBeyondEnd`. `sync --dry-run` prints the plan and writes nothing. Four retries per entry per run still obey the backoff cap.

Over-cap segment bodies answer 413 from the API layer. Malformed redact rules fail upload with an invalid error. Foreign segment bytes keep the queue entry and exit 2.

A repository admin can release quarantine. Purge and delete decrement refcounts and drop indexes.

## Verification

Capture tests compare each adapter against golden fixtures. `cwd_attribution` tests prove the workdir privacy rule. Format tests cover parsing, segments, and fixtures.

Ingest tests cover trailer merges, claim merges, and backfill. Rescan tests cover site rules, literals, and meta fields. CLI tests cover spool, upload, hooks, and export or import.

Run the format and capture test suites after adapter changes.

## Related

- [Trace format and redaction](trace-and-redaction.md)
- [Search design](search.md)
- [HTTP API conventions](http-api.md)
- [Repositories](repositories.md)
- [Storage and database design](storage-and-database.md)
- [Format specification](../format/README.md)
- [User sessions guide](../user/sessions.md)
