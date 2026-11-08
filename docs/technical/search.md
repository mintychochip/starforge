# Search

## Purpose

The search layer answers Trail and session text queries without a full database scan. It also searches repository code through `git grep` at one commit.

The index ranks nothing. The database owns every result. Each hit returns to the database for a permission check before the caller sees it.

## Scope

This page covers the Tantivy index in `crates/starforged-index`. It covers document feeding and querying in `Core`. It covers code search in `crates/starforged-git/src/grep.rs`.

Read [sessions.md](sessions.md) for session capture and read rules. Read [trails.md](trails.md) for Trail fields and mutations. Read [operations.md](operations.md) for startup, jobs, and the site-admin rebuild action.

## Design

One Tantivy index holds two document kinds. `doc_kind` separates Trail documents from event documents. Only `crates/starforged-index` depends on Tantivy.

`SearchIndex` holds one writer behind a mutex. It holds one reader behind a read lock. Every mutation stages on the writer. `commit` flushes staged changes and reloads the reader.

The schema mixes exact fields with free text. Keyword fields use the raw tokenizer. Numeric fields use fast indexed storage. Three text fields carry stored snippets.

| Field | Type | Purpose |
|---|---|---|
| `doc_kind` | keyword | `trail` or `event` |
| `repo_visibility` | keyword | `public`, `internal`, or `private` |
| `state` | keyword stored | Trail state |
| `agent` | keyword | Session agent name |
| `models` | keyword | Session model identifiers |
| `commits` | keyword | Linked commit identifiers |
| `repo_id` | i64 | Repository identifier |
| `ts` | i64 | Update time or event time |
| `trail_id` | i64 | Trail identifier |
| `author_id` | i64 | Author identifier |
| `session_id` | i64 | Session identifier |
| `seq` | i64 | Event sequence number |
| `uploader_id` | i64 | Uploader identifier |
| `published` | i64 | Publish flag as `0` or `1` |
| `quarantined` | i64 | Quarantine flag as `0` or `1` |
| `title` | text stored | Trail title |
| `body` | text stored | Trail intent plus comments |
| `text` | text stored | Event text |

`TrailDoc` carries a title, intent, and all comment bodies. `EventDoc` carries message text, tool names, and file paths. Tool inputs and tool outputs never enter the index.
Reasoning blocks and tool results produce no document.
The writer heap is 50 MB.

`visibility_of` maps unknown values to `private`. A stale schema can never widen visibility. Session models index as `[]` when stored JSON parses as invalid.

Indexing runs through the job queue. Mutations enqueue jobs and never wait for indexing. `enqueue_index` logs queue failures and swallows them.

| Job | Effect |
|---|---|
| `IndexTrail` | Replaces one Trail document |
| `IndexSessionEvents` | Replaces all events of one session |
| `IndexRepo` | Re-indexes every document of one repository |
| `DropSessionDocs` | Removes one session document set |
| `RebuildIndex` | Wipes and rebuilds the whole index |

`rebuild_search_index` clears the index and walks every live repository. Trail listing pages 1000 rows at a time. Only `complete` sessions enter the index.

Query results sort by `ts`, newest first. Text queries tokenize with unicode lowercase. Splits break on non-alphanumerics. Query operators match as literal words.

| Limit | Value |
|---|---|
| Default `per_page` | 20 |
| Maximum `per_page` | 50 |
| Maximum `page` | 1000 |
| Candidates per round | 3 times page size |
| `MAX_EVENTS_PER_SESSION` | 3 |
| Snippet cap | 500 chars |
| Code query length | 1 to 256 chars |
| `GrepLimits.max_matches` | 200 |
| `GrepLimits.max_files` | 50 |
| `GrepLimits.max_line_chars` | 500 |
| `GrepLimits.timeout` | 10 s |
| `GrepLimits.max_output_bytes` | 1 MiB |

`search_trails` fills each page from candidate rounds. Each hit passes `recheck_trail` against the database. `search_sessions` groups events by session. Each group passes `recheck_session` once per session.

The index pre-filters by viewer scope. The database re-check decides every return. A stale hit hides instead of leaking. Title edits after indexing never leak through snippets.

Session snippets carry byte ranges for highlights. Templates escape text with askama escaping. `<mark>` wraps ranged slices only. Session snippets re-read kind names from blobs.

```mermaid
flowchart LR
    A[Query] --> B[Scope filter]
    B --> C[Index candidates]
    C --> D[Database re-check]
    D --> E[Snippet page]
```

## Interfaces

`Core::search_trails` and `Core::search_sessions` take a viewer and a `SearchQuery`. `SearchQuery` carries `q`, `repo`, `agent`, `model`, `author`, `from`, `to`, `commit`, `page`, and `per_page`. Both return `Page<T>` with items, page, `per_page`, and `has_more`.

`parse_page` bounds page and `per_page`. `parse_range` validates the inclusive date range. `parse_commit` accepts 7 to 40 hex chars. Bad input answers `CoreError::Invalid` with HTTP 422.

`Core::code_search` searches one repository. Results carry the ref name, commit, matches, and a truncated flag. Each match carries path, line, and text.

| Route | Purpose |
|---|---|
| `GET /api/v1/search/trails` | Trail text search |
| `GET /api/v1/search/sessions` | Session event search |
| `GET /api/v1/repos/{owner}/{repo}/search/code` | Fixed-string code search |

API handlers require `repo:read` for tokens. Anonymous callers remain valid readers. Session search sends `X-Robots-Tag: noindex`. The code route needs read visibility on the repository.

`starforged index rebuild` wipes and rebuilds from the database and blobs. The command prints trail and event counts. The site-admin `RebuildIndex` job does the same work while the server runs.

## Failure behavior

`open_or_create_fresh` recreates a missing or corrupt directory empty. Schema drift counts as corrupt. Startup reads the fresh flag and enqueues a rebuild job.

The server never refuses to start because of the index. `open_or_create` leaves a locked directory untouched. `stats_in_dir` opens read-only and never recreates a directory.

Running `starforged index rebuild` while the server runs fails with a lock message. The message tells the operator to stop the server. The message offers the site-admin rebuild action.

Missing Trails index as no-ops. Missing or deleted sessions drop their documents. Missing or deleted repositories drop their documents. Non-`complete` sessions drop their documents.

Quarantined sessions index with quarantine state. Publication and quarantine clauses filter event queries. The uploader and repository admins keep access. Every other viewer sees nothing.

An unreadable `repo` filter returns an empty page. Existence stays undiscoverable. An unknown `author` handle also returns an empty page.

Code search never falls back to another branch. A missing default branch returns empty matches. An empty repository returns empty matches. Archived repositories stay searchable. Unreadable repositories answer `NotFound`, never `Forbidden`.

`git grep` uses `--fixed-strings` with `-I`. A query starting with `-` reaches grep as literal text. Binary files never match. Exit code 1 means no matches.

## Verification

Unit tests live in `crates/starforged-index/src/lib.rs`. Integration tests live in `crates/starforged/tests`. Search security tests cover permission re-checks and quarantine hiding. Snippet tests cover escaping behavior.

Run `cargo test -p starforged-index` for schema and query tests. Run `cargo test -p starforged --test search_index` for feeding tests. Run `cargo test -p starforged --test code_search` for grep tests.

## Related

Read [sessions.md](sessions.md) for session read rules and quarantine. Read [trails.md](trails.md) for Trail mutation and timeline rules. Read [operations.md](operations.md) for jobs, health, and startup recovery.

Read [trace-and-redaction.md](trace-and-redaction.md) for redaction before indexing. Read [security.md](security.md) for permission and abuse controls.

<!-- ste-sources
crates/starforged-index/src/lib.rs
crates/starforged-core/src/search.rs
crates/starforged-git/src/grep.rs
crates/starforged-api/src/search.rs
crates/starforged/src/index_cmd.rs
crates/starforged-core/src/jobs.rs
-->
