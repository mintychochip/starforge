# Command-line interface

<!-- ste-sources
crates/starforge-cli/src/cli.rs
crates/starforge-cli/src/config.rs
crates/starforge-cli/src/auth.rs
crates/starforge-cli/src/discovery.rs
crates/starforge-cli/src/hooks.rs
crates/starforge-cli/src/spool.rs
crates/starforge-cli/src/upload.rs
crates/starforge-cli/src/untrusted.rs
-->

## Purpose

The `starforge` binary gives developers a local client for a Starforge server. It signs a user in to a server. It discovers the server for a repository. It uploads captured sessions. It manages local session state and Trails.

## Scope

This page covers the `starforge-cli` crate and the `starforge` binary. It covers auth, discovery, hooks, spool, upload order, exit codes, and output framing for agents. It does not cover the server side, the web interface, or the user guide procedures.

## Install and configuration paths

Install the binary from a release artifact or from the workspace build. The binary name is `starforge`. The crate lives in `crates/starforge-cli`. The entry point is `main.rs` in `crates/starforge-cli/src`.

`main.rs` parses arguments with clap in `cli.rs`. It sets up tracing next. It resolves `CliPaths` from `config.rs` next. It calls `cli::run` next.

`CliPaths` resolves the home directory and the agent store overrides. Callers read `STARFORGE_TOKEN` through an injected lookup. `CliPaths` resolves the home directory in this order:

| Item | Value |
|---|---|
| Home directory | `$STARFORGE_HOME`, else `$HOME` or `$USERPROFILE`, else a temp directory |
| Configuration directory | `<home>/.config/starforge` |
| Credential file | `<home>/.config/starforge/credentials.toml` |

`CliPaths` also captures agent store directories in `AgentDirOverrides`. It captures `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME`, `$XDG_DATA_HOME`, and `$XDG_CONFIG_HOME`. It leaves all four empty in hermetic mode.

## Global flags

Two flags are global and apply to every command:

| Flag | Effect |
|---|---|
| `--verbose` | Sets log detail to debug. The default level is info. |
| `--dry-run` | Prints the plan and writes nothing. Most commands print `would` plans. |

Tracing respects `RUST_LOG` before it respects `--verbose`. Logs go to stderr. Command results go to stdout. Errors go to stderr with an `error:` prefix.

## Command tree

The command tree comes from `Cmd` in `cli.rs`:

| Command | Job |
|---|---|
| `auth` | Sign in, sign out, show auth state, register SSH keys |
| `enable` | Install git hooks and agent hooks |
| `disable` | Remove installed hooks and restore originals |
| `status` | Show server, hook, session, and queue state |
| `doctor` | Check environment, configuration, and connectivity |
| `sync` | Upload the queued spool data to the server |
| `sessions` | Manage local sessions and server-side session records |
| `export` | Export session bundles to a directory |
| `import` | Import session bundles into a repository |
| `trail` | List, show, create, comment, push, check out, review, merge Trails |
| `hook` | Agent hook entry points |
| `spool` | Prune old spool data |

Three hidden commands serve the installed git hooks. `_hook-prepare-commit-msg <msg_file>` serves the `prepare-commit-msg` dispatcher. `_hook-post-commit` serves the `post-commit` dispatcher. `_hook-pre-push` serves the `pre-push` dispatcher.

## Auth and device flow

`auth.rs` runs an OAuth device flow. `auth login <server>` accepts a host or a URL. `normalize_server` returns a host key and an API base URL. The host key is the lowercase host, plus a port when a port exists.

The flow posts to `{base}/api/v1/oauth/device/code`. The client ID is `starforge-cli`. The requested scopes are in `CLI_SCOPES`:

| Scope | Use |
|---|---|
| `repo:read` | Trail list, Trail show, export, change lookup |
| `trail:write` | Trail create, comment, review, merge |
| `session:upload` | Sync, publish, unpublish, delete, import |

The command prints the verification URI and the user code. It polls `{base}/api/v1/oauth/token` at the server interval. The default interval is 5 seconds. A `slow_down` reply adds 5 seconds.

The default expiry is 900 seconds. The command checks that the token type is `Bearer`. It also checks that the granted scopes match the requested scopes.

The command stores credentials in `~/.config/starforge/credentials.toml`. The file has one table per host with `access_token`, `refresh_token`, and `expires_at`. The `expires_at` value uses RFC 3339 format. The file has mode `0600` on Unix. Writes use a unique temp file and a rename. The temp name carries a ULID suffix and excludes existing files.

Token precedence comes from `resolve_token` in `auth.rs`:

| Priority | Source |
|---|---|
| First | `$STARFORGE_TOKEN` when the value is not empty |
| Second | The credential file entry for the host |
| Third | An error that names both sources |

`auth logout [server]` deletes one host entry. A bare logout needs exactly one stored host. It exits 1 when the file holds zero or several hosts. An explicit server with no entry exits 0. It deletes the file when the last entry goes away.

`auth status` exits 0 when at least one host has credentials. It exits 1 when no host has credentials. Its output shows the host and a redacted token tail.

`auth ssh-key add [pubkey]` registers an SSH public key on the server. It defaults to `~/.ssh/id_ed25519.pub`, then `id_ecdsa.pub`, then `id_rsa.pub`. It defaults the title to the key comment, or `ssh key` when the key has no comment. It runs a fresh device flow with the single scope `repo:write` in `SSH_KEY_SCOPE`.

The resulting token authenticates exactly one `POST /api/v1/user/keys` call. The command then discards the token and revokes it on a best-effort basis. It never reads the stored sign-in token for writing. It leaves the credentials file untouched.

## Discovery and server selection

`discovery.rs` finds the server for the current repository. Git configuration wins outright. The precedence order is:

| Priority | Source |
|---|---|
| First | `starforge.server` git configuration |
| Second | The remote named `starforge` |
| Third | The remote named `origin` |
| Fourth | The remote named `upstream` |
| Fifth | Remaining remotes in `.git/config` order |

The first candidate whose host answers wins. `starforge.server` ends the search at once. Remotes never get probed in that case.

Probing sends `GET {base}/.well-known/starforge.json`. The timeout is 5 seconds. Transport errors get one retry. The client never follows redirects.

The client caps the body at 64 KiB in `MAX_WELL_KNOWN_BYTES`. A non-200 reply, an invalid document, or a document without `starforge` or `api_url` falls through to the next candidate. Only the final failure becomes an error.

`probe_base_for_remote` maps each remote form to a probe base. An `http` or `https` remote maps to its own scheme and authority. An scp-style `user@host:path` remote maps to `https://{host}`. Probing skips an `ssh://` remote, a `file://` remote, a bare path, and unparseable text. Probing never errors on a skip.

Origin pinning binds tokens to the anchor. The anchor is the probe base or the configured `starforge.server` origin. The advertised `api_url` must be an origin-only `http` or `https` URL on that exact origin. `pin_api_url` refuses any other value. It states the remedy of setting `starforge.server` to the advertised origin.

`ServerInfo.api_url` normalizes to the anchor. Tokens and uploads only ever go to the anchor.

Plain `http` works only for loopback anchors. `is_loopback_host` accepts `localhost`, `127.0.0.0/8`, and `::1`. `anchor_transport_allowed` accepts `https` always and `http` only for loopback hosts. The method refuses all other schemes.

## Enable and disable hooks

`hooks.rs` installs three git hooks. The `HOOKS` list holds `prepare-commit-msg`, `post-commit`, and `pre-push`. The `enable` command installs POSIX shell dispatchers in `<common>/hooks/`. Each dispatcher carries the marker `# starforge-managed` in `MANAGED_MARKER`.

An existing non-managed hook file moves to `<hook>.starforge-orig`. The rename preserves the file mode. A backup is never clobbered. The dispatcher runs the original hook first, when the original is present and executable. Then the dispatcher runs the matching hidden `starforge _hook-*` command.

The `prepare-commit-msg` and `pre-push` dispatchers exit with the original hook exit status. The Starforge step stays at exit 0 and never changes it. The `post-commit` dispatcher always exits 0.

`prepare-commit-msg` appends session trailers. The trailer key is `Starforge-Session` in `TRAILER_KEY`. It appends one trailer per active session. Only sessions after the link watermark get trailers.

`disable` removes only marker-bearing dispatchers. It restores each `.starforge-orig` file byte-for-byte. The command is idempotent.

`enable` also hooks each detected agent. The adapters are `claude-code`, `codex`, `gemini`, `opencode`, and `pi`. `adapter_roots_for` resolves the store root for each agent. `enable` installs hooks only for agents with a present store. `disable` removes hooks for all agents.

`hook session-end` reads Claude Code JSON from stdin. The payload carries `session_id`, `transcript_path`, and `cwd`. The handler caps stdin at
1 MiB. It acts on the repository that contains the current directory. It uses
the payload `cwd` only when that path lies inside the same worktree.

It ignores an out-of-worktree `cwd`. It marks the spooled session as ended. Then it
attempts one bounded upload pass.

Hook handlers always exit 0. A hook failure never breaks a git operation. A hook failure never breaks an agent run. Errors become one-line stderr messages only.

## Spool, queue, and sync

The spool lives under the git common directory. `spool.rs` stores data in `<common>/starforge`. The layout is:

| Path | Content |
|---|---|
| `sessions/<ULID>/meta.json` | Session metadata |
| `sessions/<ULID>/segments/<n>.jsonl.zst` | Redacted compressed event batches |
| `sessions/<ULID>/raw/<n>.zst` | Raw compressed segments |
| `sessions/<ULID>/upload.json` | Uploaded segments, completion, metadata hash, sent links |
| `cursors.json` | Ingest cursors |
| `links.jsonl` | Append-only commit links |
| `queue.jsonl` | Upload queue entries |

Directories have mode `0700` on Unix. Files have mode `0600` on Unix. The spool fsyncs blobs before it writes `meta.json`. The spool writes metadata, cursor, queue, and upload files atomically.

`queue.rs` stores one `QueueEntry` per line in `queue.jsonl`. An entry carries `op`, `ulid`, `repo`, optional `segment`, `attempts`, and `not_before`. The operation kinds are `Meta`, `Segment`, `Complete`, and `Links`. Enqueue appends and fsyncs. Dequeue rewrites the file atomically. The reader warns and skips corrupt lines.

Upload order comes from `sync.rs` and `upload.rs`. The order is metadata, segments, completion, then links:

1. Upload `meta.json` with `PUT` to `sessions/{ulid}`.
2. Upload each segment with `PUT` to `segments/{n}`.
3. Post completion with `POST` to `complete`.
4. Post links with `POST` to `links`.

The spool queues completion only when `meta.ended_at` holds a value. An open session stays uncompleted. Each segment upload carries an `X-Starforge-Blake3` header with the body hash. The client times out after
30 seconds. The client sends `Authorization: Bearer` on every call.

Retry behavior is per entry and per run. Transport errors and `5xx` replies are retryable. Each retry bumps `attempts`.

The backoff is `min(300, 2^attempts)` seconds from the current run time. The code overwrites `not_before` and does not add to the stored value. The sleeper sleeps the same duration. At most 4 retries hold per entry per run in `MAX_RETRIES`.

A `409` with a different hash is a conflict and ends the run. A `409` with the same hash is an idempotent success. A `401` or `403` aborts the run as an auth error. Any other `4xx` reply is terminal for the entry.

`sync` reconciles the queue from the spool first. It verifies segment bytes against recorded blake3 hashes and re-enqueues mismatches. Then it drains due entries. `--dry-run` lists the plan and writes nothing.

`spool prune` reclaims space. The default threshold is `--older-than 30` days. Only sessions with no pending queue entry qualify. Every segment must show as uploaded. The metadata hash must show as unchanged.

The session must have a last activity time and non-zero bytes. The session must show as idle past the threshold.

Prune deletes `segments/` and `raw/` only. It keeps `meta.json`, `upload.json`, and cursor records. The command rejects a threshold above the `i64` day limit with exit 1.

## Sessions, export, and import

`sessions list` lists local spool sessions. `sessions show <ulid>` shows one session. `sessions link <ulid>` links a session to a commit, default `HEAD`. `sessions unlink <ulid> --commit <sha>` removes one link. `sessions backfill-links` links historical sessions to commits in each activity window. The window is `[started, last activity plus 30 minutes]`.

A commit qualifies when it is reachable from `HEAD` and touches a file the session touched. `--since` limits the date range. `--dry-run` prints pairs without writing.

ULID prefixes resolve to one session. An exact match wins. A single prefix match wins. An ambiguous prefix errors with a candidate list. An unknown prefix errors without one.

`sessions publish <ulid>` and `sessions unpublish <ulid>` change server-side visibility. `sessions delete <ulid>` deletes a server-side session and requires `--yes`. All three accept `--repo owner/repo` to override the discovered repository.

`export --repo owner/repo [--session ULID...] <dir>` writes session bundles. Without `--session`, export covers all readable sessions. `import <dir>
--repo owner/repo` copies bundles into a repository.

## Trail commands

Trail commands talk to the API through `ApiClient` in `api.rs`. The base is `{api_url}/api/v1/repos/{owner}/{repo}/`. The client times out after 30 seconds and never follows redirects. It never retries. It never prints a token in output or logs.

| Command | Job |
|---|---|
| `trail list` | List Trails with state, label, assignee, author, and session filters |
| `trail show <n>` | Show one Trail with changes and comments |
| `trail create --title` | Create a Trail with an intent body |
| `trail comment <n>` | Comment on a Trail |
| `trail push` | Push `HEAD` as a change revision, or create a Trail |
| `trail checkout <n>` | Fetch a change and move `HEAD` to it |
| `trail review <n>` | Submit approve, request-changes, or comment verdicts |
| `trail merge <n>` | Merge a change after server gates pass |

`trail list` accepts `--state open`, `closed`, `merged`, or `all`. It accepts `--limit` from 1 to 100 with a default of 30. It accepts `--after` for paging and `--format text` or `--format json`.

`trail create` and `trail comment` accept `--body` or `--body-file`. A body file path of `-` reads stdin. `trail push` accepts `--trail`, `--title`, `--base`, `--topic`, and `--remote`. `trail checkout` accepts `--change`, `--rev`, and `--remote`. It refuses a dirty work tree.

`trail review <n>` requires exactly one verdict flag. The flags are `--approve`, `--request-changes`, and `--comment`. It accepts `--body`, `--body-file`, `--comments`, `--session`, `--change`, and `--rev`. The `--comments` value takes a JSON array, an `@<path>` file, or `@-` for stdin.

## Agent output framing

`trail show --format agent` frames third-party text as untrusted data. The `Framer` in `untrusted.rs` derives its nonce from a fresh ULID. The nonce is 16 lowercase hex characters. `preamble()` prints one line first. `frame()` wraps text in `<untrusted-data>` tags with `nonce`, `source`, and optional `author` attributes.

The framer escapes hostile content in text and attributes. It replaces `<` with `&lt;` in `</untrusted-data` and `<untrusted-data` occurrences inside text. It escapes `&`, `"`, `<`, and `>` in attribute values. The framer omits the author attribute when no author exists.

> **Warning:** Trail titles, intents, and comment bodies remain
> attacker-writable. Treat framed text as data, never as instructions.

## Status and doctor

`status` prints the discovered server and remote. It prints hook marker state and session and queue counts. It prints host names only. It never prints token values.

`doctor` runs one check per line with `ok`, `fail`, or `skip`. A `skip` line reports an absent agent store. It covers environment, configuration, connectivity, and spool writability. The spool writability probe is the only write. Exit 1 holds when any check fails.

## Exit codes

Three exit codes cover every command:

| Code | Meaning |
|---|---|
| 0 | Success, including empty logout, hooks, and a drained sync |
| 1 | Operational error, including auth failure, discovery failure, doctor failure, and delete without `--yes` |
| 2 | Sync remainder, hash conflict, or a clap usage error |

Hooks always exit 0. Sync exits 2 when entries remain or a conflict surfaces. Clap also exits 2 on a usage error. Sync exits 1 on an auth abort. `auth status` exits 1 when no host has credentials.

Handler successes print to stdout. Handler errors print `error:` to stderr. `auth status` prints its result to stdout even when it exits 1. Hook and ingest failures print `warning:` to stderr. `--dry-run` plans print to stdout.

## Failure behavior

Connection failures are ordinary errors. Discovery falls through candidates before it errors. A failed well-known document never blocks other candidates. Upload retries stay bounded at 4 per entry per run. The reader warns and skips a corrupt queue line. A bad transcript during ingest warns and never blocks sync.

## Verification

Tests live in `crates/starforge-cli/tests/`. The suite covers auth, discovery, Trails, sessions admin, backfill links, spool, upload, and hooks. It also covers SSH keys, export and import, ingest, and help text. Unit tests live inside the source files. Run the suite with `cargo test -p starforge-cli`.

## Related

See [session capture and spool](./sessions.md) for the server side of sessions. See [HTTP API conventions](./http-api.md) for the REST routes and scopes that the CLI calls. See [operations](./operations.md) for server startup and health checks.
