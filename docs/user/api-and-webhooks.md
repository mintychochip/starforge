# API and webhooks

`/api/v1` accepts `Authorization: Bearer <token>`: `GET /user`, `POST /user/repos` (with `"readme": true` for a
first commit), `GET /repos/{owner}/{repo}` (including `archived`),
`PATCH /repos/{owner}/{repo}` (`{"refs_for_access": "anyone_with_read" | "members"}` — who may
push `refs/for/*`, maintain+), and
`GET`/`PUT`/`DELETE /repos/{owner}/{repo}/collaborators[/{handle}]`. Reads of a renamed repository answer `301`
with the new location.
`GET`/`POST /user/keys` and `DELETE /user/keys/{id}` manage the caller's SSH keys (the same keys as **Settings → Keys**); `GET`/`POST /repos/{owner}/{repo}/keys` (with `"read_write"`) and `DELETE /repos/{owner}/{repo}/keys/{id}` manage that repository's deploy keys (admin only; below-threshold callers get `403`, non-readers `404`; archived repositories refuse adds). Key lists carry `id`, `title`, `algorithm`, `fingerprint`, and (for deploy keys) `read_write`.
Errors use `{"error": {"code", "message"}}`.
`POST /api/v1/oauth/revoke` (form body `token=<value>`, RFC 7009) revokes the access
or refresh token whose SHA-256 hash matches and always answers `200`, even for
unknown or already-revoked tokens.
The whole API is described by an OpenAPI 3.1 document generated from the code
with [utoipa](https://github.com/juharris/utoipa) and served unauthenticated at
`GET /api/v1/openapi.json` (every route in the router appears in `paths`, with
request/response schemas and the shared error envelope, and bearer auth is
declared as `bearer_auth`).

Repository webhooks (`/{owner}/{repo}/settings/hooks`, maintain access and
up) subscribe to event types `push`, `trail`, `review`, `check`, and
`session` (empty means all; unknown names are `422` on create). The secret
shows once at creation and rests sealed under the server key.

Every delivery is `POST` with these headers:

- `Content-Type: application/json`
- `User-Agent: starforged/<version>`
- `X-Starforge-Event: <event>`
- `X-Starforge-Delivery: <delivery id>` (stable across retries of one job; new on redelivery)
- `X-Starforge-Signature-256: sha256=<lowercase hex HMAC-SHA256 of the exact body>`

The body is one envelope:

```json
{"event": "trail", "action": "updated", "cause": "review_requested",
 "at": "2026-11-05T10:00:00Z",
 "repository": {"owner": "alice", "name": "proj", "full_name": "alice/proj",
                "url": "https://forge.example/alice/proj"},
 "sender": {"handle": "alice"},
 "trail": {"number": 12, "title": "Faster sync", "state": "open", "ready": false,
           "author": "alice", "url": "https://forge.example/alice/proj/trails/12"}}
```

`action` and `cause` are always present (string or `null`); `sender` is
`null` for system-originated events; exactly one subject key matches
`event`. Verify a delivery with e.g. (openssl prints `(stdin)= <hex>`,
while the header carries `sha256=<hex>`):

```sh
sig=$(echo -n "$body" | openssl dgst -sha256 -hmac "$secret")
[ "$sig" = "(stdin)= ${header#sha256=}" ] # $header is X-Starforge-Signature-256
```

The five events, with their subjects:

- `push` (`action`/`cause` null): one per `refs/heads/*` create, update,
  and delete plus tag pushes, with `ref`, `before`, `after`, `created`,
  `deleted`, and `pusher`. `refs/for/*` proposals and server-internal refs
  never emit push.
- `trail`: `opened` on create; `ready` when the flag flips false to true;
  `merged` when the last open change merges (a completing merge emits only
  `merged`); `closed` on close; otherwise `updated` with a `cause`
  (`edited`, `ready_cleared`, `reopened`, `labeled`, `unlabeled`,
  `assigned`, `unassigned`, `review_requested`, `review_request_removed`,
  `change_opened`, `revision_pushed`, `change_merged`, `change_closed`,
  `change_reopened`, `session_linked`, `session_unlinked`). The subject carries `number`, `title`, `state`,
  `ready`, `author`, and `url`, plus `change` (`k`, `revision`) when a
  change caused the event.
- `review`: `submitted` on every review, `dismissed` on explicit dismissal
  or automatically when a new revision lands (`sender` null then). The
  subject carries `id`, `trail`, `change`, `revision`, `verdict`, `state`,
  `author`, and `body`.
- `check` (`action`/`cause` null): one per posted commit status, with
  `sha`, `context`, `state`, `target_url`, `description`, and `creator`.
- `session`: `uploaded` when the lifecycle reaches `complete`,
  `quarantined` when a scan hits, `published` on publish. The subject
  carries identifiers and state only (`ulid`, `uploader`, `agent`,
  `lifecycle_state`, `quarantine_state`, `visibility`) — never titles,
  reasons, or transcript text.

Every attempt writes one row to the delivery log — success, HTTP error,
transport error, timeout, SSRF denial, and corrupt secret alike — holding
the delivery id (stable across retries of one job), the 1-based attempt
number, the exact request headers (signature included, never the secret)
and body, the response status, headers (at most 50, each value cut to
1 KiB), and body (the first 16 KiB), plus the duration in milliseconds from
send to the end of the body. Rows older than 30 days fall out in the hourly
cleanup. The settings page lists the last 20 attempts under each hook with
a link to each attempt's request and response; the API mirrors it at
`GET .../hooks/{id}/deliveries[?limit=]` (1–100, default 20) and
`.../deliveries/{row}`. Reads and mutations need maintain access;
below-threshold readers get `403`, non-readers `404`.

`POST .../deliveries/{row}/redeliver` (maintain, active hook,
non-archived repo; `202 {"delivery_id"}`, or the redeliver form on the
delivery page) replays the stored body as a new delivery — a new id,
re-signed with the current secret, through the same SSRF gate and retry
ladder — and writes one `webhook.redelivered` timeline and audit row.
Inactive hooks and archived repos answer `422`. A hook whose stored
subscription names no known event type receives nothing and renders as
`events: []` with an invalid-subscription flag.

Only `https` URLs are accepted (`http` for localhost); loopback and private
ranges are refused, nothing is redirected, bodies cap at 64 KiB under a
10 s timeout, and failures retry on a 1m/5m/30m/2h ladder before the hook
is marked failed.

Not yet: per-context soft gates, check retries, deployments, and mirrors.

`starforge` (in `crates/starforge-cli`, MIT OR Apache-2.0) links local agent
sessions to commits and uploads them. `starforge enable` installs git-hook
dispatchers plus agent hooks for the agents it detects under their per-agent config dirs
(Claude Code's `~/.claude/settings.json`, for example), prints every file it
touches together with the agents it configured and the agents it skipped as not
detected, and suggests re-running `starforge enable` after installing an agent
to pick up its hooks — it never creates config for an agent that is not
installed (`disable` removes them from any agent config, whether or not the
agent is still detected); `status` shows the resolved server, hook
markers, spooled sessions, queue depth, and credential hosts; `doctor` checks
git, hooks, spool, credentials, adapters, and server reachability, one
`ok`/`fail` line each. `sessions list`/`show`/`link`/`unlink` manage the
local spool (prefixes resolve when unambiguous); `sync` drains queued uploads.
Spool layout is `<git common dir>/starforge` (`sessions/<ULID>/`, `links.jsonl`,
`queue.jsonl`); linked commits gain a `Starforge-Session: <ULID>` trailer, and
heuristic linking fires once per batch of new session activity. Auth is
`STARFORGE_TOKEN` when set, else `starforge auth login` (device flow) storing
per-host tokens in `~/.config/starforge/credentials.toml` (mode `0600`).
CI tokens (`STARFORGE_TOKEN`) are sent only to the pinned discovery origin:
the server named by the repository's own remote, or by an explicit
`git config starforge.server` — never to a host merely advertised in a
well-known document. Discovery pins the well-known `api_url` to that anchor
origin (origin-only, `https` required except for loopback) and refuses any
other origin; set `git config starforge.server <url>` to trust a different
server explicitly. Redirects are never followed.
Every command honors `--dry-run` (print, don't write) and `--verbose`.
Exit codes: `0` ok, `1` operational error, `2` `sync` finished with items
still queued. Hidden `_hook-prepare-commit-msg`, `_hook-post-commit`, and
`_hook-pre-push` entry points back the installed git hooks.
The CLI finds a server through `GET /.well-known/starforge.json` on the remote's host (or `git config starforge.server` / `starforge.repo`).
`starforge auth login` requests the scopes `repo:read trail:write session:upload`.
`starforge auth login` authenticates the CLI's own API calls only. The git
transport that `starforge trail push`, `trail checkout`, and plain `git push`
use authenticates with the remote's own credentials, and the CLI never hands
its token to git. Use a token in the remote URL (`http://me:<token>@host/…`),
a git credential helper, or an SSH remote.

To enable git pushes after `auth login` with an SSH remote, register your
public key with `starforge auth ssh-key add [<public-key-path>] [--server <host>] [--title <title>]`
(the default key is the first of `~/.ssh/id_ed25519.pub`, `~/.ssh/id_ecdsa.pub`, `~/.ssh/id_rsa.pub`).
It runs a one-time device-flow approval requesting only `repo:write`, posts `POST /api/v1/user/keys`
with the approval token, then revokes the one-time refresh token via `POST /api/v1/oauth/revoke`
and discards both tokens — the stored login token is never replaced or
touched. Point your git remote at the printed SSH URL (`ssh://git@<host>:<port>/<owner>/<repo>.git`)
and `git push` authenticates with the registered key; no token is handed to git.

### Command reference

| Command | Meaning and flags |
|---|---|
| `starforge auth login <server>` | Device-flow login against a server host or URL |
| `starforge auth logout [server]` | Delete stored credentials (default: the single stored host) |
| `starforge auth status` | Show auth status |
| `starforge auth ssh-key add [<public-key-path>] [--server <host>] [--title <title>]` | Register a public key via a one-time `repo:write` approval (enables `git push` over SSH; stored login token untouched) |
| `starforge enable` / `disable` | Install / remove git hooks and agent hooks for detected agents (`enable` skips undetected agents and never creates their config) |
| `starforge status` | Repo, session, and upload status |
| `starforge doctor` | Environment, config, and connectivity checks |
| `starforge sync` | Upload queued sessions (exit `2` while items remain queued) |
| `starforge sessions list` | List local (spooled) sessions |
| `starforge sessions show <ulid>` | Show a session's metadata (unambiguous prefix works) |
| `starforge sessions link <ulid> [--commit <sha>]` | Link a session to a commit (default: `HEAD`) |
| `starforge sessions unlink <ulid> --commit <sha>` | Remove a session's link to a commit |
| `starforge sessions backfill-links [--since <YYYY-MM-DD>] [--dry-run]` | Link historical sessions to commits by activity window and `files_touched` |
| `starforge spool prune [--older-than <days>] [--dry-run]` | Delete local segment/raw blobs for fully uploaded, completed sessions (default 30 days) |
| `starforge sessions publish <ulid> [--repo <owner/repo>]` | Publish a server-side session (public repositories only) |
| `starforge sessions unpublish <ulid> [--repo <owner/repo>]` | Unpublish a server-side session (`published` → `inherit`) |
| `starforge sessions delete <ulid> [--repo <owner/repo>] --yes` | Delete a server-side session and its segments and links |
| `starforge export --repo <owner/repo> [--session <ulid>…] <dir>` | Write a session bundle to `<dir>` (every readable session, or only the repeatable `--session` ULIDs) |
| `starforge import <dir> --repo <owner/repo>` | Upload a bundle's sessions into the target repository |
| `starforge trail list [--state open\|closed\|merged\|all] [--label L] [--assignee H] [--author H] [--has-changes BOOL] [--has-sessions BOOL] [--review-requested H] [--limit 1–100] [--after ID] [--format text\|json]` | List Trails (default state `open`, limit `30`) |
| `starforge trail show <n> [--format text\|json\|agent]` | Show a Trail with its changes and comments |
| `starforge trail create --title T [--body MD \| --body-file PATH] [--format text\|json]` | Create a Trail (`--body` and `--body-file` conflict; `-` reads stdin) |
| `starforge trail comment <n> (--body MD \| --body-file PATH) [--format text\|json]` | Comment on a Trail (exactly one of `--body` / `--body-file`) |
| `starforge trail push [--trail N] [--title T] [--base B] [--topic T] [--remote R] [--format text\|json]` | Push `HEAD` as a change revision (omit `--trail` to create one) |
| `starforge trail checkout <n> [--change C] [--rev R] [--remote R] [--format text\|json]` | Check out a Trail change |
| `starforge trail review <n> (--approve \| --request-changes \| --comment) [--body MD] [--body-file PATH] [--comments JSON\|@path\|@-] [--session ULID] [--change C] [--rev R] [--format text\|json]` | Submit a review (verdict flags are mutually exclusive, exactly one required) |
| `starforge trail merge <n> [--method M] [--change C] [--format text\|json]` | Merge a Trail change (default: `merge` when allowed, else the allowed method) |

`--repo` on `sessions publish`/`unpublish`/`delete` overrides the discovered
`owner/repo`; on `export` it is the required source repository and on `import`
the required target repository (imports never upload without a confirmed
target). A user who cannot read a session cannot export it: the API answers
`404` and the CLI reports `cannot export <ulid>: session not found or not readable`.

**Bundle format.** `export` writes exactly what the API returns to the caller. Round-trip fidelity is at the normalized-event level: bundles are not byte-faithful, and non-normalized uploads gain default fields on round-trip such as `model: null` and zero `usage`:

```text
<dir>/
  bundle.json                              format version 1, server URL, exported_at
  <owner>__<repo>/<ulid>/
    session.json                           the API metadata, as returned
    events.jsonl                           the normalized transcript (via /events)
    segments/<n>.raw.zst                   stored bytes when the API serves raw;
                                           otherwise the re-segmentation of the redacted /events stream
    links.json                             commit links (via /links)
```

`import` uploads each session through the normal upload API (metadata,
re-segmented events, complete), preserving ULIDs and re-creating `cli_claim`
links from `links.json`; a ULID already present in the target repository is
reported `exists` and skipped.
