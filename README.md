# Starforge

A self-hostable git forge built around agent-assisted development. Milestone M0 provides git hosting over
HTTP, local accounts, personal access tokens, user-owned repositories with collaborators, code and history
browsing, and a small REST API. Trails and agent session traces arrive in M1–M2; see
`docs/superpowers/specs/2026-11-03-starforge-design.md`.

## Requirements

- git 2.38 or newer
- Rust 1.99.1 (pinned in `rust-toolchain.toml`; rustup installs it automatically)

## Run it

```bash
cargo build --release
./target/release/starforged init --data-dir ./data
printf 'a long password\n' | ./target/release/starforged admin user create --handle me --admin --password-stdin
./target/release/starforged serve
```

Open http://127.0.0.1:3000, sign in, create a token under **Settings → Tokens** and a repository under **New repository**, then:

```bash
git push http://me:<token>@127.0.0.1:3000/me/<repository>.git main
```

## Configuration

`starforged init` writes `starforged.toml`:

| Key | Meaning |
|---|---|
| `server.http_addr` | Address to bind, e.g. `127.0.0.1:3000` |
| `server.base_url` | Public URL without a trailing slash; `https://` turns on secure cookies |
| `database.url` | Empty for SQLite in the data directory, or a `postgres://` URL |
| `database.auto_migrate` | Migrate the schema at startup (default `true`) |
| `storage.data_dir` | Repositories, SQLite database, and runtime files |
| `security.secret_key` | 64 hex characters; losing it logs everyone out |
| `registration.mode` | Who can sign up: `invite` (default; invite links only), `open`, or `domains` |
| `registration.allowed_domains` | Email domains that `domains` mode accepts, e.g. `["example.com"]` |
| `mail.url` | Empty for no email; `smtp://user:pass@host:587` (STARTTLS), `smtps://user:pass@host:465`, or `file:///dir` (writes `.eml` files) |
| `mail.from` | Sender, e.g. `Starforge <forge@example.com>` |

Any key can be overridden with an environment variable such as `STARFORGE__SERVER__HTTP_ADDR` or
`STARFORGE__DATABASE__URL`. `STARFORGE_CONFIG` sets the config file path.

## Accounts and email

New instances are invite-only: sign-up needs an invite link from a site admin. Until the admin pages ship, create
accounts with `starforged admin user create`. Set `registration.mode = "open"` to let anyone sign up, or `"domains"`
with `registration.allowed_domains` to accept only addresses at those domains (this mode requires email).

Email is optional. With `[mail]` configured, new accounts confirm their address before they can sign in, the sign-in
page offers "Forgot password?", and invites can be emailed. `smtp://` always uses STARTTLS;
`smtp://localhost:25?tls=none` is accepted only for a mail server on the same machine. Check the settings with:

```bash
./target/release/starforged admin mail test --to you@example.com
```

For local development, `url = "file:///tmp/starforge-mail"` writes each message to that directory instead of sending
it.

Signed-in users manage their display name, email address, password, sessions, and tokens under **Settings**, and
can delete their account there once they own no repositories.

## Repositories

New repositories can start with a README. Each repository has a **Settings** tab for maintainers and admins:
maintainers change the description and the default branch (new clones check it out); admins also change the
visibility, manage collaborators, rename, archive, and delete.

- **Renaming** keeps the old name working: pages, `git clone`/`fetch`/`push`, and API reads that use it are
  redirected to the new name, as long as the person asking can read the repository. A repository created with an
  old name takes the name over.
- **Archived** repositories stay readable and refuse pushes until they are unarchived.
- **Deleted** repositories disappear at once. Their owner can restore them from **Settings → Repositories** for 7
  days; then a daily job removes them for good.

The code views show branches, tags, comparisons between two refs (`/{owner}/{repo}/compare/{base}...{head}`), and
syntax-highlighted files with linkable line numbers (`#L42`). After each push, a background job runs
`git maintenance run --auto` for the repository.

## Site administration

Admins manage the instance under **Admin** (`/admin`): instance counts with the sign-up mode and mail
status, then **Users**, **Invites**, **Repositories**, and **Jobs** tabs. Users can be created
(pre-verified), suspended, granted or revoked admin, deleted, or issued a password reset; invites are
created and revoked; deleted repositories are restored or purged before the daily job removes them for
good; failed background jobs are retried or dropped.

Every `/admin` page and action answers 404 to anyone who is not a site admin, so the area is
indistinguishable from a missing page. Guards refuse to suspend or delete yourself, and the last active
admin cannot be suspended, demoted, or deleted. Each admin action is recorded in the audit log.

## API

`/api/v1` accepts `Authorization: Bearer <token>`: `GET /user`, `POST /user/repos` (with `"readme": true` for a
first commit), `GET /repos/{owner}/{repo}` (including `archived`),
`PATCH /repos/{owner}/{repo}` (`{"refs_for_access": "anyone_with_read" | "members"}` — who may
push `refs/for/*`, maintain+), and
`GET`/`PUT`/`DELETE /repos/{owner}/{repo}/collaborators[/{handle}]`. Reads of a renamed repository answer `301`
with the new location.
Errors use `{"error": {"code", "message"}}`.

## Trace format and redaction

`docs/format/` is the normative spec for Trace Format v1: session metadata, normalized
events, and the JSON Schemas uploads are validated against. Two crates implement it:
`starforge-format` (encoding, segmentation, agent-output delimiters) and
`starforge-redact` (secret scrubbing), both MIT OR Apache-2.0.
Redaction replaces matches with `[redacted:<detector>]` using the built-in detectors
(private-key, cloud-credential, known-token, credentialed-url, connection-string,
authorization, high-entropy, plus optional email/phone PII), extended per repository
with `.starforge/redact.toml`. The rule-set fingerprint travels with each session, so a
high-confidence hit on the server's re-scan quarantines the upload until a repo admin
releases or purges it.

## Capture adapters

`starforge-capture` (MIT OR Apache-2.0) reads native agent transcripts into normalized
Trace Format v1 events without redaction: five adapters cover Claude Code, Codex CLI, Pi,
OpenCode (SQLite `opencode.db` plus file-storage layouts), and Gemini CLI. omp transcripts
parse through the Pi adapter and Antigravity stores through the Gemini adapter, both
best-effort and always reported `unverified` (`adapter_version_verified == false`).
Adapters take explicit root paths (no `$HOME`, no clock), resume with stable cursors, and
preserve unmapped native fields so re-normalization stays lossless; raw-transcript storage
defaults ON for new repos. Test fixtures are synthesized in the native shape — each fixture
directory carries a `SYNTHESIZED.txt` noting the native source it mimics.

## CLI

`starforge` (in `crates/starforge-cli`, MIT OR Apache-2.0) links local agent
sessions to commits and uploads them. `starforge enable` installs git-hook
dispatchers plus the Claude Code and Pi agent hooks and prints every file it
touches (`disable` removes them); `status` shows the resolved server, hook
markers, spooled sessions, queue depth, and credential hosts; `doctor` checks
git, hooks, spool, credentials, adapters, and server reachability, one
`ok`/`fail` line each. `sessions list`/`show`/`link`/`unlink` manage the
local spool (prefixes resolve when unambiguous); `sync` drains queued uploads.
Spool layout is `<git common dir>/starforge` (`sessions/<ULID>/`, `links.jsonl`,
`queue.jsonl`); linked commits gain a `Starforge-Session: <ULID>` trailer, and
heuristic linking fires once per batch of new session activity. Auth is
`STARFORGE_TOKEN` when set, else `starforge auth login` (device flow) storing
per-host tokens in `~/.config/starforge/credentials.toml` (mode `0600`).
Every command honors `--dry-run` (print, don't write) and `--verbose`;
`sessions publish`/`unpublish`/`delete`, `export`/`import`, and `trail` are
not in M1c and exit non-zero. Exit codes: `0` ok, `1` operational error,
`2` `sync` finished with items still queued.

## Session capture and ingest

`starforge sync` uploads spooled sessions to `/api/v1/repos/{owner}/{repo}/sessions/{ulid}` with a
`session:upload` token (`starforge auth login` prints a device code the browser approves at
`/oauth/device`). The uploader needs write access to the repository; anything else answers `403`.
Four calls make an upload: `PUT` metadata (Trace Format v1 JSON, path ULID matching `meta.id`),
`PUT` each segment as zstd bytes with an `X-Starforge-Blake3` header naming their hex digest,
`POST .../complete` with an empty `{}` body, and `POST .../links` with commit SHAs to claim.
Re-sending identical bytes is a safe no-op (`200`); a changed segment at a taken number answers
`409` with exactly `{"hash": "<stored hex>"}`, and new content on a completed session is `422`.
Segments cap at 16 MiB (decompression is bounded at 256 MiB against bombs); quotas are
500 MiB per user per hour, 5 GiB stored per user, and 20 GiB stored per repository.

Every accepted segment is re-scanned server-side with `built_in < repo < site` rules (repo rules
come from `.starforge/redact.toml`, site rules from `[sessions] site_redact_toml`). A
high-confidence hit — private keys, cloud credentials, known tokens, repo literals — quarantines
the session without rejecting the bytes; low-confidence counts merge into the session's
`redaction_counts`, and the first hit wins. Quarantined sessions wait in the admin queue
(`GET .../sessions?quarantined=true`) until a repo admin releases (`POST .../release`) or purges
them (`POST .../purge`, which drops the session, its segments and links, and dereferences the
blobs). Segment bytes live content-addressed under the blob directory (default `data/blobs`
inside the data directory) at `<hash[0..2]>/<hash>`, refcounted across sessions; zero-ref files
are swept by the hourly cleanup job. The CLI learns commit links from `Starforge-Session: <ULID>`
trailers found by the post-push scan, merged with its own claims.

Not yet: raw native-slice upload — the CLI spools raw slices but never
sends them, so `raw_blob_hash` stays empty and adapter re-normalization has to wait for the M1f
follow-up — refresh-token rotation (M3), and per-token rate limiting (M5).

## Sessions in the UI

Every session opens at `/{owner}/{repo}/sessions/{ulid}`: header metadata (agent, models,
branch, usage, redaction fingerprint), the event transcript in stored order (200 per page,
`?page=N`, `#turn-<seq>` deep links), and a `Download JSONL` link carrying the same redacted
bytes the page renders. Prose renders as sanitized Markdown inside a visible untrusted frame —
with `<img>` elements stripped entirely (even relative ones), so an image in an
attacker-influenced transcript can never phone home when viewed; repository Markdown
(READMEs, blobs) keeps images. Tool input, tool output, diffs, and unknown event kinds
render as escaped text in collapsed
`<details>` blocks, and `[redacted:<id>]` markers show verbatim. Tool calls expand inline —
there is no JavaScript on the page, so nothing fetches or executes. The JSON API mirrors the
viewer: `GET /api/v1/repos/{owner}/{repo}/sessions/{ulid}` (metadata plus commit links) and
`GET .../sessions/{ulid}/events?page=N`.

Quarantined sessions show a banner (reason plus detail) over the full transcript to the uploader
and repo admins, with release, purge, and rescan buttons; everyone else gets `404`, so ULIDs
stay undiscoverable. Commit pages list a Sessions panel and blame pages list session chips —
both only for sessions the viewer may read, never locked placeholders. Publishing flips a
session to `published` on public repositories (repo `maintain` or above), which makes it
readable to strangers; unpublish flips it back to `inherit`. Delete removes the session, its
segments, and its links. Every web form carries a `_csrf` token; the API uses Bearer tokens
and answers `401` without one.

The viewer, download, and blame pages (the three surfaces rendered from
attacker-influenced content) carry a strict Content-Security-Policy
(`default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'self'`) as defense in
depth; other pages use the site default.

Not yet: a repository session index (commit panels and direct ULID links are the discovery
paths), blame syntax highlighting, and the §10.2 transcript/diff split view.

## Trails

Trails are per-repo numbered issues: `/{owner}/{repo}/trails` lists them (`?page=N`, 30 per page,
`?state=open|closed`, `?label=`, `?assignee=`), `.../trails/new` opens one, and
`.../trails/{number}` shows the detail — description, comments, labels, assignees, and the
timeline — with triage-gated close/reopen, label, assignee, and ready controls. Titles and
descriptions render as sanitized Markdown (labels are `[a-z0-9-_.]`, lowercase, max 50 chars);
creating and commenting need read access, everything curatorial needs triage, comment edits
belong to the author or an admin, and strangers get `404` so trail numbers stay undiscoverable.
Every web form carries a `_csrf` token.

The JSON API mirrors the pages: `GET`/`POST /api/v1/repos/{owner}/{repo}/trails` (keyset
`?after=&limit=`, `next_after` cursor), `GET`/`PATCH .../trails/{n}` (title, intent, ready,
state; `merged` is refused — only the merge path may set it), `GET`/`POST
.../trails/{n}/comments` plus `PATCH .../comments/{id}`, and `POST`/`DELETE .../labels` and
`.../assignees` (assignees must already be repo members). Reads need `repo:read`; every
mutation needs `trail:write` on top, so a curator token carries `"repo:read trail:write"`.
Errors use the shared `{"error": {"code", "message"}}` envelope.

Not yet: checks, gate rules, and server-side merge (M2c); `trail` CLI commands (M2d);
trail deletion (close covers M2a).

## Changes and reviews

Push to `refs/for/<branch>` to propose work without moving the branch — the `refs/for`
ref itself is never stored. `refs/for/<branch>/<topic>` names the thread; without a topic
the pusher's handle is used, so re-pushing the same `<branch>/<topic>` appends a revision
to your open change (re-pushing the same SHA is a no-op), while another user or topic
starts a fresh change:

```bash
git push origin HEAD:refs/for/main/feature-x
git push -o trail=3 -o title="Faster sync" origin HEAD:refs/for/main
```

`-o trail=<n>` files the change under that trail (default: a new trail titled from the
tip subject). Duplicate, unknown, or malformed options reject the whole push, and
anonymous pushes are rejected everywhere. Triage can also track an existing branch as a
change from the trail page.

Every change keeps its revisions with diffs (same line- and byte-caps as the compare
page) and a mergeability verdict — `clean`, or `conflict` with the conflicting paths —
recomputed on each revision and each base-branch move. Any reader may review (approve,
request changes, comment) and open file/line threads, but only reviews from writers and
above count toward merge; triage dismisses reviews, the thread author or triage resolves
them, and the creator or triage closes and reopens. Threads anchored at older revisions
are marked outdated. The change page (`/{owner}/{repo}/trails/{n}/changes/{k}`, `?rev=`
selects the revision) shows all of this with role-gated controls; the Merge button stays
disabled — merging lands in M2c.

The JSON API mirrors the page: `GET`/`POST .../trails/{n}/changes` (triage to track a
branch), `GET`/`PATCH .../changes/{k}` (close/reopen; `merged` is refused), `.../state`,
`.../diff`, `.../revisions[/{r}]`, `.../reviews` (`POST .../{id}/dismiss` for triage),
and `.../threads` (`POST .../{t}/resolve`, `.../{t}/comments`). Reads need `repo:read`,
mutations need `trail:write`; strangers get `404` so change numbers stay undiscoverable.

## Development

```bash
scripts/check.sh                      # fmt, clippy, tests on SQLite
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17 via podman or docker
```

## License

See `LICENSE.md`: the server is AGPL-3.0-or-later; the CLI and trace format (from M1) are MIT OR Apache-2.0.
