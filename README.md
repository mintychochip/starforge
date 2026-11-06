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

## Organizations and teams

Organizations share the handle namespace with users and own repositories at `/{org}/{repo}`. Any active
signed-in user can create one from **New organization** (`/orgs/new`); the creator becomes its first owner.
An org has a display name, a description, owners, members, and a **base permission** (`none`, `read`, or
`write`, default `none`) that every member holds on every org repository. The org profile (`/{org}`) is
public and lists the display name, the description, and the repositories the viewer can read; org members
also see member and team links with the member count, plus the base permission.

Owners manage membership in **Members** (`/orgs/{org}/members`): they add existing users directly as
`member` or `owner`, change roles, and remove members. The last owner cannot be removed, demoted, or leave
(the API answers 422). Removing a member also removes them from every team of the org. The member list and
every team page answer 404 to anyone who is not an org member or a site admin, so membership stays private.

**Teams** (`/orgs/{org}/teams`) belong to an org and grant one permission level (`read`, `triage`, `write`,
`maintain`, `admin`) on all of the org's repositories or on a selected set. Team names are 1–64 characters
of letters, digits, spaces, `_`, `.`, and `-`, unique per org ignoring case; team pages live at
`/orgs/{org}/teams/{team}` under the lowercased name with spaces as `-`. Team members must be org members,
and team repositories must be owned by the team's org. Org members can list teams and their members; only
owners change them, from `/orgs/{org}/teams/new` and the team page.

The **effective permission** on a repository is the highest of: site admin, the owner's own repositories,
and org ownership (all `admin`); the org base permission; every team grant covering the repository; the
collaborator grant; and implicit `read` (public repositories, and internal ones for signed-in users). A
repository **member** is a user with an explicit grant — collaborator, covering team, non-`none` base
permission, or ownership. Site admins are not members by that fact alone, and implicit read never counts.
Membership feeds `refs/for` pushes when `refs_for_access` is `members`, unpublished-session visibility, and
the dashboard. Losing a grant — member removal, team deletion, base lowering, transfer away — takes effect
immediately on every surface.

**Transfer** moves a repository to another owner from **Settings → Transfer**
(`/{owner}/{repo}/settings/transfer`). The actor must be a repository admin, and the new owner must be the
actor or an org the actor owns — site admins have no bypass. The old path redirects to the new one for
pages, API reads, and git; team links from the old org drop while collaborators stay.

The API mirrors this at `/api/v1`: `POST /orgs`; `GET`/`PATCH`/`DELETE /orgs/{org}` (deleting needs an
empty org, including soft-deleted repositories inside the grace period, else 422); `GET /orgs/{org}/repos`
and `POST` it to create (owners only; plain members get 403); `GET /orgs/{org}/members` and
`PUT`/`DELETE /orgs/{org}/members/{handle}`; `GET`/`POST /orgs/{org}/teams`;
`GET`/`PATCH`/`DELETE /orgs/{org}/teams/{team}`; `GET /orgs/{org}/teams/{team}/members` with
`PUT`/`DELETE …/{handle}`; `GET /orgs/{org}/teams/{team}/repos` with `PUT`/`DELETE …/{repo}`; and
`POST /repos/{owner}/{repo}/transfer` (`{"new_owner": "<handle>"}`). Reads need the `repo:read` token
scope and mutations need `repo:write`; member-only data answers 404 to outsiders while below-threshold
actors get 403. Every membership or permission change writes exactly one audit row.

Site admins see every org under **Admin → Orgs** (`/admin/orgs`: handle, display name, member and
repository counts, with links) and can view any org's members and teams, but have no extra org-management
powers.

## Site administration

Admins manage the instance under **Admin** (`/admin`): instance counts with the sign-up mode and mail
status, then **Users**, **Invites**, **Repositories**, **Organizations**, and **Jobs** tabs. Users can be created
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
`sessions publish`/`unpublish`/`delete` and `export`/`import` are not in M1c
and exit non-zero. Exit codes: `0` ok, `1` operational error,
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

### Trail page

Every Trail page shares three tabs — Conversation (`.../trails/{n}`),
Changes (`.../trails/{n}/changes`, one row per change with its state and a
gate summary), and Sessions (`.../trails/{n}/sessions`, with the count of
sessions the viewer may read) — plus a header with the intent, labels,
assignees, reviewers, and a gate panel per open change. The panel shows
approvals (have/need), the required checks with their states, conflicts
(mergeability and conflicting paths), and session evidence; viewers with
merge permission also get the merge button with a method selector limited
to the allowed methods, posting to the existing change merge route. The
panel reuses the gate evaluation — there is no separate gate logic — and
the merge re-checks everything server-side, so a stale page authorizes
nothing.

The Conversation timeline merges stored events with derived rows in time
order: linked sessions (one row per readable session linked through a
commit, timed at the later of the upload and the first revision containing
its commit), checks (the latest row per (context, head SHA), because the
checks table upserts, with context, state, description, and an `http(s)` target link), and readable
sentences for every stored `change.*`, `review.*`, and
`trail.session_linked/unlinked` kind. Derived rows are computed per request
and filtered for the viewer.

The Sessions tab groups one section per Trail commit that has a readable
session (newest first), then a "Linked by hand" group, each row showing the
agent name and version, models, title as prompt preview (escaped, 120
characters), token totals, link confidence (`exact`/`heuristic`/`explicit`),
uploader, start time, and a `#turn-<seq_start>` deep link when the commit
link carries a start sequence, with per-group and Trail-wide totals. The
JSON API mirrors it at `GET
/api/v1/repos/{owner}/{repo}/trails/{n}/sessions`. Sessions link two ways:
through commits (a `Starforge-Session: <ULID>` trailer or a CLI commit
claim joins an uploaded session to a commit in the Trail's changes,
whichever side arrives first) or by hand — triage and up may link any
readable same-repo session, and the Trail author may link sessions they
uploaded themselves (at most 50 explicit links per Trail; linking is
idempotent). The API is `POST .../trails/{n}/sessions` with `{"session":
"<ulid>"}` and `DELETE .../trails/{n}/sessions/{ulid}` (both answer the
Sessions JSON); the tab carries link/unlink forms. Every link and unlink
writes a `trail.session_linked`/`trail.session_unlinked` timeline row and
a matching webhook. Every session surface — the tab, the API,
`has_sessions`, the timeline, and the commit Sessions panel — applies the
session read rules for the current viewer, so no title, ULID, or total of
an unreadable session ever reaches them.

Not yet: trail deletion (close covers M2a).

### Trails from the command line (M2d)

`starforge trail` drives a trail end to end from the terminal. Every command
takes `--format text|json` (default `text`); `show` also accepts `agent`, and
`json` prints the pretty-printed response the command acted on:

```bash
starforge trail list --state open
starforge trail show 12
starforge trail show 12 --format agent
starforge trail create --title "Faster sync" --body "Why this exists"
starforge trail comment 12 --body "Needs a test"
starforge trail push --trail 12
starforge trail checkout 12
starforge trail review 12 --approve
starforge trail review 12 --request-changes --comments '[{"path":"a.txt","side":"head","start_line":1,"end_line":2,"body":"nit"}]'
starforge trail merge 12
```

Without `--body`/`--body-file`, `trail review` posts a one-line body restating the verdict ("Approved.", "Changes requested.", or "Commented."), because the server rejects empty review bodies.

`show` prints the header, the intent, one line per change, then — under each
change with any — its reviews (`#id verdict by author on revision R`, with
`(dismissed)` when dismissed, plus the body) and its inline threads
(`#id path:start-end (side, revision R)`, with `resolved`/`outdated` flags,
plus each comment as `author: body`), then the trail comments.
`show --format json` returns `{trail, changes: [{change, status}]}`, where
`change.gates` is the gate report (`passed` plus per-rule results),
`status` the combined commit status, and the change detail keeps its
`reviews` and `threads` (only `files` and `truncated` are stripped).
`--format agent` keeps the same structure and frames every review body
(source `trail #N change K review <id>`) and every thread-comment body
(source `trail #N change K thread <tid> comment <cid>`), each with its
author, in nonce-tagged `<untrusted-data>` blocks. Frame delimiters are
escaped, so a hostile body can neither close nor open a frame, and an agent
reading the trail cannot be steered by attacker-written text it is then
asked to act on (for example by running `trail merge`).

`push` defaults the base to the remote's HEAD branch and the topic to a slug
of the current branch (`--base`/`--topic` override; `--trail N` files the
revision under that trail and `--title` names a new one). After a successful
push it prints `trail #N change K revision R: <url>`; if the server has not
recorded the change within 10 s it prints `pushed <sha>; ...` instead and
still exits `0`. `checkout` creates the branch `trail/<n>/<k>` at the head
(fast-forwarding an ancestor, refusing on divergence and touching nothing),
or detaches at `--rev R` for an immutable revision. Without `--change` the
single open change wins, erroring when there are zero or several — except
`checkout`, which also accepts the only change when none is open, since
inspecting a merged change is legitimate. Without `--method`, `merge` uses
`merge` when allowed, else the single allowed
method. Git authenticates with your own remote configuration — the CLI never
hands its API token to git — so push and fetch use your usual credentials
and prompts. Exits are `0` on success, `1` on any failure; usage errors keep
clap's `2`.

## Finding Trails

Review requests mark the Trails that need eyes. They are per Trail: triage
and up may request any repository member except the Trail's author (at most
10 per Trail; adding twice is a no-op), and the request clears itself when
that user submits any review on any change of the Trail — `review.submitted`
records the clearing, so no extra timeline row appears. The API is
`POST`/`DELETE /api/v1/repos/{owner}/{repo}/trails/{n}/review-requests` with
`{"user": "<handle>"}` (`200` with the updated Trail; unknown, non-member,
and author targets are `422`, non-reader callers `404`, below-triage readers
`403`); the Trail page carries a Reviewers section with add/remove forms.
Every add and remove writes exactly one `trail.review_requested` /
`trail.review_request_removed` timeline row and fans out a `trail`
`updated` webhook with the matching `cause`.

The Trail list filters compose: `?state=open|closed|merged`, `?label=`,
`?assignee=`, `?author=`, `?has_changes=true|false`,
`?has_sessions=true|false`, and `?review_requested=<handle>` (an unknown
handle lists nothing, never `404`), 30 per page with pager links that keep
the filters. `has_sessions=true` keeps Trails with at least one linked
session the viewer may read (through commits or by hand); `false` keeps
the rest. The API and CLI reject any other `has_sessions` value with `422`;
the web list treats other values as no filter.
The API mirrors these as
keyset filters — `GET .../trails?state=&label=&assignee=&author=&has_changes=&has_sessions=&review_requested=&after=&limit=` with a `next_after` cursor
(`has_changes=maybe` and `has_sessions=maybe` are `422`) — and the CLI as
`starforge trail list [--state open|closed|merged|all] [--label=…]
[--assignee=…] [--author=…] [--has-changes true|false]
[--has-sessions true|false] [--review-requested <handle>]`.

The dashboard (`/`, signed in) adds three sections above the repository
list — "Assigned to you" and "Awaiting your review" (open Trails, newest
updated first, at most 20 each) and "Your recent sessions" (your uploads you
may still read, newest first, at most 10). Every row is re-checked against
your current permission, so losing access hides it immediately; anonymous
visitors see the marketing page with no sections.

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
selects the revision) shows all of this with role-gated controls. The merge form
offers the methods the matching gate rules allow and stays disabled until every gate
passes; the server re-checks gates, permission, and method at merge time, so a stale
page authorizes nothing. Gate and conflict failures re-render the change page with `422`.
The page's compare picker (or `?from=<r1>&to=<r2>`, two distinct revisions of the
change) shows the tree diff between those revisions' heads, labeled as such with a
note that it includes base changes when the change was rebased; an unknown revision
is `404`, `from == to` is `422`. In the default revision view, threads anchored on
that revision render inline under their `(path, side, end_line)` diff line; threads
anchored elsewhere — or whose line is absent from the displayed hunks — list below,
marked outdated where they are. Signed-in readers may mark files viewed
(`viewed=1|0`); the mark stores the file's blob at the displayed head, so a later
revision that changes the file resets it while one that leaves it alone keeps it
viewed, and viewed files render collapsed. The viewed toggle, like every other
change form, carries a `_csrf` token; anonymous viewers see no toggles, and archived
repos refuse with `422`.

The JSON API mirrors the page: `GET`/`POST .../trails/{n}/changes` (triage to track a
branch), `GET`/`PATCH .../changes/{k}` (close/reopen; `merged` is refused), `.../state`,
`.../diff[?from=&to=]`, `.../revisions[/{r}]`, `.../reviews` (`POST .../{id}/dismiss` for triage),
and `.../threads` (`POST .../{t}/resolve`, `.../{t}/comments`). Reads need `repo:read`,
mutations need `trail:write`; strangers get `404` so change numbers stay undiscoverable.

### Pending reviews

A signed-in reader holds at most one pending (draft) review per change. Posting a
thread or a thread comment with `"pending": true` attaches the comment to the
actor's draft — created on demand on the change's current revision — instead of
opening a public thread; pending comments, and threads whose only comments are
pending, are visible only to their author (web, API, and therefore CLI). Pending
reviews never count toward gates, never appear in the timeline, and dispatch
nothing. Posting a review converts the actor's draft: the review takes the given
verdict and body at the change's current revision with the draft's comments
attached, writing exactly one `review.submitted` timeline row and one
`review`/`submitted` webhook, clearing the review request and counting toward
gates; without a draft the submit behaves as before. `GET
.../changes/{k}/reviews/pending` returns the actor's draft or `404`;
`DELETE .../changes/{k}/reviews/pending` discards the draft's comments plus the
threads left empty, with no timeline row. Dismissing a pending review is `422`.
On the web the inline comment form offers "Comment" and "Add to review", and a
"Finish your review" panel shows the draft comment count with verdict, body,
Submit, and Discard.

## Commit statuses, gates, and merging

CI pushes per-commit statuses: `POST /api/v1/repos/{owner}/{repo}/statuses/{sha}` with
`{"state": "pending|success|failure|error", "context": "ci/unit"}` (context names are
1-255 characters without control characters; plus an optional `description` of at most 1024 chars and an `http(s)` `target_url` of at most 2048 chars).
Posting needs write access (`repo:write` on top of read) and answers `201`, like GitHub's;
reads need `repo:read`. `GET .../commits/{ref}/status` folds every latest-per-context row
into one state (`error` beats `failure` beats `pending` beats `success`; an unknown SHA is
`pending` with nothing behind it). `{ref}` is a SHA, a branch, or an annotated tag (a
branch shadows a same-named tag; anything else is `404`); slashes arrive percent-encoded.
A bad SHA, state, or context answers `422`. Every API error body is
`{"error": {"code", "message", "details": null}}`.

Gate rules make merging fail closed. Each rule is stored on the repository with a
branch glob (empty matches every branch); every rule matching the change's base must
pass, and zero matching rules means only clean mergeability is required. A rule can
demand N writer approvals (only write+ reviews count; each reviewer counts
once, by their latest approve or request-changes verdict, so a later approval
clears that reviewer's own request for changes; dismiss-on-push drops
older-revision votes, while request-changes blocks on rules that ask it to), green
required contexts, an up-to-date head, resolved threads, and session evidence linking
the commits to uploaded agent sessions. The change page's Gates panel — and
`GET .../trails/{n}/changes/{k}/gates` — shows which rules match and why; evaluation
writes nothing, and merging re-evaluates everything server-side, so a stale client
report can never authorize a merge. Admins manage rules from the repository
settings "Merge gates" section or via `GET`/`POST .../repos/{owner}/{repo}/gate-rules`
and `PATCH`/`DELETE .../gate-rules/{id}` (reads need `repo:read`, mutations
`repo:write` on top of maintain): each rule pairs one branch pattern (empty or
null means all branches, at most one rule per pattern) with approval, context, and
method requirements, and every change lands exactly one `gate_rule.*` timeline row.

Merging needs write access on a non-archived repo: `POST .../changes/{k}/merge` with
`{"method": "merge|squash|fast_forward"}`. `merge` writes a two-parent merge commit,
`squash` condenses the head into one commit (subject lines first, then one
`Starforge-Session:` trailer per session in order of appearance), and `fast_forward`
moves the ref only when the head already contains the base; every commit carries a
`Starforge-Trail: <owner>/<repo>#<n>` trailer. The change flips to `merged`, and its
trail closes once no open change remains. Conflicts and CAS races answer `409` with the
fresh SHAs; failing gates answer `422` with the reasons.

## Branch and tag protection

Gate rules double as branch protection. Each rule carries three push
restrictions alongside its merge gates: `block_direct_push` (changes must go
through a Trail), `block_force_push`, and `block_deletion`. Patterns are
globs (`*` matches any run, `?` one character; empty or null means all
branches, at most one rule per pattern); every rule matching the branch
applies, and a push is refused when ANY matching rule blocks it. Only the
direct-push block can be bypassed, through the rule's allow-list; force-push
and deletion blocks stop everyone, including admins and site admins. Every refusal
reaches the pusher as `remote: starforge: …`, naming the ref and the rule
pattern, and the server-side ref is left untouched.

Each rule may exempt individual users (by handle) and, on org-owned
repositories only, whole teams (by slug) from the direct-push block via
`push_allowlist: {"users": [...], "teams": [...]}`. The exemption covers
only direct pushes on that rule: an allow-listed writer still cannot force
push or delete, and allow-listed users still need write access to push at
all. Unknown handles, unknown teams, and team entries on a user-owned
repository answer `422`.

Tag protection is a separate per-repository pattern list: creating, moving,
or deleting a tag that matches any pattern needs maintain or above, while
non-matching tags need only write, as before. The API is
`GET`/`POST .../repos/{owner}/{repo}/tag-protections` (body `{"pattern"}`)
and `DELETE .../tag-protections/{id}`; reads and mutations alike need
maintain (mutations also need the `repo:write` token scope), so readers
below maintain get `403` and non-readers `404`. Gate-rule reads stay open
to any repository reader; both lists answer `404` for unknown ids.

Pushes to any other namespace are refused unless a site admin allow-lists
it in `git.allowed_ref_namespaces` (e.g. `allowed_ref_namespaces =
["refs/notes/"]`, overridable as
`STARFORGE__GIT__ALLOWED_REF_NAMESPACES`). Each entry must start with
`refs/` and end with `/`, and must neither equal nor overlap `refs/heads/`,
`refs/tags/`, `refs/for/`, or `refs/trails/` — a bad entry fails startup
naming the entry. Allow-listed namespaces need write access plus a
write-scoped token and are never subject to branch protection. Server-side
writes bypass all of this: Trail merges move protected branches, and
`refs/trails/*` stays server-only (clients cannot push it, and fetches hide
it).

The repository settings **Branch protection** page
(`/{owner}/{repo}/settings/protection`, maintain and up) lists the rules by
pattern with their gates and push restrictions, with create, edit, and
delete forms covering every gate field, every push field, and the
allow-list, plus the tag-protection list with add and remove forms. All
forms carry CSRF and answer `303` or a `422` re-render.

Every protection change writes exactly one audit row —
`gate_rule.created`/`gate_rule.updated`/`gate_rule.deleted` and
`tag_protection.created`/`tag_protection.deleted` — while no-op updates
write nothing. Branch protection lives in migration `0022`, tag protection
in `0023`.

## Webhooks

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

## Development

```bash
scripts/check.sh                      # fmt, clippy, tests on SQLite
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17 via podman or docker
```

## License

See `LICENSE.md`: the server is AGPL-3.0-or-later; the CLI and trace format (from M1) are MIT OR Apache-2.0.
