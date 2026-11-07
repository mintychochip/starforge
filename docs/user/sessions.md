# Sessions

`starforge sync` (and every hook pass — the pre-push hook and `starforge hook
session-end` — which reconciles the spool first) uploads spooled sessions to
`/api/v1/repos/{owner}/{repo}/sessions/{ulid}` with a
`session:upload` token (`starforge auth login` prints a device code the browser approves at
`/oauth/device`). The uploader needs write access to the repository; anything else answers `403`.
Four calls make an upload: `PUT` metadata (Trace Format v1 JSON, path ULID matching `meta.id`),
`PUT` each segment as zstd bytes with an `X-Starforge-Blake3` header naming their hex digest,
`POST .../complete` with an empty `{}` body, and `POST .../links` with commit SHAs to claim.
Re-sending identical bytes is a safe no-op (`200`); a changed segment at a taken number answers
`409` with exactly `{"hash": "<stored hex>"}`, and new content on a completed session is `422`.
Segments cap at 16 MiB (decompression is bounded at 256 MiB against bombs); quotas are
500 MiB per user per hour, 5 GiB stored per user, and 20 GiB stored per repository.
The CLI re-sends a session's metadata (title, models, files, end time)
whenever it changes: ingest compares the spool meta's body hash against
the last uploaded hash and re-queues the metadata `PUT` on any change.

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

Every session opens at `/{owner}/{repo}/sessions/{ulid}`: header metadata (agent, models,
branch, usage, redaction fingerprint), the event transcript in stored order (200 per page,
`?page=N`, `#turn-<seq>` deep links), and a `Download JSONL` link carrying the same redacted
bytes the page renders. Prose renders as sanitized Markdown inside a visible untrusted frame —
with `<img>` elements stripped entirely (even relative ones), so an image in an
attacker-influenced transcript can never phone home when viewed; repository Markdown
(READMEs, blobs) keeps images. Tool input, tool output, diffs, and unknown event kinds
render as escaped text in collapsed
`details>` blocks, and `[redacted:<id>]` markers show verbatim. Assistant events
with usage show per-turn input, output, cache-read, cache-write, and reasoning
counts. Commit markers render after the event at each commit link's `seq_end`,
showing the short SHA and linking to the commit page and to the split view.
In-session search is a GET form (`?q=`): a case-insensitive substring match
over message text, tool names, and file paths, capped at 200 hits, each linking
to the right page and `#turn-<seq>`. Split view (`?split=<sha>`) renders the
linked commit's diff beside the transcript; the sha must be one of the
session's linked commits in this repository (others answer `404`), and the
diff requires repository read access. The JSON API mirrors the
viewer: `GET /api/v1/repos/{owner}/{repo}/sessions/{ulid}` (metadata plus commit links) and
`GET .../sessions/{ulid}/events?page=N`.

The viewer works without JavaScript: search results and both split-view
columns are server-rendered, and every control is a link, button, or input.
One plain ES module (`/static/session-viewer.js`) only enhances the page —
in-page search highlighting and switching split-view commits without a
reload — and any failure falls back to normal link navigation.

Quarantined sessions show a banner (reason plus detail) over the full transcript to the uploader
and repo admins, with release, purge, and rescan buttons; everyone else gets `404`, so ULIDs
stay undiscoverable. Commit pages list a Sessions panel and blame pages list session chips —
both only for sessions the viewer may read, never locked placeholders. Publishing flips a
session to `published` on public repositories (repo `maintain` or above), which makes it
readable to strangers; unpublish flips it back to `inherit`. Delete removes the session, its
segments, and its links. Every web form carries a `_csrf` token; the API uses Bearer tokens
and answers `401` without one.

The repository sessions list at `/{owner}/{repo}/sessions` (also the
**Sessions** tab on every repository page) shows the sessions the viewer may
read, newest first by start time, 50 per page. By default it shows only
top-level sessions — a session with a readable parent in the same repository
is listed under its parent's subagent count instead; `?all=1` lists every
readable session. `?agent=<name>` keeps one agent name and
`?state=receiving|complete` keeps one lifecycle state. Each row links to the
viewer and shows the agent name and version, start and end times (`in
progress` while the session is still receiving), turn and tool-call counts,
and the number of readable direct subagent sessions. A session with no
title reads `Untitled session`. The list and viewer apply the same
per-session read rules as the viewer itself, so unreadable sessions never
appear — not even as locked rows.

The viewer links the subagent hierarchy: a readable parent shows as
`Subagent of <parent title>` and readable direct children list under
`Subagent sessions (N)` with title, agent, and lifecycle, oldest first.
An unreadable parent stays hidden on both the list (the child counts as
top-level while its parent is unreadable) and the viewer.

The viewer, download, and blame pages (the three surfaces rendered from
attacker-influenced content) carry a strict Content-Security-Policy
(`default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`) as defense in
depth; other pages use the site default.

Not yet: blame syntax highlighting.

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

`starforge-capture` (MIT OR Apache-2.0) reads native agent transcripts into normalized
Trace Format v1 events without redaction: five adapters cover Claude Code, Codex CLI, Pi,
OpenCode (SQLite `opencode.db`, the v2 `session_v2`/`session_message` store), and Gemini CLI. omp transcripts
parse through the Pi adapter, best-effort and always reported `unverified`
(`adapter_version_verified == false`).
Adapters take explicit root paths (no `$HOME`, no clock), resume with stable cursors, and
preserve unmapped native fields so re-normalization stays lossless; raw-transcript storage
defaults ON for new repos. Test fixtures are synthesized in the native shape — each fixture
directory carries a `SYNTHESIZED.txt` noting the native source it mimics.

## Where sessions are read from

Capture is discovery-based (at commit, push, and `sync`): the CLI reads each
agent's native store under a per-agent root derived from `$STARFORGE_HOME`
else `$HOME`. When `STARFORGE_HOME` is set, the agent env overrides below
are ignored.

| Agent | Sessions read from | Hook/config dir | Env overrides |
|---|---|---|---|
| Claude Code | `<base>/.claude/projects/<slug>/<id>.jsonl` | `<base>/.claude` (`settings.json`) | `$CLAUDE_CONFIG_DIR` for both dirs |
| Codex CLI | `<base>/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` | `<base>/.codex` | `$CODEX_HOME` for both dirs |
| Gemini CLI | `<base>/.gemini/tmp/<hash>/chats/*.json` | `<base>/.gemini` | — |
| OpenCode | `$XDG_DATA_HOME/opencode` else `<base>/.local/share/opencode` (`opencode.db`) | `$XDG_CONFIG_HOME/opencode` else `<base>/.config/opencode` | `$XDG_DATA_HOME`, `$XDG_CONFIG_HOME` |
| Pi and omp | `<base>/.pi/agent/sessions/**/*.jsonl` (Pi) and `<base>/.omp/agent/sessions/**/*.jsonl` (omp), both recursive | `<base>` | — |

Antigravity CLI sessions are not captured in v0.1.0 (see Known gaps).

Pi/omp capture is discovery-only: they have no verified JSON-config hook
surface, so `starforge enable` installs no Pi/omp hook files; sessions are
picked up by discovery at commit/push/sync.

`starforge enable` writes agent hook config only for agents it detects on the
machine (their data/config dirs are present); it lists the agents it
configured and the agents it skipped as not detected, with a hint to re-run
`starforge enable` after installing an agent. It never creates config (for
example a `~/.claude/settings.json`) for an agent that is not installed.
`starforge disable` still removes hooks from any agent config that has them,
detected or not.

Pi/omp records are the real JSONL record structure (one object per line,
each carrying `type`, `id`, `parentId`, an ISO `timestamp`, and
`runtime.version`): a `session` header record (with `cwd`, the format
`version`, and an initial title), `title` / `title_change` records (latest
non-empty wins; the empty placeholder title an untitled session starts
with is ignored), `message` records whose `message.role` shapes the event (`user`,
`assistant` with `thinking` / `text` / `toolCall` blocks, `toolResult` with
an `[image: <mime>]` placeholder for image blocks, `custom`, `developer`),
`custom_message` context injections (as readable `system` text),
`ttsr_injection` records (rendered as a readable `Rules injected: …`
`system` line), `compaction` records, and `custom` records, including ones with
`customType: "session_exit"`, which are skipped as progress markers.
`session_init` records (every omp subagent session opens with one) are
skipped: their `task` duplicates the first user message, and the rest is
runtime configuration (system prompt, tools, output schema).
omp can resume a session in the same file after a `session_exit`, so
`session_exit` does not end the session: Pi/omp sessions end only by the
24 h idle rule. Auxiliary/noise records are skipped
by rule: `model_usage` (side calls, not turns), `mode_change`,
`model_change`, `thinking_level_change` (runtime state), `credential_pin`
(never captured), and other `custom` progress markers; the header's models
and usage totals come from assistant messages only. Unknown record types
and roles keep the raw JSON as a `system` event — never dropped silently.
Record timestamps are used verbatim (never "now"), so an old session's
last activity stays old and the 24 h idle rule can end it. Every ingest
(hooks and `starforge sync`) ends sessions idle ≥ 24 h even if their
transcript never grows again.

omp stores a subagent session as a file inside a directory named after its
parent session's file stem (nesting to depth 2): the parent of
`<D>/<name>.jsonl` is the sibling file `<D>.jsonl` when it exists. Ingest
records that native parent key in `cursors.json` and sets the session's
`parent_id` to the parent's spool ULID, resolving in an end-of-ingest pass
so discovery order does not matter (a child spooled before its parent still
ends up linked). The spooled metadata is re-queued through the usual
`Meta` path whenever that link changes.

Pi/omp files-touched come from `edit`/`write` tool calls. omp's `edit`
calls usually carry no `path` argument: the edited files appear as hashline
header lines `[PATH#TAG]` (TAG a 4-hex-digit tag) in the call's `input`,
while `write` carries `path` directly (Pi's `file_path` is also honoured);
`read`, `grep`, `glob`, and `bash` never count. Trace Format v1 documents
`files_touched` as repo-relative paths, so absolute paths inside the
session's workdir are stored relative to it, absolute paths outside the
workdir stay absolute, and relative paths stay as-is.

OpenCode message rows map `synthetic`/`system` to readable `system`
events (a non-empty `description`, when present, prefixes the text as
`<description>: <text>`), `agent-switched` to a readable
`Agent switched from <previous> to <agent>` system line, and `idle`
(runtime bookkeeping) produces no event; only truly unknown types keep
the raw-JSON `system` fallback. OpenCode files-touched come from
file-modifying tool calls (`edit`, `write`, `patch`/`apply_patch`,
`multiedit`) via `path` (falling back to the older releases'
`filePath`, and the oldest `file_path`), normalized the same way as
above; read-only tools (`read`, `grep`, `glob`, `shell`, `question`)
never add paths.

Most omp sessions have no agent title (omp writes only an empty
placeholder). When a session has no title after ingest's fold, the CLI
falls back to the first `user_message`'s first non-blank line (trimmed, at
most 80 characters, cut on a char boundary with `…` appended when cut),
redacted exactly like adapter titles. A later non-empty adapter title still
replaces the fallback; the fallback never replaces an existing title.

## Backfilling commit links for historical sessions

Sessions imported from other sources (or captured before linking existed)
carry no commit links: there were no `Starforge-Session:` trailers and no
post-commit claims to upload. `starforge sessions backfill-links` recovers
them:

```shell
starforge sessions backfill-links [--since <YYYY-MM-DD>] [--dry-run]
```

It considers every spooled session with a non-empty `files_touched` and every
commit reachable from `HEAD`, and links a pair only when **both** hold:

1. The commit's committer time falls inside the session's activity window
   `[started_at, last_activity + 30 minutes]`, where `last_activity` is
   `ended_at`, else the newest cursor `last_event_at` for the session, else
   `started_at`.
2. At least one of the commit's changed paths equals one of the session's
   normalized `files_touched` paths. An absolute path is made repo-relative
   by stripping the working-tree root or any linked-worktree root; paths
   outside every root are dropped. Relative paths stay as-is.

`--since <YYYY-MM-DD>` considers only commits on or after that day's UTC
midnight. Pairs already linked locally are skipped, so the command is
idempotent — a second run records nothing new. New links are recorded through
the same claim path as `sessions link`, so the next `starforge sync` uploads
them. `--dry-run` prints `ulid  sha  matched-path` lines plus the count and
changes nothing; without it the command prints only the count
(`linked N pair(s)`).

## Pruning the local spool

The local spool (`<git-common-dir>/starforge/sessions/<ulid>/`) keeps every
captured session's segment and raw-slice blobs even after upload, so it grows
without bound. `starforge spool prune` deletes the local bulk data for
sessions the server already holds:

```shell
starforge spool prune [--older-than <days>] [--dry-run]
```

`--older-than` defaults to 30 days (a session qualifies only when its last
activity — `ended_at`, else the cursor's `last_event_at` — is older than
that). `--dry-run` prints `would prune <ulid> (<bytes> bytes, last activity
<ts>)` per eligible session and deletes nothing; both modes print the
`sessions:` / `bytes freed:` totals.

A session is pruned only when **all** of these hold: `upload.json` records
the server's `complete` acknowledgement, every local segment is recorded as
uploaded, the uploaded metadata hash still matches the current `meta.json`
body (no changed metadata awaiting upload), and no queue entry for the
session is still pending. Anything doubtful — unreadable state, missing or
unparseable timestamps, a wholly unreadable queue — excludes the session.
Only the session's `segments/` and `raw/` directories are deleted;
`meta.json`, `upload.json`, and the cursor record in `cursors.json` are
never touched, so re-ingest of the same native transcript reuses the same
ULID instead of creating a new session.

`sessions list` renders a pruned session's segment column as `pruned`, and
`sessions show` notes that the content was pruned locally and lives on the
server (view the session URL). Queued uploads for pruned sessions settle as
already-uploaded instead of erroring on the missing blobs.
