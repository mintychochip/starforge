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

The viewer, download, and blame pages (the three surfaces rendered from
attacker-influenced content) carry a strict Content-Security-Policy
(`default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`) as defense in
depth; other pages use the site default.

Not yet: a repository session index (commit panels and direct ULID links are the discovery
paths) and blame syntax highlighting.

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

Pi/omp records are the real JSONL record structure (one object per line,
each carrying `type`, `id`, `parentId`, an ISO `timestamp`, and
`runtime.version`): a `session` header record (with `cwd`, the format
`version`, and an initial title), `title` / `title_change` records (latest
wins), `message` records whose `message.role` shapes the event (`user`,
`assistant` with `thinking` / `text` / `toolCall` blocks, `toolResult` with
an `[image: <mime>]` placeholder for image blocks, `custom`, `developer`),
`custom_message` context injections (as readable `system` text),
`compaction` records, and a `custom` record with `customType:
"session_exit"` that ends the session. Auxiliary/noise records are skipped
by rule: `model_usage` (side calls, not turns), `mode_change`,
`model_change`, `thinking_level_change` (runtime state), `credential_pin`
(never captured), and other `custom` progress markers; the header's models
and usage totals come from assistant messages only. Unknown record types
and roles keep the raw JSON as a `system` event — never dropped silently.
Record timestamps are used verbatim (never "now"), so an old session's
last activity stays old and the 24 h idle rule can end it.
