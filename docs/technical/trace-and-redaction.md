# Trace format and redaction

<!-- ste-sources
crates/starforge-format/src/session.rs
crates/starforge-format/src/events.rs
crates/starforge-format/src/segments.rs
crates/starforge-redact/src/detectors.rs
crates/starforge-redact/src/rules.rs
crates/starforge-redact/src/json.rs
crates/starforged-core/src/rescan.rs
crates/starforge-cli/src/untrusted.rs
-->

## Purpose

Trace Format v1 stores each session as metadata plus events. Redaction removes secrets before storage and before viewing. This page defines the format, the segments, and the rules.

## Scope

The format covers session metadata and the event stream. Redaction covers built-in detectors, TOML rules, and fingerprints. The server re-scan and quarantine map live in this page. Raw transcript storage stays outside v0.1 scope. The viewer rendering stays outside this page.

## How it works

### Session metadata and format tags

`SessionMeta::parse` validates `format` against `starforge.session/v1`. The session identity is a ULID in `id`. `started_at` and `ended_at` must parse as RFC 3339 strings. Agent names accept only five kebab-case values.

Unknown fields parse without error at every level. Readers ignore unknown fields.

| Field | Type | Rule |
|---|---|---|
| `format` | string | exact tag `starforge.session/v1` |
| `id` | ULID string | caller-generated session identity |
| `agent.name` | string | one of five kebab-case names |
| `agent.version` | string | native agent version string |
| `models` | string array | observed model names |
| `title` | string or null | viewer title, often prompt excerpt |
| `started_at`, `ended_at` | RFC 3339 | `ended_at` absent while receiving |
| `repo` | object | remote URLs, branch, head at start |
| `parent_id` | ULID or null | parent session for subagents |
| `usage` | object | five token counters, each defaults to 0 |
| `files_touched` | string array | repository-relative paths |
| `redaction` | object | fingerprint plus per-detector counts |
| `capture` | object | mode, CLI version, verified flag |

### Events and event kinds

Each event line needs `v`, `seq`, `ts`, and `kind`. `v` must equal 1 and `ts` must parse as RFC 3339. `parse_event` rejects a missing `kind` with `MissingKind`. Unknown kinds parse as `EventKind::Unknown` and round-trip.

Unknown top-level fields enter `extra` and round-trip unchanged. A missing payload field for a known kind fails the line.

| `kind` | Extra fields |
|---|---|
| `user_message` | `text` |
| `assistant_message` | `text`, `model`, `usage` |
| `reasoning` | `text`, often a summary |
| `tool_call` | `tool` with name and input |
| `tool_result` | result with output and flags |
| `file_change` | path, change kind, optional diff |
| `compaction` | optional summary |
| `subagent_start` | subagent id and task |
| `subagent_end` | subagent id and task |
| `system` | `text` |

### Segments, compression, and hashes

Segments group event lines for storage and upload. `split_jsonl` packs lines greedily into compressed segments up to the segment cap. The cap defaults to 16 MiB of compressed bytes. A single line that alone exceeds the cap forms its own oversized segment.

`assemble` concatenates segments back into one stream. `compress` uses zstd level 3 and stays deterministic. `decompress_bounded` reads at most limit plus one byte. `blake3_hex` fingerprints every segment body.

Sequence ranges confirm that segments never overlap.

### Detectors and rule files

Seven built-in detectors run by default. Email and phone are opt-in, which gives nine detectors in fixed order. Each match keeps byte spans on character boundaries. The longest match wins when spans overlap. Ties break by detector order, then custom rule order.

One kept match increments exactly one counter. Replacement text follows `[redacted:<id>]` exactly. Literals share the id `literal` in counts and output.

| Detector id | Shape | Confidence | Default |
|---|---|---|---|
| `private-key` | PEM private key block | high | on |
| `cloud-credential` | AWS keys, AWS secret, GCP marker | high | on |
| `known-token` | GitHub, Anthropic, Slack, npm tokens | high | on |
| `credentialed-url` | user and password in URL | low | on |
| `connection-string` | password fields, Mongo URLs | low | on |
| `authorization` | `Authorization` header and Bearer text | low | on |
| `high-entropy` | Shannon entropy over 20 chars | low | on |
| `email` | email address shape | low | off |
| `phone` | phone number shape | low | off |

High entropy needs length 20 and threshold 4.5 default. `pii.email` and `pii.phone` turn email and phone on. Both PII detectors stay off unless rules turn them on. `.starforge/redact.toml` carries pii, entropy, and pattern tables.

Entropy literals share the high-confidence literal class. Custom pattern ids come from `[[pattern]]` entries.

### Fingerprint and JSON redaction

`fingerprint` hashes canonical records with BLAKE3. Records sort byte-wise and join without separators. Any rule content, toggle, or entropy change alters the hash. Record order does not alter the hash. The hash lands in `meta.redaction.fingerprint`.

`redact_event` rewrites text, output, diff, summary, task, tool input, and extra values. Tool input receives a deep walk. `redact_event` leaves model, path, flags, and ids intact. `redact_jsonl` keeps line count and order intact. Structural `v`, `seq`, `ts`, `kind`, and keys pass through.

### Server re-scan and quarantine

The server compiles built-ins plus repository plus site rules. Site rules merge last and win scalar settings. Malformed TOML fails the upload with an invalid error. `scan_segment_text` counts hits in every segment line.

High-confidence hits quarantine the session with location detail. Counts from low-confidence hits merge into session counts. Quarantine never rejects segment bytes outright. `scan_session_meta` scans title, models, files, remote URLs, branch, and agent version.

`remote_urls` counts hits but has no redacted column. Already redacted values match nothing and never double-count. `rescan_session` skips sessions already in quarantine.

### Untrusted framing for agent output

The `Framer` nonce holds 16 lowercase hex characters. The nonce comes from the low bits of a fresh ULID. `preamble` writes one instruction line first. `frame` wraps text in one `<untrusted-data>` block.

Body markers for open and close tags escape to `&lt;`. Label and author attributes escape `&`, quote, and brackets. The author attribute drops out when no author exists. `trail show --format agent` emits framed third-party text.

### Known limits

Detectors match shapes, never semantics, so misses happen. High entropy trades false hits against missed secrets. Custom patterns can match more text than intended. The regex engine stays linear but has no timeout layer.

One agent version per adapter carries golden coverage. Antigravity has no adapter in v0.1 and stays uncaptured. v0.1 stores no raw segments on the server. v0.1 never sets `raw_enabled` to 1.

Session end detection uses the 24 hour idle heuristic.

## Interfaces

Schemas live in `docs/format/schema/session-v1.json` and events. Format entry points include `SessionMeta::parse` and `parse_event`. Segment entry points include `split_jsonl` and `decompress_bounded`. Redact entry points include `redact_text` and `fingerprint`.

Server entry points include `compile_scan_rules` and `rescan_session`. Quarantine routes include release, purge, and rescan calls. Route and scope detail lives in [http-api.md](http-api.md). Session lifecycle detail lives in [sessions.md](sessions.md).

## Failure behavior

Wrong format tags fail with `BadFormatTag`. Unknown agent names fail with `BadAgent`. Bad ULIDs fail with `BadUlid` and bad dates fail with `BadTimestamp`. Events with `v` not equal to 1 fail with `UnsupportedVersion`.

Corrupt zstd frames fail with a decompress error. Expansion over the limit fails with `TooLarge`. One bad event line rejects the whole segment PUT. Invalid rule TOML fails the upload with an `invalid redact.toml` error. The error does not name a repository or site layer. A bad regular expression names the pattern id.

A rule change does not re-scan stored segments. An admin rescan applies the current rules to one session. A release does not rescan. A later rescan quarantines the session again when old segment text still hits.

## Verification

Format fixtures cover parsing, unknown fields, and version guards. Segment unit tests cover packing, caps, and assembly. Redact corpus tests cover detectors, overlap, and fingerprints.

Rescan tests cover site precedence, repository literals, and meta scans. Ingest tests cover trailer merges, claim merges, and backfill. Capture golden tests pin each covered agent version.

Run the format, redact, and rescan test suites after rule changes.

## Related

- [Session pipeline](sessions.md)
- [Format specification](../format/README.md)
- [Session metadata schema](../format/session-v1.md)
- [Events specification](../format/events-v1.md)
- [HTTP API conventions](http-api.md)
- [Search design](search.md)
