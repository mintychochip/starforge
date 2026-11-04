# Trace Format v1 — Events

Normative specification of the normalized event stream (JSONL, one event per
line, stored per segment as `segments/<n>.jsonl.zst` after redaction).
Implements §7.8 of the Starforge design spec. The Rust implementation is
`starforge-format::{Event, EventKind, parse_event}`; the JSON Schema is
`schema/events-v1.json`.

## Common fields

Every event line carries `v` (format major, `1`), `seq` (monotonic per
session), `ts` (RFC 3339), and `kind`. `id` and `parent` are optional and,
when present, travel as ordinary extra fields that survive round-trips.

| `kind` | Additional fields |
|---|---|
| `user_message` | `text` |
| `assistant_message` | `text`, `model`, `usage{input, output, cache_read, cache_write, reasoning}` |
| `reasoning` | `text` (may be empty when the agent stores only a summary) |
| `tool_call` | `tool{name, input}` |
| `tool_result` | `result{output, is_error, truncated, original_bytes}` |
| `file_change` | `path`, `change` (`add`, `modify`, `delete`, `rename`), `diff` (unified, optional) |
| `compaction` | `summary` (optional) |
| `subagent_start`, `subagent_end` | `subagent_id`, `task` |
| `system` | `text` |

## Reading rules

- `v != 1` → reject with `UnsupportedVersion(v)`.
- `ts` must be RFC 3339 → otherwise `BadTimestamp("ts")`.
- Missing `kind` → `MissingKind`.
- A `kind` value outside the table is NOT an error: it parses into
  `EventKind::Unknown` and re-serializes with the same `kind` value.
- Unknown top-level fields are NOT an error: they are captured into
  `Event.extra` and re-serialized unchanged (round-trip preserved).
- A missing required payload field for a known kind (e.g. `text` for
  `user_message`) → `InvalidField { kind, field }`.

## Evolution rules

Adding optional fields or new `kind` values does not change `v`; readers
ignore unknown fields and kinds (unknown kinds still parse, per above).
Removing or retyping a field, or changing a field's meaning, requires
`v: 2`. The server reads every published major version indefinitely. The
redacted raw native transcript is stored alongside normalized events unless
the repository disables raw storage.
