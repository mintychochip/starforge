# Starforge M1a (Trace Format v1 + Redaction) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze the cross-milestone contract every later M1 plan builds on: the Trace Format v1 written spec under `docs/format/` (session + events + JSON Schema), the `starforge-format` crate (v1 types, version handling, segmentation, agent-output delimiters), and the `starforge-redact` crate (detectors, declarative rules, JSON-aware redaction, rule-set fingerprinting). No database, no server, no CLI in this plan.

**Architecture:** Two new leaf crates, both `MIT OR Apache-2.0` per spec decision D8. `starforge-format` owns `SessionMeta`, `Event`/`EventKind`, `Usage`, segment split/assemble + BLAKE3 helpers, and `wrap_untrusted`. `starforge-redact` owns `Detector`, `RuleSet` (built-in + `.starforge/redact.toml` + site rules, one grammar), `redact_text`/`redact_event`/`redact_jsonl`, and `fingerprint`. Later plans consume: M1b (adapters emit `Event`s, spool redacts with `RuleSet`), M1c (server validates versions/hashes/sizes, re-scans with server+repo rules, quarantines on high-confidence hits), M1d (viewer renders `Event`s, CLI wraps agent output).

**Tech Stack:** Rust 1.99.1 (edition 2024), serde/serde_json, ulid, regex, blake3, zstd, toml (all via `[workspace.dependencies]`), proptest for property tests (§13).

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` §5.1 (crate table), §7.4 (redaction), §7.5 (segment size/idempotency), §7.8 (Trace Format v1), §11.2 (untrusted delimiters), §13 (unit + property tests). M1b/M1c/M1d plans follow.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** the two new crates are `MIT OR Apache-2.0`. Root `Cargo.toml` `[workspace.package]` license stays `AGPL-3.0-or-later`; the new crates set `license = "MIT OR Apache-2.0"` explicitly (NOT `.workspace`). Add `LICENSE-MIT` and `LICENSE-APACHE-2.0` (canonical texts) and extend `LICENSE.md`'s second bullet to name the new crates.
- **Dependencies:** new workspace deps pinned with versions current at implementation time; crates inherit with `dep.workspace = true`. New deps: `ulid` (serde feature), `regex`, `blake3`, `zstd`, `proptest` (used in `#[cfg(test)]`/integration tests only). Reuse existing `serde`, `serde_json`, `toml`, `thiserror`, `tempfile` from the workspace table.
- **No I/O in these crates:** pure functions over `&str`/`&[u8]`/strings; no `std::fs`, no network, no timestamps from the clock (callers supply times). Both crates must build for the CLI's Windows target (no unix-only code).
- **Determinism:** same input → same output bytes for redaction, segmentation, compression (fixed zstd level 3), and fingerprinting. Tests assert byte equality.
- **Every commit:** `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` pass, and `cargo test --workspace` is green.
- **Decisions this plan makes where the spec is silent:**
  - Replacement text is `[redacted:<detector-id>]`, e.g. `[redacted:private-key]`. Detector ids are kebab-case.
  - Rule-set fingerprint is lowercase BLAKE3 hex over a canonical encoding: detectors sorted by id, each as `id\0regex-or-literal\0threshold\0`, joined; literals and patterns both included; PII toggles included. Same rules in any order → same fingerprint.
  - Entropy detector defaults: tokens of ≥20 characters from `[A-Za-z0-9+/=_.-]`, Shannon entropy ≥ 4.5 bits/char. Tunable via rules.
  - Timestamps are RFC 3339 strings, validated with `time::OffsetDateTime::parse` (existing `time` dep); invalid → parse error naming the field.
  - Segment split is greedy over lines: accumulate lines; whenever the uncompressed buffer exceeds 256 KiB, compress and measure; if over the cap, emit everything before the current line as a segment and continue. A single line that alone exceeds the cap is emitted as its own oversized segment (the server answers 413; the CLI cannot split a line). Reassembly is byte concatenation of decompressed segments.
  - `wrap_untrusted` emits `<<<STARFORGE-UNTRUSTED-BEGINS>>>` / `<<<STARFORGE-UNTRUSTED-ENDS>>>` on their own lines; any content line starting with `<<<STARFORGE-` is prefixed with one space.
  - JSON Schema files are hand-written and normative; conformance is tested structurally in Rust (required fields, types, rejects-bad-fixture suite) — no `jsonschema` dependency.

---

## File Structure

```
docs/format/
  session-v1.md        normative session-metadata spec (A2)
  events-v1.md         normative events spec + evolution rules (A2)
  schema/session-v1.json   JSON Schema for SessionMeta (A2)
  schema/events-v1.json    JSON Schema for one event line (A2)
LICENSE-MIT, LICENSE-APACHE-2.0   canonical texts (A1)
LICENSE.md             + names starforge-format / starforge-redact (A1)
Cargo.toml             + ulid, regex, blake3, zstd, proptest workspace deps (A1)
Cargo.lock             updated by cargo (A1)
crates/starforge-format/
  Cargo.toml           MIT OR Apache-2.0 (A1)
  src/lib.rs           re-exports + crate docs (A1, extended A2–A5)
  src/session.rs       SessionMeta, Agent, Usage, RedactionSummary, CaptureInfo (A2)
  src/events.rs        Event, EventKind, parse/validate + version rules (A2)
  src/segments.rs      split/assemble, blake3_hex, zstd helpers (A4)
  src/agent.rs         wrap_untrusted (A5)
  tests/v1_fixtures.rs valid + invalid fixture suite (A2)
crates/starforge-redact/
  Cargo.toml           MIT OR Apache-2.0 (A1)
  src/lib.rs           re-exports + crate docs (A1, extended A3)
  src/detectors.rs     built-in detectors + Detector trait (A3)
  src/rules.rs         RuleSet: redact.toml grammar, site rules, merge, fingerprint (A3)
  src/json.rs          redact_text, redact_event, redact_jsonl + counts (A3)
  tests/corpus.rs      per-detector corpus + JSONL preservation tests (A3)
README.md              + format/redaction section (A5)
```

---

### Task A1: Workspace wiring, licenses, crate skeletons

**Files:**
- Modify: `Cargo.toml` (5 new workspace deps), `LICENSE.md`, `Cargo.lock` (via cargo)
- Create: `LICENSE-MIT`, `LICENSE-APACHE-2.0`
- Create: `crates/starforge-format/{Cargo.toml,src/lib.rs}`, `crates/starforge-redact/{Cargo.toml,src/lib.rs}`

**Interfaces:**
- Consumes: workspace `[package]`/`[lints]` conventions (see `crates/starforged-core/Cargo.toml`).
- Produces:
  - `Cargo.toml` gains `ulid = { version = "1", features = ["serde"] }`, `regex = "1"`, `blake3 = "1"`, `zstd = "0.13"`, `proptest = "1"` (use current compatible versions; record what cargo resolves).
  - Both crates: `version/edition/rust-version.workspace = true`, `license = "MIT OR Apache-2.0"`, `publish = true` (explicit; they are embeddable libraries, unlike the server crates), `[lints] workspace = true`. Members resolve via the existing `crates/*` glob — verify with `cargo metadata`.
  - `src/lib.rs` files compile with crate-level docs stating the spec section implemented. `starforge-format` depends on `serde`, `serde_json`, `ulid`, `thiserror`, `time`; `starforge-redact` depends on `regex`, `serde`, `serde_json`, `toml`, `blake3`, `thiserror`, `starforge-format` (path). Dev-deps: `proptest`, `tempfile` via workspace.
  - `LICENSE.md` second bullet names `starforge-format` and `starforge-redact` as shipped in M1a.

- [ ] **Step 1: Add deps + licenses + skeletons**
- [ ] **Step 2: Run to verify the workspace resolves**
- [ ] **Step 3: Commit**

Run: `cargo metadata --format-version 1 >/dev/null && cargo test -p starforge-format -p starforge-redact && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS (0 tests each; clippy clean).

```bash
cargo fmt --all
git add Cargo.toml Cargo.lock LICENSE.md LICENSE-MIT LICENSE-APACHE-2.0 crates/starforge-format crates/starforge-redact
git commit -m "Add starforge-format and starforge-redact crate skeletons"
```

---

### Task A2: Trace Format v1 — types, docs, schema, version rules

**Files:**
- Create: `docs/format/session-v1.md`, `docs/format/events-v1.md`, `docs/format/schema/session-v1.json`, `docs/format/schema/events-v1.json`
- Create: `crates/starforge-format/src/session.rs`, `src/events.rs`, `tests/v1_fixtures.rs`
- Modify: `crates/starforge-format/src/lib.rs` (modules + re-exports)

**Interfaces:**
- Consumes: A1 skeletons.
- Produces (all `pub`, `#[serde(deny_unknown_fields)]` NOWHERE — unknown fields must be tolerated):
  - `pub struct SessionMeta { format: String, id: Ulid (serde string), agent: Agent, models: Vec<String>, title: Option<String>, started_at: String, ended_at: Option<String>, repo: RepoInfo, parent_id: Option<Ulid>, usage: Usage, files_touched: Vec<String>, redaction: RedactionSummary, capture: CaptureInfo }` with `SessionMeta::parse(&str) -> Result<Self, FormatError>` validating: `format == "starforge.session/v1"`, ULIDs parse, timestamps are RFC 3339, `agent.name` is one of `claude-code|codex|pi|opencode|gemini`.
  - `pub struct Agent { name: AgentName, version: String }`, `pub enum AgentName` (5 variants, snake-kebab renames as specced), `pub struct RepoInfo { remote_urls: Vec<String>, branch: String, head_at_start: String }`, `pub struct Usage { input: u64, output: u64, cache_read: u64, cache_write: u64, reasoning: u64 }` (all `#[serde(default)]` for forward tolerance), `pub struct RedactionSummary { fingerprint: String, counts: BTreeMap<String, u64> }`, `pub struct CaptureInfo { mode: CaptureMode, cli_version: String, adapter_version_verified: bool }`, `pub enum CaptureMode { Hook, Discovery }`.
  - `pub struct Event { v: u32, seq: u64, ts: String, kind: EventKind, #[serde(flatten)] extra: BTreeMap<String, serde_json::Value> }` — unknown fields land in `extra` and re-serialize (round-trip). `pub enum EventKind` with the 11 specced variants carrying their specced payload structs (`UserMessage{ text }`, `AssistantMessage{ text, model: Option<String>, usage: Usage }`, `Reasoning{ text }`, `ToolCall{ tool: ToolRef }`, `ToolResult{ result: ToolOutcome }`, `FileChange{ path, change: FileChangeKind, diff: Option<String> }`, `Compaction{ summary: Option<String> }`, `SubagentStart{ subagent_id, task }`, `SubagentEnd{ subagent_id, task }`, `System{ text }`) plus `Unknown(String)` for any other `kind` value. Custom `Deserialize`/`Serialize` preserving unknown kinds through round-trips.
  - `pub fn parse_event(&str) -> Result<Event, FormatError>`: rejects `v != 1` with `FormatError::UnsupportedVersion(v)`; validates `ts` RFC 3339; missing `kind` → `FormatError::MissingKind`. Per-kind required payload fields missing → `FormatError::InvalidField { kind, field }`.
  - `pub enum FormatError` (thiserror): `Json`, `UnsupportedVersion(u32)`, `MissingKind`, `InvalidField{..}`, `BadUlid`, `BadTimestamp(&'static str)`, `BadAgent(String)`, `BadFormatTag`.
  - `docs/format/*.md`: normative prose transcribed from §7.8 (field tables + evolution rules verbatim in meaning). `docs/format/schema/*.json`: JSON Schema (draft 2020-12, `$schema` key) for `SessionMeta` and for one event line (open `additionalProperties: true`, `kind` open string — schemas must NOT reject future kinds/fields).
  - Property tests (proptest): arbitrary valid `SessionMeta`/`Event` serde round-trips; unknown-field injection preserved; `v: 2` always rejected.

- [ ] **Step 1: Write `docs/format/*` + skeletons + failing fixture tests**

`tests/v1_fixtures.rs`: one valid full session meta, one valid event per kind (11), invalid cases: `v: 2`, missing `kind`, bad ULID, bad timestamp, bad agent name, wrong format tag, unknown kind (must PARSE into `Unknown`), unknown extra fields (must round-trip).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p starforge-format`
Expected: FAIL — types do not exist.

- [ ] **Step 3: Implement `session.rs` + `events.rs` + schemas + docs**

Check `ulid` serde shape (string) and `time::OffsetDateTime::parse` with `time::format_description::well_known::Rfc3339` before writing. Keep every integer `u64` with `#[serde(default)]` where the spec allows absence (`usage` totals).

- [ ] **Step 4: Run tests**

Run: `cargo test -p starforge-format`
Expected: PASS (fixtures + proptest round-trips).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add docs/format crates/starforge-format
git commit -m "Add Trace Format v1 types, schema, and version rules"
```

---

### Task A3: Redaction engine — detectors, rules, fingerprint

**Files:**
- Create: `crates/starforge-redact/src/{detectors.rs,rules.rs,json.rs}`, `tests/corpus.rs`
- Modify: `crates/starforge-redact/src/lib.rs`, `crates/starforge-redact/Cargo.toml` (if a dep was missed in A1)

**Interfaces:**
- Consumes: `starforge-format::{Event, EventKind}` (A2).
- Produces:
  - `pub trait Detector: Send + Sync { fn id(&self) -> &'static str; fn high_confidence(&self) -> bool; fn find(&self, haystack: &str) -> Vec<Match>; }`, `pub struct Match { start: usize, end: usize }` (byte indices on char boundaries; overlapping matches across detectors resolve by longest-first, then detector order — document).
  - Built-in detectors (ids): `private-key` (PEM armor `----BEGIN … PRIVATE KEY----` + base64 body, high), `cloud-credential` (AWS `AKIA…` + 40-char secret assignment, GCP service-account JSON marker, high), `known-token` (`ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[baprs]-|sk-ant-|sk-|AIza|glpat-|npm_|pypi-…` prefixes with length checks, high), `credentialed-url` (`://user:password@`, redacts the whole authority credentials part only — low), `connection-string` (`Password=|Pwd=|…` ADO-style + `mongodb+srv://…` credentials — low), `authorization` (`Authorization: <scheme> <secret>` header value + bare `Bearer <secret>` — low), `high-entropy` (≥20 chars, ≥4.5 bits, low), `email` / `phone` (off by default, low).
  - `pub struct RuleSet { detectors: Vec<Rule> }`, `pub enum Rule { Detector(BuiltInId), Literal(String), Pattern { id: String, regex: String } }` + `RuleSet::built_in()`, `RuleSet::parse_toml(&str) -> Result<Self, RuleError>` for the `.starforge/redact.toml` grammar:
    ```toml
    [pii]
    email = false
    phone = false
    [entropy]
    min_len = 20
    threshold = 4.5
    literals = ["secret-string"]
    [[pattern]]
    id = "internal-token"
    regex = "INT-[0-9]{8}"
    ```
    `RuleSet::merge(&self, other: &Self) -> Self` (repo over built-in over site: M1c decides precedence; M1a provides order-preserving concat + PII/entropy override). `RuleError` (thiserror): `Toml`, `BadRegex { id, source }`, `BadThreshold`.
  - `pub fn fingerprint(rules: &RuleSet) -> String` — lowercase BLAKE3 hex over the canonical encoding (Global Constraints).
  - `pub fn redact_text(rules: &Compiled, text: &str) -> (String, BTreeMap<String, u64>)`; `pub fn redact_event(rules, event: &Event) -> (Event, counts)` (redacts `text`/`output`/`input`-ish string fields per kind + `extra` values recursively — structure preserved); `pub fn redact_jsonl(rules, jsonl: &str) -> (String, counts)` (per line: JSON object → walk values redacting strings; non-JSON line → `redact_text`; line count and order preserved). `Compiled` precompiles regexes once (`RuleSet::compile()`); regexes built with `regex::Regex::new` (no backtracking engine — document catastrophic-backtracking safety: patterns are user regexes; note the risk in docs, M1c may add timeouts).
  - Counts keyed by detector/rule id; every redaction of one match increments once.

- [ ] **Step 1: Write the failing corpus tests**

`tests/corpus.rs`: per-detector positive + negative cases (private key, AWS keypair, `ghp_` token, `https://user:pass@host`, `Password=…` string, `Authorization: Bearer …`, high-entropy blob vs. UUID/lorem negatives, email/phone off-by-default then on); JSONL structure test (nested JSON redacted, keys intact, line count kept); `redact_event` per-kind test (tool input/output redacted, `seq`/`kind` untouched); fingerprint tests (order-independent, rule-change-sensitive); `redact.toml` parse + merge tests.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p starforge-redact`
Expected: FAIL — modules do not exist.

- [ ] **Step 3: Implement `detectors.rs` + `rules.rs` + `json.rs`**

Check `regex` API + `toml` derive before writing. Char-boundary safety: operate on bytes but assert `is_char_boundary` in debug; tests include multi-byte text adjacent to secrets.

- [ ] **Step 4: Run tests**

Run: `cargo test -p starforge-redact`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforge-redact
git commit -m "Add redaction engine with detectors and rule files"
```

---

### Task A4: Segmentation, compression, hashing

**Files:**
- Create: `crates/starforge-format/src/segments.rs`
- Modify: `crates/starforge-format/src/lib.rs` (module + re-exports)
- Test: unit tests in `segments.rs` + proptest round-trip

**Interfaces:**
- Consumes: A1 (`blake3`, `zstd` deps), A2 (`Event` for the JSONL used in tests).
- Produces:
  - `pub const DEFAULT_SEGMENT_CAP: usize = 16 * 1024 * 1024;`
  - `pub fn blake3_hex(bytes: &[u8]) -> String` (lowercase hex).
  - `pub fn compress(bytes: &[u8]) -> Vec<u8>` / `pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, FormatError>` (zstd level 3; `FormatError::Decompress` on corrupt input — add variant).
  - `pub fn split_jsonl(jsonl: &str, cap: usize) -> Vec<Vec<u8>>` — greedy line algorithm (Global Constraints); returns COMPRESSED segments, each `≤ cap` unless a single line alone exceeds it. Empty input → empty vec. Input must end lines with `\n` (a final unterminated line is terminated first — document).
  - `pub fn assemble(segments: &[&[u8]]) -> Result<String, FormatError>` — decompress + concat; invalid UTF-8 → `FormatError::BadUtf8` (add variant).
  - Property tests: `assemble(split(x)) == normalized(x)` for arbitrary multi-line inputs; every emitted segment decompresses; identical input → identical bytes (determinism); boundary test at exactly the cap.

- [ ] **Step 1: Write failing unit + property tests in `segments.rs`**
- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p starforge-format segments`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `segments.rs`**

Check `zstd::stream::encode_all/decode_all` (or `zstd::bulk`) API before writing. Keep functions sync and dependency-free beyond `blake3`/`zstd`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p starforge-format`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforge-format
git commit -m "Add segment split/assemble with BLAKE3 and zstd"
```

---

### Task A5: Agent-output delimiters + README + docs close-out

**Files:**
- Create: `crates/starforge-format/src/agent.rs`
- Modify: `crates/starforge-format/src/lib.rs`, `README.md`
- Test: unit tests in `agent.rs`

**Interfaces:**
- Consumes: A1–A4.
- Produces:
  - `pub const UNTRUSTED_BEGINS: &str` / `UNTRUSTED_ENDS: &str` + `pub fn wrap_untrusted(text: &str) -> String` (Global Constraints; §11.2). Injection tests: content containing the ENDS marker, content with `<<<STARFORGE-` lines, empty content, content without trailing newline.
  - README gains a "Trace format and redaction" section (~12 lines): `docs/format/` normative spec, the two crates + their licenses, detector list + `.starforge/redact.toml` pointer, fingerprint/quarantine one-liner. Match README voice.

- [ ] **Step 1: Write failing `agent.rs` tests**
- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p starforge-format agent`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `agent.rs` + README section**
- [ ] **Step 4: Run tests**

Run: `cargo test -p starforge-format`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforge-format README.md
git commit -m "Add untrusted-data delimiters and document the format"
```

---
