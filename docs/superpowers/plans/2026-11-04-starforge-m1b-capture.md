# Starforge M1b (Capture Adapters) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `starforge-capture` library that normalizes the five agents' native transcripts (Claude Code, Codex CLI, Pi/omp, OpenCode, Gemini CLI/Antigravity) into Trace Format v1 `Event`s plus `SessionMeta` headers, with incremental cursors, unknown-version `unverified` marking, and golden-fixture tests per agent version.

**Architecture:** One new leaf crate `starforge-capture` (`MIT OR Apache-2.0`, `publish = true`). A shared `Adapter` trait plus `Cursor`/`Candidate`/`Roots` types in `src/{adapter,discover,cursor}.rs`, one parser module per agent under `src/agents/`, and golden-fixture + incremental-cursor integration tests. The crate depends on `starforge-format` only (never `starforge-redact`); redaction happens later in the CLI spool path.

**Tech Stack:** Rust 1.99.1 (edition 2024), serde/serde_json, thiserror, time, ulid, tempfile (dev), rusqlite (bundled, OpenCode only) — all via `[workspace.dependencies]`.

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` §5.1 (crate table), §6.3 (session/blob model), §7.1 (adapter contract), §7.8 (Trace Format v1 field tables), §11.2 (untrusted delimiters — not needed here, noted only), §13 (adapter golden tests). Later plans (CLI spool, git hooks, upload, server, viewer) consume this crate; they are out of scope here.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** the new crate is `MIT OR Apache-2.0`. Root `Cargo.toml` `[workspace.package]` license stays `AGPL-3.0-or-later`; the new crate sets `license = "MIT OR Apache-2.0"` explicitly (NOT `.workspace`), `publish = true`.
- **Dependencies:** crates inherit with `dep.workspace = true`. New workspace dep: `rusqlite = { version = "0.37", features = ["bundled"] }` — needed ONLY because OpenCode stores sessions in `opencode.db` (SQLite) and there is no other way to read them; `bundled` builds SQLite from C sources so it works on the CLI's Windows target with no system library. Everything else reuses the workspace table (`serde`, `serde_json`, `thiserror`, `time`, `ulid`; `tempfile` for tests). No other new dependency is permitted; if an agent module seems to need one, synthesize the parse from `serde_json`/string splitting instead.
- **No environment, no `$HOME`, no clock in this crate:** every adapter entry point takes the paths it needs as parameters (`Roots` below); `std::env` is forbidden. Callers supply timestamps: `read` takes a `fallback_ts: &str` (RFC 3339) used when a native record carries no timestamp.
- **No I/O outside the given roots:** adapters read native transcripts only under `Roots.data_dir` and write hook files only under `Roots.config_dir`. `install_hooks`/`remove_hooks` report every path they touch and never delete a file they did not write (recognized by the `starforge` marker comment).
- **Windows-safe:** no unix-only code anywhere in this crate (no `std::os::unix`, no symlink tricks, no mode bits); paths use `std::path` only.
- **No network. No redaction here:** adapters must NOT depend on `starforge-redact`; they emit raw normalized `Event`s. Redaction runs later in the CLI spool path.
- **Determinism:** same input bytes + same cursor → same events (same `seq`, same bytes). Tests assert event JSON bytes, not just parses.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green.
- **Raw-transcript storage note (binding, no code):** raw storage defaults ON for new repos; adapters therefore preserve every unmapped native field they can (extra text goes into the closest `text`/`output` field) so re-normalization after an adapter update is lossless. No M1b code follows from this beyond faithful mapping.
- **Decisions this plan makes where the spec is silent:**
  - The cross-task contract is exactly the Rust in Task B1 (trait `Adapter`, structs `Roots`, `Candidate`, `Cursor`, `ReadOutput`, `AdapterVersion`). Later tasks must not rename or reshape these.
  - `Cursor { offset: u64, lines: u64, events: u64 }` (`serde`, `Copy`, stable): for JSONL-file agents `offset` = bytes consumed, `lines` = records consumed and `events` = events emitted; for OpenCode `offset` = last SQLite `rowid` consumed, `lines` = rows consumed and `events` = events emitted. Never wall-clock, never mtime — stable across runs and machines. `seq` of the next emitted event equals `events` (0-based continuation), NOT `lines`, because one native record can carry several content blocks and therefore several events; resume never reuses, skips, or reorders a `seq`.
  - `discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate>`: returns native sessions whose working directory lies inside `roots.worktree`, filtered to sessions that are new (key not in `known`) or grew (current size/rowid beyond the stored cursor). Incremental filtering is the caller's stored-cursor lookup, not mtime.
  - `read(&self, candidate: &Candidate, cursor: &Cursor, fallback_ts: &str) -> Result<ReadOutput, CaptureError>`: parses only records after the cursor, returns `(events, next_cursor)` with `next` advanced past exactly the records read. Empty growth → empty `events`, cursor unchanged.
  - Unknown agent version: each adapter exposes `const COVERED: &[&str]` (exact pinned versions with fixtures). `fn version_status(&self, version: &str) -> AdapterVersion { covered: bool }` reports membership; `read` sets `header.capture.adapter_version_verified = status.covered` and still parses with the closest known parser. `AdapterName` reuses `starforge_format::AgentName` (`claude-code | codex | pi | opencode | gemini`); omp transcript versions and Antigravity store layouts are parsed best-effort and ALWAYS report `covered: false` (binding user decision, ships `unverified` in v0.1).
  - Hook scope: `install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>` writes at most one marker-commented JSON/settings snippet per agent under `roots.config_dir` and returns the paths written; `remove_hooks` removes only files containing the marker and returns the paths removed. Adapters without a hook story (Codex versions lacking hooks, OpenCode plugin path, Gemini/Antigravity discovery fallback) implement both as `Ok(vec![])` and document why.
  - Fixture layout: `crates/starforge-capture/tests/fixtures/<agent>/<version>/transcript.<jsonl|json|db.sql>` plus `expected.jsonl` (normalized events, one per line) plus `meta.json` (expected `SessionMeta` fields). `<agent>` is the `AgentName` kebab string (`claude-code`, `codex`, `pi`, `opencode`, `gemini`); omp fixtures live under `pi/omp-<version>/`, Antigravity under `gemini/antigravity-<version>/`. When no real transcript is available the fixture is synthesized in the native shape and the fixture directory contains `SYNTHESIZED.txt` saying so plus what native source it mimics. An `unknown/` version directory per agent proves closest-parser parsing + `adapter_version_verified == false`.
  - `fallback_ts` must itself be RFC 3339; `read` validates it with `time` and returns `CaptureError::BadTimestamp` otherwise — adapters never invent time silently.
  - Compaction/summary native records map to `EventKind::Compaction { summary }`; they are ordinary records for cursor purposes (consumed, counted in `lines`, assigned `seq`).

---

## File Structure

```
crates/starforge-capture/
  Cargo.toml                 MIT OR Apache-2.0, publish = true (B1)
  src/lib.rs                 re-exports + crate docs (B1, extended B2–B6)
  src/adapter.rs             Adapter trait, Roots, Candidate, ReadOutput, AdapterVersion, CaptureError (B1)
  src/cursor.rs              Cursor { offset, lines }, advance/helpers, serde round-trip (B1)
  src/discover.rs            workdir-prefix matching helper shared by all adapters (B1, used B6)
  src/agents/mod.rs          re-exports (B2)
  src/agents/claude.rs       Claude Code JSONL adapter (B2)
  src/agents/codex.rs        Codex CLI rollout-JSONL adapter (B3)
  src/agents/pi.rs           Pi JSONL + omp sessions adapter (B4)
  src/agents/opencode.rs     OpenCode SQLite/file adapter (B5)
  src/agents/gemini.rs       Gemini CLI chats + Antigravity adapter (B5)
  tests/golden_claude.rs     Claude golden + unknown-version tests (B2)
  tests/golden_codex.rs      Codex golden + unknown-version tests (B3)
  tests/golden_pi.rs         Pi/omp golden + unknown-version tests (B4)
  tests/golden_opencode.rs   OpenCode golden + unknown-version tests (B5)
  tests/golden_gemini.rs     Gemini/Antigravity golden + unknown-version tests (B5)
  tests/incremental.rs       cross-agent growing-transcript + compaction-boundary tests (B6)
  tests/fixtures/
    claude-code/<version>/transcript.jsonl, expected.jsonl, meta.json (+ SYNTHESIZED.txt where applicable)
    codex/<version>/transcript.jsonl, expected.jsonl, meta.json (+ …)
    pi/<version>/… ; pi/omp-<version>/… (+ SYNTHESIZED.txt, always unverified)
    opencode/<version>/transcript.sql, expected.jsonl, meta.json (+ …)
    gemini/<version>/… ; gemini/antigravity-<version>/… (+ SYNTHESIZED.txt, always unverified)
Cargo.toml                   + rusqlite workspace dep (B1)
Cargo.lock                   updated by cargo (B1)
README.md                    + capture-adapters section (B6)
```

---

### Task B1: Workspace wiring + trait/cursor/discover contract

**Files:**
- Modify: `Cargo.toml` (1 workspace dep), `Cargo.lock` (via cargo)
- Create: `crates/starforge-capture/{Cargo.toml,src/lib.rs,src/adapter.rs,src/cursor.rs,src/discover.rs}`

**Interfaces:**
- Consumes: `starforge_format::{AgentName, CaptureMode, Event, SessionMeta}` (already on main).
- Produces (all `pub`; later tasks consume these names/shapes verbatim — do not rename):
  ```rust
  // src/adapter.rs
  use std::collections::HashMap;
  use std::io;
  use std::path::{Path, PathBuf};
  use starforge_format::{AgentName, Event, SessionMeta};

  /// All paths an adapter may touch. No env, no `$HOME`: callers build this.
  pub struct Roots {
      pub config_dir: PathBuf,  // hook files may be written ONLY here
      pub data_dir: PathBuf,    // native session stores are read ONLY under here
      pub worktree: PathBuf,   // discover keeps sessions whose workdir is inside here
  }

  /// One native session found by `discover`.
  pub struct Candidate {
      pub session_key: String,   // stable id within the agent store (file stem, rollout name, row id…)
      pub native_path: PathBuf,  // exact file (or db file) to read; must be under `Roots.data_dir`
      pub agent_version: String, // native version string observed for this session
      pub workdir: PathBuf,      // session working directory (prefix-matched against `Roots.worktree`)
  }

  /// What `read` returns: new events plus the advanced cursor plus the header.
  pub struct ReadOutput {
      pub events: Vec<Event>,
      pub next: Cursor,         // advanced past exactly the records read
      pub header: SessionMeta,  // SessionMeta-shaped header; `capture.adapter_version_verified` set from `version_status`
  }

  /// Whether `agent_version` is covered by golden fixtures.
  pub struct AdapterVersion { pub covered: bool }

  #[derive(Debug, thiserror::Error)]
  pub enum CaptureError {
      #[error("native transcript is not valid JSONL/JSON: {0}")]
      BadNative(String),
      #[error("cursor points past end of transcript (offset {0} > len {1})")]
      CursorBeyondEnd(u64, u64),
      #[error("bad fallback timestamp (must be RFC 3339): {0}")]
      BadTimestamp(String),
      #[error("sqlite error: {0}")]
      Sqlite(String),
      #[error("i/o error: {0}")]
      Io(#[from] io::Error),
  }

  pub trait Adapter {
      fn id(&self) -> AgentName;
      /// Exact native versions pinned by golden fixtures in `tests/fixtures/<agent>/<version>/`.
      const COVERED: &[&str];
      fn version_status(&self, version: &str) -> AdapterVersion {
          AdapterVersion { covered: Self::COVERED.contains(&version) }
      }
      /// True when the agent's store markers exist under `roots.data_dir`.
      fn detect(&self, roots: &Roots) -> bool;
      /// Write hook integration under `roots.config_dir` only; return paths written.
      fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;
      /// Remove only files containing the starforge marker; return paths removed.
      fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;
      /// Sessions under `roots.worktree` that are new or grew past `known`.
      fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate>;
      /// Parse records after `cursor`; empty growth → empty events, cursor unchanged.
      fn read(&self, candidate: &Candidate, cursor: &Cursor, fallback_ts: &str) -> Result<ReadOutput, CaptureError>;
  }
  ```
  ```rust
  // src/cursor.rs
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
  pub struct Cursor { pub offset: u64, pub lines: u64 }
  impl Cursor {
      pub fn start() -> Self { Self { offset: 0, lines: 0 } }
      /// Next `seq` to assign: resume never reuses or skips a `seq`.
      pub fn next_seq(&self) -> u64 { self.lines }
  }
  ```
  ```rust
  // src/discover.rs
  /// True when `workdir` lies inside `worktree` (prefix match on path components).
  pub fn workdir_inside(worktree: &Path, workdir: &Path) -> bool;
  ```
- `src/lib.rs` re-exports `adapter::{Adapter, AdapterVersion, Candidate, CaptureError, ReadOutput, Roots}`, `cursor::Cursor`, `discover::workdir_inside`, and documents the spec section implemented (§7.1) plus the no-env/no-clock/no-redact rules.
- `Cargo.toml`: `version/edition/rust-version.workspace = true`, `license = "MIT OR Apache-2.0"`, `publish = true`, `[lints] workspace = true`; deps: `serde`, `serde_json`, `thiserror`, `time`, `ulid`, `starforge-format` (path) via workspace; `rusqlite` via workspace (used only by `agents/opencode.rs` in B5); dev-deps: `tempfile` via workspace.

- [ ] **Step 1: Write the failing contract test.** Create `src/cursor.rs` + `src/adapter.rs` + `src/discover.rs` signatures is B1's green; first write a unit test in `src/cursor.rs` asserting `Cursor::start() == Cursor { offset: 0, lines: 0 }`, `next_seq() == 0`, and a serde round-trip `serde_json::to_string(&Cursor { offset: 7, lines: 3 })` → parse back equal:
  ```rust
  #[test]
  fn cursor_start_and_round_trip() {
      let c = Cursor::start();
      assert_eq!(c.next_seq(), 0);
      let s = serde_json::to_string(&c).unwrap();
      assert_eq!(serde_json::from_str::<Cursor>(&s).unwrap(), c);
  }
  ```
  and a `src/discover.rs` test asserting `workdir_inside("/repo", "/repo/sub")` is true while `workdir_inside("/repo", "/other")` and `workdir_inside("/repo", "/repo2")` are false (component-wise, not string prefix).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-capture` — Expected: FAIL (crate/modules do not exist).
- [ ] **Step 3: Implement the wiring + contract.** Add `rusqlite` to workspace `Cargo.toml`; create the crate with the exact types above; check `starforge_format::AgentName` variant names (`ClaudeCode`, `Codex`, `Pi`, `Opencode`, `Gemini`) before writing `id()` docs. Keep `discover.rs` to the one helper; per-agent `discover` logic lands in B2–B6.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-capture` — Expected: PASS (cursor + workdir tests).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add Cargo.toml Cargo.lock crates/starforge-capture
  git commit -m "Add starforge-capture skeleton with Adapter trait and Cursor"
  ```

---

### Task B2: Claude Code adapter + fixtures

**Files:**
- Create: `crates/starforge-capture/src/agents/mod.rs`, `src/agents/claude.rs`, `tests/golden_claude.rs`, `tests/fixtures/claude-code/<version>/{transcript.jsonl,expected.jsonl,meta.json}` (one directory per covered version, ≥1 version) + `tests/fixtures/claude-code/unknown/{transcript.jsonl,expected.jsonl,meta.json}`.
- Modify: `crates/starforge-capture/src/lib.rs` (register `agents` module).

**Interfaces:**
- Consumes: B1 (`Adapter`, `Roots`, `Candidate`, `Cursor`, `ReadOutput`, `CaptureError`).
- Produces:
  ```rust
  // src/agents/claude.rs
  pub struct ClaudeAdapter;
  impl Adapter for ClaudeAdapter {
      fn id(&self) -> AgentName; // AgentName::ClaudeCode
      const COVERED: &[&str];    // e.g. &["1.2.3"] — exact dir names under tests/fixtures/claude-code/
      fn detect(&self, roots: &Roots) -> bool;    // true when <data_dir>/projects/<slug> exists
      fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>; // writes <config_dir>/claude-code/settings.json snippet with marker; returns [path]
      fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;  // removes it only if marker present
      fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate>;
      fn read(&self, candidate: &Candidate, cursor: &Cursor, fallback_ts: &str) -> Result<ReadOutput, CaptureError>;
  }
  ```
  Native mapping (Claude `~/.claude/projects/<slug>/<id>.jsonl` lines: `user`/`assistant`/`tool_use`/`tool_result`/`summary` records): `user` → `user_message{text}`; `assistant` text → `assistant_message{text, model, usage}` (usage counters summed into the header `usage`); thinking blocks → `reasoning{text}`; `tool_use` → `tool_call{tool{name,input}}`; `tool_result` → `tool_result{result{output,is_error,truncated,original_bytes}}`; `summary`/compact records → `compaction{summary}`; file-edit tool calls (`Edit`/`Write`) additionally append repo-relative paths to `header.files_touched`. `header.agent = {ClaudeCode, <agent_version>}`, `header.models` = distinct models seen, `header.capture.mode = Discovery` (hook mode sets `Hook` only when hook events supplied them — out of scope; B2 always `Discovery`).

- [ ] **Step 1: Write failing golden test.** `tests/golden_claude.rs` drives tempdirs (never `$HOME`): writes the pinned fixture transcript bytes into `<tmp>/data/projects/<slug>/`, builds `Roots { config_dir, data_dir: <tmp>/data, worktree }`, asserts `detect` true, `discover` finds the session, `read` from `Cursor::start()` yields events whose JSON bytes equal `expected.jsonl` line-for-line, `seq` is `0..n` contiguous, every `kind`/`text`/`tool.name` matches, and `header` fields (`agent.name == "claude-code"`, `capture.adapter_version_verified == true`, usage totals) equal `meta.json`:
  ```rust
  #[test]
  fn claude_golden_pinned_version() {
      let tmp = tempfile::tempdir().unwrap();
      // copy tests/fixtures/claude-code/<V>/transcript.jsonl under data/projects/…
      let roots = Roots { config_dir: tmp.path().join("cfg"), data_dir: tmp.path().join("data"), worktree: tmp.path().join("repo") };
      let a = ClaudeAdapter;
      assert!(a.detect(&roots));
      let found = a.discover(&roots, &HashMap::new());
      assert_eq!(found.len(), 1);
      let out = a.read(&found[0], &Cursor::start(), "2026-11-04T12:00:00Z").unwrap();
      let expected = std::fs::read_to_string(fixture("expected.jsonl")).unwrap();
      let got: Vec<String> = out.events.iter().map(|e| serde_json::to_string(e).unwrap()).collect();
      assert_eq!(got.join("\n") + "\n", expected);
      assert!(out.header.capture.adapter_version_verified);
  }
  ```
  plus an unknown-version test reading `tests/fixtures/claude-code/unknown/` asserting identical event bytes but `adapter_version_verified == false`, and a hooks test asserting `install_hooks` writes exactly one path under `config_dir` and `remove_hooks` removes it (second `remove_hooks` returns empty).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-capture --test golden_claude` — Expected: FAIL (`ClaudeAdapter` does not exist).
- [ ] **Step 3: Create fixtures, then implement `claude.rs`.** Write the fixture trio first (synthesize the transcript shape when no real transcript is available and add `SYNTHESIZED.txt`); check `starforge_format::Event` construction + `kind_name` expectations before writing the mapper. Byte-offset cursor: after reading record `i`, `next = Cursor { offset: bytes consumed through line i, lines: i + 1 }`; validate `cursor.offset <= file len` else `CursorBeyondEnd`; a cursor mid-line is rounded back to the previous `\n` (document). Missing native timestamps use `fallback_ts` (validated RFC 3339 via `time`).
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-capture --test golden_claude` — Expected: PASS (golden + unknown + hooks).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-capture
  git commit -m "Add Claude Code capture adapter with golden fixtures"
  ```

---

### Task B3: Codex CLI adapter

**Files:**
- Create: `crates/starforge-capture/src/agents/codex.rs`, `tests/golden_codex.rs`, `tests/fixtures/codex/<version>/{transcript.jsonl,expected.jsonl,meta.json}` + `tests/fixtures/codex/unknown/{…}`.
- Modify: `crates/starforge-capture/src/agents/mod.rs`, `src/lib.rs` (re-export).

**Interfaces:**
- Consumes: B1 contract; follows the B2 module pattern (no B2 code dependency).
- Produces:
  ```rust
  // src/agents/codex.rs
  pub struct CodexAdapter;
  impl Adapter for CodexAdapter {
      fn id(&self) -> AgentName; // AgentName::Codex
      const COVERED: &[&str];
      fn detect(&self, roots: &Roots) -> bool;    // true when <data_dir>/sessions/YYYY/MM/DD exists
      fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>; // Ok(vec![]) — Codex versions with hooks are handled by discovery until a hook story is pinned; document
      fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;  // Ok(vec![])
      fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate>; // walks rollout-*.jsonl
      fn read(&self, candidate: &Candidate, cursor: &Cursor, fallback_ts: &str) -> Result<ReadOutput, CaptureError>;
  }
  ```
  Native mapping (Codex `sessions/YYYY/MM/DD/rollout-*.jsonl`: `response`/`function_call`/`function_call_output`/`compacted` records): prompt text → `user_message`; model output → `assistant_message` with `usage`; `function_call` → `tool_call`; outputs → `tool_result`; `compacted` records → `compaction{summary}`; reasoning summaries → `reasoning`. Rolling-window compaction: a `compacted` record closes prior context — the adapter still emits every record exactly once in file order (no reordering, no dropping); the incremental test in B6 pins this.

- [ ] **Step 1: Write failing golden test.** Same shape as B2 step 1: tempdir store `<tmp>/data/sessions/2026/11/04/rollout-*.jsonl`, `detect`/`discover`/`read` assertions, byte-equal `expected.jsonl`, contiguous `seq`, `header.agent.name == "codex"`, verified flag true; unknown-version fixture asserting same events with `adapter_version_verified == false`.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-capture --test golden_codex` — Expected: FAIL (`CodexAdapter` does not exist).
- [ ] **Step 3: Create fixtures, then implement `codex.rs`.** Same cursor semantics as B2 (byte offset + lines; `CursorBeyondEnd`; mid-line rounds back). Document why hooks return empty for now.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-capture --test golden_codex` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-capture
  git commit -m "Add Codex CLI capture adapter with golden fixtures"
  ```

---

### Task B4: Pi/omp adapter

**Files:**
- Create: `crates/starforge-capture/src/agents/pi.rs`, `tests/golden_pi.rs`, `tests/fixtures/pi/<version>/{transcript.jsonl,expected.jsonl,meta.json}` + `tests/fixtures/pi/omp-<version>/{…}` (with `SYNTHESIZED.txt`; always `unverified`) + `tests/fixtures/pi/unknown/{…}`.
- Modify: `crates/starforge-capture/src/agents/mod.rs`, `src/lib.rs`.

**Interfaces:**
- Consumes: B1 contract; B2 module pattern.
- Produces:
  ```rust
  // src/agents/pi.rs
  pub struct PiAdapter;
  impl Adapter for PiAdapter {
      fn id(&self) -> AgentName; // AgentName::Pi — omp shares the Pi agent name per §7.8's 5-name table
      const COVERED: &[&str];    // Pi versions only; "omp-*" versions are NEVER members
      fn version_status(&self, version: &str) -> AdapterVersion; // override: false for any "omp-" prefixed version (binding: omp ships unverified)
      fn detect(&self, roots: &Roots) -> bool;    // true when <data_dir>/sessions (Pi) or <data_dir>/omp/agent/sessions exists
      fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>; // Pi extension-event snippet under config_dir; omp side: Ok(vec![]) documented
      fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;
      fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate>; // both store layouts
      fn read(&self, candidate: &Candidate, cursor: &Cursor, fallback_ts: &str) -> Result<ReadOutput, CaptureError>;
  }
  ```
  Native mapping (Pi documented JSONL session format; omp `~/.omp/agent/sessions/` JSONL): messages → `user_message`/`assistant_message`; tool executions → `tool_call`/`tool_result`; subagent spawn/finish → `subagent_start`/`subagent_end{subagent_id, task}`; session summaries → `compaction`. omp records parse with the same mapper; any omp-only record shape falls back to `system{text: <raw JSON>}` (never dropped, never an error) and the header is always `adapter_version_verified == false` for omp versions.

- [ ] **Step 1: Write failing golden tests.** Pi pinned-version test (byte-equal events, contiguous `seq`, `agent.name == "pi"`, verified true) + omp test (parses, event kinds asserted per record, `seq` contiguous, verified FALSE) + unknown-Pi-version test (verified false, same parser) + hooks round-trip test. All stores under tempdirs.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-capture --test golden_pi` — Expected: FAIL (`PiAdapter` does not exist).
- [ ] **Step 3: Create fixtures, then implement `pi.rs`.** omp fixture always carries `SYNTHESIZED.txt` unless a real omp transcript was available; unknown-shape records must map to `system`, asserted in the omp fixture by including at least one such record.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-capture --test golden_pi` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-capture
  git commit -m "Add Pi and omp capture adapters with golden fixtures"
  ```

---

### Task B5: OpenCode + Gemini/Antigravity adapters

**Files:**
- Create: `crates/starforge-capture/src/agents/opencode.rs`, `src/agents/gemini.rs`, `tests/golden_opencode.rs`, `tests/golden_gemini.rs`, `tests/fixtures/opencode/<version>/{transcript.sql,expected.jsonl,meta.json}` + `tests/fixtures/opencode/unknown/{…}`, `tests/fixtures/gemini/<version>/{transcript.json,expected.jsonl,meta.json}` + `tests/fixtures/gemini/antigravity-<version>/{…}` (with `SYNTHESIZED.txt`; always `unverified`) + `tests/fixtures/gemini/unknown/{…}`.
- Modify: `crates/starforge-capture/src/agents/mod.rs`, `src/lib.rs`.

**Interfaces:**
- Consumes: B1 contract (+ `rusqlite` workspace dep for OpenCode only); B2–B4 module pattern.
- Produces:
  ```rust
  // src/agents/opencode.rs
  pub struct OpencodeAdapter;
  impl Adapter for OpencodeAdapter {
      fn id(&self) -> AgentName; // AgentName::Opencode
      const COVERED: &[&str];
      fn detect(&self, roots: &Roots) -> bool;    // true when <data_dir>/opencode.db exists (or file-storage dir, by version)
      fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>; // Ok(vec![]) until a plugin-event story is pinned; document
      fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;  // Ok(vec![])
      fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate>; // one Candidate per session row-set newer than known
      fn read(&self, candidate: &Candidate, cursor: &Cursor, fallback_ts: &str) -> Result<ReadOutput, CaptureError>;
  }
  // Cursor semantics for OpenCode: `offset` = last SQLite rowid consumed (0 = none), `lines` = rows consumed; next read selects rowid > offset in rowid order.
  // File-storage versions (by version): same trait methods over message JSON files; cursor falls back to byte-offset semantics; both paths share COVERED gating.
  // src/agents/gemini.rs
  pub struct GeminiAdapter;
  impl Adapter for GeminiAdapter {
      fn id(&self) -> AgentName; // AgentName::Gemini — Antigravity shares the Gemini agent name per §7.8
      const COVERED: &[&str];    // Gemini CLI versions only; "antigravity-*" NEVER members
      fn version_status(&self, version: &str) -> AdapterVersion; // override: false for "antigravity-*" (binding: ships unverified)
      fn detect(&self, roots: &Roots) -> bool;    // true when <data_dir>/tmp/<hash>/chats exists or the Antigravity store dir exists
      fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>; // Ok(vec![]) — discovery only until a hook story is pinned; document
      fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;  // Ok(vec![])
      fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate>;
      fn read(&self, candidate: &Candidate, cursor: &Cursor, fallback_ts: &str) -> Result<ReadOutput, CaptureError>;
  }
  ```
  OpenCode mapping (SQLite message/part rows or file-storage JSON): user/model/tool records → the matching `EventKind`s; file-write parts → `file_change{path, change, diff: None}` plus `files_touched`; session-summary rows → `compaction`. Gemini mapping (`chats/` JSON): prompts → `user_message`; responses → `assistant_message`; tool records → `tool_call`/`tool_result`. Antigravity records parse with the same mapper; unmapped shapes → `system{text: <raw JSON>}`, always `adapter_version_verified == false`.

- [ ] **Step 1: Write the two failing golden suites.** `tests/golden_opencode.rs`: build the SQLite db in a tempdir by executing the fixture `transcript.sql` with `rusqlite` (no committed binaries), then `detect`/`discover`/`read` asserting byte-equal `expected.jsonl`, contiguous `seq`, `agent.name == "opencode"`, verified true; plus unknown-version db asserting verified false. `tests/golden_gemini.rs`: pinned Gemini CLI test (verified true) + Antigravity test (parses, kinds asserted, verified FALSE) + unknown test (verified false). Fixture SQL/JSON synthesized where no real transcript exists → each such dir gets `SYNTHESIZED.txt`.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-capture --test golden_opencode --test golden_gemini` — Expected: FAIL (adapters do not exist).
- [ ] **Step 3: Create fixtures, then implement `opencode.rs` + `gemini.rs`.** Check `rusqlite` bundled open/query API before writing; keep SQLite reads read-only (`open` + `SELECT`, never `CREATE`/write). OpenCode cursor uses rowid semantics (documented above); Gemini uses byte-offset semantics like B2.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-capture --test golden_opencode --test golden_gemini` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-capture
  git commit -m "Add OpenCode and Gemini capture adapters with golden fixtures"
  ```

---

### Task B6: Discovery sweep + incremental cursors + unknown-version conformance + docs

**Files:**
- Create: `crates/starforge-capture/tests/incremental.rs`
- Modify: `README.md` (capture-adapters section), `crates/starforge-capture/src/lib.rs` (final crate docs)

**Interfaces:**
- Consumes: B1 contract + B2–B5 adapters (all five `Adapter` impls, no signature changes).
- Produces:
  - `tests/incremental.rs`: for EACH of the five adapters — (a) growing-transcript test: `read` from `start`, append records to the native store, `read` again from the returned cursor yields ONLY the new events with `seq` continuing (`next_seq` == first new `seq`), and the concatenation equals a fresh full `read`; (b) compaction-boundary test: append a `summary`/`compacted` record and assert it maps to exactly one `compaction` event and the cursor advances past it; (c) discover-incrementality: `discover` with the post-read cursor map returns no candidates, and returns the session again after growth. For OpenCode the "append" is an `INSERT`; cursor uses rowid semantics.
  - Unknown-version conformance sweep: one test iterating all five adapters asserting `version_status("v0.0.0-unknown") == { covered: false }` and that `read` on each `unknown/` fixture still parses with `adapter_version_verified == false`.
  - README section (~12 lines, matching README voice): what `starforge-capture` does, the five adapters + omp/Antigravity `unverified` note, fixture policy pointer, raw-storage-ON note.

- [ ] **Step 1: Write the failing incremental + conformance tests.** One `#[test]` per adapter per case (15 growth/compaction/discover tests + 1 sweep = 16 tests), each asserting non-trivial content: new-event `kind`s, contiguous `seq` across the resume boundary, byte-equality of concatenation vs. full read, and `compaction.summary` text. No test that asserts nothing: every test pins at least event kinds + `seq` + one payload field.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-capture --test incremental` — Expected: FAIL (test file does not exist; if scaffolding exists, growth tests fail on uncovered edge cases).
- [ ] **Step 3: Fix adapter resume bugs + write README section.** Run each adapter's growth test and fix off-by-one cursor advance, mid-line rounding, or rowid comparison bugs in place (no contract changes). Add the README section.
- [ ] **Step 4: Run the full sweep.** Run: `cargo test -p starforge-capture` then `cargo test --workspace` — Expected: PASS everything (all golden + incremental + pre-existing M0/M0.5/M1a suites).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-capture README.md
  git commit -m "Add capture discovery sweep, incremental tests, and docs"
  ```
