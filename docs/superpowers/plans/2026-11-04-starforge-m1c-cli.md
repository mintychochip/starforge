# Starforge M1c (Developer CLI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `starforge` developer CLI that implements the client half of spec §7: device-flow login and credential storage (§7.6), server discovery via `GET /.well-known/starforge.json` or `.git/config` keys, `enable`/`disable` installing chaining git hooks plus agent hooks from `starforge-capture`, session discovery → client redaction → local spool (§7.3 layout exactly), segment split + BLAKE3, the upload protocol (§7.5: PUT metadata, PUT segments, POST complete, POST links; idempotent 409 semantics, 16 MiB cap, exponential backoff, push never fails because of upload), `sync`, and the `sessions list/show/link/unlink` + `status`/`doctor` commands from §10.3.

**Architecture:** One new binary+lib crate `starforge-cli` (`MIT OR Apache-2.0`, `publish = true`, binary `starforge`). Thin `main.rs` over a `cli.rs` (clap derive) dispatcher; one module per concern (`config`, `auth`, `discovery`, `hooks`, `git`, `spool`, `queue`, `upload`, `sessions`) plus `commands/*` handlers. The crate consumes `starforge-format` (SessionMeta/Event, `split_jsonl`, `blake3_hex`, `wrap_untrusted`), `starforge-redact` (`RuleSet::parse_toml`/`merge`/`compile`/`fingerprint`, `redact_event`/`redact_jsonl`), and `starforge-capture` (all five `Adapter`s, `Roots`, `Cursor`) exactly through their existing public APIs; it never re-specifies what M1a/M1b provide. No server code, no web UI.

**Tech Stack:** Rust 1.99.1 (edition 2024), clap 4 (derive, workspace), reqwest (workspace, blocking disabled — async via workspace tokio), serde/serde_json, thiserror, time, ulid, toml, zstd via `starforge-format`, tempfile (dev), axum (dev/stub server only — already in workspace).

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` §7.2 (commit linking), §7.3 (local spool), §7.4 (redaction), §7.5 (upload protocol), §7.6 (discovery + auth), §10.3 (CLI command table), §11.3–11.5, §13 (CLI end-to-end). Later milestones (server ingest M1d, Trails/web M2+, `trail` commands, `export`/`import`, `sessions publish/unpublish/delete`) consume this CLI; they are out of scope here.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide; workspace lints inherited.
- **License:** the new crate is `MIT OR Apache-2.0`. Root `[workspace.package]` license stays `AGPL-3.0-or-later`; the new crate sets `license = "MIT OR Apache-2.0"` explicitly (NOT `.workspace`), `publish = true`.
- **Dependencies:** crate deps inherit with `dep.workspace = true`. New workspace deps: NONE planned. `clap` and `reqwest` are already in `[workspace.dependencies]`; do not add a second HTTP or arg-parse stack. If C6 finds the pinned reqwest build has no TLS backend for `https://` servers, enable a TLS backend feature on the existing workspace `reqwest` entry (feature change only, no new crate) and record the exact feature name in the C6 commit message. Any other new dep must be named in the task, pinned in `[workspace.dependencies]`, and justified in one sentence; otherwise synthesize from std + workspace table.
- **No `$HOME`/env reads inside library code:** exactly one function touches environment — `CliPaths::resolve()` in `config.rs` (reads `STARFORGE_HOME`, then `HOME`/`USERPROFILE`). Every other function takes paths as parameters. Tests inject tempdirs via `STARFORGE_HOME` or explicit `CliPaths` values, never the real home.
- **No network in unit tests:** all HTTP is exercised against an in-process stub `axum` server (workspace already has `axum`) bound to `127.0.0.1:0`; tests assert request bodies (metadata fields, segment bytes/hash, link payloads). No external services, no live server.
- **No real sleeps in tests:** backoff/retry and device-flow polling take an injected `Sleeper` (prod = `tokio::time::sleep`; tests = fake that records durations). No sleep exceeding a few hundred ms anywhere in the test suite.
- **Windows-safe:** no unix-only code outside `#[cfg(unix)]`-gated permission bits; paths via `std::path` only; no symlinks; shell hook scripts are POSIX `sh` executed by git (same as every git hook) — the Rust side never assumes unix.
- **Determinism:** same native input + same cursors + same rules → byte-identical spool files (same `seq`, same segment bytes, same hashes). Tests assert file bytes and request bodies, never bare `is_ok()`.
- **Every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green.
- **Out of scope (do not build):** `trail` subcommands, `export`/`import`, `sessions publish/unpublish/delete`, any server code, any web UI, real OAuth against a live server.
- **Decisions this plan makes where the spec is silent:**
  - Argument parsing is `clap` derive (workspace `clap`, `derive` feature). One `Cli` enum in `cli.rs`; hidden `_*hook*` subcommands invoked by installed git hooks.
  - Hook chaining: an existing hook file without the `starforge` marker is moved to `<hook>.starforge-orig` (executable bit preserved); the installed dispatcher is a POSIX `sh` script with a `# starforge-managed` marker that runs the `.starforge-orig` file first (if present and executable), then the `starforge` hidden hook command, and always exits with the orig hook's semantics for `prepare-commit-msg` while `pre-push`/`post-commit` always exit `0`. `disable` deletes only marker-bearing dispatchers and restores `.starforge-orig`. Starforge never deletes or edits user hook code in place.
  - "OS keychain" (§7.6): v0.1 has NO keychain backend (no new deps). `STARFORGE_TOKEN` env wins when set; otherwise tokens live in `~/.config/starforge/credentials.toml` with mode `0600` (enforced via `#[cfg(unix)]` permission bits; on Windows the file lives under `%USERPROFILE%\.config\starforge\` and inherits the profile ACL — documented limitation). The TOML shape is per-server-host sections so a future keychain backend is a drop-in `store/load` swap.
  - Spool layout is exactly §7.3 (`sessions/<ULID>/meta.json`, `segments/<n>.jsonl.zst`, `raw/<n>.zst`, `cursors.json`, `links.jsonl`, `queue.jsonl` under `<git common dir>/starforge/`) plus ONE local-only file `sessions/<ULID>/upload.json` (`{uploaded_segments: {n: blake3}, complete: bool}`) that is never uploaded and exists only so re-uploads are idempotent without a server round-trip. Segment numbers start at `0`, contiguous.
  - `cursors.json` shape: `{"sessions": {"<agent>/<session_key>": {"ulid": "<ULID>", "cursor": {"offset":N,"lines":N,"events":N}, "native_path": "<path>"}}}` — the `Cursor` JSON is exactly `starforge_capture::Cursor`'s serde form.
  - `links.jsonl`: one object per line `{"ulid":..,"commit":"..","source":"trailer|cli_claim","confidence":"exact|heuristic","seq_start":N,"seq_end":N}`.
  - `queue.jsonl`: one object per line `{"op":"meta|segment|complete|links","ulid":..,"segment":N|null,"attempts":K,"not_before":"<RFC3339>"}`. The file is append-only during enqueue; `sync` rewrites it atomically (temp file + rename) after each op settles. Backoff is deterministic exponential: `min(300, 2^attempts)` seconds from the stored `not_before`; no jitter (determinism beats thundering-herd avoidance for a dev CLI).
  - `--dry-run` (on `enable`, `sync`, `sessions link/unlink`): print the planned actions, write nothing, exit `0`. `--verbose` (global): `tracing` debug level instead of info; default is human-readable one-line-per-action stderr, machine output only on stdout (`--format json` where offered).
  - Exit codes: `0` success (including hooks and `sync` that made progress); `1` operational error (not a repo, no server found, bad config, auth required); `2` `sync` finished with items still queued (will retry next trigger). Git hooks installed by this CLI ALWAYS exit `0` (a push never fails because of a session upload, per §7.5) except `prepare-commit-msg`, which propagates the previous hook's exit code when chaining.
  - Repo choice with several remotes: `starforge.repo` git-config value wins; else the remote named `starforge`; else `origin`; else `upstream`; else the first remote whose host answers `/.well-known/starforge.json`. All remote URLs are recorded in `meta.repo.remote_urls`; the chosen one is recorded in the queue entry's `repo` field. A repo with no remotes and no `starforge.server` config is an error (`exit 1`, "no server configured").
  - Device flow polling honors the server's `interval` via the injected `Sleeper`; gives up at `expires_in`.
  - `PUT segments/{n}` conveys the hash in an `X-Starforge-Blake3: <hex of the request body>` header (M1c-chosen convention; the M1d server must accept it, and can always recompute the hash itself). Bodies: metadata PUT = `SessionMeta` JSON; links POST = `{"links": [<links.jsonl objects>]}`; complete POST = `{}`.
  - Redaction precedence: `RuleSet::built_in().merge(&repo_file)` where the repo `.starforge/redact.toml` wins on every `Some` setting; absent repo file = built-ins. The resulting `fingerprint` is stored in `meta.redaction`, with accumulated per-detector `counts`. Raw slices are redacted with the same compiled set before compression.
  - Cross-task contract is exactly the Rust in Task C1 (`CliPaths`, `Credentials`, `ServerInfo`, `Spool`, `QueueEntry`, `UploadClient`, `Sleeper`). Later tasks consume these names/shapes verbatim — do not rename.

---

## File Structure

```
crates/starforge-cli/
  Cargo.toml                 MIT OR Apache-2.0, publish = true, [[bin]] starforge (C1)
  src/main.rs                #[tokio::main], tracing init, Cli dispatch (C1)
  src/cli.rs                 clap derive: auth/enable/disable/status/doctor/sync/sessions/* + hidden _hook-* (C1)
  src/config.rs              CliPaths::resolve (SOLE env reader), credentials-file load/store, repo .starforge/redact.toml load (C1)
  src/auth.rs                Credentials, device-flow client vs base_url, STARFORGE_TOKEN precedence (C2)
  src/discovery.rs           ServerInfo, well-known fetch, .git/config keys, remote pick order (C3)
  src/git.rs                 common-dir, remotes list, config get, hook paths, `git` runner (C3, used C5)
  src/spool.rs               Spool, session append (redact→split→compress→write), cursors/links/queue files (C4)
  src/queue.rs               QueueEntry, enqueue/rewrite, backoff due-check, Sleeper trait (C4/C6)
  src/upload.rs              UploadClient (PUT meta/segments, POST complete/links, 409 + retry) (C6)
  src/hooks.rs               dispatcher template, install/remove with .starforge-orig chaining (C5)
  src/sessions.rs            link-confidence select, trailer format, list/show/link/unlink logic (C5/C7)
  src/commands/mod.rs        shared handler context (Spool + ServerInfo + Credentials) (C2)
  src/commands/auth.rs       auth login/logout/status (C2)
  src/commands/enable.rs     enable/disable/status/doctor (C5, status/doctor finished C7)
  src/commands/sync.rs       sync loop over queue (C6)
  src/commands/sessions.rs   sessions list/show/link/unlink (C7)
  tests/auth_flow.rs         stub device-flow + login/logout/status (C2)
  tests/discovery.rs         stub well-known + temp-repo remote picking (C3)
  tests/spool.rs             fixture session → redact → spool layout + cursors (C4)
  tests/hooks.rs             temp repo install/chain/remove + trailer (C5)
  tests/upload.rs            stub §7.5 endpoints + retry/backoff incl. 409 (C6)
  tests/e2e_cli.rs           temp repo + fixture session → enable → commit → sync vs stub (C7)
  tests/fixtures/pi-session.jsonl   minimal Pi-shaped transcript incl. a planted `ghp_…` token (C4, reused C7)
README.md                    + CLI section (C7)
```

---

### Task C1: Crate wiring + CliPaths/config + CLI skeleton

**Files:**
- Create: `crates/starforge-cli/{Cargo.toml,src/main.rs,src/cli.rs,src/config.rs}`
- Modify: root `Cargo.toml` (workspace members pick up `crates/*` automatically — no change needed; verify).

**Interfaces:**
- Consumes: nothing (leaf wiring; later tasks consume this task's contract verbatim).
- Produces (all `pub`; cross-task contract — do not rename):
  ```rust
  // src/config.rs — the ONLY module that reads env/home in the whole crate.
  pub struct CliPaths {
      pub home: std::path::PathBuf,        // $STARFORGE_HOME, else $HOME / %USERPROFILE%
      pub config_dir: std::path::PathBuf,  // <home>/.config/starforge
      pub credential_file: std::path::PathBuf, // <config_dir>/credentials.toml
  }
  impl CliPaths {
      pub fn resolve() -> Self;            // sole std::env access; never fails (falls back to temp dir)
      pub fn from_home(home: std::path::PathBuf) -> Self; // tests + all non-root construction
  }

  // src/auth.rs (declared C1, implemented C2)
  #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
  pub struct Credentials { pub access_token: String, pub refresh_token: String, pub expires_at: String }
  // stored file shape: { [servers."<host>"] = Credentials }

  // src/discovery.rs (declared C1, implemented C3)
  #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
  pub struct ServerInfo { pub api_url: String, pub ssh_url: String, pub version: String }

  // src/spool.rs (declared C1, implemented C4)
  pub struct Spool { pub root: std::path::PathBuf } // <git common dir>/starforge
  impl Spool {
      pub fn open(common_dir: &std::path::Path) -> Self;
      pub fn ensure_layout(&self) -> std::io::Result<()>;
  }

  // src/queue.rs (declared C1, implemented C4/C6)
  #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
  pub struct QueueEntry {
      pub op: QueueOp, pub ulid: String, pub repo: String,
      pub segment: Option<u64>, pub attempts: u32, pub not_before: String, // RFC 3339
  }
  #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
  #[serde(rename_all = "lowercase")]
  pub enum QueueOp { Meta, Segment, Complete, Links }

  // src/upload.rs (declared C1, implemented C6)
  pub struct UploadClient { pub api_url: String, pub token: String, pub client: reqwest::Client }
  impl UploadClient {
      pub fn new(api_url: String, token: String) -> Self;
  }

  // src/queue.rs — injected clock for backoff + device-flow polling (C2/C6 implement users)
  #[async_trait::async_trait(?Send)] // via manual async fn desugar — NO new dep: plain trait with boxed future
  pub trait Sleeper { async fn sleep(&self, dur: std::time::Duration); }
  pub struct TokioSleeper;
  ```
  `Sleeper` is a plain `trait Sleeper { fn sleep(&self, dur: Duration) -> impl Future<Output=()> + '_; }` (RPITIT, no async-trait dep).
- `src/cli.rs`: clap derive `Cli { #[command(subcommand)] cmd: Cmd, #[arg(long, global)] verbose: bool, #[arg(long, global)] dry_run: bool }`, `Cmd::{Auth{AuthCmd}, Enable, Disable, Status, Doctor, Sync, Sessions{SessionsCmd}, #[command(hide=true)] HookPrepare{msg_file: PathBuf}, #[command(hide=true)] HookPostCommit, #[command(hide=true)] HookPrePush}` — every variant named here must exist (handlers land C2–C7; C1 wires them to `todo!()`-free "not yet implemented" errors, exit 1).
- `Cargo.toml`: `version/edition/rust-version.workspace = true`, `license = "MIT OR Apache-2.0"`, `publish = true`, `[[bin]] name = "starforge" path = "src/main.rs"`, `[lints] workspace = true`; deps: `clap`, `reqwest`, `tokio`, `serde`, `serde_json`, `thiserror`, `time`, `ulid`, `toml`, `tracing`, `tracing-subscriber`, `starforge-format`, `starforge-redact`, `starforge-capture` (all `.workspace = true`); dev-deps: `tempfile`, `axum`, `tokio` via workspace.

- [ ] **Step 1: Write the failing tests.** `src/config.rs` unit tests: `from_home` builds the three paths; `resolve` honors `STARFORGE_HOME` (set/restore around the test; serial — no parallel env mutation elsewhere in C1):
  ```rust
  #[test]
  fn cli_paths_from_home_shapes() {
      let p = CliPaths::from_home(std::path::PathBuf::from("/tmp/h"));
      assert_eq!(p.credential_file, std::path::PathBuf::from("/tmp/h/.config/starforge/credentials.toml"));
  }
  ```
  plus a `tests/cli_help.rs` smoke test asserting `starforge --help` lists `enable`, `sync`, `sessions`, `auth` (pins the §10.3 surface from day one).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-cli` — Expected: FAIL (crate does not exist).
- [ ] **Step 3: Implement wiring + CliPaths + clap skeleton.** Keep every non-`config.rs` module to its struct declarations + handler stubs returning `CliError::Unimplemented`; `main.rs` parses `Cli`, sets tracing (`RUST_LOG` or `--verbose` → debug), dispatches, maps exit codes (0/1/2 per constraints). Verify `cargo run -p starforge-cli -- --help` output names match the test.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-cli` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-cli
  git commit -m "Add starforge-cli skeleton with CliPaths and command surface"
  ```

---

### Task C2: Credentials + device flow + `auth login/logout/status`

**Files:**
- Create: `crates/starforge-cli/src/auth.rs`, `src/commands/mod.rs`, `src/commands/auth.rs`, `tests/auth_flow.rs`
- Modify: `src/main.rs`, `src/cli.rs` (wire `Auth` handlers), `src/config.rs` (credential file load/store helpers).

**Interfaces:**
- Consumes: C1 (`CliPaths`, `Sleeper`, error/exit-code mapping).
- Produces:
  ```rust
  // src/auth.rs
  pub fn token_for(paths: &CliPaths) -> Option<String>; // STARFORGE_TOKEN env wins; else None (file read is explicit below so callers can distinguish "no creds" from errors)
  pub fn load_credentials(paths: &CliPaths) -> Result<std::collections::BTreeMap<String, Credentials>, AuthError>;
  pub fn save_credentials(paths: &CliPaths, map: &std::collections::BTreeMap<String, Credentials>) -> Result<(), AuthError>; // parents + 0600 on unix
  pub fn credentials_for(map: &std::collections::BTreeMap<String, Credentials>, server_host: &str) -> Option<Credentials>;
  pub struct DeviceFlow { pub client: reqwest::Client, pub base_url: String } // base_url = api_url, no trailing slash
  impl DeviceFlow {
      pub fn new(base_url: String) -> Self;
      /// Runs POST /api/v1/oauth/device/code then polls POST /api/v1/oauth/token.
      /// Prints the user_code + verification_uri to stderr; polls every `interval`
      /// via `sleeper`; stops at `expires_in`. Returns tokens on `access_token` grant.
      pub async fn login(&self, sleeper: &dyn Sleeper) -> Result<Credentials, AuthError>;
  }
  #[derive(Debug, thiserror::Error)]
  pub enum AuthError { #[error("http: {0}")] Http(String), #[error("auth rejected: {0}")] Rejected(String), #[error("device flow expired")] Expired, #[error("i/o: {0}")] Io(String), #[error("config: {0}")] Config(String) }
  ```

- [ ] **Step 1: Write failing stub-server tests.** `tests/auth_flow.rs` spins an in-process `axum` stub implementing exactly `POST /api/v1/oauth/device/code` (returns `{device_code, user_code, verification_uri, verification_uri_complete, expires_in: 900, interval: 5}`) and `POST /api/v1/oauth/token` (first call returns `{"error":"authorization_pending"}`, second returns `{access_token, refresh_token: "r1", token_type: "Bearer", expires_in: 3600}`), asserting the device-code request body and the polling grant body (`grant_type == "urn:ietf:params:oauth:grant-type:device_code"`, `device_code` echoed); then `auth login` writes the per-host section to a `STARFORGE_HOME` credentials file with `0600` bits asserted on unix, `auth status` prints the host, `auth logout` removes the section (second logout errors exit 1). A fake `Sleeper` records sleep durations (asserting the second sleep used the server `interval`) and performs no real waiting. Also assert `STARFORGE_TOKEN` wins over the file in `token_for`.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-cli --test auth_flow` — Expected: FAIL (`DeviceFlow`/`login` do not exist).
- [ ] **Step 3: Implement `auth.rs` + `commands/auth.rs` + config file helpers.** Device-code request body `{"client_id": "starforge-cli"}`; token poll body includes `grant_type`, `device_code`, `client_id`. `expires_at` stored as RFC 3339 (`now + expires_in`). Never log tokens (assert by code review: only host + expiry appear in output). `0600` via `std::os::unix::fs::PermissionsExt` under `#[cfg(unix)]`.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-cli --test auth_flow` — Expected: PASS (login writes file, status shows host, logout clears, env precedence pinned, interval sleeps recorded).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-cli
  git commit -m "Add CLI device-flow login and credential management"
  ```

---

### Task C3: Server discovery (well-known + `.git/config`)

**Files:**
- Create: `crates/starforge-cli/src/discovery.rs`, `src/git.rs`, `tests/discovery.rs`
- Modify: `src/lib` wiring (`main.rs` module list), `src/commands/mod.rs` (shared `resolve_server(repo_path, paths)` helper used by C5–C7).

**Interfaces:**
- Consumes: C1 (`ServerInfo`, `CliPaths`), C2 (`token_for` for authenticated discovery — well-known itself is anonymous).
- Produces:
  ```rust
  // src/discovery.rs
  /// Probe each remote URL's host for GET {scheme}://{host}/.well-known/starforge.json
  /// (5 s timeout, anonymous). Only http(s) remotes are probed; file://, ssh:, and
  /// scp-style remotes without an http counterpart are skipped, never errors.
  pub async fn probe_well_known(client: &reqwest::Client, remote_url: &str) -> Option<ServerInfo>;
  /// Full resolution: starforge.server git-config wins; else per-remote well-known
  /// in remote pick order; starforge.repo supplies the owner/repo path.
  pub async fn resolve_server(client: &reqwest::Client, repo: &std::path::Path) -> Result<(ServerInfo, String, String), DiscoverError>;
  // returns (server, owner_repo "owner/repo", chosen_remote_url)
  /// Parse {"starforge": "<version>", "api_url": "<url>", "ssh_url": "<url>"}; rejects missing api_url.
  pub fn parse_well_known(body: &[u8]) -> Result<ServerInfo, DiscoverError>;
  // src/git.rs
  pub fn common_dir(repo: &std::path::Path) -> Result<std::path::PathBuf, GitError>; // git rev-parse --git-common-dir
  pub fn remotes(repo: &std::path::Path) -> Result<Vec<(String, String)>, GitError>; // (name, url) via git remote -v
  pub fn config_get(repo: &std::path::Path, key: &str) -> Result<Option<String>, GitError>; // git config --get
  pub fn pick_remote(remotes: &[(String, String)], configured: Option<&str>) -> Option<(String, String)>;
  ```
  Remote pick order (binding): `starforge.repo`-named remote? No — `configured` (`starforge.repo` is the `owner/repo` path, not a remote name): explicit `starforge.server` URL wins outright; else remote named `starforge` → `origin` → `upstream` → first remote with a well-known hit. Tests shell out to the system `git` binary (no git2 dep).

- [ ] **Step 1: Write failing tests.** `tests/discovery.rs`: (a) `parse_well_known` accepts the §7.6 shape and rejects a body missing `api_url`; (b) stub-axum `GET /.well-known/starforge.json` + temp git repo (`git init`, two remotes: `origin` → stub host, `backup` → dead host) asserting `resolve_server` picks `origin` and returns the stub `api_url`; (c) `starforge.server` git-config override wins over remotes (points at a second stub; assert its `api_url` returned and no request hit the first stub); (d) `starforge.repo = acme/app` supplies the `owner/repo` path; (e) repo with only a `file://` remote and no config errors (exit-path `DiscoverError::NoServer`, message names the repo).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-cli --test discovery` — Expected: FAIL (modules do not exist).
- [ ] **Step 3: Implement `discovery.rs` + `git.rs`.** Remote-URL host extraction handles `https://host/owner/repo(.git)`, `http://host:port/…`, and `user@host:owner/repo` (probe `https://host`); everything else is skipped. `reqwest` timeout 5 s, one retry, then `None` — discovery never fails a command by itself; only the final "no server anywhere" is an error.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-cli --test discovery` — Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-cli
  git commit -m "Add CLI server discovery via well-known and git config"
  ```

---

### Task C4: Spool (sessions/segments/raw/cursors/links/queue) with redaction + segmentation

**Files:**
- Create: `crates/starforge-cli/src/spool.rs`, `src/queue.rs`, `tests/spool.rs`, `tests/fixtures/pi-session.jsonl`
- Modify: `src/main.rs` (module list).

**Interfaces:**
- Consumes: C1 (`Spool`, `QueueEntry`/`QueueOp`), `starforge_format::{SessionMeta, split_jsonl, blake3_hex, DEFAULT_SEGMENT_CAP}`, `starforge_redact::{RuleSet, fingerprint, redact_jsonl}`, `starforge_capture::{Adapter, Roots, Cursor}` public APIs (no adapter internals).
- Produces:
  ```rust
  // src/spool.rs
  impl Spool {
      /// Discover new/grown sessions via `adapters` + stored cursors, read them,
      /// redact (built_in merged with <repo>/.starforge/redact.toml), split at
      /// DEFAULT_SEGMENT_CAP, compress, and append: returns per-session ULIDs + new segment numbers.
      /// Writes meta.json (SessionMeta with redaction fingerprint+counts, capture.cli_version),
      /// segments/<n>.jsonl.zst, raw/<n>.zst, updates cursors.json. Idempotent: no growth → no writes.
      pub fn ingest(&self, adapters: &[&dyn starforge_capture::Adapter], roots: &starforge_capture::Roots, repo_urls: &[String], branch: &str, head: &str) -> Result<Vec<Ingested>, SpoolError>;
      pub fn record_link(&self, ulid: &str, commit: &str, source: LinkSource, confidence: Confidence, seq_start: u64, seq_end: u64) -> Result<(), SpoolError>; // appends links.jsonl
      pub fn read_meta(&self, ulid: &str) -> Result<starforge_format::SessionMeta, SpoolError>;
      pub fn segment_bytes(&self, ulid: &str, n: u64) -> Result<Vec<u8>, SpoolError>; // exact compressed bytes (hash-stable)
  }
  pub struct Ingested { pub ulid: String, pub new_segments: Vec<u64>, pub events: u64 }
  // src/queue.rs
  pub fn enqueue(spool: &Spool, entry: QueueEntry) -> Result<(), QueueError>; // appends queue.jsonl
  pub fn read_queue(spool: &Spool) -> Result<Vec<QueueEntry>, QueueError>;
  pub fn rewrite_queue(spool: &Spool, entries: &[QueueEntry]) -> Result<(), QueueError>; // atomic temp+rename
  pub fn backoff_due(entry: &QueueEntry, now_rfc3339: &str) -> bool; // not_before <= now (pure, string-compare RFC3339)
  ```

- [ ] **Step 1: Write the failing spool test + fixture.** `tests/fixtures/pi-session.jsonl`: 3 Pi-shaped records (one user prompt, one assistant message containing a planted `ghp_0123456789abcdef0123456789abcdef0123` token, one tool record touching `src/lib.rs`). `tests/spool.rs` builds a temp repo dir, `Roots` pointing at the fixture, runs `Spool::ingest` with the real `PiAdapter` (COVERED version string read from the adapter, never hardcoded), then asserts: `sessions/<ULID>/meta.json` parses as `SessionMeta` with `agent.name == "pi"`, `redaction.fingerprint` == `fingerprint(&built_in)` recomputed in-test, `redaction.counts` non-empty; `segments/0.jsonl.zst` decompresses (via `starforge_format::decompress`) to JSONL containing NO `ghp_` substring and containing `[redacted:`; `raw/0.zst` likewise contains no secret; `cursors.json` holds the adapter cursor with `events == 3`-ish (exact: equals the emitted event count); second `ingest` with no growth writes no new segments (segment count unchanged). Every assertion pins bytes/counts, none asserts bare success.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-cli --test spool` — Expected: FAIL (`Spool::ingest` does not exist).
- [ ] **Step 3: Implement `spool.rs` + `queue.rs`.** ULID per new session via `ulid::Ulid::new()`; stable mapping `agent/session_key → ULID` persisted in `cursors.json` so resume reuses the ULID. Event `seq` continues from stored cursor (`next_seq`). `meta.json` written via `serde_json` only after segments+raw are fsynced (crash order). `redact_jsonl` on the normalized JSONL; raw native slice redacted as plain text lines then compressed (document: raw keeps line structure, values redacted).
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-cli --test spool` — Expected: PASS (secret absent from both blobs, fingerprint pinned, idempotent second run).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-cli
  git commit -m "Add CLI spool with redaction and segmentation"
  ```

---

### Task C5: Git hooks install/remove + `enable`/`disable` + trailer logic

**Files:**
- Create: `crates/starforge-cli/src/hooks.rs`, `src/sessions.rs` (link-select + trailer helpers), `src/commands/enable.rs`, `tests/hooks.rs`
- Modify: `src/cli.rs`, `src/main.rs` (wire `Enable`/`Disable`/hidden hook cmds), `src/git.rs` (hook-path helpers).

**Interfaces:**
- Consumes: C1 (`Spool`, exit codes), C3 (`common_dir`, `remotes`, `config_get`), C4 (`Spool::ingest`, `record_link`), `starforge_capture::Adapter::install_hooks/remove_hooks`.
- Produces:
  ```rust
  // src/hooks.rs
  pub const MANAGED_MARKER: &str = "# starforge-managed";
  /// Install dispatcher for `hook` (prepare-commit-msg|post-commit|pre-push) in <common_dir>/hooks.
  /// Existing non-managed file → moved to <hook>.starforge-orig. Returns path written.
  pub fn install_hook(common_dir: &std::path::Path, hook: &str) -> std::io::Result<std::path::PathBuf>;
  /// Remove dispatcher only if it carries the marker; restore .starforge-orig. Returns paths changed.
  pub fn remove_hook(common_dir: &std::path::Path, hook: &str) -> std::io::Result<Vec<std::path::PathBuf>>;
  pub fn dispatcher_body(hook: &str) -> String; // sh script calling starforge _hook-* then orig
  // src/sessions.rs
  /// §7.2 link selection: sessions whose files_touched ∩ staged files ≠ ∅ → exact;
  /// sessions active since last link with no file data → heuristic claim. Never duplicates a ULID already in the message.
  pub fn select_links(staged: &[String], candidates: &[SessionCandidate]) -> Vec<PendingLink>;
  pub fn trailer_line(ulid: &str) -> String; // format!("Starforge-Session: {ulid}")
  pub fn append_trailers(msg: &str, ulids: &[String]) -> String;
  ```

- [ ] **Step 1: Write failing hook tests.** `tests/hooks.rs` in a temp git repo: (a) `enable` installs all three dispatchers, each carrying the marker, prints every file changed, exit 0; (b) pre-existing `prepare-commit-msg` shell hook (appends `ORIG-LINE`) still runs after install — invoking the dispatcher yields both `ORIG-LINE` and the `Starforge-Session:` trailer for a fixture session whose `files_touched` overlaps the staged file (exact confidence pinned in `links.jsonl`); (c) `enable` twice is idempotent (no `.starforge-orig.starforge-orig`, dispatcher unchanged); (d) `disable` restores the original hook byte-for-byte and removes dispatchers (second `disable` changes nothing); (e) amend/rebase survival is asserted by message inspection (trailer is message text — assert the trailer line survives `git commit --amend --no-edit`).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-cli --test hooks` — Expected: FAIL (handlers do not exist).
- [ ] **Step 3: Implement `hooks.rs` + `sessions.rs` + `commands/enable.rs` + hidden `_hook-*` handlers.** `prepare-commit-msg` handler: run `discover`+`read` from stored cursors (via C4 `ingest`), compute staged files (`git diff --cached --name-only`), `select_links`, append trailers, `post-commit` records SHA + seq range. `pre-push` enqueues meta+segments+links ops (C4 queue) and attempts best-effort upload with a short timeout — ALWAYS exits 0. `enable` also calls each detected adapter's `install_hooks` (agent `Roots.config_dir` = repo-local agent config path or user config — document per adapter), `disable` reverses both and prints every path.
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-cli --test hooks` — Expected: PASS (chaining, idempotence, restore, trailer + confidence all pinned).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-cli
  git commit -m "Add CLI git hooks with chaining and session trailers"
  ```

---

### Task C6: Upload client + `sync` (idempotency, retry/backoff, never block push)

**Files:**
- Create: `crates/starforge-cli/src/upload.rs`, `src/commands/sync.rs`, `tests/upload.rs`
- Modify: `src/queue.rs` (`mark_due`, attempt bump — signatures fixed here), `src/cli.rs`/`main.rs` (wire `Sync`).

**Interfaces:**
- Consumes: C1 (`UploadClient`, `Sleeper`, `QueueEntry`), C4 (`segment_bytes`, `read_meta`, `read_queue`/`rewrite_queue`), C2 (token).
- Produces:
  ```rust
  // src/upload.rs
  impl UploadClient {
      /// PUT /api/v1/repos/{owner}/{repo}/sessions/{ulid} with SessionMeta JSON. 200/201 ok.
      pub async fn put_meta(&self, owner_repo: &str, meta: &starforge_format::SessionMeta) -> Result<(), UploadError>;
      /// PUT .../segments/{n} with zstd bytes + X-Starforge-Blake3. 200 ok; 409 with identical
      /// hash → treated as success (marks uploaded); 409 with different content → UploadError::Conflict (stops, never retries blindly).
      pub async fn put_segment(&self, owner_repo: &str, ulid: &str, n: u64, bytes: &[u8]) -> Result<(), UploadError>;
      /// POST .../complete with {}. POST .../links with {"links": [...]}.
      pub async fn post_complete(&self, owner_repo: &str, ulid: &str) -> Result<(), UploadError>;
      pub async fn post_links(&self, owner_repo: &str, ulid: &str, links: &[serde_json::Value]) -> Result<(), UploadError>;
  }
  // src/commands/sync.rs
  /// Drain due queue entries: meta → segments (in n order) → links → complete-when-eligible
  /// (adapter reports end OR 24 h without new events — v0.1: complete only when the spool
  /// session's meta has ended_at set, else leave uncompleted and succeed). Failures bump
  /// attempts + not_before (2^attempts s, cap 300) via injected now; exit 0 drained / 2 remainder.
  pub async fn sync(spool: &Spool, server: &ServerInfo, owner_repo: &str, token: &str, sleeper: &dyn Sleeper, now_rfc3339: &str, dry_run: bool) -> Result<SyncSummary, UploadError>;
  ```

- [ ] **Step 1: Write failing stub-server tests.** `tests/upload.rs` stub implements the four §7.5 endpoints, asserting: metadata body has `id`, `agent.name`, `redaction.fingerprint`; segment body bytes equal the spool's `segment_bytes` with matching `X-Starforge-Blake3`; links body carries the `commit` SHA; complete called last. Cases: (a) full drain empties the queue and writes `upload.json` (`uploaded_segments` hashes pinned); (b) re-`sync` after drain performs zero HTTP calls (idempotent via `upload.json` — stub counts requests); (c) stub returns `409` for segment 0 with a DIFFERENT hash → `sync` surfaces `Conflict`, leaves the entry queued with bumped attempts, exit would be 2; (d) first segment PUT fails `500` then succeeds: fake `Sleeper` records a backoff sleep (no real waiting), retry Drain succeeds; (e) 16 MiB cap: `split_jsonl` unit case with a tiny cap produces >1 segment and each compressed segment respects the cap (uses `split_jsonl_with_trigger`? No — public `split_jsonl` with small cap; asserts each output `<= cap` unless a single line exceeds it).
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-cli --test upload` — Expected: FAIL (client methods do not exist).
- [ ] **Step 3: Implement `upload.rs` + `sync.rs`.** Bearer auth (`STARFORGE_TOKEN`-or-file token). Retry only on 5xx/io/timeout (max 4 retries per entry per run, backoff via `Sleeper`); 4xx other than the idempotent-409 path is terminal for that entry (left queued, error reported, run continues with other entries). Request timeout 30 s. `--dry-run` lists ops, performs zero calls. The `pre-push` path calls `sync` with a 10 s overall deadline and ignores the result (always exit 0 — pinned by a C5-adjacent assertion in `tests/upload.rs`: best-effort wrapper returns `Ok` even when the stub is down).
- [ ] **Step 4: Run tests.** Run: `cargo test -p starforge-cli --test upload` — Expected: PASS (bodies asserted, idempotence with zero second-run calls, 409/conflict, backoff sleeps recorded).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-cli
  git commit -m "Add CLI upload client and sync with idempotent retry"
  ```

---

### Task C7: `sessions`/`status` commands + end-to-end test + docs close-out

**Files:**
- Create: `crates/starforge-cli/src/commands/sessions.rs`, `tests/e2e_cli.rs`
- Modify: `src/commands/enable.rs` (`status`/`doctor` full output), `src/cli.rs`, `src/main.rs`, `src/sessions.rs` (show formatting incl. `--format agent` untrusted delimiters), `README.md` (CLI section).

**Interfaces:**
- Consumes: every prior task (auth C2, discovery C3, spool/queue C4, hooks C5, upload/sync C6).
- Produces:
  ```rust
  // src/commands/sessions.rs
  pub fn list(spool: &Spool, format: OutputFormat) -> Result<String, SessionsError>; // table or json of ULID/agent/title/events/segments/uploaded
  pub fn show(spool: &Spool, ulid_prefix: &str, format: OutputFormat) -> Result<String, SessionsError>; // meta + links; agent format wraps past-session text via starforge_format::wrap_untrusted (§11.2)
  pub fn link(spool: &Spool, ulid_prefix: &str, commit: Option<&str>) -> Result<String, SessionsError>; // cli_claim/exact wrote to links.jsonl + queue op Links
  pub fn unlink(spool: &Spool, ulid_prefix: &str, commit: &str) -> Result<String, SessionsError>; // removes the links.jsonl line (rewrite)
  pub enum OutputFormat { Human, Json, Agent }
  // status: server api_url, chosen remote, hooks installed (3 paths), spooled sessions, queue depth, credential presence (host only, never tokens)
  // doctor: git version, hooks valid, spool readable, credentials present, well-known reachable — each line ok/fail, exit 1 on any fail
  ```

- [ ] **Step 1: Write the failing end-to-end test.** `tests/e2e_cli.rs`: temp git repo + `STARFORGE_HOME` tempdir + fixture `tests/fixtures/pi-session.jsonl` installed as a Pi store; stub axum serving `/.well-known/starforge.json` + all four §7.5 endpoints (recording bodies); run the built binary (via `cargo run --quiet -p starforge-cli --` or `env!("CARGO_BIN_EXE_starforge")`): `enable` (exit 0) → stage a file the fixture session touched → `commit` through the installed `prepare-commit-msg` dispatcher (assert `git log -1 --format=%B` contains exactly one `Starforge-Session: <ULID>` trailer) → `sync` (exit 0) → assert the stub received metadata whose `redaction.fingerprint` equals the in-test recomputed fingerprint, a segment whose decompressed JSONL contains NO `ghp_` secret and DOES contain `[redacted:`, and a links payload with the commit SHA; then `sessions list` shows the ULID, `sessions show <ulid>` prints agent `pi`, `sessions link <ulid> HEAD` + `unlink` round-trip (links.jsonl gains then loses the line), and `status` prints the stub host. No test asserts bare success: every step pins a file, a body, or a trailer.
- [ ] **Step 2: Run to verify failure.** Run: `cargo test -p starforge-cli --test e2e_cli` — Expected: FAIL (subcommands/handlers incomplete).
- [ ] **Step 3: Implement `commands/sessions.rs` + `status`/`doctor` output + README CLI section.** (~25 lines, matching README voice): install (`cargo install starforge-cli`), `auth login`, `enable`, trailer behavior, `sync`, spool location, credential fallback + `0600`, `STARFORGE_TOKEN`, well-known vs `starforge.server`/`starforge.repo` config, exit codes 0/1/2, `--dry-run`/`--verbose`. ULID prefixes resolve only when unambiguous (else exit 1 listing candidates).
- [ ] **Step 4: Run the full sweep.** Run: `cargo test -p starforge-cli` then `cargo test --workspace` — Expected: PASS everything (auth, discovery, spool, hooks, upload, e2e + all pre-existing M0/M0.5/M1a/M1b suites).
- [ ] **Step 5: Commit.**
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  git add crates/starforge-cli README.md
  git commit -m "Add CLI sessions commands, status, e2e test, and docs"
  ```
