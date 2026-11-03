# Starforge M0 (Hosting Skeleton) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single `starforged` binary that hosts git repositories over smart HTTP with local accounts, personal access tokens, user-owned repositories with collaborators, a minimal REST API, and server-rendered code, history, and diff browsing — on SQLite by default or Postgres.

**Architecture:** One Cargo workspace. `starforged-db` holds portable SQL (sqlx `Any` driver, one schema per engine). `starforged-core` holds every domain rule and is the only path to stored state. `starforged-git` runs `git` for the network protocol and diffs and uses gix for reads. `starforged-web` (HTML + git smart HTTP) and `starforged-api` (`/api/v1`) are thin HTTP layers over core. `starforged` is the binary: config, `init`, `serve`, `migrate`, `admin`, and the git `hook` entry point.

**Tech Stack:** Rust 1.99.1 (edition 2024), tokio, axum 0.8, sqlx 0.9 (`Any` + SQLite + Postgres), askama 0.16, gix 0.90, system `git` ≥ 2.38, argon2 0.6, comrak 0.59 + ammonia 4.

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` (milestone M0 in §14). Read §5 (architecture), §6.1 (access), §8.1–§8.2 (git transport and ref policy), §9 (auth), §11 (security), §12 (operations) before starting.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide.
- **Runtime:** system `git` 2.38 or newer on `PATH` (spec §5.5). `starforged serve` refuses to start otherwise.
- **License:** every M0 crate is `AGPL-3.0-or-later` (spec D8). The MIT OR Apache-2.0 crates arrive in M1.
- **Dependencies:** versions exactly as in the root `Cargo.toml` `[workspace.dependencies]` table written in Task 1. Add new third-party dependencies there and inherit them with `dep.workspace = true`. Internal crates depend on each other by relative path (`starforged-db = { path = "../starforged-db" }`).
- **SQL portability (spec §12):** every statement in `starforged-db` must run unchanged on SQLite and Postgres:
  - placeholders are `$1, $2, …`, and each number first appears in ascending order in the statement (SQLite numbers `$N` parameters by first appearance);
  - integer columns are `INTEGER` (SQLite) / `BIGINT` (Postgres) and decode as `i64`;
  - booleans are stored as `0`/`1` integers and decoded as `i64`;
  - timestamps are unix seconds (`i64`);
  - SQL strings are `'static` literals (sqlx 0.9 requires `sqlx::AssertSqlSafe` for anything built at runtime; only test helpers may use it).
- **Both engines are tested:** DB-touching tests use `starforged_db::testing::TestDb`, which uses a fresh Postgres database when `STARFORGE_TEST_PG_URL` is set and a temporary SQLite file otherwise. `scripts/check.sh` with `STARFORGE_TEST_PG=1` runs the whole suite on both.
- **Error mapping:** `starforged-db` returns `DbResult<T>`; `starforged-core` returns `CoreResult<T>` (`CoreError::{NotFound, Forbidden, Unauthenticated, Invalid, Conflict, Git, Internal, Db}`). HTTP layers map: `NotFound`→404, `Forbidden`→403, `Unauthenticated`→401 (API, git) or a redirect to `/login` (web), `Invalid`→422 (API, web forms), `Conflict`→409 (API) / 422 (web forms).
- **No existence leaks:** a private repository is reported exactly like a missing one (`CoreError::NotFound`) to anyone without read access (spec §6.1).
- **Secrets:** personal access tokens and session cookies are stored only as SHA-256 hex; CSRF tokens are compared in constant time (`subtle`); secrets are never logged.
- **git subprocesses** are built only through `starforged_git::command::git()` (hermetic environment). Object ids passed to `git` are validated as hex first; nothing goes through a shell.
- **HTML:** askama auto-escaping everywhere; `|safe` is allowed only on Markdown output from `starforged_web::markdown::render`.
- **Tests:** integration tests that start a server use `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` and run the `git` CLI through `common::git`, which uses `spawn_blocking`.
- **Every commit:** `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` pass, and `cargo test --workspace` is green.
- **Deliberate deferrals (spec items not in M0):** OpenAPI generation (utoipa) → M1; syntax highlighting → M1 (with blame); htmx → M2; the hook socket, `refs/for`, and Trails → M2 (M0's `pre-receive` only enforces the branch/tag namespace); orgs, teams, branch protection, SSH, OIDC, TOTP → M3; rate limits, quotas, audit-log UI, `X-Forwarded-For`, and the SQLite reader-pool split (§12) → M5. M0 uses one SQLite connection.
- **Decision not covered by the spec:** site admins have `admin` permission on every repository (consistent with spec §6.4, where site admins can delete any session).

## File Structure

```
Cargo.toml                      workspace, shared dependency versions, lints
rust-toolchain.toml             pins Rust 1.99.1
LICENSE.md                      explains the AGPL / MIT-or-Apache split
LICENSE-AGPL-3.0                AGPL text (downloaded)
README.md                       quickstart (Task 14)
scripts/check.sh                fmt + clippy + tests (+ Postgres with STARFORGE_TEST_PG=1)
crates/
  starforged/                   the binary
    src/main.rs                 clap CLI: init, migrate, serve, admin, hook
    src/lib.rs                  module list (integration tests use the library half)
    src/config.rs               starforged.toml + STARFORGE__SECTION__KEY overrides
    src/init.rs                 `init`: config file + data directory
    src/admin.rs                open_core(), `migrate`, `admin user create`, `admin token create`
    src/hook.rs                 `hook pre-receive`
    src/serve.rs                build(): full router; run(); serve_on()
    tests/common/mod.rs         TestServer harness, git helpers, HTML scraping helpers
    tests/*.rs                  CLI and HTTP integration tests
  starforged-db/                portable SQL
    migrations/sqlite/0001_initial.sql
    migrations/postgres/0001_initial.sql
    src/lib.rs                  Db, Backend, DbError, now()
    src/testing.rs              TestDb
    src/users.rs  src/tokens.rs  src/audit.rs  src/repos.rs  src/collaborators.rs  src/web_sessions.rs
  starforged-core/              domain rules + service layer (`impl Core` blocks per area)
    src/lib.rs                  Core, CoreConfig, repo_path(), test fixture
    src/error.rs                CoreError
    src/crypto.rs               random_hex(), sha256_hex()
    src/validate.rs             handle / repo name / email / password rules
    src/accounts.rs             User, create_user, authenticate_password
    src/audit.rs                Core::audit, Core::audit_client
    src/tokens.rs               Scope, personal access tokens
    src/permission.rs           Permission, Visibility, effective()
    src/repos.rs                Repo, RepoAccess, create/lookup/collaborators
    src/sessions.rs             web login sessions
    src/content.rs              tree/blob/log/commit/diff for a RepoAccess
  starforged-git/               repositories on disk
    src/command.rs              git(), run(), version check, GitError
    src/init.rs                 init_bare(), hook scripts
    src/refpolicy.rs            pre-receive namespace rule
    src/http.rs                 smart HTTP advertisement + RPC processes
    src/read.rs                 gix: branches, resolve, tree, blob, log, commit
    src/diff.rs                 `git show` + unified diff parser
  starforged-web/               HTML pages + git smart HTTP
    src/lib.rs                  router(), AppState, WebSettings, security headers
    src/auth.rs                 MaybeUser, RequireUser, cookies, CSRF
    src/error.rs                WebError → HTML error page
    src/views.rs                NavUser, RepoItem, time formatting, path encoding
    src/markdown.rs             comrak + ammonia
    src/githttp.rs              info/refs, upload-pack, receive-pack
    src/pages/*.rs              login, dashboard, tokens, repo_new, owner, collaborators, code, history
    templates/*.html            askama templates
    static/starforge.css
  starforged-api/               /api/v1 JSON
    src/lib.rs  src/error.rs  src/auth.rs  src/user.rs  src/repos.rs
```

---

### Task 1: Workspace, configuration, and `starforged init`

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `LICENSE.md`, `LICENSE-AGPL-3.0`
- Create: `crates/starforged/Cargo.toml`, `crates/starforged/src/main.rs`, `crates/starforged/src/lib.rs`, `crates/starforged/src/config.rs`, `crates/starforged/src/init.rs`
- Test: `crates/starforged/src/config.rs` (unit), `crates/starforged/tests/init_cli.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `starforged::config::{Config, ServerConfig, DatabaseConfig, StorageConfig, SecurityConfig}` (all `pub` fields; `Serialize + Deserialize + Clone + PartialEq + Debug`).
  - `Config::load(path: &Path) -> anyhow::Result<Config>`; `Config::apply_env(&mut self, vars: impl IntoIterator<Item = (String, String)>) -> anyhow::Result<()>`; `Config::validate(&self) -> anyhow::Result<()>`; `Config::database_url(&self) -> String`; `Config::repos_dir(&self) -> PathBuf`; `Config::secure_cookies(&self) -> bool`.
  - `starforged::init::{InitOptions, run}`: `run(&InitOptions) -> anyhow::Result<Config>`.
  - CLI: `starforged [--config PATH] init --data-dir DIR [--base-url URL] [--http-addr ADDR]`. `--config` defaults to `starforged.toml`, also settable with env `STARFORGE_CONFIG`.

- [ ] **Step 1: Create the workspace files**

`Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/*"]

[workspace.package]
version = "0.0.0"
edition = "2024"
rust-version = "1.99"
license = "AGPL-3.0-or-later"
publish = false

[workspace.dependencies]
ammonia = "4.2.4"
anyhow = "1.0.104"
argon2 = "0.6.0"
askama = "0.16.1"
askama_web = { version = "0.16.0", features = ["axum-0.8"] }
async-compression = { version = "0.4.52", features = ["tokio", "gzip"] }
axum = "0.8.9"
axum-extra = { version = "0.12.6", features = ["cookie", "form"] }
base64 = "0.23.1"
clap = { version = "4.6.7", features = ["derive", "env"] }
comrak = "0.59.0"
flate2 = "1.1.10"
futures-util = "0.3.34"
getrandom = "0.4.3"
gix = "0.90.0"
hex = "0.4.3"
percent-encoding = "2.3.2"
reqwest = { version = "0.13.5", default-features = false, features = ["cookies", "json", "form"] }
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.154"
sha2 = "0.11.1"
sqlx = { version = "0.9.0", default-features = false, features = ["runtime-tokio", "any", "sqlite", "postgres", "migrate", "macros"] }
subtle = "2.6.1"
tempfile = "3.27.0"
thiserror = "2.0.21"
time = { version = "0.3.55", features = ["formatting", "macros"] }
tokio = { version = "1.54.1", features = ["full"] }
tokio-util = { version = "0.7.20", features = ["io"] }
toml = "1.1.8"
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.23", features = ["env-filter"] }
url = "2.5.8"

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.99.1"
components = ["rustfmt", "clippy"]
```

`.gitignore`:

```
/target
/data
/starforged.toml
*.db
*.db-shm
*.db-wal
```

`LICENSE.md`:

```markdown
# Licensing

Starforge is split-licensed (design spec, decision D8):

- The server — the `starforged` binary and every `crates/starforged*` crate — is licensed under the
  GNU Affero General Public License, version 3 or (at your option) any later version. See `LICENSE-AGPL-3.0`.
- The developer CLI, the trace format, the redaction engine, and the agent adapters (`crates/starforge-*`,
  added in milestone M1) are dual-licensed under the MIT license or the Apache License 2.0, at your option.
```

Download the AGPL text:

```bash
curl -fsSL https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE-AGPL-3.0
head -n 3 LICENSE-AGPL-3.0
```

Expected: the first lines read `GNU AFFERO GENERAL PUBLIC LICENSE` / `Version 3, 19 November 2007`.

`crates/starforged/Cargo.toml`:

```toml
[package]
name = "starforged"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true

[dependencies]
anyhow.workspace = true
clap.workspace = true
getrandom.workspace = true
hex.workspace = true
serde.workspace = true
toml.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`crates/starforged/src/lib.rs`:

```rust
//! starforged: the Starforge server. The library half exists so integration tests can build the app in-process.

pub mod config;
pub mod init;
```

- [ ] **Step 2: Write the failing config unit tests**

Create `crates/starforged/src/config.rs` with only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            server: ServerConfig { http_addr: "127.0.0.1:3000".into(), base_url: "http://127.0.0.1:3000".into() },
            database: DatabaseConfig::default(),
            storage: StorageConfig { data_dir: PathBuf::from("/srv/starforge") },
            security: SecurityConfig { secret_key: "ab".repeat(32) },
        }
    }

    #[test]
    fn env_overrides_apply_and_ignore_other_variables() {
        let mut config = sample();
        config
            .apply_env([
                ("STARFORGE__SERVER__HTTP_ADDR".to_owned(), "0.0.0.0:80".to_owned()),
                ("STARFORGE__DATABASE__URL".to_owned(), "postgres://db/starforge".to_owned()),
                ("STARFORGE__DATABASE__AUTO_MIGRATE".to_owned(), "false".to_owned()),
                ("STARFORGE_CONFIG".to_owned(), "/etc/starforged.toml".to_owned()),
                ("HOME".to_owned(), "/root".to_owned()),
            ])
            .unwrap();
        assert_eq!(config.server.http_addr, "0.0.0.0:80");
        assert_eq!(config.database.url, "postgres://db/starforge");
        assert!(!config.database.auto_migrate);
    }

    #[test]
    fn unknown_overrides_are_rejected() {
        let err = sample().apply_env([("STARFORGE__SERVER__PORT".to_owned(), "1".to_owned())]).unwrap_err();
        assert!(err.to_string().contains("STARFORGE__SERVER__PORT"));
    }

    #[test]
    fn empty_database_url_means_sqlite_in_the_data_dir() {
        assert_eq!(sample().database_url(), "sqlite:///srv/starforge/starforge.db?mode=rwc");
        assert_eq!(sample().repos_dir(), PathBuf::from("/srv/starforge/repos"));
    }

    #[test]
    fn validation_checks_secret_key_and_base_url() {
        assert!(sample().validate().is_ok());
        let mut short_key = sample();
        short_key.security.secret_key = "abc".into();
        assert!(short_key.validate().is_err());
        let mut slash = sample();
        slash.server.base_url = "http://x/".into();
        assert!(slash.validate().is_err());
        let mut https = sample();
        https.server.base_url = "https://forge.example.com".into();
        assert!(https.secure_cookies());
        assert!(!sample().secure_cookies());
    }
}
```

- [ ] **Step 3: Run the tests to see them fail**

Run: `cargo test -p starforged --lib`
Expected: compile errors (`cannot find type Config`).

- [ ] **Step 4: Implement `config.rs`**

Put this above the test module in `crates/starforged/src/config.rs`:

```rust
//! `starforged.toml`: loading, `STARFORGE__SECTION__KEY` environment overrides, and derived paths (spec §12).

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Socket address the HTTP server binds, e.g. `127.0.0.1:3000`.
    pub http_addr: String,
    /// Public URL of the server without a trailing slash, e.g. `https://forge.example.com`.
    pub base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Empty means SQLite at `<data_dir>/starforge.db`.
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_true")]
    pub auto_migrate: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig { url: String::new(), auto_migrate: true }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// 64 hex characters (32 bytes). Losing it logs everyone out (spec §12).
    pub secret_key: String,
}

impl Config {
    /// Reads `path`, applies environment overrides, and validates.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.apply_env(std::env::vars())?;
        config.validate()?;
        Ok(config)
    }

    /// Applies `STARFORGE__<SECTION>__<KEY>` overrides; other variables are ignored.
    pub fn apply_env(&mut self, vars: impl IntoIterator<Item = (String, String)>) -> anyhow::Result<()> {
        for (key, value) in vars {
            let Some(rest) = key.strip_prefix("STARFORGE__") else { continue };
            match rest.to_ascii_lowercase().as_str() {
                "server__http_addr" => self.server.http_addr = value,
                "server__base_url" => self.server.base_url = value,
                "database__url" => self.database.url = value,
                "database__auto_migrate" => self.database.auto_migrate = parse_bool(&key, &value)?,
                "storage__data_dir" => self.storage.data_dir = PathBuf::from(value),
                "security__secret_key" => self.security.secret_key = value,
                _ => bail!("unknown configuration override {key}"),
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let key = &self.security.secret_key;
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("security.secret_key must be 64 hex characters");
        }
        if self.server.base_url.ends_with('/') {
            bail!("server.base_url must not end with '/'");
        }
        Ok(())
    }

    pub fn database_url(&self) -> String {
        if self.database.url.is_empty() {
            format!("sqlite://{}?mode=rwc", self.storage.data_dir.join("starforge.db").display())
        } else {
            self.database.url.clone()
        }
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.storage.data_dir.join("repos")
    }

    /// Cookies carry `Secure` when the public URL is HTTPS.
    pub fn secure_cookies(&self) -> bool {
        self.server.base_url.starts_with("https://")
    }
}

fn parse_bool(key: &str, value: &str) -> anyhow::Result<bool> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => bail!("{key} must be true or false"),
    }
}
```

- [ ] **Step 5: Run the config tests**

Run: `cargo test -p starforged --lib`
Expected: 4 passed.

- [ ] **Step 6: Write the failing `init` CLI tests**

`crates/starforged/tests/init_cli.rs`:

```rust
use std::process::Command;

fn starforged() -> Command {
    Command::new(env!("CARGO_BIN_EXE_starforged"))
}

#[test]
fn init_writes_a_private_config_and_the_data_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    let data = tmp.path().join("data");
    let out = starforged()
        .args(["--config", config.to_str().unwrap(), "init", "--data-dir", data.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for sub in ["repos", "tmp", "run"] {
        assert!(data.join(sub).is_dir(), "{sub} missing");
    }
    let loaded = starforged::config::Config::load(&config).unwrap();
    assert_eq!(loaded.security.secret_key.len(), 64);
    assert_eq!(loaded.server.base_url, "http://127.0.0.1:3000");
    assert_eq!(loaded.server.http_addr, "127.0.0.1:3000");
    assert_eq!(loaded.storage.data_dir, std::fs::canonicalize(&data).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&config).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn init_refuses_to_overwrite_an_existing_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    std::fs::write(&config, "keep me").unwrap();
    let out = starforged()
        .args(["--config", config.to_str().unwrap(), "init", "--data-dir", tmp.path().join("d").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "keep me");
}
```

- [ ] **Step 7: Run them to see them fail**

Run: `cargo test -p starforged --test init_cli`
Expected: compile error — there is no `main.rs` / `init` module yet.

- [ ] **Step 8: Implement `init.rs` and `main.rs`**

`crates/starforged/src/init.rs`:

```rust
//! `starforged init`: writes a fresh `starforged.toml` and data directory.

use std::path::Path;

use anyhow::{Context, bail};

use crate::config::{Config, DatabaseConfig, SecurityConfig, ServerConfig, StorageConfig};

pub struct InitOptions<'a> {
    pub config_path: &'a Path,
    pub data_dir: &'a Path,
    pub base_url: &'a str,
    pub http_addr: &'a str,
}

pub fn run(opts: &InitOptions<'_>) -> anyhow::Result<Config> {
    if opts.config_path.exists() {
        bail!("{} already exists; refusing to overwrite it", opts.config_path.display());
    }
    for sub in ["repos", "tmp", "run"] {
        let dir = opts.data_dir.join(sub);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let data_dir = std::fs::canonicalize(opts.data_dir)?;
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|e| anyhow::anyhow!("reading OS randomness: {e}"))?;
    let config = Config {
        server: ServerConfig {
            http_addr: opts.http_addr.to_owned(),
            base_url: opts.base_url.trim_end_matches('/').to_owned(),
        },
        database: DatabaseConfig::default(),
        storage: StorageConfig { data_dir },
        security: SecurityConfig { secret_key: hex::encode(key) },
    };
    config.validate()?;
    write_private(opts.config_path, &toml::to_string_pretty(&config)?)?;
    Ok(config)
}

#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    std::fs::write(path, text).with_context(|| format!("creating {}", path.display()))
}
```

`crates/starforged/src/main.rs`:

```rust
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "starforged", version, about = "Starforge server")]
struct Cli {
    /// Path to starforged.toml.
    #[arg(long, env = "STARFORGE_CONFIG", default_value = "starforged.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a new config file and data directory.
    Init {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        base_url: String,
        #[arg(long, default_value = "127.0.0.1:3000")]
        http_addr: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { data_dir, base_url, http_addr } => {
            let config = starforged::init::run(&starforged::init::InitOptions {
                config_path: &cli.config,
                data_dir: &data_dir,
                base_url: &base_url,
                http_addr: &http_addr,
            })?;
            println!("wrote {} (data directory {})", cli.config.display(), config.storage.data_dir.display());
        }
    }
    Ok(())
}
```

- [ ] **Step 9: Run all tests for the crate**

Run: `cargo test -p starforged`
Expected: 4 unit tests and 2 integration tests pass.

- [ ] **Step 10: Lint, format, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add Cargo.toml Cargo.lock rust-toolchain.toml .gitignore LICENSE.md LICENSE-AGPL-3.0 crates/starforged
git commit -m "feat(starforged): workspace, config loading, and init command"
```

---

### Task 2: Database crate — connection, portable migrations, test databases

**Files:**
- Create: `crates/starforged-db/Cargo.toml`, `crates/starforged-db/src/lib.rs`, `crates/starforged-db/src/testing.rs`
- Create: `crates/starforged-db/migrations/sqlite/0001_initial.sql`, `crates/starforged-db/migrations/postgres/0001_initial.sql`
- Create: `scripts/check.sh`
- Test: `crates/starforged-db/src/lib.rs` (unit)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `starforged_db::Db` (`Clone + Debug`): `Db::connect(url: &str) -> DbResult<Db>`, `Db::migrate(&self) -> DbResult<()>`, `Db::pool(&self) -> &sqlx::AnyPool`, `Db::backend(&self) -> Backend`.
  - `starforged_db::Backend { Sqlite, Postgres }`.
  - `starforged_db::DbError` with `is_unique_violation(&self) -> bool`; `starforged_db::DbResult<T>`.
  - `starforged_db::now() -> i64` (unix seconds).
  - `starforged_db::testing::TestDb { pub db: Db, pub url: String }` with `TestDb::new().await`; available in this crate's tests and to other crates through the `testing` feature.
  - Tables (both engines): `owners`, `users`, `access_tokens`, `web_sessions`, `repos`, `collaborators`, `audit_log`.

- [ ] **Step 1: Create the crate manifest**

`crates/starforged-db/Cargo.toml`:

```toml
[package]
name = "starforged-db"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true

[features]
testing = ["dep:getrandom", "dep:hex", "dep:tempfile", "dep:url"]

[dependencies]
sqlx.workspace = true
thiserror.workspace = true
getrandom = { workspace = true, optional = true }
hex = { workspace = true, optional = true }
tempfile = { workspace = true, optional = true }
url = { workspace = true, optional = true }

[dev-dependencies]
getrandom.workspace = true
hex.workspace = true
tempfile.workspace = true
tokio.workspace = true
url.workspace = true
```

- [ ] **Step 2: Write both migrations**

`crates/starforged-db/migrations/sqlite/0001_initial.sql`:

```sql
-- Starforge M0 schema for SQLite. Keep in lockstep with ../postgres/0001_initial.sql.

CREATE TABLE owners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'org')),
    handle TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY REFERENCES owners (id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT UNIQUE,
    password_hash TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended')),
    created_at INTEGER NOT NULL
);

CREATE TABLE access_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_hint TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX access_tokens_user ON access_tokens (user_id);

CREATE TABLE web_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX web_sessions_user ON web_sessions (user_id);

CREATE TABLE repos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    lower_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal', 'private')),
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (owner_id, lower_name)
);

CREATE TABLE collaborators (
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'triage', 'write', 'maintain', 'admin')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (repo_id, user_id)
);
CREATE INDEX collaborators_user ON collaborators (user_id);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX audit_log_created ON audit_log (created_at);
```

`crates/starforged-db/migrations/postgres/0001_initial.sql`:

```sql
-- Starforge M0 schema for Postgres. Keep in lockstep with ../sqlite/0001_initial.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

CREATE TABLE owners (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'org')),
    handle TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE users (
    id BIGINT PRIMARY KEY REFERENCES owners (id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT UNIQUE,
    password_hash TEXT,
    is_admin BIGINT NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended')),
    created_at BIGINT NOT NULL
);

CREATE TABLE access_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_hint TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_used_at BIGINT,
    revoked_at BIGINT
);
CREATE INDEX access_tokens_user ON access_tokens (user_id);

CREATE TABLE web_sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX web_sessions_user ON web_sessions (user_id);

CREATE TABLE repos (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    lower_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal', 'private')),
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (owner_id, lower_name)
);

CREATE TABLE collaborators (
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'triage', 'write', 'maintain', 'admin')),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (repo_id, user_id)
);
CREATE INDEX collaborators_user ON collaborators (user_id);

CREATE TABLE audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
CREATE INDEX audit_log_created ON audit_log (created_at);
```

- [ ] **Step 3: Write the failing tests**

`crates/starforged-db/src/lib.rs` — start with the module declaration and tests only:

```rust
#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests {
    use crate::testing::TestDb;
    use crate::{Db, DbError};

    #[tokio::test]
    async fn migrations_create_every_table_and_rerun_cleanly() {
        let t = TestDb::new().await;
        t.db.migrate().await.unwrap();
        for table in ["owners", "users", "access_tokens", "web_sessions", "repos", "collaborators", "audit_log"] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            let rows: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(t.db.pool()).await.unwrap();
            assert_eq!(rows, 0, "{table}");
        }
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let t = TestDb::new().await;
        let err = sqlx::query("INSERT INTO users (id, display_name, created_at) VALUES ($1, $2, $3)")
            .bind(999_i64)
            .bind("ghost")
            .bind(0_i64)
            .execute(t.db.pool())
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some(), "{err}");
    }

    #[tokio::test]
    async fn unique_violations_are_recognized() {
        let t = TestDb::new().await;
        let insert = || {
            sqlx::query("INSERT INTO owners (kind, handle, created_at) VALUES ('user', $1, $2)")
                .bind("alice")
                .bind(0_i64)
                .execute(t.db.pool())
        };
        insert().await.unwrap();
        let err = DbError::from(insert().await.unwrap_err());
        assert!(err.is_unique_violation());
    }

    #[tokio::test]
    async fn rejects_unknown_url_schemes() {
        let err = Db::connect("mysql://localhost/starforge").await.unwrap_err();
        assert!(matches!(err, DbError::UnsupportedUrl(_)));
    }
}
```

`crates/starforged-db/src/testing.rs`:

```rust
//! Throwaway databases for tests. With `STARFORGE_TEST_PG_URL` set (a Postgres URL allowed to
//! `CREATE DATABASE`), every `TestDb` is a fresh Postgres database; otherwise a SQLite file in a temp dir.

use crate::Db;

pub struct TestDb {
    pub db: Db,
    pub url: String,
    _dir: Option<tempfile::TempDir>,
}

impl TestDb {
    pub async fn new() -> TestDb {
        let (url, dir) = match std::env::var("STARFORGE_TEST_PG_URL") {
            Ok(admin_url) => (create_pg_database(&admin_url).await, None),
            Err(_) => {
                let dir = tempfile::tempdir().expect("create temp dir");
                (format!("sqlite://{}?mode=rwc", dir.path().join("test.db").display()), Some(dir))
            }
        };
        let db = Db::connect(&url).await.expect("connect to test database");
        db.migrate().await.expect("migrate test database");
        TestDb { db, url, _dir: dir }
    }
}

async fn create_pg_database(admin_url: &str) -> String {
    let mut bytes = [0_u8; 6];
    getrandom::fill(&mut bytes).expect("OS randomness");
    let name = format!("sf_test_{}", hex::encode(bytes));
    let admin = Db::connect(admin_url).await.expect("connect with STARFORGE_TEST_PG_URL");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(admin.pool())
        .await
        .expect("create test database");
    admin.pool().close().await;
    let mut url = url::Url::parse(admin_url).expect("STARFORGE_TEST_PG_URL is a URL");
    url.set_path(&format!("/{name}"));
    url.to_string()
}
```

- [ ] **Step 4: Run them to see them fail**

Run: `cargo test -p starforged-db`
Expected: compile errors (`Db`, `DbError` missing).

- [ ] **Step 5: Implement the connection layer**

Insert this at the very top of `crates/starforged-db/src/lib.rs`, above the `testing` module declaration from Step 3 (inner `//!` docs must start the file). From Task 3 on, `pub mod <name>;` lines for new modules go directly below the `use` lines.

```rust
//! Data access for starforged: one schema, two engines (SQLite, Postgres), through sqlx's `Any` driver.
//!
//! Every statement in this crate must run unchanged on both engines:
//! - placeholders are `$1, $2, …` and each number first appears in ascending order
//!   (SQLite numbers `$N` parameters by first appearance);
//! - integer columns decode as `i64` (Postgres `BIGINT`, SQLite `INTEGER`);
//! - booleans are stored as `0`/`1` integers;
//! - timestamps are unix seconds.

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::Executor;
use sqlx::any::{AnyPool, AnyPoolOptions};

static SQLITE_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("unsupported database url (expected sqlite: or postgres:): {0}")]
    UnsupportedUrl(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

impl DbError {
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, DbError::Sqlx(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()))
    }
}

pub type DbResult<T> = Result<T, DbError>;

#[derive(Debug, Clone)]
pub struct Db {
    pool: AnyPool,
    backend: Backend,
}

impl Db {
    pub async fn connect(url: &str) -> DbResult<Db> {
        sqlx::any::install_default_drivers();
        let backend = if url.starts_with("sqlite:") {
            Backend::Sqlite
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Backend::Postgres
        } else {
            return Err(DbError::UnsupportedUrl(url.to_owned()));
        };
        let pool = match backend {
            // One connection: SQLite serializes writes anyway, and a single connection avoids SQLITE_BUSY.
            // The reader-pool split from spec §12 lands in M5.
            Backend::Sqlite => {
                AnyPoolOptions::new()
                    .max_connections(1)
                    .after_connect(|conn, _meta| {
                        Box::pin(async move {
                            conn.execute("PRAGMA foreign_keys = ON").await?;
                            conn.execute("PRAGMA journal_mode = WAL").await?;
                            conn.execute("PRAGMA busy_timeout = 5000").await?;
                            Ok(())
                        })
                    })
                    .connect(url)
                    .await?
            }
            Backend::Postgres => AnyPoolOptions::new().max_connections(16).connect(url).await?,
        };
        Ok(Db { pool, backend })
    }

    pub async fn migrate(&self) -> DbResult<()> {
        match self.backend {
            Backend::Sqlite => SQLITE_MIGRATIONS.run(&self.pool).await?,
            Backend::Postgres => POSTGRES_MIGRATIONS.run(&self.pool).await?,
        }
        Ok(())
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }
}

/// Current time in unix seconds.
pub fn now() -> i64 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock is after 1970").as_secs();
    i64::try_from(secs).expect("unix time fits in i64")
}
```

- [ ] **Step 6: Run the tests on SQLite**

Run: `cargo test -p starforged-db`
Expected: 4 passed.

- [ ] **Step 7: Add `scripts/check.sh` and run the tests on Postgres**

`scripts/check.sh`:

```bash
#!/usr/bin/env bash
# Format check, lints, and tests. STARFORGE_TEST_PG=1 also runs the suite against a throwaway
# Postgres 17 container (podman or docker).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

if [[ "${STARFORGE_TEST_PG:-0}" == "1" ]]; then
  engine="$(command -v podman || command -v docker)"
  name="starforge-test-pg-$$"
  "$engine" run -d --rm --name "$name" -e POSTGRES_PASSWORD=starforge \
    -p 127.0.0.1:55439:5432 docker.io/library/postgres:17 >/dev/null
  trap '"$engine" stop -t 2 "$name" >/dev/null' EXIT
  for _ in $(seq 1 60); do
    "$engine" exec "$name" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break
    sleep 0.5
  done
  STARFORGE_TEST_PG_URL="postgres://postgres:starforge@127.0.0.1:55439/postgres" cargo test --workspace
fi
```

Run:

```bash
chmod +x scripts/check.sh
STARFORGE_TEST_PG=1 scripts/check.sh
```

Expected: fmt and clippy clean; the `starforged-db` tests pass twice (SQLite, then Postgres).

- [ ] **Step 8: Commit**

```bash
git add crates/starforged-db scripts/check.sh Cargo.lock
git commit -m "feat(db): portable schema for SQLite and Postgres with throwaway test databases"
```

---

### Task 3: Accounts — users table, core crate, validation, password login

**Files:**
- Create: `crates/starforged-db/src/users.rs`; Modify: `crates/starforged-db/src/lib.rs` (add `pub mod users;`)
- Create: `crates/starforged-core/Cargo.toml`, `crates/starforged-core/src/lib.rs`, `crates/starforged-core/src/error.rs`, `crates/starforged-core/src/crypto.rs`, `crates/starforged-core/src/validate.rs`, `crates/starforged-core/src/accounts.rs`
- Test: unit tests in `users.rs`, `validate.rs`, `accounts.rs`

**Interfaces:**
- Consumes: `starforged_db::{Db, DbResult, DbError, now, testing::TestDb}` (Task 2).
- Produces:
  - `starforged_db::users::{UserRow, NewUser, insert, by_id, by_handle, by_email, set_state}`. `insert(&Db, &NewUser) -> DbResult<i64>` writes `owners` + `users` in one transaction.
  - `starforged_core::{Core, CoreConfig, CoreError, CoreResult}`; `Core::new(Db, CoreConfig)`, `Core::db()`, `Core::config()`; `CoreConfig { repos_dir: PathBuf, hook_exe: PathBuf }`.
  - `starforged_core::crypto::{random_hex(bytes: usize) -> String, sha256_hex(&str) -> String}`.
  - `starforged_core::validate::{handle, repo_name, email, password, RESERVED_HANDLES}`. `handle` and `email` return the normalized lowercase `String`; `repo_name` returns the trimmed `String`.
  - `starforged_core::accounts::{User, CreateUser}` (`CreateUser: Default`); `Core::create_user(CreateUser) -> CoreResult<User>`, `Core::authenticate_password(login: &str, password: &str) -> CoreResult<User>`, `Core::user_by_id(i64) -> CoreResult<Option<User>>`, `Core::user_by_handle(&str) -> CoreResult<Option<User>>`.
  - Test fixture (crate-private, `cfg(test)`): `crate::testing::{test_core() -> (Core, Fixture), user(&Core, &str) -> User}`.

- [ ] **Step 1: Write the failing `users` table tests**

Create `crates/starforged-db/src/users.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDb;

    fn alice() -> NewUser<'static> {
        NewUser { handle: "alice", display_name: "Alice", email: Some("alice@example.com"), password_hash: Some("hash"), is_admin: false }
    }

    #[tokio::test]
    async fn insert_and_look_up() {
        let t = TestDb::new().await;
        let id = insert(&t.db, &alice()).await.unwrap();
        let row = by_handle(&t.db, "alice").await.unwrap().unwrap();
        assert_eq!(row.id, id);
        assert_eq!(row.display_name, "Alice");
        assert_eq!(row.email.as_deref(), Some("alice@example.com"));
        assert_eq!(row.password_hash.as_deref(), Some("hash"));
        assert!(!row.is_admin);
        assert_eq!(row.state, "active");
        assert_eq!(by_email(&t.db, "alice@example.com").await.unwrap().unwrap().id, id);
        assert_eq!(by_id(&t.db, id).await.unwrap().unwrap().handle, "alice");
        assert!(by_handle(&t.db, "bob").await.unwrap().is_none());
        set_state(&t.db, id, "suspended").await.unwrap();
        assert_eq!(by_id(&t.db, id).await.unwrap().unwrap().state, "suspended");
    }

    #[tokio::test]
    async fn duplicate_handle_or_email_is_a_unique_violation() {
        let t = TestDb::new().await;
        insert(&t.db, &alice()).await.unwrap();
        let same_handle = insert(&t.db, &NewUser { email: Some("other@example.com"), ..alice() }).await.unwrap_err();
        assert!(same_handle.is_unique_violation());
        let same_email = insert(&t.db, &NewUser { handle: "alice2", ..alice() }).await.unwrap_err();
        assert!(same_email.is_unique_violation());
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM owners WHERE handle = $1")
            .bind("alice2")
            .fetch_one(t.db.pool())
            .await
            .unwrap();
        assert_eq!(owners, 0, "a failed insert must roll back its owner row");
    }
}
```

Add `pub mod users;` to `crates/starforged-db/src/lib.rs` (below the `use` lines).

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-db users`
Expected: compile errors (`NewUser`, `insert` missing).

- [ ] **Step 3: Implement `users.rs`**

Insert at the top of `crates/starforged-db/src/users.rs`:

```rust
//! `owners` + `users`: accounts and the handle namespace shared with orgs (spec §6.1).

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub id: i64,
    pub handle: String,
    pub display_name: String,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub state: String,
    pub created_at: i64,
}

pub struct NewUser<'a> {
    pub handle: &'a str,
    pub display_name: &'a str,
    pub email: Option<&'a str>,
    pub password_hash: Option<&'a str>,
    pub is_admin: bool,
}

macro_rules! select_user {
    ($tail:literal) => {
        concat!(
            "SELECT u.id, o.handle, u.display_name, u.email, u.password_hash, u.is_admin, u.state, u.created_at ",
            "FROM users u JOIN owners o ON o.id = u.id ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<UserRow> {
    Ok(UserRow {
        id: row.try_get("id")?,
        handle: row.try_get("handle")?,
        display_name: row.try_get("display_name")?,
        email: row.try_get("email")?,
        password_hash: row.try_get("password_hash")?,
        is_admin: row.try_get::<i64, _>("is_admin")? != 0,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Inserts the owner row and the user row in one transaction and returns the shared id.
pub async fn insert(db: &Db, new: &NewUser<'_>) -> DbResult<i64> {
    let created_at = now();
    let mut tx = db.pool().begin().await?;
    let id: i64 = sqlx::query_scalar("INSERT INTO owners (kind, handle, created_at) VALUES ('user', $1, $2) RETURNING id")
        .bind(new.handle)
        .bind(created_at)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO users (id, display_name, email, password_hash, is_admin, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(new.display_name)
    .bind(new.email.map(str::to_owned))
    .bind(new.password_hash.map(str::to_owned))
    .bind(i64::from(new.is_admin))
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<UserRow>> {
    let row = sqlx::query(select_user!("WHERE u.id = $1")).bind(id).fetch_optional(db.pool()).await?;
    row.as_ref().map(from_row).transpose()
}

/// `handle` must already be lowercase.
pub async fn by_handle(db: &Db, handle: &str) -> DbResult<Option<UserRow>> {
    let row = sqlx::query(select_user!("WHERE o.handle = $1")).bind(handle).fetch_optional(db.pool()).await?;
    row.as_ref().map(from_row).transpose()
}

/// `email` must already be lowercase.
pub async fn by_email(db: &Db, email: &str) -> DbResult<Option<UserRow>> {
    let row = sqlx::query(select_user!("WHERE u.email = $1")).bind(email).fetch_optional(db.pool()).await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn set_state(db: &Db, id: i64, state: &str) -> DbResult<()> {
    sqlx::query("UPDATE users SET state = $1 WHERE id = $2").bind(state).bind(id).execute(db.pool()).await?;
    Ok(())
}
```

- [ ] **Step 4: Run the `users` tests**

Run: `cargo test -p starforged-db users`
Expected: 2 passed.

- [ ] **Step 5: Create the core crate with failing validation tests**

`crates/starforged-core/Cargo.toml`:

```toml
[package]
name = "starforged-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true

[dependencies]
argon2.workspace = true
getrandom.workspace = true
hex.workspace = true
sha2.workspace = true
starforged-db = { path = "../starforged-db" }
thiserror.workspace = true
tokio.workspace = true

[dev-dependencies]
sqlx.workspace = true
starforged-db = { path = "../starforged-db", features = ["testing"] }
tempfile.workspace = true
```

`crates/starforged-core/src/error.rs`:

```rust
use starforged_db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("not found")]
    NotFound,
    #[error("permission denied")]
    Forbidden,
    #[error("authentication required")]
    Unauthenticated,
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("git: {0}")]
    Git(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

pub type CoreResult<T> = Result<T, CoreError>;
```

`crates/starforged-core/src/crypto.rs`:

```rust
//! Randomness and hashing for secrets (spec §6.1: tokens and cookies are stored as SHA-256).

use sha2::{Digest, Sha256};

/// `bytes` bytes from the OS random number generator, hex-encoded.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0_u8; bytes];
    getrandom::fill(&mut buf).expect("the OS random number generator is available");
    hex::encode(buf)
}

pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_is_fresh_and_sized() {
        let a = random_hex(32);
        assert_eq!(a.len(), 64);
        assert_ne!(a, random_hex(32));
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
```

`crates/starforged-core/src/validate.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles() {
        assert_eq!(handle(" Alice ").unwrap(), "alice");
        assert_eq!(handle("a-b-9").unwrap(), "a-b-9");
        assert_eq!(handle(&"a".repeat(39)).unwrap().len(), 39);
        for bad in ["", "-a", "a-", "a--b", "a_b", "a.b", "日本", "login", "API", "a".repeat(40).as_str()] {
            assert!(handle(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn repo_names() {
        for good in ["proj", "Proj.rs", "a_b-c", ".github"] {
            assert_eq!(repo_name(good).unwrap(), good);
        }
        for bad in ["", ".", "..", "x.git", "X.GIT", "a/b", "a b", "a".repeat(101).as_str()] {
            assert!(repo_name(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn emails() {
        assert_eq!(email(" Al@Example.COM ").unwrap(), "al@example.com");
        for bad in ["", "a", "@x.com", "a@", "a@x", "a@.com", "a@x.", "a b@x.com", "a@b@c.com"] {
            assert!(email(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn passwords() {
        assert!(password("0123456789").is_ok());
        assert!(password("short").is_err());
        assert!(password(&"x".repeat(1025)).is_err());
    }
}
```

`crates/starforged-core/src/lib.rs`:

```rust
//! starforged-core: domain rules and the service layer (spec §5.1). The web UI and the API call `Core`;
//! nothing else reads or writes stored state.

pub mod accounts;
pub mod crypto;
pub mod error;
pub mod validate;

use std::path::PathBuf;
use std::sync::Arc;

use starforged_db::Db;

pub use error::{CoreError, CoreResult};

#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Directory holding bare repositories (`<data_dir>/repos`).
    pub repos_dir: PathBuf,
    /// Program that repository hooks execute (`starforged`); tests point it at the built binary.
    pub hook_exe: PathBuf,
}

/// The service layer. Cheap to clone; share one per process.
#[derive(Debug, Clone)]
pub struct Core {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    db: Db,
    config: CoreConfig,
}

impl Core {
    pub fn new(db: Db, config: CoreConfig) -> Core {
        Core { inner: Arc::new(Inner { db, config }) }
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    pub fn config(&self) -> &CoreConfig {
        &self.inner.config
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::accounts::{CreateUser, User};

    pub(crate) struct Fixture {
        _db: starforged_db::testing::TestDb,
        _dir: tempfile::TempDir,
    }

    pub(crate) async fn test_core() -> (Core, Fixture) {
        let db = starforged_db::testing::TestDb::new().await;
        let dir = tempfile::tempdir().unwrap();
        let config = CoreConfig { repos_dir: dir.path().join("repos"), hook_exe: PathBuf::from("/bin/false") };
        (Core::new(db.db.clone(), config), Fixture { _db: db, _dir: dir })
    }

    pub(crate) async fn user(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser { handle: handle.into(), ..Default::default() }).await.unwrap()
    }
}
```

`crates/starforged-core/src/accounts.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, user};

    const PASSWORD: &str = "correct horse battery";

    #[tokio::test]
    async fn create_and_authenticate_by_handle_or_email() {
        let (core, _f) = test_core().await;
        let created = core
            .create_user(CreateUser {
                handle: "Alice".into(),
                email: Some("Alice@Example.com".into()),
                password: Some(PASSWORD.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(created.handle, "alice");
        assert_eq!(created.email.as_deref(), Some("alice@example.com"));
        assert!(created.active);
        assert_eq!(core.authenticate_password("alice", PASSWORD).await.unwrap().id, created.id);
        assert_eq!(core.authenticate_password("ALICE@example.com", PASSWORD).await.unwrap().id, created.id);
        assert!(matches!(core.authenticate_password("alice", "wrong password!").await, Err(CoreError::Unauthenticated)));
        assert!(matches!(core.authenticate_password("nobody", PASSWORD).await, Err(CoreError::Unauthenticated)));
        assert_eq!(core.user_by_handle("ALICE").await.unwrap().unwrap().id, created.id);
    }

    #[tokio::test]
    async fn rejects_duplicates_and_invalid_input() {
        let (core, _f) = test_core().await;
        user(&core, "alice").await;
        let dup = core.create_user(CreateUser { handle: "ALICE".into(), ..Default::default() }).await;
        assert!(matches!(dup, Err(CoreError::Conflict(_))));
        let reserved = core.create_user(CreateUser { handle: "login".into(), ..Default::default() }).await;
        assert!(matches!(reserved, Err(CoreError::Invalid(_))));
        let short = core
            .create_user(CreateUser { handle: "bob".into(), password: Some("short".into()), ..Default::default() })
            .await;
        assert!(matches!(short, Err(CoreError::Invalid(_))));
    }

    #[tokio::test]
    async fn suspended_and_passwordless_accounts_cannot_log_in() {
        let (core, _f) = test_core().await;
        let carol = core
            .create_user(CreateUser { handle: "carol".into(), password: Some(PASSWORD.into()), ..Default::default() })
            .await
            .unwrap();
        starforged_db::users::set_state(core.db(), carol.id, "suspended").await.unwrap();
        assert!(matches!(core.authenticate_password("carol", PASSWORD).await, Err(CoreError::Unauthenticated)));
        assert!(!core.user_by_id(carol.id).await.unwrap().unwrap().active);
        user(&core, "dave").await;
        assert!(matches!(core.authenticate_password("dave", "").await, Err(CoreError::Unauthenticated)));
    }
}
```

- [ ] **Step 6: Run them to see them fail**

Run: `cargo test -p starforged-core`
Expected: compile errors (`handle`, `CreateUser`, … missing).

- [ ] **Step 7: Implement `validate.rs`**

Insert at the top of `crates/starforged-core/src/validate.rs`:

```rust
//! Input rules for handles, repository names, emails, and passwords.

use crate::CoreError;

/// Handles that would collide with top-level routes (`/<handle>` pages).
pub const RESERVED_HANDLES: &[&str] = &[
    "admin", "api", "assets", "explore", "healthz", "login", "logout", "metrics", "new", "org", "orgs", "readyz",
    "repo", "repos", "settings", "static", "user", "users",
];

/// Lowercases and checks a user or org handle: 1–39 of `a-z 0-9 -`, no leading, trailing, or doubled `-`,
/// and not reserved.
pub fn handle(input: &str) -> Result<String, CoreError> {
    let h = input.trim().to_ascii_lowercase();
    let allowed = h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if h.is_empty() || h.len() > 39 || !allowed || h.starts_with('-') || h.ends_with('-') || h.contains("--") {
        return Err(CoreError::Invalid(
            "handles are 1-39 characters of a-z, 0-9, and single hyphens, not at the start or end".into(),
        ));
    }
    if RESERVED_HANDLES.contains(&h.as_str()) {
        return Err(CoreError::Invalid(format!("'{h}' is reserved")));
    }
    Ok(h)
}

/// Repository names: 1–100 of `A-Z a-z 0-9 . _ -`, not `.` or `..`, and not ending in `.git`.
pub fn repo_name(input: &str) -> Result<String, CoreError> {
    let name = input.trim();
    let allowed = name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if name.is_empty()
        || name.len() > 100
        || !allowed
        || name == "."
        || name == ".."
        || name.to_ascii_lowercase().ends_with(".git")
    {
        return Err(CoreError::Invalid(
            "repository names are 1-100 characters of letters, digits, '.', '_', and '-', and must not end in .git".into(),
        ));
    }
    Ok(name.to_owned())
}

/// Lowercases and checks an email: one `@`, a non-empty local part, a dotted domain, at most 254 characters.
pub fn email(input: &str) -> Result<String, CoreError> {
    let e = input.trim().to_ascii_lowercase();
    let valid = e.len() <= 254
        && !e.contains(char::is_whitespace)
        && match e.split_once('@') {
            Some((local, domain)) => {
                !local.is_empty()
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && !domain.contains('@')
            }
            None => false,
        };
    if valid { Ok(e) } else { Err(CoreError::Invalid("invalid email address".into())) }
}

pub fn password(input: &str) -> Result<(), CoreError> {
    if (10..=1024).contains(&input.chars().count()) {
        Ok(())
    } else {
        Err(CoreError::Invalid("passwords are 10-1024 characters".into()))
    }
}
```

- [ ] **Step 8: Implement `accounts.rs`**

Insert at the top of `crates/starforged-core/src/accounts.rs`:

```rust
//! Accounts: creation, password authentication, lookups.

use std::sync::OnceLock;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use starforged_db::users::{self, NewUser, UserRow};

use crate::{Core, CoreError, CoreResult, validate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub handle: String,
    pub display_name: String,
    pub email: Option<String>,
    pub is_admin: bool,
    pub active: bool,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> User {
        User {
            id: row.id,
            handle: row.handle,
            display_name: row.display_name,
            email: row.email,
            is_admin: row.is_admin,
            active: row.state == "active",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CreateUser {
    pub handle: String,
    pub display_name: String,
    pub email: Option<String>,
    /// `None` creates an account that cannot sign in with a password.
    pub password: Option<String>,
    pub is_admin: bool,
}

impl Core {
    pub async fn create_user(&self, input: CreateUser) -> CoreResult<User> {
        let handle = validate::handle(&input.handle)?;
        let email = input.email.as_deref().map(validate::email).transpose()?;
        let password_hash = match input.password {
            Some(password) => {
                validate::password(&password)?;
                Some(hash_password(password).await?)
            }
            None => None,
        };
        let new = NewUser {
            handle: &handle,
            display_name: input.display_name.trim(),
            email: email.as_deref(),
            password_hash: password_hash.as_deref(),
            is_admin: input.is_admin,
        };
        let id = users::insert(self.db(), &new).await.map_err(|e| {
            if e.is_unique_violation() {
                CoreError::Conflict("that handle or email is already taken".into())
            } else {
                e.into()
            }
        })?;
        self.user_by_id(id).await?.ok_or_else(|| CoreError::Internal("user missing after insert".into()))
    }

    /// `login` is a handle or an email. Unknown accounts, wrong passwords, password-less accounts,
    /// and suspended accounts all fail with `Unauthenticated`.
    pub async fn authenticate_password(&self, login: &str, password: &str) -> CoreResult<User> {
        let login = login.trim().to_ascii_lowercase();
        let row = if login.contains('@') {
            users::by_email(self.db(), &login).await?
        } else {
            users::by_handle(self.db(), &login).await?
        };
        let stored = row.as_ref().and_then(|r| r.password_hash.clone());
        let has_password = stored.is_some();
        // Unknown accounts are verified against a dummy hash so timing does not reveal which logins exist.
        let matches = verify_password(stored, password.to_owned()).await?;
        match row {
            Some(row) if matches && has_password && row.state == "active" => Ok(row.into()),
            _ => Err(CoreError::Unauthenticated),
        }
    }

    pub async fn user_by_id(&self, id: i64) -> CoreResult<Option<User>> {
        Ok(users::by_id(self.db(), id).await?.map(User::from))
    }

    pub async fn user_by_handle(&self, handle: &str) -> CoreResult<Option<User>> {
        Ok(users::by_handle(self.db(), &handle.trim().to_ascii_lowercase()).await?.map(User::from))
    }
}

async fn hash_password(password: String) -> CoreResult<String> {
    tokio::task::spawn_blocking(move || Argon2::default().hash_password(password.as_bytes()).map(|h| h.to_string()))
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?
        .map_err(|e| CoreError::Internal(e.to_string()))
}

async fn verify_password(stored: Option<String>, password: String) -> CoreResult<bool> {
    tokio::task::spawn_blocking(move || {
        let hash = stored.unwrap_or_else(|| dummy_hash().to_owned());
        PasswordHash::new(&hash)
            .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
            .unwrap_or(false)
    })
    .await
    .map_err(|e| CoreError::Internal(e.to_string()))
}

fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        Argon2::default().hash_password(b"starforge timing equalizer").expect("argon2 hashing works").to_string()
    })
}
```

- [ ] **Step 9: Run the core tests**

Run: `cargo test -p starforged-core`
Expected: 9 passed (2 crypto, 4 validate, 3 accounts).

- [ ] **Step 10: Lint, format, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/starforged-db crates/starforged-core Cargo.lock
git commit -m "feat(core): accounts with validated handles and argon2id password login"
```

---

### Task 4: Personal access tokens, audit log, and the admin CLI

**Files:**
- Create: `crates/starforged-db/src/tokens.rs`, `crates/starforged-db/src/audit.rs`; Modify: `crates/starforged-db/src/lib.rs` (add `pub mod audit;`, `pub mod tokens;`)
- Create: `crates/starforged-core/src/tokens.rs`, `crates/starforged-core/src/audit.rs`; Modify: `crates/starforged-core/src/lib.rs` (add `pub mod audit;`, `pub mod tokens;`)
- Create: `crates/starforged/src/admin.rs`; Modify: `crates/starforged/src/main.rs` (full replacement), `crates/starforged/src/lib.rs`, `crates/starforged/Cargo.toml`
- Test: unit tests in `crates/starforged-core/src/tokens.rs`; `crates/starforged/tests/admin_cli.rs`

**Interfaces:**
- Consumes: `Core`, `User`, `crypto::{random_hex, sha256_hex}` (Task 3); `starforged_db::now` (Task 2).
- Produces:
  - `starforged_db::tokens::{TokenRow, NewToken, insert, by_hash, list_for_user, revoke, touch}`; `starforged_db::audit::{AuditEntry, AuditRow, record, recent}`.
  - `starforged_core::tokens::{Scope, TOKEN_PREFIX, parse_scopes, format_scopes, grants, CreatedToken, TokenInfo, TokenAuth}`. `Scope::{RepoRead, RepoWrite, TrailWrite, SessionUpload, Admin}`, `Scope::ALL`, `Scope::as_str`, `Scope::parse`. `grants(held: &[Scope], needed: Scope) -> bool`.
  - `Core::create_token(&User, name: &str, scopes: &[Scope], expires_in_days: u32) -> CoreResult<CreatedToken>` (`CreatedToken { id, secret }`), `Core::authenticate_token(&str) -> CoreResult<TokenAuth>` (`TokenAuth { user, scopes, token_id }`), `Core::list_tokens(&User) -> CoreResult<Vec<TokenInfo>>`, `Core::revoke_token(&User, i64) -> CoreResult<()>`.
  - `Core::audit(actor_id: Option<i64>, action: &str, target: &str, detail: &str) -> CoreResult<()>`, `Core::audit_client(…, ip: &str, user_agent: &str)`.
  - `starforged::admin::{open_core(&Config, hook_exe: PathBuf) -> anyhow::Result<Core>, migrate, NewUserArgs, create_user, create_token}`.
  - CLI: `starforged migrate`; `starforged admin user create --handle H [--email E] [--display-name N] [--admin] [--password-stdin]`; `starforged admin token create --user H --name N [--scopes LIST] [--expires-days D]` (prints only the token).

- [ ] **Step 1: Implement the table modules**

These are thin SQL wrappers; their behavior is covered by the core tests in Step 2.

`crates/starforged-db/src/tokens.rs`:

```rust
//! `access_tokens`: personal access tokens, stored as SHA-256 hex of the secret.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRow {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub token_hint: String,
    pub scopes: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub struct NewToken<'a> {
    pub user_id: i64,
    pub name: &'a str,
    pub token_hash: &'a str,
    pub token_hint: &'a str,
    pub scopes: &'a str,
    pub expires_at: i64,
}

macro_rules! select_token {
    ($tail:literal) => {
        concat!(
            "SELECT id, user_id, name, token_hint, scopes, created_at, expires_at, last_used_at, revoked_at ",
            "FROM access_tokens ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<TokenRow> {
    Ok(TokenRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        name: row.try_get("name")?,
        token_hint: row.try_get("token_hint")?,
        scopes: row.try_get("scopes")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub async fn insert(db: &Db, token: &NewToken<'_>) -> DbResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO access_tokens (user_id, name, token_hash, token_hint, scopes, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(token.user_id)
    .bind(token.name)
    .bind(token.token_hash)
    .bind(token.token_hint)
    .bind(token.scopes)
    .bind(now())
    .bind(token.expires_at)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

pub async fn by_hash(db: &Db, token_hash: &str) -> DbResult<Option<TokenRow>> {
    let row = sqlx::query(select_token!("WHERE token_hash = $1")).bind(token_hash).fetch_optional(db.pool()).await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn list_for_user(db: &Db, user_id: i64) -> DbResult<Vec<TokenRow>> {
    let rows = sqlx::query(select_token!("WHERE user_id = $1 ORDER BY id DESC")).bind(user_id).fetch_all(db.pool()).await?;
    rows.iter().map(from_row).collect()
}

/// Revokes the user's token; `false` when it does not exist, belongs to someone else, or is already revoked.
pub async fn revoke(db: &Db, user_id: i64, token_id: i64) -> DbResult<bool> {
    let result = sqlx::query(
        "UPDATE access_tokens SET revoked_at = $1 WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(token_id)
    .bind(user_id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn touch(db: &Db, token_id: i64) -> DbResult<()> {
    sqlx::query("UPDATE access_tokens SET last_used_at = $1 WHERE id = $2").bind(now()).bind(token_id).execute(db.pool()).await?;
    Ok(())
}
```

`crates/starforged-db/src/audit.rs`:

```rust
//! `audit_log`: append-only record of security-relevant events (spec §6.5). Never stores transcript content.

use sqlx::Row;

use crate::{Db, DbResult, now};

pub struct AuditEntry<'a> {
    pub actor_id: Option<i64>,
    pub action: &'a str,
    pub target: &'a str,
    pub detail: &'a str,
    pub ip: &'a str,
    pub user_agent: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: i64,
    pub actor_id: Option<i64>,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub created_at: i64,
}

pub async fn record(db: &Db, entry: &AuditEntry<'_>) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, target, detail, ip, user_agent, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(entry.actor_id)
    .bind(entry.action)
    .bind(entry.target)
    .bind(entry.detail)
    .bind(entry.ip)
    .bind(entry.user_agent)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Newest first.
pub async fn recent(db: &Db, limit: i64) -> DbResult<Vec<AuditRow>> {
    let rows = sqlx::query("SELECT id, actor_id, action, target, detail, created_at FROM audit_log ORDER BY id DESC LIMIT $1")
        .bind(limit)
        .fetch_all(db.pool())
        .await?;
    rows.iter()
        .map(|row| {
            Ok(AuditRow {
                id: row.try_get("id")?,
                actor_id: row.try_get("actor_id")?,
                action: row.try_get("action")?,
                target: row.try_get("target")?,
                detail: row.try_get("detail")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}
```

Add `pub mod audit;` and `pub mod tokens;` to `crates/starforged-db/src/lib.rs`.

`crates/starforged-core/src/audit.rs`:

```rust
use starforged_db::audit::{self, AuditEntry};

use crate::{Core, CoreResult};

impl Core {
    /// Appends to the audit log. `target` names the object, e.g. `token:12` or `repo:alice/proj`.
    pub async fn audit(&self, actor_id: Option<i64>, action: &str, target: &str, detail: &str) -> CoreResult<()> {
        self.audit_client(actor_id, action, target, detail, "", "").await
    }

    /// Like [`Core::audit`], recording the client's IP address and user agent.
    pub async fn audit_client(
        &self,
        actor_id: Option<i64>,
        action: &str,
        target: &str,
        detail: &str,
        ip: &str,
        user_agent: &str,
    ) -> CoreResult<()> {
        audit::record(self.db(), &AuditEntry { actor_id, action, target, detail, ip, user_agent }).await?;
        Ok(())
    }
}
```

Add `pub mod audit;` and `pub mod tokens;` to `crates/starforged-core/src/lib.rs`.

- [ ] **Step 2: Write the failing token tests**

Create `crates/starforged-core/src/tokens.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, user};

    #[test]
    fn scope_parsing_and_implication() {
        assert_eq!(parse_scopes("repo:read, repo:write repo:read").unwrap(), vec![Scope::RepoRead, Scope::RepoWrite]);
        assert!(parse_scopes("").is_err());
        assert!(parse_scopes("repo:delete").is_err());
        assert!(grants(&[Scope::RepoWrite], Scope::RepoRead));
        assert!(!grants(&[Scope::RepoRead], Scope::RepoWrite));
        assert!(grants(&[Scope::Admin], Scope::SessionUpload));
        assert_eq!(format_scopes(&[Scope::RepoRead, Scope::TrailWrite]), "repo:read trail:write");
    }

    #[tokio::test]
    async fn token_lifecycle_is_audited() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let created = core.create_token(&alice, "laptop", &[Scope::RepoWrite], 30).await.unwrap();
        assert!(created.secret.starts_with(TOKEN_PREFIX));
        assert_eq!(created.secret.len(), TOKEN_PREFIX.len() + 64);
        let auth = core.authenticate_token(&created.secret).await.unwrap();
        assert_eq!((auth.user.id, auth.scopes.clone(), auth.token_id), (alice.id, vec![Scope::RepoWrite], created.id));
        let listed = core.list_tokens(&alice).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hint, created.secret[created.secret.len() - 4..]);
        assert!(listed[0].last_used_at.is_some(), "authentication records last use");
        assert!(!listed[0].revoked);
        core.revoke_token(&alice, created.id).await.unwrap();
        assert!(matches!(core.authenticate_token(&created.secret).await, Err(CoreError::Unauthenticated)));
        assert!(matches!(core.revoke_token(&alice, created.id).await, Err(CoreError::NotFound)));
        let actions: Vec<String> =
            starforged_db::audit::recent(core.db(), 10).await.unwrap().into_iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["token.revoke", "token.create"]);
    }

    #[tokio::test]
    async fn rejects_foreign_expired_and_malformed_tokens() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        assert!(matches!(core.authenticate_token("ghp_abc").await, Err(CoreError::Unauthenticated)));
        let unknown = format!("{TOKEN_PREFIX}{}", "0".repeat(64));
        assert!(matches!(core.authenticate_token(&unknown).await, Err(CoreError::Unauthenticated)));
        assert!(matches!(core.create_token(&alice, "x", &[Scope::Admin], 1).await, Err(CoreError::Forbidden)));
        assert!(matches!(core.create_token(&alice, " ", &[Scope::RepoRead], 1).await, Err(CoreError::Invalid(_))));
        assert!(matches!(core.create_token(&alice, "x", &[Scope::RepoRead], 0).await, Err(CoreError::Invalid(_))));
        let token = core.create_token(&alice, "x", &[Scope::RepoRead], 1).await.unwrap();
        assert!(matches!(core.revoke_token(&bob, token.id).await, Err(CoreError::NotFound)));
        sqlx::query("UPDATE access_tokens SET expires_at = $1 WHERE id = $2")
            .bind(0_i64)
            .bind(token.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        assert!(matches!(core.authenticate_token(&token.secret).await, Err(CoreError::Unauthenticated)));
    }
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test -p starforged-core tokens`
Expected: compile errors (`Scope`, `parse_scopes` missing).

- [ ] **Step 4: Implement `tokens.rs`**

Insert at the top of `crates/starforged-core/src/tokens.rs`:

```rust
//! Personal access tokens (spec §6.1): `sfp_` + 64 hex characters, stored as SHA-256, scoped, expiring.

use starforged_db::tokens::{self as db_tokens, NewToken, TokenRow};

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, crypto};

pub const TOKEN_PREFIX: &str = "sfp_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    RepoRead,
    RepoWrite,
    TrailWrite,
    SessionUpload,
    Admin,
}

impl Scope {
    pub const ALL: [Scope; 5] = [Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite, Scope::SessionUpload, Scope::Admin];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::RepoRead => "repo:read",
            Scope::RepoWrite => "repo:write",
            Scope::TrailWrite => "trail:write",
            Scope::SessionUpload => "session:upload",
            Scope::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|scope| scope.as_str() == s)
    }
}

/// Parses a comma- or whitespace-separated scope list, dropping duplicates. Unknown or empty lists are invalid.
pub fn parse_scopes(input: &str) -> CoreResult<Vec<Scope>> {
    let mut scopes = Vec::new();
    for part in input.split(|c: char| c == ',' || c.is_whitespace()).filter(|p| !p.is_empty()) {
        let scope = Scope::parse(part).ok_or_else(|| CoreError::Invalid(format!("unknown scope '{part}'")))?;
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        return Err(CoreError::Invalid("at least one scope is required".into()));
    }
    Ok(scopes)
}

pub fn format_scopes(scopes: &[Scope]) -> String {
    scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")
}

/// Whether `held` allows an operation needing `needed`: `repo:write` implies `repo:read`; `admin` implies everything.
pub fn grants(held: &[Scope], needed: Scope) -> bool {
    held.contains(&needed)
        || held.contains(&Scope::Admin)
        || (needed == Scope::RepoRead && held.contains(&Scope::RepoWrite))
}

#[derive(Debug, Clone)]
pub struct CreatedToken {
    pub id: i64,
    /// Shown to the user once; only its hash is stored.
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub id: i64,
    pub name: String,
    /// Last four characters of the secret.
    pub hint: String,
    pub scopes: Vec<Scope>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct TokenAuth {
    pub user: User,
    pub scopes: Vec<Scope>,
    pub token_id: i64,
}

impl Core {
    pub async fn create_token(
        &self,
        user: &User,
        name: &str,
        scopes: &[Scope],
        expires_in_days: u32,
    ) -> CoreResult<CreatedToken> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(CoreError::Invalid("token names are 1-64 characters".into()));
        }
        if !(1..=366).contains(&expires_in_days) {
            return Err(CoreError::Invalid("tokens expire after 1-366 days".into()));
        }
        if scopes.is_empty() {
            return Err(CoreError::Invalid("at least one scope is required".into()));
        }
        if scopes.contains(&Scope::Admin) && !user.is_admin {
            return Err(CoreError::Forbidden);
        }
        let secret = format!("{TOKEN_PREFIX}{}", crypto::random_hex(32));
        let hint = &secret[secret.len() - 4..];
        let expires_at = starforged_db::now() + i64::from(expires_in_days) * 86_400;
        let id = db_tokens::insert(
            self.db(),
            &NewToken {
                user_id: user.id,
                name,
                token_hash: &crypto::sha256_hex(&secret),
                token_hint: hint,
                scopes: &format_scopes(scopes),
                expires_at,
            },
        )
        .await?;
        self.audit(Some(user.id), "token.create", &format!("token:{id}"), name).await?;
        Ok(CreatedToken { id, secret })
    }

    /// Resolves a secret to its user and scopes. Unknown, revoked, and expired tokens, and tokens of
    /// suspended users, fail with `Unauthenticated`.
    pub async fn authenticate_token(&self, secret: &str) -> CoreResult<TokenAuth> {
        if !secret.starts_with(TOKEN_PREFIX) {
            return Err(CoreError::Unauthenticated);
        }
        let row = db_tokens::by_hash(self.db(), &crypto::sha256_hex(secret)).await?.ok_or(CoreError::Unauthenticated)?;
        if row.revoked_at.is_some() || row.expires_at <= starforged_db::now() {
            return Err(CoreError::Unauthenticated);
        }
        let user = self.user_by_id(row.user_id).await?.filter(|u| u.active).ok_or(CoreError::Unauthenticated)?;
        let scopes = parse_scopes(&row.scopes)?;
        db_tokens::touch(self.db(), row.id).await?;
        Ok(TokenAuth { user, scopes, token_id: row.id })
    }

    pub async fn list_tokens(&self, user: &User) -> CoreResult<Vec<TokenInfo>> {
        db_tokens::list_for_user(self.db(), user.id).await?.into_iter().map(token_info).collect()
    }

    pub async fn revoke_token(&self, user: &User, token_id: i64) -> CoreResult<()> {
        if !db_tokens::revoke(self.db(), user.id, token_id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(Some(user.id), "token.revoke", &format!("token:{token_id}"), "").await
    }
}

fn token_info(row: TokenRow) -> CoreResult<TokenInfo> {
    Ok(TokenInfo {
        id: row.id,
        name: row.name,
        hint: row.token_hint,
        scopes: parse_scopes(&row.scopes)?,
        created_at: row.created_at,
        expires_at: row.expires_at,
        last_used_at: row.last_used_at,
        revoked: row.revoked_at.is_some(),
    })
}
```

- [ ] **Step 5: Run the core tests**

Run: `cargo test -p starforged-core`
Expected: 12 passed.

- [ ] **Step 6: Write the failing admin CLI test**

`crates/starforged/tests/admin_cli.rs`:

```rust
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(config: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn admin_creates_users_and_tokens() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    let data = tmp.path().join("data");
    assert!(run(&config, &["init", "--data-dir", data.to_str().unwrap()], None).status.success());

    let created = run(
        &config,
        &["admin", "user", "create", "--handle", "Alice", "--email", "alice@example.com", "--admin", "--password-stdin"],
        Some("correct horse battery\n"),
    );
    assert!(created.status.success(), "{}", String::from_utf8_lossy(&created.stderr));
    assert!(String::from_utf8_lossy(&created.stdout).starts_with("created user alice (id "));

    let token = run(&config, &["admin", "token", "create", "--user", "alice", "--name", "ci", "--scopes", "repo:read"], None);
    assert!(token.status.success(), "{}", String::from_utf8_lossy(&token.stderr));
    let secret = String::from_utf8(token.stdout).unwrap().trim().to_owned();
    assert!(secret.starts_with("sfp_") && secret.len() == 68, "{secret}");

    let duplicate = run(&config, &["admin", "user", "create", "--handle", "alice"], None);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already taken"));

    let migrate = run(&config, &["migrate"], None);
    assert!(migrate.status.success());
}
```

- [ ] **Step 7: Run it to see it fail**

Run: `cargo test -p starforged --test admin_cli`
Expected: FAIL — the binary does not know the `admin` subcommand.

- [ ] **Step 8: Implement `admin.rs`, the new `main.rs`, and the manifest**

`crates/starforged/Cargo.toml` `[dependencies]` becomes:

```toml
[dependencies]
anyhow.workspace = true
clap.workspace = true
getrandom.workspace = true
hex.workspace = true
serde.workspace = true
starforged-core = { path = "../starforged-core" }
starforged-db = { path = "../starforged-db" }
tokio.workspace = true
toml.workspace = true
```

`crates/starforged/src/lib.rs`:

```rust
//! starforged: the Starforge server. The library half exists so integration tests can build the app in-process.

pub mod admin;
pub mod config;
pub mod init;
```

`crates/starforged/src/admin.rs`:

```rust
//! Administrative commands that act on the database directly, without a running server.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Context;
use starforged_core::accounts::{CreateUser, User};
use starforged_core::{Core, CoreConfig, tokens};
use starforged_db::Db;

use crate::config::Config;

/// Connects to the configured database (migrating it when `database.auto_migrate` is on) and builds `Core`.
pub async fn open_core(config: &Config, hook_exe: PathBuf) -> anyhow::Result<Core> {
    let db = Db::connect(&config.database_url()).await.context("connecting to the database")?;
    if config.database.auto_migrate {
        db.migrate().await.context("migrating the database")?;
    }
    Ok(Core::new(db, CoreConfig { repos_dir: config.repos_dir(), hook_exe }))
}

pub async fn migrate(config: &Config) -> anyhow::Result<()> {
    let db = Db::connect(&config.database_url()).await.context("connecting to the database")?;
    db.migrate().await.context("migrating the database")?;
    Ok(())
}

pub struct NewUserArgs {
    pub handle: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub admin: bool,
    pub password_stdin: bool,
}

pub async fn create_user(config: &Config, args: NewUserArgs) -> anyhow::Result<User> {
    let password = if args.password_stdin {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text).context("reading the password from stdin")?;
        Some(text.trim_end_matches(['\r', '\n']).to_owned())
    } else {
        None
    };
    let core = open_core(config, std::env::current_exe()?).await?;
    let user = core
        .create_user(CreateUser {
            handle: args.handle,
            display_name: args.display_name.unwrap_or_default(),
            email: args.email,
            password,
            is_admin: args.admin,
        })
        .await?;
    Ok(user)
}

pub async fn create_token(
    config: &Config,
    handle: &str,
    name: &str,
    scopes: &str,
    expires_days: u32,
) -> anyhow::Result<String> {
    let core = open_core(config, std::env::current_exe()?).await?;
    let user = core.user_by_handle(handle).await?.with_context(|| format!("no user named '{handle}'"))?;
    let scopes = tokens::parse_scopes(scopes)?;
    Ok(core.create_token(&user, name, &scopes, expires_days).await?.secret)
}
```

`crates/starforged/src/main.rs` (full replacement):

```rust
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use starforged::admin::{self, NewUserArgs};
use starforged::config::Config;

#[derive(Parser)]
#[command(name = "starforged", version, about = "Starforge server")]
struct Cli {
    /// Path to starforged.toml.
    #[arg(long, env = "STARFORGE_CONFIG", default_value = "starforged.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a new config file and data directory.
    Init {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        base_url: String,
        #[arg(long, default_value = "127.0.0.1:3000")]
        http_addr: String,
    },
    /// Create or update the database schema.
    Migrate,
    /// Administrative tasks.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Manage users.
    User {
        #[command(subcommand)]
        command: AdminUserCommand,
    },
    /// Manage personal access tokens.
    Token {
        #[command(subcommand)]
        command: AdminTokenCommand,
    },
}

#[derive(Subcommand)]
enum AdminUserCommand {
    /// Create a local user.
    Create {
        #[arg(long)]
        handle: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        display_name: Option<String>,
        /// Make the user a site administrator.
        #[arg(long)]
        admin: bool,
        /// Read the password from standard input.
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum AdminTokenCommand {
    /// Create a personal access token and print it once.
    Create {
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: String,
        /// Comma-separated scopes.
        #[arg(long, default_value = "repo:read,repo:write")]
        scopes: String,
        #[arg(long, default_value_t = 30)]
        expires_days: u32,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { data_dir, base_url, http_addr } => {
            let config = starforged::init::run(&starforged::init::InitOptions {
                config_path: &cli.config,
                data_dir: &data_dir,
                base_url: &base_url,
                http_addr: &http_addr,
            })?;
            println!("wrote {} (data directory {})", cli.config.display(), config.storage.data_dir.display());
        }
        Command::Migrate => {
            admin::migrate(&Config::load(&cli.config)?).await?;
            println!("database schema is up to date");
        }
        Command::Admin { command } => {
            let config = Config::load(&cli.config)?;
            match command {
                AdminCommand::User {
                    command: AdminUserCommand::Create { handle, email, display_name, admin: is_admin, password_stdin },
                } => {
                    let args = NewUserArgs { handle, email, display_name, admin: is_admin, password_stdin };
                    let user = admin::create_user(&config, args).await?;
                    println!("created user {} (id {})", user.handle, user.id);
                }
                AdminCommand::Token { command: AdminTokenCommand::Create { user, name, scopes, expires_days } } => {
                    println!("{}", admin::create_token(&config, &user, &name, &scopes, expires_days).await?);
                }
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 9: Run the crate's tests**

Run: `cargo test -p starforged`
Expected: all pass (4 unit, 2 `init_cli`, 1 `admin_cli`).

- [ ] **Step 10: Lint, format, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates Cargo.lock
git commit -m "feat: personal access tokens, audit log, and admin CLI"
```

---

### Task 5: Repositories, permissions, and bare repository creation

**Files:**
- Create: `crates/starforged-git/Cargo.toml`, `crates/starforged-git/src/lib.rs`, `crates/starforged-git/src/command.rs`, `crates/starforged-git/src/init.rs`
- Create: `crates/starforged-db/src/repos.rs`, `crates/starforged-db/src/collaborators.rs`; Modify: `crates/starforged-db/src/lib.rs`
- Create: `crates/starforged-core/src/permission.rs`, `crates/starforged-core/src/repos.rs`; Modify: `crates/starforged-core/src/lib.rs`, `crates/starforged-core/src/error.rs`, `crates/starforged-core/Cargo.toml`
- Test: unit tests in `command.rs`, `init.rs`, `permission.rs`, `repos.rs`

**Interfaces:**
- Consumes: `Core`, `User`, `validate::repo_name`, `Core::audit`, `Core::user_by_handle` (Tasks 3–4).
- Produces:
  - `starforged_git::command::{git() -> tokio::process::Command, run(args) -> Result<Vec<u8>, GitError>, parse_version(&str) -> Option<(u32, u32)>, check_version() -> Result<(u32, u32), GitError>}`; `starforged_git::GitError::{Failed { command, stderr }, Io, Gix(String), TooOld(String)}`.
  - `starforged_git::init::{HOOKS, init_bare(path, default_branch, hook_exe), install_hooks(repo, hook_exe), hook_script(hook_exe, name) -> String, shell_quote(&str) -> String}`.
  - `starforged_db::repos::{RepoRow, NewRepo, insert, by_owner_and_name, by_id, list_by_owner, list_collaborating, delete}`; `starforged_db::collaborators::{CollaboratorRow, upsert, remove, permission, list}`.
  - `starforged_core::permission::{Permission, Visibility, Viewer, effective}`. `Permission` is ordered `Read < Triage < Write < Maintain < Admin`; both enums have `as_str()` and `parse(&str) -> Option<Self>`.
  - `starforged_core::repos::{Repo, RepoAccess, CreateRepo, Collaborator}`; `Repo::full_name()`.
  - `Core::repo_path(i64) -> PathBuf`; `Core::create_repo(&User, CreateRepo) -> CoreResult<Repo>`; `Core::repo_for(Option<&User>, owner, name) -> CoreResult<RepoAccess>`; `Core::require_repo(Option<&User>, owner, name, Permission) -> CoreResult<RepoAccess>`; `Core::permission_on(&Repo, Option<&User>) -> CoreResult<Option<Permission>>`; `Core::repos_of(Option<&User>, owner) -> CoreResult<Vec<Repo>>`; `Core::dashboard_repos(&User) -> CoreResult<Vec<Repo>>`; `Core::collaborators(&User, owner, name)`; `Core::set_collaborator(&User, owner, name, handle, Permission)`; `Core::remove_collaborator(&User, owner, name, handle)`.
  - `impl From<GitError> for CoreError` (→ `CoreError::Git`).

- [ ] **Step 1: Create the git crate with failing tests**

`crates/starforged-git/Cargo.toml`:

```toml
[package]
name = "starforged-git"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true

[dependencies]
thiserror.workspace = true
tokio.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`crates/starforged-git/src/lib.rs`:

```rust
//! starforged-git: repositories on disk. The network protocol, merges, and diffs run the `git` binary;
//! read paths use gix (spec D11).

pub mod command;
pub mod init;

pub use command::GitError;
```

`crates/starforged-git/src/command.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_versions() {
        assert_eq!(parse_version("git version 2.53.0\n"), Some((2, 53)));
        assert_eq!(parse_version("git version 2.39.5 (Apple Git-154)"), Some((2, 39)));
        assert_eq!(parse_version("git version 2.38.0.windows.1"), Some((2, 38)));
        assert_eq!(parse_version("hg version 6.0"), None);
    }

    #[tokio::test]
    async fn installed_git_is_new_enough() {
        assert!(check_version().await.unwrap() >= (2, 38));
    }

    #[tokio::test]
    async fn failures_carry_stderr() {
        let err = run(["--git-dir", "/nonexistent/starforge-test", "rev-parse", "HEAD"]).await.unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }));
        assert!(err.to_string().contains("not a git repository"), "{err}");
    }
}
```

`crates/starforged-git/src/init.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::run;

    #[tokio::test]
    async fn init_bare_creates_head_config_and_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("07").join("7.git");
        init_bare(&repo, "main", Path::new("/opt/star forge/starforged")).await.unwrap();
        assert_eq!(std::fs::read_to_string(repo.join("HEAD")).unwrap().trim(), "ref: refs/heads/main");
        let hook = std::fs::read_to_string(repo.join("hooks/pre-receive")).unwrap();
        assert_eq!(hook, "#!/bin/sh\nexec '/opt/star forge/starforged' hook pre-receive\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(repo.join("hooks/pre-receive")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        let filter = run([
            std::ffi::OsStr::new("--git-dir"),
            repo.as_os_str(),
            std::ffi::OsStr::new("config"),
            std::ffi::OsStr::new("--get"),
            std::ffi::OsStr::new("uploadpack.allowFilter"),
        ])
        .await
        .unwrap();
        assert_eq!(String::from_utf8(filter).unwrap().trim(), "true");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-git`
Expected: compile errors (`parse_version`, `init_bare` missing).

- [ ] **Step 3: Implement `command.rs` and `init.rs`**

Insert at the top of `crates/starforged-git/src/command.rs`:

```rust
//! Running `git` with a hermetic environment.

use std::ffi::{OsStr, OsString};
use std::process::Stdio;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git {command} failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error("running git: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Gix(String),
    #[error("unsupported git ({0}); starforged needs git 2.38 or newer")]
    TooOld(String),
}

/// A `git` command isolated from system and user configuration, with prompts disabled and
/// stdin closed. Callers that stream data replace stdin/stdout/stderr.
pub fn git() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    cmd
}

/// Runs git and returns stdout; a non-zero exit becomes [`GitError::Failed`] with stderr.
pub async fn run<I, S>(args: I) -> Result<Vec<u8>, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<OsString> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();
    let out = git().args(&args).output().await?;
    if !out.status.success() {
        return Err(GitError::Failed {
            command: args.iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" "),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    Ok(out.stdout)
}

/// Parses `git version 2.53.0` (and vendor suffixes) into `(major, minor)`.
pub fn parse_version(output: &str) -> Option<(u32, u32)> {
    let version = output.trim().strip_prefix("git version ")?;
    let mut numbers = version.split(|c: char| !c.is_ascii_digit());
    Some((numbers.next()?.parse().ok()?, numbers.next()?.parse().ok()?))
}

/// Fails unless the installed git is 2.38+ (`merge-tree --write-tree`, spec §5.5).
pub async fn check_version() -> Result<(u32, u32), GitError> {
    let text = String::from_utf8_lossy(&run(["version"]).await?).into_owned();
    match parse_version(&text) {
        Some(version) if version >= (2, 38) => Ok(version),
        _ => Err(GitError::TooOld(text.trim().to_owned())),
    }
}
```

Insert at the top of `crates/starforged-git/src/init.rs`:

```rust
//! Creating hosted repositories and installing their hooks.

use std::ffi::OsStr;
use std::path::Path;

use crate::command::{GitError, run};

/// Hooks installed in every hosted repository; each runs `<hook_exe> hook <name>`.
pub const HOOKS: &[&str] = &["pre-receive"];

/// Creates a bare repository at `path` (parents included) whose HEAD points at `default_branch`,
/// enables partial-clone filters, and installs the hooks.
pub async fn init_bare(path: &Path, default_branch: &str, hook_exe: &Path) -> Result<(), GitError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    run([
        OsStr::new("init"),
        OsStr::new("--bare"),
        OsStr::new("--quiet"),
        OsStr::new("--initial-branch"),
        OsStr::new(default_branch),
        path.as_os_str(),
    ])
    .await?;
    run([
        OsStr::new("--git-dir"),
        path.as_os_str(),
        OsStr::new("config"),
        OsStr::new("uploadpack.allowFilter"),
        OsStr::new("true"),
    ])
    .await?;
    install_hooks(path, hook_exe).await
}

pub async fn install_hooks(repo: &Path, hook_exe: &Path) -> Result<(), GitError> {
    let dir = repo.join("hooks");
    tokio::fs::create_dir_all(&dir).await?;
    for name in HOOKS {
        let path = dir.join(name);
        tokio::fs::write(&path, hook_script(hook_exe, name)).await?;
        set_executable(&path).await?;
    }
    Ok(())
}

pub fn hook_script(hook_exe: &Path, name: &str) -> String {
    format!("#!/bin/sh\nexec {} hook {name}\n", shell_quote(&hook_exe.to_string_lossy()))
}

/// Single-quotes `s` for `/bin/sh`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(unix)]
async fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).await
}

#[cfg(not(unix))]
async fn set_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
```

- [ ] **Step 4: Run the git crate tests**

Run: `cargo test -p starforged-git`
Expected: 5 passed.

- [ ] **Step 5: Add the repository and collaborator table modules**

These are thin SQL wrappers; the core tests in Step 6 cover their behavior.

`crates/starforged-db/src/repos.rs`:

```rust
//! `repos`: repository metadata. Git data lives on disk under `<data_dir>/repos` (spec §5.3).

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRow {
    pub id: i64,
    pub owner_id: i64,
    pub owner_handle: String,
    pub name: String,
    pub description: String,
    pub visibility: String,
    pub default_branch: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct NewRepo<'a> {
    pub owner_id: i64,
    pub name: &'a str,
    pub description: &'a str,
    pub visibility: &'a str,
    pub default_branch: &'a str,
}

macro_rules! select_repo {
    ($tail:literal) => {
        concat!(
            "SELECT r.id, r.owner_id, o.handle AS owner_handle, r.name, r.description, r.visibility, ",
            "r.default_branch, r.created_at, r.updated_at FROM repos r JOIN owners o ON o.id = r.owner_id ",
            $tail
        )
    };
}

fn from_row(row: &AnyRow) -> DbResult<RepoRow> {
    Ok(RepoRow {
        id: row.try_get("id")?,
        owner_id: row.try_get("owner_id")?,
        owner_handle: row.try_get("owner_handle")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        visibility: row.try_get("visibility")?,
        default_branch: row.try_get("default_branch")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub async fn insert(db: &Db, repo: &NewRepo<'_>) -> DbResult<i64> {
    let ts = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO repos (owner_id, name, lower_name, description, visibility, default_branch, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(repo.owner_id)
    .bind(repo.name)
    .bind(repo.name.to_ascii_lowercase())
    .bind(repo.description)
    .bind(repo.visibility)
    .bind(repo.default_branch)
    .bind(ts)
    .bind(ts)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

/// Case-insensitive lookup by owner handle and repository name.
pub async fn by_owner_and_name(db: &Db, owner_handle: &str, name: &str) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!("WHERE o.handle = $1 AND r.lower_name = $2"))
        .bind(owner_handle.to_ascii_lowercase())
        .bind(name.to_ascii_lowercase())
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!("WHERE r.id = $1")).bind(id).fetch_optional(db.pool()).await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn list_by_owner(db: &Db, owner_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!("WHERE r.owner_id = $1 ORDER BY r.lower_name")).bind(owner_id).fetch_all(db.pool()).await?;
    rows.iter().map(from_row).collect()
}

/// Repositories where `user_id` is a collaborator, by owner then name.
pub async fn list_collaborating(db: &Db, user_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "JOIN collaborators c ON c.repo_id = r.id WHERE c.user_id = $1 ORDER BY o.handle, r.lower_name"
    ))
    .bind(user_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

pub async fn delete(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM repos WHERE id = $1").bind(id).execute(db.pool()).await?;
    Ok(())
}
```

`crates/starforged-db/src/collaborators.rs`:

```rust
//! `collaborators`: direct per-repository grants to users (spec §6.1).

use sqlx::Row;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollaboratorRow {
    pub user_id: i64,
    pub handle: String,
    pub permission: String,
}

/// Grants `permission`, replacing any existing grant.
pub async fn upsert(db: &Db, repo_id: i64, user_id: i64, permission: &str) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO collaborators (repo_id, user_id, permission, created_at) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (repo_id, user_id) DO UPDATE SET permission = excluded.permission",
    )
    .bind(repo_id)
    .bind(user_id)
    .bind(permission)
    .bind(now())
    .execute(db.pool())
    .await?;
    Ok(())
}

pub async fn remove(db: &Db, repo_id: i64, user_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM collaborators WHERE repo_id = $1 AND user_id = $2")
        .bind(repo_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn permission(db: &Db, repo_id: i64, user_id: i64) -> DbResult<Option<String>> {
    let value: Option<String> = sqlx::query_scalar("SELECT permission FROM collaborators WHERE repo_id = $1 AND user_id = $2")
        .bind(repo_id)
        .bind(user_id)
        .fetch_optional(db.pool())
        .await?;
    Ok(value)
}

pub async fn list(db: &Db, repo_id: i64) -> DbResult<Vec<CollaboratorRow>> {
    let rows = sqlx::query(
        "SELECT c.user_id, o.handle, c.permission FROM collaborators c JOIN owners o ON o.id = c.user_id \
         WHERE c.repo_id = $1 ORDER BY o.handle",
    )
    .bind(repo_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|row| Ok(CollaboratorRow { user_id: row.try_get("user_id")?, handle: row.try_get("handle")?, permission: row.try_get("permission")? }))
        .collect()
}
```

Add `pub mod collaborators;` and `pub mod repos;` to `crates/starforged-db/src/lib.rs`.

- [ ] **Step 6: Write the failing permission and repository tests**

Add to `crates/starforged-core/Cargo.toml` `[dependencies]`:

```toml
starforged-git = { path = "../starforged-git" }
```

Append to `crates/starforged-core/src/error.rs`:

```rust
impl From<starforged_git::GitError> for CoreError {
    fn from(e: starforged_git::GitError) -> CoreError {
        CoreError::Git(e.to_string())
    }
}
```

Add `pub mod permission;` and `pub mod repos;` to `crates/starforged-core/src/lib.rs`, and add this method inside `impl Core` there:

```rust
    /// `<repos_dir>/<id % 100, two digits>/<id>.git` (spec §5.3). Renames never move directories.
    pub fn repo_path(&self, repo_id: i64) -> PathBuf {
        self.inner
            .config
            .repos_dir
            .join(format!("{:02}", repo_id.rem_euclid(100)))
            .join(format!("{repo_id}.git"))
    }
```

`crates/starforged-core/src/permission.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_permission_matrix() {
        use Permission::*;
        use Visibility::*;
        let owner = Viewer { user_id: 1, is_admin: false };
        let other = Viewer { user_id: 2, is_admin: false };
        let site_admin = Viewer { user_id: 3, is_admin: true };
        let cases = [
            (Private, Some(owner), None, Some(Admin)),
            (Private, Some(site_admin), None, Some(Admin)),
            (Private, Some(other), None, None),
            (Private, None, None, None),
            (Private, Some(other), Some(Write), Some(Write)),
            (Internal, Some(other), None, Some(Read)),
            (Internal, None, None, None),
            (Internal, Some(other), Some(Maintain), Some(Maintain)),
            (Public, None, None, Some(Read)),
            (Public, Some(other), None, Some(Read)),
            (Public, Some(other), Some(Triage), Some(Triage)),
        ];
        for (visibility, viewer, collaborator, expected) in cases {
            assert_eq!(effective(1, visibility, viewer, collaborator), expected, "{visibility:?} {viewer:?} {collaborator:?}");
        }
    }

    #[test]
    fn names_round_trip() {
        for p in Permission::ALL {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
        }
        for v in [Visibility::Public, Visibility::Internal, Visibility::Private] {
            assert_eq!(Visibility::parse(v.as_str()), Some(v));
        }
        assert_eq!(Permission::parse("owner"), None);
        assert!(Permission::Read < Permission::Admin);
    }
}
```

`crates/starforged-core/src/repos.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, user};

    fn new(name: &str, visibility: Visibility) -> CreateRepo {
        CreateRepo { name: name.into(), description: String::new(), visibility }
    }

    #[tokio::test]
    async fn repo_paths_are_sharded_by_the_last_two_digits() {
        let (core, _f) = test_core().await;
        let root = core.config().repos_dir.clone();
        assert_eq!(core.repo_path(7), root.join("07").join("7.git"));
        assert_eq!(core.repo_path(1234), root.join("34").join("1234.git"));
    }

    #[tokio::test]
    async fn create_repo_initializes_a_bare_repository() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = core
            .create_repo(&alice, CreateRepo { name: "Proj".into(), description: " demo ".into(), visibility: Visibility::Private })
            .await
            .unwrap();
        assert_eq!(
            (repo.owner.as_str(), repo.name.as_str(), repo.description.as_str(), repo.default_branch.as_str()),
            ("alice", "Proj", "demo", "main")
        );
        assert_eq!(repo.full_name(), "alice/Proj");
        let path = core.repo_path(repo.id);
        assert!(path.join("HEAD").is_file());
        assert!(path.join("hooks/pre-receive").is_file());
        assert!(matches!(core.create_repo(&alice, new("proj", Visibility::Public)).await, Err(CoreError::Conflict(_))));
        assert!(matches!(core.create_repo(&alice, new("x.git", Visibility::Public)).await, Err(CoreError::Invalid(_))));
        let actions: Vec<String> =
            starforged_db::audit::recent(core.db(), 5).await.unwrap().into_iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["repo.create"]);
    }

    #[tokio::test]
    async fn access_follows_visibility_and_collaborators() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        core.create_repo(&alice, new("secret", Visibility::Private)).await.unwrap();

        assert!(matches!(core.repo_for(Some(&bob), "alice", "secret").await, Err(CoreError::NotFound)));
        assert!(matches!(core.repo_for(None, "alice", "secret").await, Err(CoreError::NotFound)));
        assert_eq!(core.repo_for(Some(&alice), "ALICE", "Secret").await.unwrap().permission, Permission::Admin);

        core.set_collaborator(&alice, "alice", "secret", "bob", Permission::Write).await.unwrap();
        assert_eq!(core.repo_for(Some(&bob), "alice", "secret").await.unwrap().permission, Permission::Write);
        assert!(matches!(
            core.require_repo(Some(&bob), "alice", "secret", Permission::Admin).await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.set_collaborator(&bob, "alice", "secret", "bob", Permission::Admin).await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.set_collaborator(&alice, "alice", "secret", "alice", Permission::Read).await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.set_collaborator(&alice, "alice", "secret", "nobody", Permission::Read).await,
            Err(CoreError::Invalid(_))
        ));
        assert_eq!(
            core.collaborators(&alice, "alice", "secret").await.unwrap(),
            vec![Collaborator { user_id: bob.id, handle: "bob".into(), permission: Permission::Write }]
        );
        assert_eq!(core.repos_of(Some(&bob), "alice").await.unwrap().len(), 1);
        assert_eq!(core.dashboard_repos(&bob).await.unwrap().len(), 1);

        core.remove_collaborator(&alice, "alice", "secret", "bob").await.unwrap();
        assert!(core.repos_of(Some(&bob), "alice").await.unwrap().is_empty());
        assert!(matches!(core.remove_collaborator(&alice, "alice", "secret", "bob").await, Err(CoreError::NotFound)));

        core.create_repo(&alice, new("open", Visibility::Public)).await.unwrap();
        assert_eq!(core.repo_for(None, "alice", "open").await.unwrap().permission, Permission::Read);
        assert!(matches!(
            core.require_repo(None, "alice", "open", Permission::Write).await,
            Err(CoreError::Unauthenticated)
        ));
        let anonymous: Vec<String> = core.repos_of(None, "alice").await.unwrap().into_iter().map(|r| r.name).collect();
        assert_eq!(anonymous, vec!["open"]);
        assert_eq!(core.dashboard_repos(&alice).await.unwrap().len(), 2);
        assert!(matches!(core.repos_of(None, "nobody").await, Err(CoreError::NotFound)));
    }
}
```

- [ ] **Step 7: Run them to see them fail**

Run: `cargo test -p starforged-core`
Expected: compile errors (`Permission`, `CreateRepo`, … missing).

- [ ] **Step 8: Implement `permission.rs`**

Insert at the top of `crates/starforged-core/src/permission.rs`:

```rust
//! Permission levels and the effective-permission rule (spec §6.1).

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    Read,
    Triage,
    Write,
    Maintain,
    Admin,
}

impl Permission {
    pub const ALL: [Permission; 5] =
        [Permission::Read, Permission::Triage, Permission::Write, Permission::Maintain, Permission::Admin];

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Triage => "triage",
            Permission::Write => "write",
            Permission::Maintain => "maintain",
            Permission::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Permission> {
        Permission::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    /// Readable by every signed-in user.
    Internal,
    Private,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Internal => "internal",
            Visibility::Private => "private",
        }
    }

    pub fn parse(s: &str) -> Option<Visibility> {
        match s {
            "public" => Some(Visibility::Public),
            "internal" => Some(Visibility::Internal),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }
}

/// A signed-in, active user asking for access. Anonymous visitors are `None`.
#[derive(Debug, Clone, Copy)]
pub struct Viewer {
    pub user_id: i64,
    pub is_admin: bool,
}

/// Effective permission on a user-owned repository: site admins and the owner are admins; otherwise the
/// higher of the collaborator grant and the implicit read that public repositories give everyone and
/// internal repositories give signed-in users.
pub fn effective(
    owner_id: i64,
    visibility: Visibility,
    viewer: Option<Viewer>,
    collaborator: Option<Permission>,
) -> Option<Permission> {
    if let Some(v) = viewer
        && (v.is_admin || v.user_id == owner_id)
    {
        return Some(Permission::Admin);
    }
    let implicit = match visibility {
        Visibility::Public => Some(Permission::Read),
        Visibility::Internal if viewer.is_some() => Some(Permission::Read),
        _ => None,
    };
    collaborator.max(implicit)
}
```

- [ ] **Step 9: Implement `repos.rs`**

Insert at the top of `crates/starforged-core/src/repos.rs`:

```rust
//! Repositories: creation, permission-checked lookup, collaborators.

use starforged_db::collaborators;
use starforged_db::repos::{self as db_repos, NewRepo, RepoRow};

use crate::accounts::User;
use crate::permission::{self, Permission, Viewer, Visibility};
use crate::{Core, CoreError, CoreResult, validate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub id: i64,
    pub owner_id: i64,
    pub owner: String,
    pub name: String,
    pub description: String,
    pub visibility: Visibility,
    pub default_branch: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Repo {
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// A repository plus the viewer's effective permission — proof that the viewer may at least read it.
#[derive(Debug, Clone)]
pub struct RepoAccess {
    pub repo: Repo,
    pub permission: Permission,
}

#[derive(Debug, Clone)]
pub struct CreateRepo {
    pub name: String,
    pub description: String,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collaborator {
    pub user_id: i64,
    pub handle: String,
    pub permission: Permission,
}

fn to_repo(row: RepoRow) -> CoreResult<Repo> {
    let visibility = Visibility::parse(&row.visibility)
        .ok_or_else(|| CoreError::Internal(format!("unknown visibility '{}'", row.visibility)))?;
    Ok(Repo {
        id: row.id,
        owner_id: row.owner_id,
        owner: row.owner_handle,
        name: row.name,
        description: row.description,
        visibility,
        default_branch: row.default_branch,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Suspended users are treated as anonymous.
fn viewer(user: Option<&User>) -> Option<Viewer> {
    user.filter(|u| u.active).map(|u| Viewer { user_id: u.id, is_admin: u.is_admin })
}

impl Core {
    /// Creates a repository owned by `actor` (organizations arrive in M3) and its bare git directory.
    pub async fn create_repo(&self, actor: &User, input: CreateRepo) -> CoreResult<Repo> {
        let name = validate::repo_name(&input.name)?;
        let description = input.description.trim();
        if description.chars().count() > 350 {
            return Err(CoreError::Invalid("descriptions are at most 350 characters".into()));
        }
        let new = NewRepo {
            owner_id: actor.id,
            name: &name,
            description,
            visibility: input.visibility.as_str(),
            default_branch: "main",
        };
        let id = db_repos::insert(self.db(), &new).await.map_err(|e| {
            if e.is_unique_violation() {
                CoreError::Conflict(format!("{}/{name} already exists", actor.handle))
            } else {
                e.into()
            }
        })?;
        let path = self.repo_path(id);
        if let Err(err) = starforged_git::init::init_bare(&path, "main", &self.config().hook_exe).await {
            db_repos::delete(self.db(), id).await?;
            let _ = tokio::fs::remove_dir_all(&path).await;
            return Err(err.into());
        }
        let repo = to_repo(db_repos::by_id(self.db(), id).await?.ok_or(CoreError::NotFound)?)?;
        self.audit(Some(actor.id), "repo.create", &format!("repo:{}", repo.full_name()), repo.visibility.as_str()).await?;
        Ok(repo)
    }

    /// The repository and the viewer's permission. A missing repository and one the viewer cannot read
    /// are both `NotFound`.
    pub async fn repo_for(&self, user: Option<&User>, owner: &str, name: &str) -> CoreResult<RepoAccess> {
        let row = db_repos::by_owner_and_name(self.db(), owner, name).await?.ok_or(CoreError::NotFound)?;
        let repo = to_repo(row)?;
        let permission = self.permission_on(&repo, user).await?.ok_or(CoreError::NotFound)?;
        Ok(RepoAccess { repo, permission })
    }

    /// [`Core::repo_for`] plus a minimum permission: below it, signed-in viewers get `Forbidden` and
    /// anonymous viewers `Unauthenticated`.
    pub async fn require_repo(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
        needed: Permission,
    ) -> CoreResult<RepoAccess> {
        let access = self.repo_for(user, owner, name).await?;
        if access.permission < needed {
            return Err(if viewer(user).is_some() { CoreError::Forbidden } else { CoreError::Unauthenticated });
        }
        Ok(access)
    }

    pub async fn permission_on(&self, repo: &Repo, user: Option<&User>) -> CoreResult<Option<Permission>> {
        let v = viewer(user);
        let collaborator = match v {
            Some(v) => collaborators::permission(self.db(), repo.id, v.user_id).await?.as_deref().and_then(Permission::parse),
            None => None,
        };
        Ok(permission::effective(repo.owner_id, repo.visibility, v, collaborator))
    }

    /// Repositories of `owner` that `user` can read, by name. `NotFound` when the owner does not exist.
    pub async fn repos_of(&self, user: Option<&User>, owner: &str) -> CoreResult<Vec<Repo>> {
        let owner_row =
            starforged_db::users::by_handle(self.db(), &owner.to_ascii_lowercase()).await?.ok_or(CoreError::NotFound)?;
        let mut visible = Vec::new();
        for row in db_repos::list_by_owner(self.db(), owner_row.id).await? {
            let repo = to_repo(row)?;
            if self.permission_on(&repo, user).await?.is_some() {
                visible.push(repo);
            }
        }
        Ok(visible)
    }

    /// The user's own repositories, then the ones they collaborate on.
    pub async fn dashboard_repos(&self, user: &User) -> CoreResult<Vec<Repo>> {
        let mut repos = Vec::new();
        for row in db_repos::list_by_owner(self.db(), user.id).await? {
            repos.push(to_repo(row)?);
        }
        for row in db_repos::list_collaborating(self.db(), user.id).await? {
            repos.push(to_repo(row)?);
        }
        Ok(repos)
    }

    pub async fn collaborators(&self, actor: &User, owner: &str, name: &str) -> CoreResult<Vec<Collaborator>> {
        let access = self.require_repo(Some(actor), owner, name, Permission::Admin).await?;
        collaborators::list(self.db(), access.repo.id)
            .await?
            .into_iter()
            .map(|row| {
                let permission = Permission::parse(&row.permission)
                    .ok_or_else(|| CoreError::Internal(format!("unknown permission '{}'", row.permission)))?;
                Ok(Collaborator { user_id: row.user_id, handle: row.handle, permission })
            })
            .collect()
    }

    pub async fn set_collaborator(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        handle: &str,
        permission: Permission,
    ) -> CoreResult<()> {
        let access = self.require_repo(Some(actor), owner, name, Permission::Admin).await?;
        let target = self.user_by_handle(handle).await?.ok_or_else(|| CoreError::Invalid(format!("no user named '{handle}'")))?;
        if target.id == access.repo.owner_id {
            return Err(CoreError::Invalid("the owner already has admin access".into()));
        }
        collaborators::upsert(self.db(), access.repo.id, target.id, permission.as_str()).await?;
        let detail = format!("{}={}", target.handle, permission.as_str());
        self.audit(Some(actor.id), "repo.collaborator.set", &format!("repo:{}", access.repo.full_name()), &detail).await
    }

    pub async fn remove_collaborator(&self, actor: &User, owner: &str, name: &str, handle: &str) -> CoreResult<()> {
        let access = self.require_repo(Some(actor), owner, name, Permission::Admin).await?;
        let target = self.user_by_handle(handle).await?.ok_or(CoreError::NotFound)?;
        if !collaborators::remove(self.db(), access.repo.id, target.id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(Some(actor.id), "repo.collaborator.remove", &format!("repo:{}", access.repo.full_name()), &target.handle)
            .await
    }
}
```

- [ ] **Step 10: Run the tests**

Run: `cargo test -p starforged-core && cargo test -p starforged-git`
Expected: core 17 passed (12 earlier + 2 permission + 3 repos); git 5 passed.

- [ ] **Step 11: Lint, format, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates Cargo.lock
git commit -m "feat: repositories with permission levels and bare repository creation"
```

---

### Task 6: The `pre-receive` ref policy

**Files:**
- Create: `crates/starforged-git/src/refpolicy.rs`; Modify: `crates/starforged-git/src/lib.rs` (add `pub mod refpolicy;`)
- Create: `crates/starforged/src/hook.rs`; Modify: `crates/starforged/src/lib.rs`, `crates/starforged/src/main.rs`, `crates/starforged/Cargo.toml`
- Test: unit tests in `refpolicy.rs` and `hook.rs`; `crates/starforged/tests/hook_cli.rs`

**Interfaces:**
- Consumes: `init::HOOKS` (Task 5) — the hook scripts already exec `starforged hook pre-receive`.
- Produces:
  - `starforged_git::refpolicy::{RefUpdate { old, new, name }, parse_line(&str) -> Option<RefUpdate>, check(&RefUpdate) -> Result<(), String>}`.
  - `starforged::hook::pre_receive(input: impl BufRead, err: impl Write) -> i32` (exit code).
  - CLI: `starforged hook pre-receive` (hidden).

- [ ] **Step 1: Write the failing policy tests**

`crates/starforged-git/src/refpolicy.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn update(name: &str) -> RefUpdate {
        RefUpdate { old: "0".repeat(40), new: "1".repeat(40), name: name.into() }
    }

    #[test]
    fn parses_hook_lines() {
        assert_eq!(parse_line("aaa bbb refs/heads/main"), Some(RefUpdate { old: "aaa".into(), new: "bbb".into(), name: "refs/heads/main".into() }));
        assert_eq!(parse_line("aaa bbb"), None);
        assert_eq!(parse_line("aaa bbb refs/heads/main extra"), None);
    }

    #[test]
    fn only_branches_and_tags_are_accepted() {
        assert!(check(&update("refs/heads/main")).is_ok());
        assert!(check(&update("refs/heads/feature/x")).is_ok());
        assert!(check(&update("refs/tags/v1.0")).is_ok());
        for rejected in ["refs/notes/commits", "refs/entire/checkpoints/ab/x", "refs/trails/1/changes/1/head", "refs/for/main", "HEAD"] {
            let err = check(&update(rejected)).unwrap_err();
            assert!(err.contains(rejected), "{err}");
        }
    }
}
```

- [ ] **Step 2: Run them to see them fail**

Add `pub mod refpolicy;` to `crates/starforged-git/src/lib.rs`, then run: `cargo test -p starforged-git refpolicy`
Expected: compile errors.

- [ ] **Step 3: Implement `refpolicy.rs`**

Insert at the top of `crates/starforged-git/src/refpolicy.rs`:

```rust
//! Which refs clients may push (spec §8.2). M0 accepts branches and tags only; `refs/for/*` (M2) and
//! branch protection (M3) extend this through the server socket.

/// One line of `pre-receive` input: `<old-oid> <new-oid> <refname>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

pub fn parse_line(line: &str) -> Option<RefUpdate> {
    let mut parts = line.split_whitespace();
    let (old, new, name) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(RefUpdate { old: old.to_owned(), new: new.to_owned(), name: name.to_owned() })
}

pub fn check(update: &RefUpdate) -> Result<(), String> {
    if update.name.starts_with("refs/heads/") || update.name.starts_with("refs/tags/") {
        Ok(())
    } else {
        Err(format!("pushing to {} is not allowed; only branches and tags are accepted", update.name))
    }
}
```

Run: `cargo test -p starforged-git refpolicy`
Expected: 2 passed.

- [ ] **Step 4: Write the failing hook tests**

`crates/starforged/src/hook.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str) -> (i32, String) {
        let mut err = Vec::new();
        let code = pre_receive(input.as_bytes(), &mut err);
        (code, String::from_utf8(err).unwrap())
    }

    #[test]
    fn accepts_branches_and_tags() {
        assert_eq!(run("0 1 refs/heads/main\n0 2 refs/tags/v1\n\n"), (0, String::new()));
    }

    #[test]
    fn rejects_other_namespaces_and_reports_each() {
        let (code, err) = run("0 1 refs/heads/main\n0 2 refs/notes/x\n0 3 refs/entire/y\n");
        assert_eq!(code, 1);
        assert!(err.contains("starforge: pushing to refs/notes/x is not allowed"), "{err}");
        assert!(err.contains("refs/entire/y"), "{err}");
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(run("garbage\n").0, 1);
    }
}
```

`crates/starforged/tests/hook_cli.rs`:

```rust
use std::io::Write;
use std::process::{Command, Stdio};

fn hook(input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .args(["hook", "pre-receive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn the_binary_runs_the_pre_receive_policy() {
    assert!(hook("0 1 refs/heads/main\n").status.success());
    let rejected = hook("0 1 refs/entire/checkpoints/ab/x\n");
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("refs/entire/checkpoints/ab/x is not allowed"));
}
```

- [ ] **Step 5: Run them to see them fail**

Run: `cargo test -p starforged hook`
Expected: compile errors (`pre_receive` missing).

- [ ] **Step 6: Implement the hook and wire the subcommand**

Add to `crates/starforged/Cargo.toml` `[dependencies]`:

```toml
starforged-git = { path = "../starforged-git" }
```

Add `pub mod hook;` to `crates/starforged/src/lib.rs`.

Insert at the top of `crates/starforged/src/hook.rs`:

```rust
//! Entry points that git runs inside hosted repositories (see `starforged_git::init::HOOKS`).
//! Anything written to stderr reaches the pusher as `remote: …`.

use std::io::{BufRead, Write};

use starforged_git::refpolicy;

/// `starforged hook pre-receive`: checks every pushed ref; returns the process exit code.
pub fn pre_receive(input: impl BufRead, mut err: impl Write) -> i32 {
    let mut code = 0;
    for line in input.lines() {
        let Ok(line) = line else { return 1 };
        if line.trim().is_empty() {
            continue;
        }
        let Some(update) = refpolicy::parse_line(&line) else {
            let _ = writeln!(err, "starforge: malformed pre-receive input");
            return 1;
        };
        if let Err(message) = refpolicy::check(&update) {
            let _ = writeln!(err, "starforge: {message}");
            code = 1;
        }
    }
    code
}
```

In `crates/starforged/src/main.rs`, add this variant at the end of `enum Command`:

```rust
    /// Entry points for git hooks in hosted repositories.
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        hook: HookCommand,
    },
```

add this enum below `enum AdminTokenCommand`:

```rust
#[derive(Subcommand)]
enum HookCommand {
    /// Checks pushed refs (`<old> <new> <ref>` lines on stdin).
    PreReceive,
}
```

and this arm at the end of the `match cli.command` in `main`:

```rust
        Command::Hook { hook: HookCommand::PreReceive } => {
            std::process::exit(starforged::hook::pre_receive(std::io::stdin().lock(), std::io::stderr()));
        }
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -p starforged`
Expected: all pass, including 3 `hook` unit tests and `hook_cli`.

- [ ] **Step 8: Lint, format, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates Cargo.lock
git commit -m "feat: pre-receive hook restricts pushes to branches and tags"
```

---

### Task 7: Git smart HTTP, server assembly, and the test harness

**Files:**
- Create: `crates/starforged-git/src/http.rs`; Modify: `crates/starforged-git/src/lib.rs` (add `pub mod http;`)
- Create: `crates/starforged-web/Cargo.toml`, `crates/starforged-web/src/lib.rs`, `crates/starforged-web/src/githttp.rs`
- Create: `crates/starforged/src/serve.rs`; Modify: `crates/starforged/src/lib.rs`, `crates/starforged/src/main.rs`, `crates/starforged/Cargo.toml`
- Test: unit tests in `http.rs` and `githttp.rs`; `crates/starforged/tests/common/mod.rs`, `crates/starforged/tests/smart_http.rs`

**Interfaces:**
- Consumes: `Core::{authenticate_token, require_repo, repo_path}`, `tokens::{grants, Scope}`, `Permission` (Tasks 4–5); `init::init_bare` (Task 5).
- Produces:
  - `starforged_git::http::{Service, pkt_line, advertisement, spawn_rpc, RpcProcess}`. `Service::{UploadPack, ReceivePack}` with `from_query(&str)`, `name()`, `advertisement_content_type()`, `result_content_type()`. `advertisement(repo, Service, git_protocol: Option<&str>) -> Result<Vec<u8>, GitError>`. `spawn_rpc(repo, Service, git_protocol, env: &[(&str, String)]) -> Result<RpcProcess, GitError>` where `RpcProcess { child, stdin, stdout, stderr }`.
  - `starforged_web::{router(Core, WebSettings) -> axum::Router, WebSettings { base_url, secure_cookies }, AppState { core, settings }}`.
  - `starforged_web::githttp::{info_refs, upload_pack, receive_pack, basic_password(&HeaderMap) -> Option<String>, request_reader(Body, gzip: bool)}`.
  - `starforged::serve::{App { router, core }, build(&Config, hook_exe: PathBuf) -> anyhow::Result<App>, serve_on(TcpListener, Router, shutdown) -> io::Result<()>, run(Config)}`. `serve_on` always provides `ConnectInfo<SocketAddr>`.
  - CLI: `starforged serve`.
  - Test harness `tests/common/mod.rs`: `TestServer::{start, url, user, token, repo, git_url}`, `PASSWORD`, `git`, `git_ok`, `work_repo`, `commit_files`, `noise`.

- [ ] **Step 1: Write the failing smart-HTTP plumbing tests**

`crates/starforged-git/src/http.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_lines_are_length_prefixed() {
        assert_eq!(pkt_line("# service=git-upload-pack\n"), b"001e# service=git-upload-pack\n");
    }

    #[test]
    fn service_names_and_content_types() {
        assert_eq!(Service::from_query("git-receive-pack"), Some(Service::ReceivePack));
        assert_eq!(Service::from_query("git-upload-archive"), None);
        assert_eq!(Service::UploadPack.advertisement_content_type(), "application/x-git-upload-pack-advertisement");
        assert_eq!(Service::ReceivePack.result_content_type(), "application/x-git-receive-pack-result");
    }

    #[test]
    fn detects_protocol_v2() {
        assert!(is_v2(Some("version=2")));
        assert!(is_v2(Some("object-format=sha1:version=2")));
        assert!(!is_v2(Some("version=1")));
        assert!(!is_v2(None));
    }

    #[tokio::test]
    async fn advertisement_preamble_depends_on_protocol_version() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false")).await.unwrap();
        let v0 = advertisement(&repo, Service::UploadPack, None).await.unwrap();
        assert!(v0.starts_with(b"001e# service=git-upload-pack\n0000"));
        let v2 = advertisement(&repo, Service::UploadPack, Some("version=2")).await.unwrap();
        assert!(v2.starts_with(b"000eversion 2\n"), "{}", String::from_utf8_lossy(&v2));
    }
}
```

Add `pub mod http;` to `crates/starforged-git/src/lib.rs`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-git http`
Expected: compile errors.

- [ ] **Step 3: Implement `http.rs`**

Insert at the top of `crates/starforged-git/src/http.rs`:

```rust
//! Smart HTTP plumbing: ref advertisement and stateless RPC processes (gitprotocol-http).

use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};

use crate::command::{GitError, git};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    /// Parses the `service` query parameter of `GET info/refs`.
    pub fn from_query(name: &str) -> Option<Service> {
        match name {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }

    fn subcommand(self) -> &'static str {
        match self {
            Service::UploadPack => "upload-pack",
            Service::ReceivePack => "receive-pack",
        }
    }

    pub fn advertisement_content_type(self) -> String {
        format!("application/x-{}-advertisement", self.name())
    }

    pub fn result_content_type(self) -> String {
        format!("application/x-{}-result", self.name())
    }
}

pub fn pkt_line(payload: &str) -> Vec<u8> {
    format!("{:04x}{payload}", payload.len() + 4).into_bytes()
}

fn is_v2(git_protocol: Option<&str>) -> bool {
    git_protocol.is_some_and(|p| p.split(':').any(|kv| kv == "version=2"))
}

/// Body for `GET info/refs?service=…`. Protocol v2 responses have no `# service=` preamble.
pub async fn advertisement(repo: &Path, service: Service, git_protocol: Option<&str>) -> Result<Vec<u8>, GitError> {
    let mut cmd = git();
    cmd.arg(service.subcommand()).arg("--stateless-rpc").arg("--advertise-refs").arg(repo);
    if let Some(protocol) = git_protocol {
        cmd.env("GIT_PROTOCOL", protocol);
    }
    let out = cmd.output().await?;
    if !out.status.success() {
        return Err(GitError::Failed {
            command: format!("{} --advertise-refs", service.subcommand()),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    let mut body = Vec::with_capacity(out.stdout.len() + 40);
    if !is_v2(git_protocol) {
        body.extend(pkt_line(&format!("# service={}\n", service.name())));
        body.extend_from_slice(b"0000");
    }
    body.extend(out.stdout);
    Ok(body)
}

pub struct RpcProcess {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
}

/// Spawns `git <service> --stateless-rpc <repo>` with piped stdio. `env` reaches the repository's hooks.
pub fn spawn_rpc(
    repo: &Path,
    service: Service,
    git_protocol: Option<&str>,
    env: &[(&str, String)],
) -> Result<RpcProcess, GitError> {
    let mut cmd = git();
    cmd.arg(service.subcommand())
        .arg("--stateless-rpc")
        .arg(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(protocol) = git_protocol {
        cmd.env("GIT_PROTOCOL", protocol);
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn()?;
    let stdin = child.stdin.take().expect("stdin is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    Ok(RpcProcess { child, stdin, stdout, stderr })
}
```

Run: `cargo test -p starforged-git http`
Expected: 4 passed.

- [ ] **Step 4: Create the web crate with failing request-handling tests**

`crates/starforged-web/Cargo.toml`:

```toml
[package]
name = "starforged-web"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true

[dependencies]
async-compression.workspace = true
axum.workspace = true
base64.workspace = true
futures-util.workspace = true
serde.workspace = true
starforged-core = { path = "../starforged-core" }
starforged-git = { path = "../starforged-git" }
tokio.workspace = true
tokio-util.workspace = true
tracing.workspace = true

[dev-dependencies]
flate2.workspace = true
```

`crates/starforged-web/src/lib.rs`:

```rust
//! starforged-web: HTML pages and git smart HTTP (spec §8.1, §10.1).

pub mod githttp;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use starforged_core::Core;

#[derive(Debug, Clone)]
pub struct WebSettings {
    /// Public URL without a trailing slash.
    pub base_url: String,
    pub secure_cookies: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub core: Core,
    pub settings: Arc<WebSettings>,
}

pub fn router(core: Core, settings: WebSettings) -> Router {
    let state = AppState { core, settings: Arc::new(settings) };
    git_routes().with_state(state)
}

/// Smart HTTP. Pushes can be arbitrarily large, so the request body limit is disabled here.
fn git_routes() -> Router<AppState> {
    Router::new()
        .route("/{owner}/{repo}/info/refs", get(githttp::info_refs))
        .route("/{owner}/{repo}/git-upload-pack", post(githttp::upload_pack))
        .route("/{owner}/{repo}/git-receive-pack", post(githttp::receive_pack))
        .layer(DefaultBodyLimit::disable())
}
```

`crates/starforged-web/src/githttp.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn basic_password_extraction() {
        let mut headers = HeaderMap::new();
        assert_eq!(basic_password(&headers), None);
        let encoded = base64::engine::general_purpose::STANDARD.encode("git:sfp_secret");
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Basic {encoded}")).unwrap());
        assert_eq!(basic_password(&headers).as_deref(), Some("sfp_secret"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer sfp_secret"));
        assert_eq!(basic_password(&headers), None);
    }

    #[tokio::test]
    async fn request_reader_gunzips_when_asked() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"0032want 0123456789abcdef\n").unwrap();
        let compressed = encoder.finish().unwrap();
        let mut out = Vec::new();
        request_reader(Body::from(compressed), true).read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"0032want 0123456789abcdef\n");
        let mut plain = Vec::new();
        request_reader(Body::from("abc"), false).read_to_end(&mut plain).await.unwrap();
        assert_eq!(plain, b"abc");
    }
}
```

- [ ] **Step 5: Run them to see them fail**

Run: `cargo test -p starforged-web`
Expected: compile errors.

- [ ] **Step 6: Implement `githttp.rs`**

Insert at the top of `crates/starforged-web/src/githttp.rs`:

```rust
//! Git smart HTTP (spec §8.1). Fetching public repositories is anonymous; everything else uses HTTP Basic
//! with a personal access token as the password.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures_util::TryStreamExt;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::accounts::User;
use starforged_core::permission::Permission;
use starforged_core::repos::RepoAccess;
use starforged_core::tokens::{self, Scope};
use starforged_git::http::{self as smart, Service};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::AppState;

#[derive(Debug)]
pub enum GitHttpError {
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest(&'static str),
    Internal(String),
}

impl IntoResponse for GitHttpError {
    fn into_response(self) -> Response {
        match self {
            GitHttpError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"Starforge\""))],
                "authentication required\n",
            )
                .into_response(),
            GitHttpError::Forbidden => (StatusCode::FORBIDDEN, "permission denied\n").into_response(),
            GitHttpError::NotFound => (StatusCode::NOT_FOUND, "repository not found\n").into_response(),
            GitHttpError::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            GitHttpError::Internal(message) => {
                tracing::error!(%message, "git smart HTTP failure");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
            }
        }
    }
}

#[derive(Deserialize)]
pub struct InfoRefsQuery {
    service: Option<String>,
}

/// The password of `Authorization: Basic …`; the username is ignored.
pub fn basic_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (_, password) = text.split_once(':')?;
    Some(password.to_owned())
}

fn git_protocol(headers: &HeaderMap) -> Option<String> {
    headers.get("git-protocol").and_then(|v| v.to_str().ok()).map(str::to_owned)
}

/// Authenticates (optional for fetch), checks token scope and repository permission.
/// Anonymous requests that fail get 401 so git prompts for credentials; authenticated ones get 404 or 403.
async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    repo_segment: &str,
    service: Service,
) -> Result<RepoAccess, GitHttpError> {
    let name = repo_segment.strip_suffix(".git").unwrap_or(repo_segment);
    let auth = match basic_password(headers) {
        Some(secret) => Some(state.core.authenticate_token(&secret).await.map_err(|_| GitHttpError::Unauthorized)?),
        None => None,
    };
    let (needed, scope) = match service {
        Service::UploadPack => (Permission::Read, Scope::RepoRead),
        Service::ReceivePack => (Permission::Write, Scope::RepoWrite),
    };
    if let Some(auth) = &auth
        && !tokens::grants(&auth.scopes, scope)
    {
        return Err(GitHttpError::Forbidden);
    }
    let user: Option<&User> = auth.as_ref().map(|a| &a.user);
    match state.core.require_repo(user, owner, name, needed).await {
        Ok(access) => Ok(access),
        Err(CoreError::NotFound | CoreError::Unauthenticated) if user.is_none() => Err(GitHttpError::Unauthorized),
        Err(CoreError::NotFound) => Err(GitHttpError::NotFound),
        Err(CoreError::Forbidden) => Err(GitHttpError::Forbidden),
        Err(other) => Err(GitHttpError::Internal(other.to_string())),
    }
}

pub async fn info_refs(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Result<Response, GitHttpError> {
    let service = query
        .service
        .as_deref()
        .and_then(Service::from_query)
        .ok_or(GitHttpError::BadRequest("only the smart HTTP protocol is supported\n"))?;
    let access = authorize(&state, &headers, &owner, &repo, service).await?;
    let path = state.core.repo_path(access.repo.id);
    let body = smart::advertisement(&path, service, git_protocol(&headers).as_deref())
        .await
        .map_err(|e| GitHttpError::Internal(e.to_string()))?;
    Ok((
        [(header::CONTENT_TYPE, service.advertisement_content_type()), (header::CACHE_CONTROL, "no-cache".to_owned())],
        body,
    )
        .into_response())
}

pub async fn upload_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, GitHttpError> {
    rpc(state, &owner, &repo, headers, body, Service::UploadPack).await
}

pub async fn receive_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, GitHttpError> {
    rpc(state, &owner, &repo, headers, body, Service::ReceivePack).await
}

/// Streams the request body into `git <service> --stateless-rpc` and its stdout back out.
async fn rpc(
    state: AppState,
    owner: &str,
    repo: &str,
    headers: HeaderMap,
    body: Body,
    service: Service,
) -> Result<Response, GitHttpError> {
    let access = authorize(&state, &headers, owner, repo, service).await?;
    let path = state.core.repo_path(access.repo.id);
    let gzip = headers.get(header::CONTENT_ENCODING).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    let process = smart::spawn_rpc(&path, service, git_protocol(&headers).as_deref(), &[])
        .map_err(|e| GitHttpError::Internal(e.to_string()))?;

    let mut input = request_reader(body, gzip);
    let mut stdin = process.stdin;
    tokio::spawn(async move {
        if let Err(err) = tokio::io::copy(&mut input, &mut stdin).await {
            tracing::warn!(%err, "copying the git request body failed");
        }
    });

    let mut stderr = process.stderr;
    let mut child = process.child;
    tokio::spawn(async move {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        let status = child.wait().await;
        let failed = !matches!(&status, Ok(s) if s.success());
        if failed || !text.trim().is_empty() {
            tracing::warn!(stderr = %text.trim(), ?status, "git rpc finished");
        }
    });

    Ok((
        [(header::CONTENT_TYPE, service.result_content_type()), (header::CACHE_CONTROL, "no-cache".to_owned())],
        Body::from_stream(ReaderStream::new(process.stdout)),
    )
        .into_response())
}

/// The request body as bytes, gunzipped when the client sent `Content-Encoding: gzip`.
pub fn request_reader(body: Body, gzip: bool) -> Box<dyn AsyncRead + Send + Unpin> {
    let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    if gzip {
        Box::new(async_compression::tokio::bufread::GzipDecoder::new(reader))
    } else {
        Box::new(reader)
    }
}
```

Run: `cargo test -p starforged-web`
Expected: 2 passed.

- [ ] **Step 7: Add server assembly and `starforged serve`**

`crates/starforged/Cargo.toml` — `[dependencies]` and `[dev-dependencies]` become:

```toml
[dependencies]
anyhow.workspace = true
axum.workspace = true
clap.workspace = true
getrandom.workspace = true
hex.workspace = true
serde.workspace = true
starforged-core = { path = "../starforged-core" }
starforged-db = { path = "../starforged-db" }
starforged-git = { path = "../starforged-git" }
starforged-web = { path = "../starforged-web" }
tokio.workspace = true
toml.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true

[dev-dependencies]
reqwest.workspace = true
starforged-db = { path = "../starforged-db", features = ["testing"] }
tempfile.workspace = true
```

Add `pub mod serve;` to `crates/starforged/src/lib.rs`.

`crates/starforged/src/serve.rs`:

```rust
//! `starforged serve`: builds the HTTP application and runs it.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use axum::Router;
use axum::routing::get;
use starforged_core::Core;
use tokio::net::TcpListener;

use crate::admin::open_core;
use crate::config::Config;

pub struct App {
    pub router: Router,
    pub core: Core,
}

/// The whole application: `/healthz`, web pages, and git smart HTTP.
pub async fn build(config: &Config, hook_exe: PathBuf) -> anyhow::Result<App> {
    let core = open_core(config, hook_exe).await?;
    let web = starforged_web::router(
        core.clone(),
        starforged_web::WebSettings { base_url: config.server.base_url.clone(), secure_cookies: config.secure_cookies() },
    );
    let router = Router::new().route("/healthz", get(|| async { "ok" })).merge(web);
    Ok(App { router, core })
}

/// Serves `router` with `ConnectInfo<SocketAddr>` available to handlers until `shutdown` resolves.
pub async fn serve_on(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown)
        .await
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let (major, minor) = starforged_git::command::check_version().await?;
    let app = build(&config, std::env::current_exe()?).await?;
    let listener = TcpListener::bind(&config.server.http_addr)
        .await
        .with_context(|| format!("binding {}", config.server.http_addr))?;
    tracing::info!(
        addr = %config.server.http_addr,
        base_url = %config.server.base_url,
        git = %format!("{major}.{minor}"),
        "starforged listening"
    );
    serve_on(listener, app.router, shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
```

In `crates/starforged/src/main.rs`, add this variant to `enum Command` (after `Migrate`):

```rust
    /// Run the server.
    Serve,
```

and this arm to the `match` (after the `Migrate` arm):

```rust
        Command::Serve => {
            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            tracing_subscriber::fmt().with_env_filter(filter).init();
            starforged::serve::run(Config::load(&cli.config)?).await?;
        }
```

- [ ] **Step 8: Write the test harness and the failing smart-HTTP integration tests**

`crates/starforged/tests/common/mod.rs`:

```rust
//! Shared integration-test harness: an in-process server on a random port, plus git helpers.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Output;

use starforged::config::{Config, DatabaseConfig, SecurityConfig, ServerConfig, StorageConfig};
use starforged_core::Core;
use starforged_core::accounts::{CreateUser, User};
use starforged_core::permission::Visibility;
use starforged_core::repos::{CreateRepo, Repo};
use starforged_core::tokens::Scope;

pub const PASSWORD: &str = "correct horse battery";

pub struct TestServer {
    pub base: String,
    pub core: Core,
    pub data: tempfile::TempDir,
    _db: starforged_db::testing::TestDb,
}

impl TestServer {
    pub async fn start() -> TestServer {
        let db = starforged_db::testing::TestDb::new().await;
        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let config = Config {
            server: ServerConfig { http_addr: addr.to_string(), base_url: base.clone() },
            database: DatabaseConfig { url: db.url.clone(), auto_migrate: true },
            storage: StorageConfig { data_dir: data.path().to_path_buf() },
            security: SecurityConfig { secret_key: "0".repeat(64) },
        };
        let app = starforged::serve::build(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged"))).await.unwrap();
        tokio::spawn(starforged::serve::serve_on(listener, app.router, std::future::pending()));
        TestServer { base, core: app.core, data, _db: db }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// A user whose password is [`PASSWORD`].
    pub async fn user(&self, handle: &str) -> User {
        self.core
            .create_user(CreateUser { handle: handle.into(), password: Some(PASSWORD.into()), ..Default::default() })
            .await
            .unwrap()
    }

    pub async fn token(&self, user: &User, scopes: &[Scope]) -> String {
        self.core.create_token(user, "test", scopes, 1).await.unwrap().secret
    }

    pub async fn repo(&self, owner: &User, name: &str, visibility: Visibility) -> Repo {
        self.core.create_repo(owner, CreateRepo { name: name.into(), description: String::new(), visibility }).await.unwrap()
    }

    /// `http://host/owner/repo.git`, with `token` as the Basic-auth password when given.
    pub fn git_url(&self, owner: &str, repo: &str, token: Option<&str>) -> String {
        let host = self.base.trim_start_matches("http://");
        match token {
            Some(token) => format!("http://git:{token}@{host}/{owner}/{repo}.git"),
            None => format!("http://{host}/{owner}/{repo}.git"),
        }
    }
}

/// Runs `git` in `dir` on a blocking thread, isolated from the developer's configuration.
/// Defaults to protocol v2; pass `-c protocol.version=0` to override.
pub async fn git(dir: &Path, args: &[&str]) -> Output {
    let dir = dir.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new("git")
            .args(["-c", "credential.helper=", "-c", "user.name=Test", "-c", "user.email=test@example.com"])
            .args(["-c", "init.defaultBranch=main", "-c", "protocol.version=2"])
            .args(&args)
            .current_dir(&dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

/// [`git`] that must succeed; returns stdout.
pub async fn git_ok(dir: &Path, args: &[&str]) -> String {
    let out = git(dir, args).await;
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

/// Creates the working copy `dir/name` with one commit, "initial commit", containing `files`.
pub async fn work_repo(dir: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
    git_ok(dir, &["init", "-q", name]).await;
    let work = dir.join(name);
    let files: Vec<(&str, &[u8])> = files.iter().map(|(p, c)| (*p, c.as_bytes())).collect();
    commit_files(&work, &files, "initial commit").await;
    work
}

/// Writes `files` (paths relative to `work`) and commits them.
pub async fn commit_files(work: &Path, files: &[(&str, &[u8])], message: &str) {
    for (path, content) in files {
        let full = work.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    git_ok(work, &["add", "-A"]).await;
    git_ok(work, &["commit", "-q", "-m", message]).await;
}

/// Deterministic, incompressible bytes (xorshift).
pub fn noise(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}
```

`crates/starforged/tests/smart_http.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_and_clone_over_protocol_v0_and_v2() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    // Larger than axum's 2 MB default body limit: the push must stream.
    commit_files(&work, &[("data/blob.bin", &noise(3 * 1024 * 1024))], "add binary data").await;
    git_ok(&work, &["push", "-q", &s.git_url("alice", "proj", Some(&token)), "main"]).await;
    for version in ["0", "2"] {
        let dest = format!("clone-v{version}");
        let protocol = format!("protocol.version={version}");
        git_ok(tmp.path(), &["-c", &protocol, "clone", "-q", &s.git_url("alice", "proj", Some(&token)), &dest]).await;
        assert_eq!(std::fs::read_to_string(tmp.path().join(&dest).join("README.md")).unwrap(), "# proj\n");
        assert_eq!(std::fs::metadata(tmp.path().join(&dest).join("data/blob.bin")).unwrap().len(), 3 * 1024 * 1024);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_access_follows_visibility_permissions_and_scopes() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "private", Visibility::Private).await;
    s.repo(&alice, "public", Visibility::Public).await;
    let alice_write = s.token(&alice, &[Scope::RepoWrite]).await;
    let alice_read = s.token(&alice, &[Scope::RepoRead]).await;
    let bob_write = s.token(&bob, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(&work, &["push", "-q", &s.git_url("alice", "public", Some(&alice_write)), "main"]).await;

    // Anyone can clone a public repository; nobody pushes anonymously.
    git_ok(tmp.path(), &["clone", "-q", &s.git_url("alice", "public", None), "anonymous"]).await;
    assert!(!git(&work, &["push", &s.git_url("alice", "public", None), "main"]).await.status.success());

    // A private repository is invisible to anonymous users and to strangers.
    assert!(!git(tmp.path(), &["clone", &s.git_url("alice", "private", None), "x1"]).await.status.success());
    let stranger = git(tmp.path(), &["clone", &s.git_url("alice", "private", Some(&bob_write)), "x2"]).await;
    assert!(String::from_utf8_lossy(&stranger.stderr).contains("not found"), "{}", String::from_utf8_lossy(&stranger.stderr));

    // A read collaborator can clone but not push; a read-only token cannot push either.
    s.core.set_collaborator(&alice, "alice", "private", "bob", Permission::Read).await.unwrap();
    git_ok(tmp.path(), &["clone", "-q", &s.git_url("alice", "private", Some(&bob_write)), "bob-clone"]).await;
    let denied = git(&work, &["push", &s.git_url("alice", "private", Some(&bob_write)), "main"]).await;
    assert!(String::from_utf8_lossy(&denied.stderr).contains("403"), "{}", String::from_utf8_lossy(&denied.stderr));
    let read_only = git(&work, &["push", &s.git_url("alice", "private", Some(&alice_read)), "main"]).await;
    assert!(String::from_utf8_lossy(&read_only.stderr).contains("403"), "{}", String::from_utf8_lossy(&read_only.stderr));

    // A write collaborator can push.
    s.core.set_collaborator(&alice, "alice", "private", "bob", Permission::Write).await.unwrap();
    git_ok(&work, &["push", "-q", &s.git_url("alice", "private", Some(&bob_write)), "main"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushes_outside_branches_and_tags_are_rejected() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let url = s.git_url("alice", "proj", Some(&s.token(&alice, &[Scope::RepoWrite]).await));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    let rejected = git(&work, &["push", &url, "HEAD:refs/entire/checkpoints/ab/x"]).await;
    assert!(!rejected.status.success());
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("refs/entire/checkpoints/ab/x is not allowed"), "{stderr}");
    git_ok(&work, &["push", "-q", &url, "main", "HEAD:refs/tags/v1"]).await;
    let refs = git_ok(&work, &["ls-remote", &url]).await;
    assert!(refs.contains("refs/heads/main") && refs.contains("refs/tags/v1"), "{refs}");
    assert!(!refs.contains("refs/entire"), "{refs}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dumb_http_is_refused_and_challenges_use_basic_auth() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.repo(&alice, "closed", Visibility::Private).await;
    let client = reqwest::Client::new();
    assert_eq!(client.get(s.url("/alice/open.git/info/refs")).send().await.unwrap().status(), 400);
    let challenge = client.get(s.url("/alice/closed.git/info/refs?service=git-upload-pack")).send().await.unwrap();
    assert_eq!(challenge.status(), 401);
    assert_eq!(challenge.headers()["www-authenticate"], "Basic realm=\"Starforge\"");
    let without_suffix = client.get(s.url("/alice/open/info/refs?service=git-upload-pack")).send().await.unwrap();
    assert_eq!(without_suffix.status(), 200, "the .git suffix is optional");
    assert_eq!(without_suffix.headers()["content-type"], "application/x-git-upload-pack-advertisement");
    assert_eq!(client.get(s.url("/healthz")).send().await.unwrap().text().await.unwrap(), "ok");
}
```

- [ ] **Step 9: Run the integration tests**

Run: `cargo test -p starforged --test smart_http`
Expected: 4 passed. (If they fail because pre-receive output is missing, check that `CARGO_BIN_EXE_starforged` is the hook program — the hook scripts in test repositories must exec the built binary.)

- [ ] **Step 10: Full suite, lint, format, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates Cargo.lock
git commit -m "feat: git smart HTTP with token auth, streaming bodies, and the serve command"
```

---

### Task 8: Web foundation — sessions, login, CSRF, layout, dashboard

**Files:**
- Create: `crates/starforged-db/src/web_sessions.rs`; Modify: `crates/starforged-db/src/lib.rs` (add `pub mod web_sessions;`)
- Create: `crates/starforged-core/src/sessions.rs`; Modify: `crates/starforged-core/src/lib.rs` (add `pub mod sessions;`)
- Create: `crates/starforged-web/src/auth.rs`, `crates/starforged-web/src/error.rs`, `crates/starforged-web/src/views.rs`, `crates/starforged-web/src/pages/mod.rs`, `crates/starforged-web/src/pages/login.rs`, `crates/starforged-web/src/pages/dashboard.rs`
- Create: `crates/starforged-web/templates/base.html`, `error.html`, `login.html`, `dashboard.html`; `crates/starforged-web/static/starforge.css`
- Modify: `crates/starforged-web/src/lib.rs` (full replacement), `crates/starforged-web/Cargo.toml`, `crates/starforged/tests/common/mod.rs` (append)
- Test: unit tests in `sessions.rs`, `auth.rs`, `views.rs`; `crates/starforged/tests/web_auth.rs`

**Interfaces:**
- Consumes: `Core::{authenticate_password, audit_client, dashboard_repos}`, `crypto::{random_hex, sha256_hex}`, `Repo` (Tasks 3–5); `serve_on` provides `ConnectInfo<SocketAddr>` (Task 7).
- Produces:
  - `starforged_db::web_sessions::{WebSessionRow, NewWebSession, insert, active_by_hash, delete_by_hash}`.
  - `starforged_core::sessions::{WebSession { user, csrf_token }, NewSession { cookie_value, csrf_token, max_age_secs }, WEB_SESSION_TTL_SECS}`; `Core::login(login, password, user_agent, ip) -> CoreResult<(User, NewSession)>`, `Core::web_session(cookie_value) -> CoreResult<Option<WebSession>>`, `Core::logout(cookie_value)`.
  - `starforged_web::auth::{MaybeUser, RequireUser, CsrfForm, verify_csrf, safe_next, session_cookie, login_csrf_cookie, removal, SESSION_COOKIE, LOGIN_CSRF_COOKIE}`.
  - `starforged_web::error::WebError::{NotFound, Forbidden, BadRequest(String), Internal(String)}` with `From<CoreError>` and an HTML `IntoResponse`.
  - `starforged_web::views::{NavUser { handle, csrf }, nav(Option<&WebSession>), RepoItem { owner, name, visibility, description }, format_time(i64) -> String}`.
  - Every page template extends `base.html` and has a `nav_user: Option<NavUser>` field. Every POST form carries `<input type="hidden" name="_csrf" value="…">` in exactly that attribute order (tests scrape it).
  - Routes: `GET /`, `GET|POST /login`, `POST /logout`, `GET /static/starforge.css`. All web responses get CSP, `X-Content-Type-Options`, `Referrer-Policy`, and `X-Frame-Options` unless the handler set them.
  - Test harness additions: `TestServer::{browser, login}`, `extract_input`, `between`, `get_text`.

- [ ] **Step 1: Write the failing session tests**

`crates/starforged-db/src/web_sessions.rs`:

```rust
//! `web_sessions`: browser sessions, keyed by SHA-256 of the cookie value.

use sqlx::Row;

use crate::{Db, DbResult, now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSessionRow {
    pub id: i64,
    pub user_id: i64,
    pub csrf_token: String,
    pub expires_at: i64,
}

pub struct NewWebSession<'a> {
    pub session_hash: &'a str,
    pub user_id: i64,
    pub csrf_token: &'a str,
    pub expires_at: i64,
    pub user_agent: &'a str,
    pub ip: &'a str,
}

pub async fn insert(db: &Db, session: &NewWebSession<'_>) -> DbResult<i64> {
    let ts = now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO web_sessions (session_hash, user_id, csrf_token, created_at, expires_at, last_seen_at, user_agent, ip) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(session.session_hash)
    .bind(session.user_id)
    .bind(session.csrf_token)
    .bind(ts)
    .bind(session.expires_at)
    .bind(ts)
    .bind(session.user_agent)
    .bind(session.ip)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

/// The session whose cookie hashes to `session_hash`, if it expires after `now_ts`.
pub async fn active_by_hash(db: &Db, session_hash: &str, now_ts: i64) -> DbResult<Option<WebSessionRow>> {
    let row = sqlx::query("SELECT id, user_id, csrf_token, expires_at FROM web_sessions WHERE session_hash = $1 AND expires_at > $2")
        .bind(session_hash)
        .bind(now_ts)
        .fetch_optional(db.pool())
        .await?;
    row.map(|row| {
        Ok(WebSessionRow {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            csrf_token: row.try_get("csrf_token")?,
            expires_at: row.try_get("expires_at")?,
        })
    })
    .transpose()
}

pub async fn delete_by_hash(db: &Db, session_hash: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM web_sessions WHERE session_hash = $1").bind(session_hash).execute(db.pool()).await?;
    Ok(())
}
```

Add `pub mod web_sessions;` to `crates/starforged-db/src/lib.rs`.

`crates/starforged-core/src/sessions.rs` — tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::test_core;

    const PASSWORD: &str = "correct horse battery";

    async fn alice(core: &Core) -> User {
        core.create_user(CreateUser { handle: "alice".into(), password: Some(PASSWORD.into()), ..Default::default() })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn login_lookup_and_logout() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert!(matches!(core.login("alice", "wrong password!", "ua", "127.0.0.1").await, Err(CoreError::Unauthenticated)));
        let (user, session) = core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();
        assert_eq!(user.id, alice.id);
        assert_eq!(session.max_age_secs, WEB_SESSION_TTL_SECS);
        let found = core.web_session(&session.cookie_value).await.unwrap().unwrap();
        assert_eq!((found.user.id, found.csrf_token.as_str()), (alice.id, session.csrf_token.as_str()));
        assert!(core.web_session("not-a-session").await.unwrap().is_none());

        starforged_db::users::set_state(core.db(), alice.id, "suspended").await.unwrap();
        assert!(core.web_session(&session.cookie_value).await.unwrap().is_none(), "suspended users lose their sessions");
        starforged_db::users::set_state(core.db(), alice.id, "active").await.unwrap();

        core.logout(&session.cookie_value).await.unwrap();
        assert!(core.web_session(&session.cookie_value).await.unwrap().is_none());
        let actions: Vec<String> =
            starforged_db::audit::recent(core.db(), 5).await.unwrap().into_iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["auth.login", "auth.login_failed"]);
    }

    #[tokio::test]
    async fn expired_sessions_are_ignored() {
        let (core, _f) = test_core().await;
        alice(&core).await;
        let (_, session) = core.login("alice", PASSWORD, "ua", "127.0.0.1").await.unwrap();
        sqlx::query("UPDATE web_sessions SET expires_at = $1").bind(0_i64).execute(core.db().pool()).await.unwrap();
        assert!(core.web_session(&session.cookie_value).await.unwrap().is_none());
    }
}
```

Add `pub mod sessions;` to `crates/starforged-core/src/lib.rs`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-core sessions`
Expected: compile errors (`Core::login` missing).

- [ ] **Step 3: Implement `sessions.rs`**

Insert at the top of `crates/starforged-core/src/sessions.rs`:

```rust
//! Browser sessions (spec §9): random cookie value stored as SHA-256, 30-day lifetime, per-session CSRF token.

use starforged_db::web_sessions::{self, NewWebSession};

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, crypto};

pub const WEB_SESSION_TTL_SECS: i64 = 30 * 86_400;

#[derive(Debug, Clone)]
pub struct WebSession {
    pub user: User,
    pub csrf_token: String,
}

/// A session opened by [`Core::login`]. `cookie_value` goes to the browser and is never stored.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub cookie_value: String,
    pub csrf_token: String,
    pub max_age_secs: i64,
}

impl Core {
    /// Checks the password and opens a session. Successes and failures are audited with the client address.
    pub async fn login(&self, login: &str, password: &str, user_agent: &str, ip: &str) -> CoreResult<(User, NewSession)> {
        let user_agent: String = user_agent.chars().take(256).collect();
        let user = match self.authenticate_password(login, password).await {
            Ok(user) => user,
            Err(CoreError::Unauthenticated) => {
                let target = format!("login:{}", login.trim().to_ascii_lowercase());
                self.audit_client(None, "auth.login_failed", &target, "", ip, &user_agent).await?;
                return Err(CoreError::Unauthenticated);
            }
            Err(other) => return Err(other),
        };
        let cookie_value = crypto::random_hex(32);
        let csrf_token = crypto::random_hex(32);
        web_sessions::insert(
            self.db(),
            &NewWebSession {
                session_hash: &crypto::sha256_hex(&cookie_value),
                user_id: user.id,
                csrf_token: &csrf_token,
                expires_at: starforged_db::now() + WEB_SESSION_TTL_SECS,
                user_agent: &user_agent,
                ip,
            },
        )
        .await?;
        self.audit_client(Some(user.id), "auth.login", &format!("user:{}", user.handle), "", ip, &user_agent).await?;
        Ok((user, NewSession { cookie_value, csrf_token, max_age_secs: WEB_SESSION_TTL_SECS }))
    }

    /// The user behind a session cookie, if the session is unexpired and the user is active.
    pub async fn web_session(&self, cookie_value: &str) -> CoreResult<Option<WebSession>> {
        let hash = crypto::sha256_hex(cookie_value);
        let Some(row) = web_sessions::active_by_hash(self.db(), &hash, starforged_db::now()).await? else {
            return Ok(None);
        };
        let user = self.user_by_id(row.user_id).await?.filter(|u| u.active);
        Ok(user.map(|user| WebSession { user, csrf_token: row.csrf_token }))
    }

    pub async fn logout(&self, cookie_value: &str) -> CoreResult<()> {
        web_sessions::delete_by_hash(self.db(), &crypto::sha256_hex(cookie_value)).await?;
        Ok(())
    }
}
```

Run: `cargo test -p starforged-core sessions`
Expected: 2 passed.

- [ ] **Step 4: Add the web building blocks**

Add to `crates/starforged-web/Cargo.toml` `[dependencies]`:

```toml
askama.workspace = true
askama_web.workspace = true
axum-extra.workspace = true
percent-encoding.workspace = true
subtle.workspace = true
time.workspace = true
```

`crates/starforged-web/src/views.rs`:

```rust
//! View models shared by templates.

use starforged_core::repos::Repo;
use starforged_core::sessions::WebSession;

/// What the page header needs: the signed-in handle and the CSRF token for its sign-out form.
pub struct NavUser {
    pub handle: String,
    pub csrf: String,
}

impl NavUser {
    pub fn from_session(session: &WebSession) -> NavUser {
        NavUser { handle: session.user.handle.clone(), csrf: session.csrf_token.clone() }
    }
}

pub fn nav(session: Option<&WebSession>) -> Option<NavUser> {
    session.map(NavUser::from_session)
}

pub struct RepoItem {
    pub owner: String,
    pub name: String,
    pub visibility: &'static str,
    pub description: String,
}

impl From<Repo> for RepoItem {
    fn from(repo: Repo) -> RepoItem {
        RepoItem { owner: repo.owner, name: repo.name, visibility: repo.visibility.as_str(), description: repo.description }
    }
}

/// Formats unix seconds as `2026-11-03 12:00 UTC`.
pub fn format_time(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC")).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_time_in_utc() {
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13 UTC");
    }
}
```

`crates/starforged-web/src/error.rs`:

```rust
//! Errors for HTML routes, rendered as an error page.

use askama::Template;
use askama_web::WebTemplate;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use starforged_core::CoreError;

use crate::views::NavUser;

#[derive(Debug)]
pub enum WebError {
    NotFound,
    Forbidden,
    BadRequest(String),
    Internal(String),
}

impl From<CoreError> for WebError {
    fn from(err: CoreError) -> WebError {
        match err {
            CoreError::NotFound => WebError::NotFound,
            CoreError::Forbidden | CoreError::Unauthenticated => WebError::Forbidden,
            CoreError::Invalid(message) | CoreError::Conflict(message) => WebError::BadRequest(message),
            other => WebError::Internal(other.to_string()),
        }
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
struct ErrorPage {
    nav_user: Option<NavUser>,
    title: &'static str,
    message: String,
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status, title, message) = match self {
            WebError::NotFound => {
                (StatusCode::NOT_FOUND, "Not found", "That page does not exist, or you do not have access to it.".to_owned())
            }
            WebError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden", "You do not have permission to do that.".to_owned()),
            WebError::BadRequest(message) => (StatusCode::BAD_REQUEST, "Invalid request", message),
            WebError::Internal(message) => {
                tracing::error!(error = %message, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Server error", "Something went wrong; the error was logged.".to_owned())
            }
        };
        (status, ErrorPage { nav_user: None, title, message }).into_response()
    }
}
```

`crates/starforged-web/src/auth.rs`:

```rust
//! Session cookies, signed-in-user extractors, and CSRF checks (spec §9).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use starforged_core::sessions::WebSession;
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::error::WebError;

pub const SESSION_COOKIE: &str = "sf_session";
pub const LOGIN_CSRF_COOKIE: &str = "sf_login_csrf";

/// The signed-in user, if any.
pub struct MaybeUser(pub Option<WebSession>);

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        match jar.get(SESSION_COOKIE) {
            Some(cookie) => Ok(MaybeUser(state.core.web_session(cookie.value()).await?)),
            None => Ok(MaybeUser(None)),
        }
    }
}

/// A signed-in user. Anonymous requests are redirected to `/login?next=<path>`.
pub struct RequireUser(pub WebSession);

impl FromRequestParts<AppState> for RequireUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        match MaybeUser::from_request_parts(parts, state).await {
            Ok(MaybeUser(Some(session))) => Ok(RequireUser(session)),
            Ok(MaybeUser(None)) => {
                let next = utf8_percent_encode(parts.uri.path(), NON_ALPHANUMERIC);
                Err(Redirect::to(&format!("/login?next={next}")).into_response())
            }
            Err(err) => Err(err.into_response()),
        }
    }
}

/// A form body carrying only the CSRF token.
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(rename = "_csrf")]
    pub csrf: String,
}

/// Constant-time comparison; an empty expected token never matches.
pub fn verify_csrf(expected: &str, submitted: &str) -> Result<(), WebError> {
    if !expected.is_empty() && bool::from(expected.as_bytes().ct_eq(submitted.as_bytes())) {
        Ok(())
    } else {
        Err(WebError::Forbidden)
    }
}

/// Keeps only same-site absolute paths; anything else becomes `/` (no open redirects). Control characters
/// are refused too: `Redirect::to` panics on values that are not valid header text.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(path)
            if path.starts_with('/')
                && !path.starts_with("//")
                && !path.contains('\\')
                && !path.chars().any(char::is_control) =>
        {
            path.to_owned()
        }
        _ => "/".to_owned(),
    }
}

pub fn session_cookie(value: String, secure: bool, max_age_secs: i64) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::seconds(max_age_secs));
    cookie
}

/// Double-submit CSRF cookie for the anonymous login form.
pub fn login_csrf_cookie(value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(LOGIN_CSRF_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::hours(1));
    cookie
}

/// Pass to `CookieJar::remove` to clear the cookie `name` (path `/`).
pub fn removal(name: &'static str) -> Cookie<'static> {
    let mut cookie = Cookie::from(name);
    cookie.set_path("/");
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_paths_stay_on_site() {
        assert_eq!(safe_next(Some("/alice/proj")), "/alice/proj");
        let unsafe_paths =
            [None, Some(""), Some("//evil.example"), Some("https://evil.example"), Some("/\\evil.example"), Some("x"), Some("/a\r\nSet-Cookie: x=1")];
        for unsafe_next in unsafe_paths {
            assert_eq!(safe_next(unsafe_next), "/", "{unsafe_next:?}");
        }
    }

    #[test]
    fn csrf_tokens_must_match_exactly() {
        assert!(verify_csrf("abc", "abc").is_ok());
        assert!(verify_csrf("abc", "abd").is_err());
        assert!(verify_csrf("", "").is_err());
    }
}
```

`crates/starforged-web/src/pages/mod.rs`:

```rust
//! One module per page or page group.

pub mod dashboard;
pub mod login;
```

`crates/starforged-web/src/pages/login.rs`:

```rust
use std::net::SocketAddr;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;

use crate::AppState;
use crate::auth::{
    CsrfForm, LOGIN_CSRF_COOKIE, MaybeUser, RequireUser, SESSION_COOKIE, login_csrf_cookie, removal, safe_next,
    session_cookie, verify_csrf,
};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    next: String,
    login: String,
    password: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginPage {
    nav_user: Option<NavUser>,
    csrf: String,
    next: String,
    login: String,
    error: Option<String>,
}

pub async fn form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = safe_next(query.next.as_deref());
    if session.is_some() {
        return Redirect::to(&next).into_response();
    }
    let csrf = starforged_core::crypto::random_hex(32);
    let jar = jar.add(login_csrf_cookie(csrf.clone(), state.settings.secure_cookies));
    (jar, LoginPage { nav_user: None, csrf, next, login: String::new(), error: None }).into_response()
}

pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, WebError> {
    let expected = jar.get(LOGIN_CSRF_COOKIE).map(|c| c.value().to_owned()).unwrap_or_default();
    verify_csrf(&expected, &form.csrf)?;
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let next = safe_next(Some(&form.next));
    match state.core.login(&form.login, &form.password, user_agent, &addr.ip().to_string()).await {
        Ok((_, session)) => {
            let cookie = session_cookie(session.cookie_value, state.settings.secure_cookies, session.max_age_secs);
            let jar = jar.remove(removal(LOGIN_CSRF_COOKIE)).add(cookie);
            Ok((jar, Redirect::to(&next)).into_response())
        }
        Err(CoreError::Unauthenticated) => {
            let page = LoginPage {
                nav_user: None,
                csrf: form.csrf,
                next,
                login: form.login,
                error: Some("Incorrect handle, email, or password.".into()),
            };
            Ok((StatusCode::UNAUTHORIZED, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    RequireUser(session): RequireUser,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        state.core.logout(cookie.value()).await?;
    }
    Ok((jar.remove(removal(SESSION_COOKIE)), Redirect::to("/")).into_response())
}
```

`crates/starforged-web/src/pages/dashboard.rs`:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoItem, nav};

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    nav_user: Option<NavUser>,
    repos: Vec<RepoItem>,
}

pub async fn show(State(state): State<AppState>, MaybeUser(session): MaybeUser) -> Result<DashboardPage, WebError> {
    let repos = match &session {
        Some(session) => state.core.dashboard_repos(&session.user).await?.into_iter().map(RepoItem::from).collect(),
        None => Vec::new(),
    };
    Ok(DashboardPage { nav_user: nav(session.as_ref()), repos })
}
```

- [ ] **Step 5: Add the templates and stylesheet**

`crates/starforged-web/templates/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}Starforge{% endblock %}</title>
<link rel="stylesheet" href="/static/starforge.css">
</head>
<body>
<header class="site">
  <a class="brand" href="/">Starforge</a>
  <nav>
  {% if let Some(u) = nav_user %}
    <a href="/new">New repository</a>
    <a href="/settings/tokens">Tokens</a>
    <a href="/{{ u.handle }}">{{ u.handle }}</a>
    <form method="post" action="/logout" class="inline">
      <input type="hidden" name="_csrf" value="{{ u.csrf }}">
      <button type="submit">Sign out</button>
    </form>
  {% else %}
    <a href="/login">Sign in</a>
  {% endif %}
  </nav>
</header>
<main>
{% block content %}{% endblock %}
</main>
</body>
</html>
```

`crates/starforged-web/templates/error.html`:

```html
{% extends "base.html" %}
{% block title %}{{ title }} · Starforge{% endblock %}
{% block content %}
<h1>{{ title }}</h1>
<p>{{ message }}</p>
{% endblock %}
```

`crates/starforged-web/templates/login.html`:

```html
{% extends "base.html" %}
{% block title %}Sign in · Starforge{% endblock %}
{% block content %}
<h1>Sign in</h1>
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/login" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <input type="hidden" name="next" value="{{ next }}">
  <label>Handle or email <input name="login" autocomplete="username" required value="{{ login }}"></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>
{% endblock %}
```

`crates/starforged-web/templates/dashboard.html`:

```html
{% extends "base.html" %}
{% block content %}
{% if nav_user.is_some() %}
<h1>Your repositories</h1>
{% if repos.is_empty() %}
<p>No repositories yet. <a href="/new">Create one</a>.</p>
{% else %}
<ul class="repo-list">
{% for r in repos %}
<li><a href="/{{ r.owner }}/{{ r.name }}">{{ r.owner }}/{{ r.name }}</a> <span class="badge">{{ r.visibility }}</span>{% if !r.description.is_empty() %} <span class="muted">{{ r.description }}</span>{% endif %}</li>
{% endfor %}
</ul>
{% endif %}
{% else %}
<h1>Starforge</h1>
<p>A self-hosted forge for code and the agent sessions behind it. <a href="/login">Sign in</a> to continue.</p>
{% endif %}
{% endblock %}
```

`crates/starforged-web/static/starforge.css`:

```css
:root { color-scheme: light dark; --fg: #1f2328; --muted: #59636e; --border: #d1d9e0; --accent: #0969da; --add: #dafbe1; --del: #ffebe9; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6edf3; --muted: #9198a1; --border: #3d444d; --accent: #4493f8; --add: #12261e; --del: #25171c; }
}
body { font: 15px/1.5 system-ui, sans-serif; color: var(--fg); margin: 0; }
header.site { display: flex; justify-content: space-between; align-items: center; padding: .6rem 1.2rem; border-bottom: 1px solid var(--border); }
header.site nav { display: flex; gap: 1rem; align-items: center; }
main { max-width: 72rem; margin: 1.5rem auto; padding: 0 1.2rem; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.brand { font-weight: 700; }
.muted { color: var(--muted); }
.badge { border: 1px solid var(--border); border-radius: 1rem; padding: 0 .5rem; font-size: .8rem; color: var(--muted); }
.error { color: #cf222e; }
.notice { border: 1px solid var(--border); border-radius: .4rem; padding: .5rem 1rem; }
form.inline { display: inline; }
form.stack { display: grid; gap: .8rem; max-width: 28rem; }
form.stack label { display: grid; gap: .2rem; }
label.check { display: flex; gap: .4rem; align-items: center; }
table.list, table.code, table.diff { border-collapse: collapse; width: 100%; }
table.list td, table.list th { border-bottom: 1px solid var(--border); padding: .35rem .5rem; text-align: left; }
table.code td, table.diff td { padding: 0 .5rem; vertical-align: top; }
td.ln { color: var(--muted); text-align: right; user-select: none; width: 1%; white-space: nowrap; }
pre { margin: 0; white-space: pre-wrap; word-break: break-word; font: 13px/1.45 ui-monospace, monospace; }
tr.add { background: var(--add); }
tr.del { background: var(--del); }
tr.hunk td { color: var(--muted); padding: .3rem .5rem; }
td.dir a::before { content: "▸ "; }
ul.repo-list, ol.commits { list-style: none; padding: 0; }
ul.repo-list li, ol.commits li { padding: .4rem 0; border-bottom: 1px solid var(--border); }
nav.tabs { display: flex; gap: 1rem; margin: .5rem 0 1rem; }
pre.token { font-size: 1rem; padding: .5rem; border: 1px dashed var(--border); }
article.readme { border: 1px solid var(--border); border-radius: .4rem; padding: 1rem 1.5rem; margin-top: 1.5rem; }
section.file { border: 1px solid var(--border); border-radius: .4rem; margin: 1rem 0; }
section.file h3 { margin: 0; padding: .4rem .8rem; border-bottom: 1px solid var(--border); font-size: .95rem; }
```

- [ ] **Step 6: Replace `crates/starforged-web/src/lib.rs`**

```rust
//! starforged-web: HTML pages and git smart HTTP (spec §8.1, §10.1).

pub mod auth;
pub mod error;
pub mod githttp;
mod pages;
pub mod views;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use starforged_core::Core;

#[derive(Debug, Clone)]
pub struct WebSettings {
    /// Public URL without a trailing slash.
    pub base_url: String,
    pub secure_cookies: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub core: Core,
    pub settings: Arc<WebSettings>,
}

pub fn router(core: Core, settings: WebSettings) -> Router {
    let state = AppState { core, settings: Arc::new(settings) };
    Router::new()
        .merge(page_routes())
        .merge(git_routes())
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::dashboard::show))
        .route("/login", get(pages::login::form).post(pages::login::submit))
        .route("/logout", post(pages::login::logout))
        .route("/static/starforge.css", get(stylesheet))
}

/// Smart HTTP. Pushes can be arbitrarily large, so the request body limit is disabled here.
fn git_routes() -> Router<AppState> {
    Router::new()
        .route("/{owner}/{repo}/info/refs", get(githttp::info_refs))
        .route("/{owner}/{repo}/git-upload-pack", post(githttp::upload_pack))
        .route("/{owner}/{repo}/git-receive-pack", post(githttp::receive_pack))
        .layer(DefaultBodyLimit::disable())
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=3600")],
        include_str!("../static/starforge.css"),
    )
}

/// Default security headers (spec §11.1); handlers that set their own (raw files) keep them.
async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.entry(header::CONTENT_SECURITY_POLICY).or_insert(HeaderValue::from_static(
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ));
    headers.entry(header::X_CONTENT_TYPE_OPTIONS).or_insert(HeaderValue::from_static("nosniff"));
    headers.entry(header::REFERRER_POLICY).or_insert(HeaderValue::from_static("same-origin"));
    headers.entry(header::X_FRAME_OPTIONS).or_insert(HeaderValue::from_static("DENY"));
    response
}
```

Run: `cargo test -p starforged-web`
Expected: 5 passed (2 githttp, 2 auth, 1 views).

- [ ] **Step 7: Extend the harness and write the failing browser-flow tests**

Append to `crates/starforged/tests/common/mod.rs`:

```rust
impl TestServer {
    /// A cookie-keeping client that does not follow redirects.
    pub fn browser(&self) -> reqwest::Client {
        reqwest::Client::builder().cookie_store(true).redirect(reqwest::redirect::Policy::none()).build().unwrap()
    }

    /// Signs `handle` in through the login form; returns the client and the session's CSRF token.
    pub async fn login(&self, handle: &str) -> (reqwest::Client, String) {
        let client = self.browser();
        let page = client.get(self.url("/login")).send().await.unwrap().text().await.unwrap();
        let csrf = extract_input(&page, "_csrf");
        let response = client
            .post(self.url("/login"))
            .form(&[("_csrf", csrf.as_str()), ("next", "/"), ("login", handle), ("password", PASSWORD)])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303, "signing in as {handle} failed");
        let dashboard = client.get(self.url("/")).send().await.unwrap().text().await.unwrap();
        let session_csrf = extract_input(&dashboard, "_csrf");
        (client, session_csrf)
    }
}

/// The value of the first `<input … name="{name}" value="…">` in `html`.
pub fn extract_input(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker).unwrap_or_else(|| panic!("no input named {name} in:\n{html}")) + marker.len();
    html[start..].split('"').next().unwrap().to_owned()
}

/// The text between the first `start` and the next `end`.
pub fn between(html: &str, start: &str, end: &str) -> String {
    let from = html.find(start).unwrap_or_else(|| panic!("{start:?} not found in:\n{html}")) + start.len();
    let len = html[from..].find(end).unwrap_or_else(|| panic!("{end:?} not found after {start:?}"));
    html[from..from + len].to_owned()
}

/// GET that must succeed; returns the body.
pub async fn get_text(client: &reqwest::Client, url: &str) -> String {
    let response = client.get(url).send().await.unwrap();
    assert!(response.status().is_success(), "GET {url} returned {}", response.status());
    response.text().await.unwrap()
}
```

`crates/starforged/tests/web_auth.rs`:

```rust
mod common;

use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_logout_csrf_and_security_headers() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = s.browser();

    let page = client.get(s.url("/login")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let headers = page.headers().clone();
    assert!(headers["content-security-policy"].to_str().unwrap().starts_with("default-src 'self'"));
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    let csrf = extract_input(&page.text().await.unwrap(), "_csrf");

    let wrong = client
        .post(s.url("/login"))
        .form(&[("_csrf", csrf.as_str()), ("next", "/"), ("login", "alice"), ("password", "wrong password!")])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    assert!(wrong.text().await.unwrap().contains("Incorrect handle, email, or password."));

    let forged = client
        .post(s.url("/login"))
        .form(&[("_csrf", "forged"), ("next", "/"), ("login", "alice"), ("password", PASSWORD)])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);

    let ok = client
        .post(s.url("/login"))
        .form(&[("_csrf", csrf.as_str()), ("next", "/settings/tokens"), ("login", "alice"), ("password", PASSWORD)])
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 303);
    assert_eq!(ok.headers()["location"], "/settings/tokens");
    let cookies: Vec<String> = ok.headers().get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_owned()).collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("sf_session=") && c.contains("HttpOnly") && c.contains("SameSite=Lax")),
        "{cookies:?}"
    );

    let dashboard = get_text(&client, &s.url("/")).await;
    assert!(dashboard.contains(r#"<a href="/alice">alice</a>"#));
    assert_eq!(client.get(s.url("/login")).send().await.unwrap().status(), 303, "signed-in users skip the form");

    let session_csrf = extract_input(&dashboard, "_csrf");
    let bad_logout = client.post(s.url("/logout")).form(&[("_csrf", "nope")]).send().await.unwrap();
    assert_eq!(bad_logout.status(), 403);
    let logout = client.post(s.url("/logout")).form(&[("_csrf", session_csrf.as_str())]).send().await.unwrap();
    assert_eq!(logout.status(), 303);
    assert!(get_text(&client, &s.url("/")).await.contains(r#"<a href="/login">Sign in</a>"#));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_never_redirects_off_site() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = s.browser();
    let page = get_text(&client, &s.url("/login?next=//evil.example/x")).await;
    assert!(page.contains(r#"name="next" value="/""#), "the form carries a sanitized next");
    let csrf = extract_input(&page, "_csrf");
    let response = client
        .post(s.url("/login"))
        .form(&[("_csrf", csrf.as_str()), ("next", "https://evil.example"), ("login", "alice"), ("password", PASSWORD)])
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], "/");
}
```

- [ ] **Step 8: Run the browser-flow tests**

Run: `cargo test -p starforged --test web_auth`
Expected: 2 passed.

- [ ] **Step 9: Full suite, lint, format, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates Cargo.lock
git commit -m "feat(web): login sessions, CSRF protection, security headers, and dashboard"
```

---

### Task 9: Token management and repository creation pages

**Files:**
- Create: `crates/starforged-web/src/pages/tokens.rs`, `crates/starforged-web/src/pages/repo_new.rs`, `crates/starforged-web/templates/tokens.html`, `crates/starforged-web/templates/repo_new.html`
- Modify: `crates/starforged-web/src/pages/mod.rs`, `crates/starforged-web/src/lib.rs` (`page_routes`)
- Test: `crates/starforged/tests/web_settings.rs`

**Interfaces:**
- Consumes: `RequireUser`, `CsrfForm`, `verify_csrf`, `NavUser`, `format_time`, `WebError` (Task 8); `Core::{create_token, list_tokens, revoke_token, create_repo}`, `tokens::{parse_scopes, format_scopes, Scope}` (Tasks 4–5).
- Produces routes: `GET|POST /settings/tokens`, `POST /settings/tokens/{id}/revoke`, `GET|POST /new`. A created token is shown once in `<pre class="token">…</pre>`; invalid input re-renders the form with status 422.

- [ ] **Step 1: Write the failing tests**

`crates/starforged/tests/web_settings.rs`:

```rust
mod common;

use common::*;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokens_are_created_shown_once_and_revoked() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let anonymous = s.browser().get(s.url("/settings/tokens")).send().await.unwrap();
    assert_eq!(anonymous.status(), 303);
    assert_eq!(anonymous.headers()["location"], "/login?next=%2Fsettings%2Ftokens");

    let (client, csrf) = s.login("alice").await;
    let created = client
        .post(s.url("/settings/tokens"))
        .form(&[("_csrf", csrf.as_str()), ("name", "laptop"), ("scopes", "repo:read"), ("scopes", "repo:write"), ("expires_days", "7")])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);
    let secret = between(&created.text().await.unwrap(), r#"<pre class="token">"#, "</pre>");
    let auth = s.core.authenticate_token(&secret).await.unwrap();
    assert_eq!(auth.scopes, vec![Scope::RepoRead, Scope::RepoWrite]);

    let listing = get_text(&client, &s.url("/settings/tokens")).await;
    assert!(!listing.contains(&secret), "the secret is never shown again");
    assert!(listing.contains(&format!("sfp_…{}", &secret[secret.len() - 4..])));
    assert!(!listing.contains(r#"value="admin""#), "non-admins cannot pick the admin scope");

    let no_scopes = client
        .post(s.url("/settings/tokens"))
        .form(&[("_csrf", csrf.as_str()), ("name", "x"), ("expires_days", "7")])
        .send()
        .await
        .unwrap();
    assert_eq!(no_scopes.status(), 422);
    assert!(no_scopes.text().await.unwrap().contains("at least one scope is required"));

    let forged = client.post(s.url("/settings/tokens")).form(&[("_csrf", "x"), ("name", "x"), ("scopes", "repo:read"), ("expires_days", "7")]).send().await.unwrap();
    assert_eq!(forged.status(), 403);

    let id = s.core.list_tokens(&auth.user).await.unwrap()[0].id;
    let revoked = client.post(s.url(&format!("/settings/tokens/{id}/revoke"))).form(&[("_csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(revoked.status(), 303);
    assert!(s.core.authenticate_token(&secret).await.is_err());
    assert!(get_text(&client, &s.url("/settings/tokens")).await.contains("revoked"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repositories_are_created_from_the_form() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    assert!(get_text(&client, &s.url("/new")).await.contains(r#"name="name""#));
    let created = client
        .post(s.url("/new"))
        .form(&[("_csrf", csrf.as_str()), ("name", "Proj"), ("description", "demo"), ("visibility", "public")])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    assert_eq!(created.headers()["location"], "/alice/Proj");
    let duplicate = client
        .post(s.url("/new"))
        .form(&[("_csrf", csrf.as_str()), ("name", "proj"), ("description", ""), ("visibility", "private")])
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 422);
    assert!(duplicate.text().await.unwrap().contains("already exists"));
    let dashboard = get_text(&client, &s.url("/")).await;
    assert!(dashboard.contains(r#"<a href="/alice/Proj">alice/Proj</a>"#));
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged --test web_settings`
Expected: FAIL — `/settings/tokens` and `/new` return 404.

- [ ] **Step 3: Implement the pages**

`crates/starforged-web/src/pages/tokens.rs`:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::accounts::User;
use starforged_core::sessions::WebSession;
use starforged_core::tokens::{self, CreatedToken, Scope};
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, format_time};

#[derive(Deserialize)]
pub struct CreateTokenForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
    expires_days: u32,
}

pub struct TokenRow {
    id: i64,
    name: String,
    hint: String,
    scopes: String,
    expires: String,
    last_used: String,
    revoked: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "tokens.html")]
pub struct TokensPage {
    nav_user: Option<NavUser>,
    csrf: String,
    tokens: Vec<TokenRow>,
    scope_choices: Vec<&'static str>,
    created: Option<String>,
    error: Option<String>,
}

pub async fn list(State(state): State<AppState>, RequireUser(session): RequireUser) -> Result<TokensPage, WebError> {
    page(&state, &session, None, None).await
}

pub async fn create(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<CreateTokenForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match create_from_form(&state, &session.user, &form).await {
        Ok(created) => Ok(page(&state, &session, Some(created.secret), None).await?.into_response()),
        Err(CoreError::Invalid(message)) => {
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page(&state, &session, None, Some(message)).await?).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.revoke_token(&session.user, id).await?;
    Ok(Redirect::to("/settings/tokens").into_response())
}

async fn create_from_form(state: &AppState, user: &User, form: &CreateTokenForm) -> CoreResult<CreatedToken> {
    let scopes = tokens::parse_scopes(&form.scopes.join(","))?;
    state.core.create_token(user, &form.name, &scopes, form.expires_days).await
}

async fn page(
    state: &AppState,
    session: &WebSession,
    created: Option<String>,
    error: Option<String>,
) -> Result<TokensPage, WebError> {
    let rows = state
        .core
        .list_tokens(&session.user)
        .await?
        .into_iter()
        .map(|t| TokenRow {
            id: t.id,
            name: t.name,
            hint: t.hint,
            scopes: tokens::format_scopes(&t.scopes),
            expires: format_time(t.expires_at),
            last_used: t.last_used_at.map(format_time).unwrap_or_else(|| "never".into()),
            revoked: t.revoked,
        })
        .collect();
    let scope_choices =
        Scope::ALL.into_iter().filter(|s| *s != Scope::Admin || session.user.is_admin).map(Scope::as_str).collect();
    Ok(TokensPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        tokens: rows,
        scope_choices,
        created,
        error,
    })
}
```

`crates/starforged-web/src/pages/repo_new.rs`:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::permission::Visibility;
use starforged_core::repos::CreateRepo;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct NewRepoForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    #[serde(default)]
    description: String,
    visibility: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_new.html")]
pub struct RepoNewPage {
    nav_user: Option<NavUser>,
    csrf: String,
    owner: String,
    name: String,
    description: String,
    error: Option<String>,
}

fn page(session: &WebSession, name: String, description: String, error: Option<String>) -> RepoNewPage {
    RepoNewPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        owner: session.user.handle.clone(),
        name,
        description,
        error,
    }
}

pub async fn form(RequireUser(session): RequireUser) -> RepoNewPage {
    page(&session, String::new(), String::new(), None)
}

pub async fn submit(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<NewRepoForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let visibility = Visibility::parse(&form.visibility).ok_or_else(|| WebError::BadRequest("unknown visibility".into()))?;
    let input = CreateRepo { name: form.name.clone(), description: form.description.clone(), visibility };
    match state.core.create_repo(&session.user, input).await {
        Ok(repo) => Ok(Redirect::to(&format!("/{}/{}", repo.owner, repo.name)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&session, form.name, form.description, Some(message));
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}
```

`crates/starforged-web/templates/tokens.html`:

```html
{% extends "base.html" %}
{% block title %}Tokens · Starforge{% endblock %}
{% block content %}
<h1>Personal access tokens</h1>
{% if let Some(secret) = created %}
<div class="notice">
<p>Copy your new token now. It will not be shown again.</p>
<pre class="token">{{ secret }}</pre>
</div>
{% endif %}
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/settings/tokens" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Name <input name="name" required maxlength="64"></label>
  <fieldset>
    <legend>Scopes</legend>
    {% for scope in scope_choices %}<label class="check"><input type="checkbox" name="scopes" value="{{ scope }}"> {{ scope }}</label>{% endfor %}
  </fieldset>
  <label>Expires in days <input name="expires_days" type="number" min="1" max="366" value="30"></label>
  <button type="submit">Create token</button>
</form>
<h2>Existing tokens</h2>
<table class="list">
<thead><tr><th>Name</th><th>Token</th><th>Scopes</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
<tbody>
{% for t in tokens %}
<tr>
<td>{{ t.name }}</td><td><code>sfp_…{{ t.hint }}</code></td><td>{{ t.scopes }}</td><td>{{ t.expires }}</td><td>{{ t.last_used }}</td>
<td>{% if t.revoked %}revoked{% else %}<form method="post" action="/settings/tokens/{{ t.id }}/revoke" class="inline"><input type="hidden" name="_csrf" value="{{ csrf }}"><button type="submit">Revoke</button></form>{% endif %}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endblock %}
```

`crates/starforged-web/templates/repo_new.html`:

```html
{% extends "base.html" %}
{% block title %}New repository · Starforge{% endblock %}
{% block content %}
<h1>New repository</h1>
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/new" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Owner <input value="{{ owner }}" disabled></label>
  <label>Name <input name="name" required maxlength="100" value="{{ name }}"></label>
  <label>Description <input name="description" maxlength="350" value="{{ description }}"></label>
  <fieldset>
    <legend>Visibility</legend>
    <label class="check"><input type="radio" name="visibility" value="private" checked> Private</label>
    <label class="check"><input type="radio" name="visibility" value="internal"> Internal (every signed-in user can read)</label>
    <label class="check"><input type="radio" name="visibility" value="public"> Public</label>
  </fieldset>
  <button type="submit">Create repository</button>
</form>
{% endblock %}
```

`crates/starforged-web/src/pages/mod.rs`:

```rust
//! One module per page or page group.

pub mod dashboard;
pub mod login;
pub mod repo_new;
pub mod tokens;
```

In `crates/starforged-web/src/lib.rs`, `page_routes` becomes:

```rust
fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::dashboard::show))
        .route("/login", get(pages::login::form).post(pages::login::submit))
        .route("/logout", post(pages::login::logout))
        .route("/new", get(pages::repo_new::form).post(pages::repo_new::submit))
        .route("/settings/tokens", get(pages::tokens::list).post(pages::tokens::create))
        .route("/settings/tokens/{id}/revoke", post(pages::tokens::revoke))
        .route("/static/starforge.css", get(stylesheet))
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p starforged --test web_settings`
Expected: 2 passed.

- [ ] **Step 5: Lint, format, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates
git commit -m "feat(web): personal access token management and repository creation pages"
```

---

### Task 10: Owner pages and collaborator management

**Files:**
- Create: `crates/starforged-web/src/pages/owner.rs`, `crates/starforged-web/src/pages/collaborators.rs`, `crates/starforged-web/templates/owner.html`, `crates/starforged-web/templates/collaborators.html`
- Modify: `crates/starforged-web/src/pages/mod.rs`, `crates/starforged-web/src/lib.rs` (`page_routes`)
- Test: `crates/starforged/tests/web_collaborators.rs`

**Interfaces:**
- Consumes: `MaybeUser`, `RequireUser`, `CsrfForm`, `verify_csrf`, `nav`, `NavUser`, `RepoItem` (Task 8); `Core::{repos_of, require_repo, collaborators, set_collaborator, remove_collaborator}`, `Permission` (Task 5).
- Produces routes: `GET /{owner}`; `GET|POST /{owner}/{repo}/settings/collaborators`; `POST /{owner}/{repo}/settings/collaborators/{handle}/remove`. Redirect targets are built only from names that matched an existing repository, so they are always valid header values.

- [ ] **Step 1: Write the failing test**

`crates/starforged/tests/web_collaborators.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::Visibility;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_pages_and_collaborator_management() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "secret", Visibility::Private).await;
    s.repo(&alice, "open", Visibility::Public).await;

    let anonymous = s.browser();
    let owner_page = get_text(&anonymous, &s.url("/alice")).await;
    assert!(owner_page.contains(r#"href="/alice/open""#));
    assert!(!owner_page.contains("secret"), "private repositories stay hidden");
    assert_eq!(anonymous.get(s.url("/nobody")).send().await.unwrap().status(), 404);

    let (bob, bob_csrf) = s.login("bob").await;
    assert_eq!(bob.get(s.url("/alice/secret/settings/collaborators")).send().await.unwrap().status(), 404);

    let (alice_client, csrf) = s.login("alice").await;
    let settings = s.url("/alice/secret/settings/collaborators");
    let unknown = alice_client
        .post(&settings)
        .form(&[("_csrf", csrf.as_str()), ("handle", "nobody"), ("permission", "read")])
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 422);
    assert!(unknown.text().await.unwrap().contains("no user named"));
    let added = alice_client
        .post(&settings)
        .form(&[("_csrf", csrf.as_str()), ("handle", "bob"), ("permission", "read")])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    assert_eq!(added.headers()["location"], "/alice/secret/settings/collaborators");
    assert!(get_text(&alice_client, &settings).await.contains(r#"<td><a href="/bob">bob</a></td><td>read</td>"#));

    // bob can now see the repository but cannot manage it
    assert!(get_text(&bob, &s.url("/alice")).await.contains(r#"href="/alice/secret""#));
    assert_eq!(bob.get(&settings).send().await.unwrap().status(), 403);
    let escalate = bob
        .post(&settings)
        .form(&[("_csrf", bob_csrf.as_str()), ("handle", "bob"), ("permission", "admin")])
        .send()
        .await
        .unwrap();
    assert_eq!(escalate.status(), 403);

    let removed = alice_client
        .post(s.url("/alice/secret/settings/collaborators/bob/remove"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 303);
    assert!(!get_text(&bob, &s.url("/alice")).await.contains("secret"));
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p starforged --test web_collaborators`
Expected: FAIL — `/alice` returns 404.

- [ ] **Step 3: Implement the pages**

`crates/starforged-web/src/pages/owner.rs`:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoItem, nav};

#[derive(Template, WebTemplate)]
#[template(path = "owner.html")]
pub struct OwnerPage {
    nav_user: Option<NavUser>,
    owner: String,
    repos: Vec<RepoItem>,
}

pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path(owner): Path<String>,
) -> Result<OwnerPage, WebError> {
    let viewer = session.as_ref().map(|s| &s.user);
    let repos = state.core.repos_of(viewer, &owner).await?.into_iter().map(RepoItem::from).collect();
    Ok(OwnerPage { nav_user: nav(session.as_ref()), owner: owner.to_ascii_lowercase(), repos })
}
```

`crates/starforged-web/src/pages/collaborators.rs`:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct AddForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    handle: String,
    permission: String,
}

pub struct CollaboratorRow {
    handle: String,
    permission: &'static str,
}

#[derive(Template, WebTemplate)]
#[template(path = "collaborators.html")]
pub struct CollaboratorsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    owner: String,
    name: String,
    collaborators: Vec<CollaboratorRow>,
    permission_choices: Vec<&'static str>,
    error: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<CollaboratorsPage, WebError> {
    page(&state, &session, &owner, &repo, None).await
}

pub async fn add(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<AddForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let permission = Permission::parse(&form.permission).ok_or_else(|| WebError::BadRequest("unknown permission".into()))?;
    match state.core.set_collaborator(&session.user, &owner, &repo, &form.handle, permission).await {
        Ok(()) => Ok(Redirect::to(&settings_path(&state, &session, &owner, &repo).await?).into_response()),
        Err(CoreError::Invalid(message)) => {
            let page = page(&state, &session, &owner, &repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn remove(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, handle)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.remove_collaborator(&session.user, &owner, &repo, &handle).await?;
    Ok(Redirect::to(&settings_path(&state, &session, &owner, &repo).await?).into_response())
}

/// The settings URL built from the repository's stored names (never from raw path input).
async fn settings_path(state: &AppState, session: &WebSession, owner: &str, repo: &str) -> Result<String, WebError> {
    let access = state.core.repo_for(Some(&session.user), owner, repo).await?;
    Ok(format!("/{}/{}/settings/collaborators", access.repo.owner, access.repo.name))
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> Result<CollaboratorsPage, WebError> {
    let access = state.core.require_repo(Some(&session.user), owner, repo, Permission::Admin).await?;
    let collaborators = state
        .core
        .collaborators(&session.user, owner, repo)
        .await?
        .into_iter()
        .map(|c| CollaboratorRow { handle: c.handle, permission: c.permission.as_str() })
        .collect();
    Ok(CollaboratorsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        owner: access.repo.owner,
        name: access.repo.name,
        collaborators,
        permission_choices: Permission::ALL.into_iter().map(Permission::as_str).collect(),
        error,
    })
}
```

`crates/starforged-web/templates/owner.html`:

```html
{% extends "base.html" %}
{% block title %}{{ owner }} · Starforge{% endblock %}
{% block content %}
<h1>{{ owner }}</h1>
{% if repos.is_empty() %}
<p class="muted">No repositories to show.</p>
{% else %}
<ul class="repo-list">
{% for r in repos %}
<li><a href="/{{ r.owner }}/{{ r.name }}">{{ r.name }}</a> <span class="badge">{{ r.visibility }}</span>{% if !r.description.is_empty() %} <span class="muted">{{ r.description }}</span>{% endif %}</li>
{% endfor %}
</ul>
{% endif %}
{% endblock %}
```

`crates/starforged-web/templates/collaborators.html`:

```html
{% extends "base.html" %}
{% block title %}Collaborators · {{ owner }}/{{ name }}{% endblock %}
{% block content %}
<h1><a href="/{{ owner }}">{{ owner }}</a> / <a href="/{{ owner }}/{{ name }}">{{ name }}</a> · Collaborators</h1>
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
{% if collaborators.is_empty() %}
<p class="muted">No collaborators yet.</p>
{% else %}
<table class="list">
<thead><tr><th>User</th><th>Permission</th><th></th></tr></thead>
<tbody>
{% for c in collaborators %}
<tr><td><a href="/{{ c.handle }}">{{ c.handle }}</a></td><td>{{ c.permission }}</td>
<td><form method="post" action="/{{ owner }}/{{ name }}/settings/collaborators/{{ c.handle }}/remove" class="inline"><input type="hidden" name="_csrf" value="{{ csrf }}"><button type="submit">Remove</button></form></td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
<h2>Add or change a collaborator</h2>
<form method="post" action="/{{ owner }}/{{ name }}/settings/collaborators" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Handle <input name="handle" required></label>
  <label>Permission <select name="permission">{% for p in permission_choices %}<option value="{{ p }}">{{ p }}</option>{% endfor %}</select></label>
  <button type="submit">Save</button>
</form>
{% endblock %}
```

Add `pub mod collaborators;` and `pub mod owner;` to `crates/starforged-web/src/pages/mod.rs`, and add these routes to `page_routes` in `crates/starforged-web/src/lib.rs` (before `.route("/static/starforge.css", …)`):

```rust
        .route("/{owner}", get(pages::owner::show))
        .route(
            "/{owner}/{repo}/settings/collaborators",
            get(pages::collaborators::list).post(pages::collaborators::add),
        )
        .route("/{owner}/{repo}/settings/collaborators/{handle}/remove", post(pages::collaborators::remove))
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p starforged --test web_collaborators`
Expected: 1 passed.

- [ ] **Step 5: Full suite, lint, format, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates
git commit -m "feat(web): owner pages and collaborator management"
```

---

### Task 11: Code browsing — repository home, trees, files, raw, README

**Files:**
- Create: `crates/starforged-git/src/read.rs`; Modify: `crates/starforged-git/src/lib.rs` (add `pub mod read;`), `crates/starforged-git/Cargo.toml` (add `gix`)
- Create: `crates/starforged-core/src/content.rs`; Modify: `crates/starforged-core/src/lib.rs` (add `pub mod content;`)
- Create: `crates/starforged-web/src/markdown.rs`, `crates/starforged-web/src/pages/code.rs`, `crates/starforged-web/templates/tree.html`, `crates/starforged-web/templates/blob.html`
- Modify: `crates/starforged-web/src/views.rs` (append path helpers), `crates/starforged-web/src/lib.rs` (add `pub mod markdown;`, routes), `crates/starforged-web/src/pages/mod.rs`, `crates/starforged-web/Cargo.toml`
- Test: unit tests in `read.rs`, `markdown.rs`, `views.rs`; `crates/starforged/tests/web_code.rs`

**Interfaces:**
- Consumes: `Core::{repo_for, repo_path}`, `RepoAccess`, `Permission` (Task 5); `MaybeUser`, `nav`, `NavUser`, `WebError` (Task 8).
- Produces:
  - `starforged_git::read::{EntryKind, TreeEntry { name, kind }, CommitInfo { id, summary, message, author_name, author_email, author_time, parents }, Resolved { ref_name, commit_id, path }, Blob::{Text(String), Binary}}` and functions `branches(repo)`, `resolve(repo, rest)`, `tree(repo, commit_id, dir)`, `blob_bytes(repo, commit_id, file)`, `classify(Vec<u8>) -> Blob`, `log(repo, commit_id, skip, limit)`, `commit(repo, id)`. All take the repository path and return `Result<_, GitError>`; lookups that find nothing return `Ok(None)`. `CommitInfo::short_id()` gives the first 10 characters.
  - `starforged_core::content::MAX_INLINE_BLOB_BYTES` (1 MiB); `Core::{branches, resolve, tree, blob, log, commit}` taking `&RepoAccess` and returning `NotFound` for missing content. They run gix on the blocking thread pool.
  - `starforged_web::markdown::{render(&str) -> String, plain(&str) -> String}`.
  - `starforged_web::views::{encode_path, content_href(owner, repo, kind, ref_name, path), Crumb { name, href }, crumbs(owner, repo, ref_name, dir)}`.
  - Routes: `GET /{owner}/{repo}`, `GET /{owner}/{repo}/tree/{*rest}`, `GET /{owner}/{repo}/blob/{*rest}`, `GET /{owner}/{repo}/raw/{*rest}`, where `rest` is `<ref>/<path>` and refs may contain `/`.

- [ ] **Step 1: Write the failing read-path tests**

Add to `crates/starforged-git/Cargo.toml` `[dependencies]`:

```toml
gix.workspace = true
```

Add `pub mod read;` to `crates/starforged-git/src/lib.rs`.

`crates/starforged-git/src/read.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str], date: Option<&str>) {
        let mut cmd = Command::new("git");
        cmd.args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        if let Some(date) = date {
            cmd.env("GIT_AUTHOR_DATE", date).env("GIT_COMMITTER_DATE", date);
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// `main`: README.md, src/lib.rs, docs/a b.txt, bin.dat. `feature/x` adds feature.txt. Tag `v1` is the first commit.
    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        git(p, &["init", "-q", "-b", "main", "."], None);
        std::fs::write(p.join("README.md"), "# Demo\n").unwrap();
        std::fs::create_dir_all(p.join("src")).unwrap();
        std::fs::write(p.join("src/lib.rs"), "pub fn x() {}\n").unwrap();
        git(p, &["add", "-A"], None);
        git(p, &["commit", "-q", "-m", "first"], Some("2024-01-01T00:00:00Z"));
        git(p, &["tag", "v1"], None);
        std::fs::create_dir_all(p.join("docs")).unwrap();
        std::fs::write(p.join("docs/a b.txt"), "spaced\n").unwrap();
        std::fs::write(p.join("bin.dat"), [0_u8, 1, 2, 3]).unwrap();
        git(p, &["add", "-A"], None);
        git(p, &["commit", "-q", "-m", "second\n\nbody line"], Some("2024-01-02T00:00:00Z"));
        git(p, &["checkout", "-q", "-b", "feature/x"], None);
        std::fs::write(p.join("feature.txt"), "f\n").unwrap();
        git(p, &["add", "-A"], None);
        git(p, &["commit", "-q", "-m", "feature"], Some("2024-01-03T00:00:00Z"));
        git(p, &["checkout", "-q", "main"], None);
        dir
    }

    #[test]
    fn branches_are_sorted() {
        assert_eq!(branches(fixture().path()).unwrap(), vec!["feature/x", "main"]);
    }

    #[test]
    fn resolves_the_longest_ref_prefix() {
        let f = fixture();
        let p = f.path();
        let feature = resolve(p, "feature/x/src/lib.rs").unwrap().unwrap();
        assert_eq!((feature.ref_name.as_str(), feature.path.as_str()), ("feature/x", "src/lib.rs"));
        let main = resolve(p, "main").unwrap().unwrap();
        assert_eq!(main.path, "");
        let tag = resolve(p, "v1/README.md").unwrap().unwrap();
        assert_eq!((tag.ref_name.as_str(), tag.path.as_str()), ("v1", "README.md"));
        assert_ne!(tag.commit_id, main.commit_id);
        let by_id = resolve(p, &format!("{}/src", main.commit_id)).unwrap().unwrap();
        assert_eq!((by_id.commit_id.as_str(), by_id.path.as_str()), (main.commit_id.as_str(), "src"));
        assert!(resolve(p, "nope/README.md").unwrap().is_none());
        assert!(resolve(p, "").unwrap().is_none());
    }

    #[test]
    fn trees_list_directories_first() {
        let f = fixture();
        let p = f.path();
        let main = resolve(p, "main").unwrap().unwrap();
        let root = tree(p, &main.commit_id, "").unwrap().unwrap();
        let listed: Vec<(&str, EntryKind)> = root.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(
            listed,
            vec![("docs", EntryKind::Tree), ("src", EntryKind::Tree), ("README.md", EntryKind::Blob), ("bin.dat", EntryKind::Blob)]
        );
        assert_eq!(tree(p, &main.commit_id, "docs").unwrap().unwrap()[0].name, "a b.txt");
        assert!(tree(p, &main.commit_id, "README.md").unwrap().is_none(), "a file is not a tree");
        assert!(tree(p, &main.commit_id, "missing").unwrap().is_none());
    }

    #[test]
    fn blobs_and_their_classification() {
        let f = fixture();
        let p = f.path();
        let main = resolve(p, "main").unwrap().unwrap();
        assert_eq!(blob_bytes(p, &main.commit_id, "docs/a b.txt").unwrap().unwrap(), b"spaced\n");
        assert_eq!(classify(blob_bytes(p, &main.commit_id, "README.md").unwrap().unwrap()), Blob::Text("# Demo\n".into()));
        assert_eq!(classify(blob_bytes(p, &main.commit_id, "bin.dat").unwrap().unwrap()), Blob::Binary);
        assert_eq!(classify(vec![0xff, 0xfe]), Blob::Binary);
        assert!(blob_bytes(p, &main.commit_id, "src").unwrap().is_none(), "a directory is not a blob");
        assert!(blob_bytes(p, &main.commit_id, "missing").unwrap().is_none());
    }

    #[test]
    fn history_is_newest_first_and_pages() {
        let f = fixture();
        let p = f.path();
        let feature = resolve(p, "feature/x").unwrap().unwrap();
        let all: Vec<String> = log(p, &feature.commit_id, 0, 10).unwrap().into_iter().map(|c| c.summary).collect();
        assert_eq!(all, vec!["feature", "second", "first"]);
        let second = &log(p, &feature.commit_id, 1, 1).unwrap()[0];
        assert_eq!(second.summary, "second");
        let found = commit(p, &second.id).unwrap().unwrap();
        assert_eq!(found.author_name, "T");
        assert_eq!(found.author_email, "t@example.com");
        assert_eq!(found.author_time, 1_704_153_600);
        assert!(found.message.contains("body line"));
        assert_eq!(found.parents.len(), 1);
        assert_eq!(found.short_id().len(), 10);
        assert!(commit(p, "not-an-id").unwrap().is_none());
        assert!(commit(p, &"0".repeat(40)).unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-git read`
Expected: compile errors.

- [ ] **Step 3: Implement `read.rs`**

Insert at the top of `crates/starforged-git/src/read.rs`:

```rust
//! Read paths over gix (spec D11): branches, ref resolution, trees, blobs, history.
//! Blocking; async callers run these on the blocking thread pool.

use std::path::Path;

use crate::command::GitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Tree,
    Blob,
    Symlink,
    Submodule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub name: String,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub id: String,
    pub summary: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    /// Unix seconds.
    pub author_time: i64,
    pub parents: Vec<String>,
}

impl CommitInfo {
    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(10)]
    }
}

/// A `<ref>/<path>` URL suffix resolved to a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub ref_name: String,
    pub commit_id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blob {
    Text(String),
    Binary,
}

fn gix_err(err: impl std::fmt::Display) -> GitError {
    GitError::Gix(err.to_string())
}

fn open(repo: &Path) -> Result<gix::Repository, GitError> {
    gix::open(repo).map_err(gix_err)
}

fn branch_names(repo: &gix::Repository) -> Result<Vec<String>, GitError> {
    let platform = repo.references().map_err(gix_err)?;
    let mut names = Vec::new();
    for reference in platform.local_branches().map_err(gix_err)? {
        names.push(reference.map_err(gix_err)?.name().shorten().to_string());
    }
    names.sort();
    Ok(names)
}

fn tag_names(repo: &gix::Repository) -> Result<Vec<String>, GitError> {
    let platform = repo.references().map_err(gix_err)?;
    let mut names = Vec::new();
    for reference in platform.tags().map_err(gix_err)? {
        names.push(reference.map_err(gix_err)?.name().shorten().to_string());
    }
    Ok(names)
}

fn commit_id_of(repo: &gix::Repository, spec: &str) -> Option<String> {
    let commit = repo.rev_parse_single(spec).ok()?.object().ok()?.peel_to_commit().ok()?;
    Some(commit.id.to_string())
}

fn is_object_id(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Local branch names, sorted.
pub fn branches(repo: &Path) -> Result<Vec<String>, GitError> {
    branch_names(&open(repo)?)
}

/// Splits `rest` at the longest prefix naming a branch (then a tag); a full commit id also works.
pub fn resolve(repo: &Path, rest: &str) -> Result<Option<Resolved>, GitError> {
    let r = open(repo)?;
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Ok(None);
    }
    let branches = branch_names(&r)?;
    let tags = tag_names(&r)?;
    for split in (1..=parts.len()).rev() {
        let candidate = parts[..split].join("/");
        let full = if branches.contains(&candidate) {
            format!("refs/heads/{candidate}")
        } else if tags.contains(&candidate) {
            format!("refs/tags/{candidate}")
        } else {
            continue;
        };
        if let Some(commit_id) = commit_id_of(&r, &full) {
            return Ok(Some(Resolved { ref_name: candidate, commit_id, path: parts[split..].join("/") }));
        }
    }
    if is_object_id(parts[0])
        && let Some(commit_id) = commit_id_of(&r, parts[0])
    {
        return Ok(Some(Resolved { ref_name: parts[0].to_owned(), commit_id, path: parts[1..].join("/") }));
    }
    Ok(None)
}

/// Entries of directory `dir` (empty = root) in `commit_id`: directories first, then by name.
/// `None` when `dir` does not exist or is not a directory.
pub fn tree(repo: &Path, commit_id: &str, dir: &str) -> Result<Option<Vec<TreeEntry>>, GitError> {
    let r = open(repo)?;
    let tree = if dir.is_empty() {
        let Ok(id) = r.rev_parse_single(commit_id) else { return Ok(None) };
        id.object().map_err(gix_err)?.peel_to_commit().map_err(gix_err)?.tree().map_err(gix_err)?
    } else {
        let Ok(id) = r.rev_parse_single(format!("{commit_id}:{dir}").as_str()) else { return Ok(None) };
        let object = id.object().map_err(gix_err)?;
        if object.kind != gix::object::Kind::Tree {
            return Ok(None);
        }
        object.into_tree()
    };
    let mut entries = Vec::new();
    for entry in tree.iter() {
        let entry = entry.map_err(gix_err)?;
        let mode = entry.mode();
        let kind = if mode.is_tree() {
            EntryKind::Tree
        } else if mode.is_link() {
            EntryKind::Symlink
        } else if mode.is_commit() {
            EntryKind::Submodule
        } else {
            EntryKind::Blob
        };
        entries.push(TreeEntry { name: entry.filename().to_string(), kind });
    }
    entries.sort_by(|a, b| (a.kind != EntryKind::Tree).cmp(&(b.kind != EntryKind::Tree)).then_with(|| a.name.cmp(&b.name)));
    Ok(Some(entries))
}

/// Bytes of file `file` in `commit_id`; `None` when it is missing or not a file.
pub fn blob_bytes(repo: &Path, commit_id: &str, file: &str) -> Result<Option<Vec<u8>>, GitError> {
    if file.is_empty() {
        return Ok(None);
    }
    let r = open(repo)?;
    let Ok(id) = r.rev_parse_single(format!("{commit_id}:{file}").as_str()) else { return Ok(None) };
    let object = id.object().map_err(gix_err)?;
    if object.kind != gix::object::Kind::Blob {
        return Ok(None);
    }
    Ok(Some(object.detach().data))
}

/// Text when the first 8000 bytes contain no NUL and the whole blob is UTF-8.
pub fn classify(bytes: Vec<u8>) -> Blob {
    if bytes[..bytes.len().min(8000)].contains(&0) {
        return Blob::Binary;
    }
    String::from_utf8(bytes).map(Blob::Text).unwrap_or(Blob::Binary)
}

/// Up to `limit` commits reachable from `commit_id`, newest first (by commit time), after skipping `skip`.
pub fn log(repo: &Path, commit_id: &str, skip: usize, limit: usize) -> Result<Vec<CommitInfo>, GitError> {
    let r = open(repo)?;
    let start = r.rev_parse_single(commit_id).map_err(gix_err)?.detach();
    let walk = r
        .rev_walk([start])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(Default::default()))
        .all()
        .map_err(gix_err)?;
    let mut commits = Vec::new();
    for info in walk.skip(skip).take(limit) {
        let commit = info.map_err(gix_err)?.object().map_err(gix_err)?;
        commits.push(commit_info(&commit)?);
    }
    Ok(commits)
}

/// The commit with full object id `id`; `None` for anything else.
pub fn commit(repo: &Path, id: &str) -> Result<Option<CommitInfo>, GitError> {
    if !is_object_id(id) {
        return Ok(None);
    }
    let r = open(repo)?;
    let Ok(found) = r.rev_parse_single(id) else { return Ok(None) };
    let Ok(object) = found.object() else { return Ok(None) };
    let Ok(commit) = object.try_into_commit() else { return Ok(None) };
    Ok(Some(commit_info(&commit)?))
}

fn commit_info(commit: &gix::Commit<'_>) -> Result<CommitInfo, GitError> {
    let author = commit.author().map_err(gix_err)?;
    Ok(CommitInfo {
        id: commit.id.to_string(),
        summary: commit.message().map_err(gix_err)?.summary().to_string(),
        message: commit.message_raw().map_err(gix_err)?.to_string(),
        author_name: author.name.to_string(),
        author_email: author.email.to_string(),
        author_time: author.time().map_err(gix_err)?.seconds,
        parents: commit.parent_ids().map(|id| id.to_string()).collect(),
    })
}
```

Run: `cargo test -p starforged-git read`
Expected: 5 passed.

- [ ] **Step 4: Add the core content service**

`crates/starforged-core/src/content.rs`:

```rust
//! Repository content for viewers who passed a permission check (they hold a `RepoAccess`).

use starforged_git::GitError;
use starforged_git::read::{self, CommitInfo, Resolved, TreeEntry};

use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// Largest file the web UI renders inline.
pub const MAX_INLINE_BLOB_BYTES: usize = 1024 * 1024;

async fn blocking<T, F>(f: F) -> CoreResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, GitError> + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(|e| CoreError::Internal(e.to_string()))?.map_err(CoreError::from)
}

impl Core {
    pub async fn branches(&self, access: &RepoAccess) -> CoreResult<Vec<String>> {
        let repo = self.repo_path(access.repo.id);
        blocking(move || read::branches(&repo)).await
    }

    /// Resolves a `<ref>/<path>` URL suffix; `NotFound` when no branch, tag, or commit matches.
    pub async fn resolve(&self, access: &RepoAccess, rest: &str) -> CoreResult<Resolved> {
        let repo = self.repo_path(access.repo.id);
        let rest = rest.to_owned();
        blocking(move || read::resolve(&repo, &rest)).await?.ok_or(CoreError::NotFound)
    }

    pub async fn tree(&self, access: &RepoAccess, commit_id: &str, dir: &str) -> CoreResult<Vec<TreeEntry>> {
        let repo = self.repo_path(access.repo.id);
        let (commit_id, dir) = (commit_id.to_owned(), dir.to_owned());
        blocking(move || read::tree(&repo, &commit_id, &dir)).await?.ok_or(CoreError::NotFound)
    }

    pub async fn blob(&self, access: &RepoAccess, commit_id: &str, file: &str) -> CoreResult<Vec<u8>> {
        let repo = self.repo_path(access.repo.id);
        let (commit_id, file) = (commit_id.to_owned(), file.to_owned());
        blocking(move || read::blob_bytes(&repo, &commit_id, &file)).await?.ok_or(CoreError::NotFound)
    }

    pub async fn log(&self, access: &RepoAccess, commit_id: &str, skip: usize, limit: usize) -> CoreResult<Vec<CommitInfo>> {
        let repo = self.repo_path(access.repo.id);
        let commit_id = commit_id.to_owned();
        blocking(move || read::log(&repo, &commit_id, skip, limit)).await
    }

    pub async fn commit(&self, access: &RepoAccess, id: &str) -> CoreResult<CommitInfo> {
        let repo = self.repo_path(access.repo.id);
        let id = id.to_owned();
        blocking(move || read::commit(&repo, &id)).await?.ok_or(CoreError::NotFound)
    }
}
```

Add `pub mod content;` to `crates/starforged-core/src/lib.rs`.

- [ ] **Step 5: Write the failing web unit tests**

Add to `crates/starforged-web/Cargo.toml` `[dependencies]`:

```toml
ammonia.workspace = true
comrak.workspace = true
```

`crates/starforged-web/src/markdown.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_loses_scripts_and_javascript_links() {
        let html = render("# Hi\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1)) **b**\n\n| a |\n|---|\n| 1 |\n");
        assert!(html.contains("<h1>Hi</h1>"), "{html}");
        assert!(html.contains("<strong>b</strong>"), "{html}");
        assert!(html.contains("<table>"), "{html}");
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("javascript:"), "{html}");
    }

    #[test]
    fn plain_text_is_escaped() {
        assert_eq!(plain("<b>&"), "<pre>&lt;b&gt;&amp;</pre>");
    }
}
```

Append to the test module in `crates/starforged-web/src/views.rs`:

```rust
    #[test]
    fn content_hrefs_encode_each_segment() {
        assert_eq!(content_href("alice", "proj", "blob", "feature/x", "docs/a b.txt"), "/alice/proj/blob/feature/x/docs/a%20b.txt");
        assert_eq!(content_href("alice", "proj", "tree", "main", ""), "/alice/proj/tree/main");
        assert_eq!(encode_path("a#b/c?d"), "a%23b/c%3Fd");
        let hrefs: Vec<String> = crumbs("alice", "proj", "main", "src/bin").into_iter().map(|c| c.href).collect();
        assert_eq!(hrefs, vec!["/alice/proj/tree/main/src", "/alice/proj/tree/main/src/bin"]);
    }
```

Add `pub mod markdown;` to `crates/starforged-web/src/lib.rs`.

Run: `cargo test -p starforged-web`
Expected: compile errors (`render`, `content_href` missing).

- [ ] **Step 6: Implement `markdown.rs` and the path helpers**

Insert at the top of `crates/starforged-web/src/markdown.rs`:

```rust
//! Untrusted Markdown to safe HTML (spec §11.1): comrak with raw HTML disabled, then ammonia.

pub fn render(markdown: &str) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    ammonia::clean(&comrak::markdown_to_html(markdown, &options))
}

/// Plain text as escaped, preformatted HTML.
pub fn plain(text: &str) -> String {
    format!("<pre>{}</pre>", ammonia::clean_text(text))
}
```

Add to `crates/starforged-web/src/views.rs`, below the existing items and above the test module:

```rust
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

/// Characters percent-encoded inside a single URL path segment.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\');

/// Percent-encodes each `/`-separated segment of `path`, dropping empty segments.
pub fn encode_path(path: &str) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| utf8_percent_encode(s, SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// `/{owner}/{repo}/{kind}/{ref}[/{path}]`, every ref and path segment encoded.
pub fn content_href(owner: &str, repo: &str, kind: &str, ref_name: &str, path: &str) -> String {
    let mut href = format!("/{owner}/{repo}/{kind}/{}", encode_path(ref_name));
    let encoded = encode_path(path);
    if !encoded.is_empty() {
        href.push('/');
        href.push_str(&encoded);
    }
    href
}

pub struct Crumb {
    pub name: String,
    pub href: String,
}

/// One tree link per directory level of `dir`.
pub fn crumbs(owner: &str, repo: &str, ref_name: &str, dir: &str) -> Vec<Crumb> {
    let mut out = Vec::new();
    let mut prefix = String::new();
    for segment in dir.split('/').filter(|s| !s.is_empty()) {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(segment);
        out.push(Crumb { name: segment.to_owned(), href: content_href(owner, repo, "tree", ref_name, &prefix) });
    }
    out
}
```

Run: `cargo test -p starforged-web`
Expected: 8 passed.

- [ ] **Step 7: Write the failing browsing tests**

`crates/starforged/tests/web_code.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browsing_trees_files_raw_and_readme() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url("alice", "proj", Some(&s.token(&alice, &[Scope::RepoWrite]).await));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[("README.md", "# Hello\n\n<script>alert(1)</script>\n"), ("src/main.rs", "fn main() {}\n"), ("docs/a b.txt", "spaced\n")],
    )
    .await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("feature.txt", b"on the branch\n")], "feature work").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
    let client = s.browser();

    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(home.contains("<h1>Hello</h1>"), "{home}");
    assert!(!home.contains("<script>alert"), "README HTML is sanitized");
    assert!(home.contains(r#"<a href="/alice/proj/tree/main/src">src</a>"#), "{home}");
    assert!(home.contains(r#"<a href="/alice/proj/blob/main/README.md">README.md</a>"#), "{home}");
    assert!(!home.contains("feature.txt"), "the home page shows the default branch");

    let docs = get_text(&client, &s.url("/alice/proj/tree/feature/x/docs")).await;
    assert!(docs.contains(r#"href="/alice/proj/blob/feature/x/docs/a%20b.txt""#), "{docs}");
    assert!(get_text(&client, &s.url("/alice/proj/tree/feature/x")).await.contains("feature.txt"));

    let file = get_text(&client, &s.url("/alice/proj/blob/main/src/main.rs")).await;
    assert!(file.contains("<pre>fn main() {}</pre>"), "{file}");
    assert!(file.contains(r#"href="/alice/proj/raw/main/src/main.rs""#), "{file}");

    let raw = client.get(s.url("/alice/proj/raw/main/src/main.rs")).send().await.unwrap();
    assert_eq!(raw.headers()["content-type"], "text/plain; charset=utf-8");
    assert_eq!(raw.headers()["content-security-policy"], "sandbox");
    assert_eq!(raw.text().await.unwrap(), "fn main() {}\n");

    for missing in ["/alice/proj/blob/main/missing.rs", "/alice/proj/tree/nope", "/alice/proj/tree/main/README.md"] {
        assert_eq!(client.get(s.url(missing)).send().await.unwrap().status(), 404, "{missing}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_and_empty_repositories() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "hidden", Visibility::Private).await;
    s.repo(&alice, "empty", Visibility::Public).await;
    let client = s.browser();
    assert_eq!(client.get(s.url("/alice/hidden")).send().await.unwrap().status(), 404);
    let empty = get_text(&client, &s.url("/alice/empty")).await;
    assert!(empty.contains("This repository is empty"));
    assert!(empty.contains(&format!("git remote add origin {}/alice/empty.git", s.base)));
    assert!(!empty.contains("Collaborators"), "only admins see the settings tab");
    let (owner, _) = s.login("alice").await;
    assert!(get_text(&owner, &s.url("/alice/hidden")).await.contains("Collaborators"));
}
```

Run: `cargo test -p starforged --test web_code`
Expected: FAIL — `/alice/proj` returns 404.

- [ ] **Step 8: Implement the code pages**

`crates/starforged-web/src/pages/code.rs`:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use starforged_core::content::MAX_INLINE_BLOB_BYTES;
use starforged_core::permission::Permission;
use starforged_core::repos::RepoAccess;
use starforged_core::sessions::WebSession;
use starforged_git::read::{Blob, EntryKind, TreeEntry, classify};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::markdown;
use crate::views::{Crumb, NavUser, content_href, crumbs, encode_path, nav};

const README_NAMES: [&str; 3] = ["readme.md", "readme.markdown", "readme"];

pub struct EntryRow {
    name: String,
    /// Empty for submodules, which have nothing to browse.
    href: String,
    is_dir: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "tree.html")]
pub struct TreePage {
    nav_user: Option<NavUser>,
    owner: String,
    name: String,
    description: String,
    visibility: &'static str,
    clone_url: String,
    can_admin: bool,
    empty: bool,
    ref_name: String,
    commits_href: String,
    crumbs: Vec<Crumb>,
    entries: Vec<EntryRow>,
    readme_html: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "blob.html")]
pub struct BlobPage {
    nav_user: Option<NavUser>,
    owner: String,
    name: String,
    ref_name: String,
    path: String,
    file_name: String,
    crumbs: Vec<Crumb>,
    raw_href: String,
    size: usize,
    lines: Vec<String>,
    notice: Option<&'static str>,
}

/// `/{owner}/{repo}`: the default branch's root directory, or push instructions for an empty repository.
pub async fn repo_home(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Response, WebError> {
    let access = state.core.repo_for(session.as_ref().map(|s| &s.user), &owner, &repo).await?;
    let branches = state.core.branches(&access).await?;
    let default = if branches.contains(&access.repo.default_branch) {
        Some(access.repo.default_branch.clone())
    } else {
        branches.first().cloned()
    };
    let Some(default) = default else {
        return Ok(tree_page(&state, session.as_ref(), &access, None, "", Vec::new(), None).into_response());
    };
    let resolved = state.core.resolve(&access, &default).await?;
    render_tree(&state, session.as_ref(), &access, &resolved.ref_name, &resolved.commit_id, "").await
}

pub async fn tree(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<Response, WebError> {
    let access = state.core.repo_for(session.as_ref().map(|s| &s.user), &owner, &repo).await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    render_tree(&state, session.as_ref(), &access, &resolved.ref_name, &resolved.commit_id, &resolved.path).await
}

pub async fn blob(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<BlobPage, WebError> {
    let access = state.core.repo_for(session.as_ref().map(|s| &s.user), &owner, &repo).await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    let bytes = state.core.blob(&access, &resolved.commit_id, &resolved.path).await?;
    let size = bytes.len();
    let (lines, notice) = if size > MAX_INLINE_BLOB_BYTES {
        (Vec::new(), Some("This file is too large to display."))
    } else {
        match classify(bytes) {
            Blob::Text(text) => (text.lines().map(str::to_owned).collect(), None),
            Blob::Binary => (Vec::new(), Some("Binary file not shown.")),
        }
    };
    let repo = &access.repo;
    let (dir, file_name) = resolved.path.rsplit_once('/').unwrap_or(("", resolved.path.as_str()));
    Ok(BlobPage {
        nav_user: nav(session.as_ref()),
        owner: repo.owner.clone(),
        name: repo.name.clone(),
        ref_name: resolved.ref_name.clone(),
        crumbs: crumbs(&repo.owner, &repo.name, &resolved.ref_name, dir),
        file_name: file_name.to_owned(),
        raw_href: content_href(&repo.owner, &repo.name, "raw", &resolved.ref_name, &resolved.path),
        path: resolved.path.clone(),
        size,
        lines,
        notice,
    })
}

/// Raw file bytes: plain text or an attachment, inside a CSP sandbox, never rendered as HTML (spec §11.1).
pub async fn raw(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<Response, WebError> {
    let access = state.core.repo_for(session.as_ref().map(|s| &s.user), &owner, &repo).await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    let bytes = state.core.blob(&access, &resolved.commit_id, &resolved.path).await?;
    let is_text = !bytes[..bytes.len().min(8000)].contains(&0) && std::str::from_utf8(&bytes).is_ok();
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    if is_text {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    } else {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    }
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox"));
    Ok(response)
}

async fn render_tree(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    ref_name: &str,
    commit_id: &str,
    dir: &str,
) -> Result<Response, WebError> {
    let entries = state.core.tree(access, commit_id, dir).await?;
    let readme_html = readme(state, access, commit_id, dir, &entries).await?;
    let repo = &access.repo;
    let rows = entries
        .into_iter()
        .map(|entry| {
            let child = if dir.is_empty() { entry.name.clone() } else { format!("{dir}/{}", entry.name) };
            let href = match entry.kind {
                EntryKind::Tree => content_href(&repo.owner, &repo.name, "tree", ref_name, &child),
                EntryKind::Blob | EntryKind::Symlink => content_href(&repo.owner, &repo.name, "blob", ref_name, &child),
                EntryKind::Submodule => String::new(),
            };
            EntryRow { is_dir: entry.kind == EntryKind::Tree, href, name: entry.name }
        })
        .collect();
    Ok(tree_page(state, session, access, Some(ref_name), dir, rows, readme_html).into_response())
}

fn tree_page(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    ref_name: Option<&str>,
    dir: &str,
    entries: Vec<EntryRow>,
    readme_html: Option<String>,
) -> TreePage {
    let repo = &access.repo;
    let ref_name = ref_name.unwrap_or_default();
    TreePage {
        nav_user: nav(session),
        owner: repo.owner.clone(),
        name: repo.name.clone(),
        description: repo.description.clone(),
        visibility: repo.visibility.as_str(),
        clone_url: format!("{}/{}/{}.git", state.settings.base_url, repo.owner, repo.name),
        can_admin: access.permission >= Permission::Admin,
        empty: ref_name.is_empty(),
        ref_name: ref_name.to_owned(),
        commits_href: format!("/{}/{}/commits/{}", repo.owner, repo.name, encode_path(ref_name)),
        crumbs: crumbs(&repo.owner, &repo.name, ref_name, dir),
        entries,
        readme_html,
    }
}

/// Rendered README of `dir`, if it has one that is text and at most `MAX_INLINE_BLOB_BYTES`.
async fn readme(
    state: &AppState,
    access: &RepoAccess,
    commit_id: &str,
    dir: &str,
    entries: &[TreeEntry],
) -> Result<Option<String>, WebError> {
    let found = README_NAMES
        .iter()
        .find_map(|wanted| entries.iter().find(|e| e.kind == EntryKind::Blob && e.name.to_ascii_lowercase() == *wanted));
    let Some(entry) = found else { return Ok(None) };
    let file = if dir.is_empty() { entry.name.clone() } else { format!("{dir}/{}", entry.name) };
    let bytes = state.core.blob(access, commit_id, &file).await?;
    if bytes.len() > MAX_INLINE_BLOB_BYTES {
        return Ok(None);
    }
    let lower = entry.name.to_ascii_lowercase();
    Ok(match classify(bytes) {
        Blob::Text(text) if lower.ends_with(".md") || lower.ends_with(".markdown") => Some(markdown::render(&text)),
        Blob::Text(text) => Some(markdown::plain(&text)),
        Blob::Binary => None,
    })
}
```

`crates/starforged-web/templates/tree.html`:

```html
{% extends "base.html" %}
{% block title %}{{ owner }}/{{ name }} · Starforge{% endblock %}
{% block content %}
<div class="repo-head">
<h1><a href="/{{ owner }}">{{ owner }}</a> / <a href="/{{ owner }}/{{ name }}">{{ name }}</a> <span class="badge">{{ visibility }}</span></h1>
{% if !description.is_empty() %}<p class="muted">{{ description }}</p>{% endif %}
<nav class="tabs">
<a href="/{{ owner }}/{{ name }}">Code</a>
{% if !empty %}<a href="{{ commits_href }}">Commits</a>{% endif %}
{% if can_admin %}<a href="/{{ owner }}/{{ name }}/settings/collaborators">Collaborators</a>{% endif %}
</nav>
<p>Clone with <code>git clone {{ clone_url }}</code></p>
</div>
{% if empty %}
<p>This repository is empty. Push an existing repository to it:</p>
<pre>git remote add origin {{ clone_url }}
git push -u origin main</pre>
{% else %}
<p class="crumbs"><span class="badge">{{ ref_name }}</span>{% for c in crumbs %} / <a href="{{ c.href }}">{{ c.name }}</a>{% endfor %}</p>
<table class="list files"><tbody>
{% for e in entries %}
<tr><td class="{% if e.is_dir %}dir{% else %}file{% endif %}">{% if e.href.is_empty() %}{{ e.name }}{% else %}<a href="{{ e.href }}">{{ e.name }}</a>{% endif %}</td></tr>
{% endfor %}
</tbody></table>
{% if let Some(html) = readme_html %}<article class="readme">{{ html|safe }}</article>{% endif %}
{% endif %}
{% endblock %}
```

`crates/starforged-web/templates/blob.html`:

```html
{% extends "base.html" %}
{% block title %}{{ path }} · {{ owner }}/{{ name }}{% endblock %}
{% block content %}
<h1><a href="/{{ owner }}">{{ owner }}</a> / <a href="/{{ owner }}/{{ name }}">{{ name }}</a></h1>
<p class="crumbs"><span class="badge">{{ ref_name }}</span>{% for c in crumbs %} / <a href="{{ c.href }}">{{ c.name }}</a>{% endfor %} / {{ file_name }} · <a href="{{ raw_href }}">Raw</a> · {{ size }} bytes</p>
{% if let Some(n) = notice %}
<p class="muted">{{ n }}</p>
{% else %}
<table class="code"><tbody>
{% for line in lines %}<tr><td class="ln">{{ loop.index }}</td><td><pre>{{ line }}</pre></td></tr>
{% endfor %}
</tbody></table>
{% endif %}
{% endblock %}
```

Add `pub mod code;` to `crates/starforged-web/src/pages/mod.rs` and these routes to `page_routes` in `crates/starforged-web/src/lib.rs`:

```rust
        .route("/{owner}/{repo}", get(pages::code::repo_home))
        .route("/{owner}/{repo}/tree/{*rest}", get(pages::code::tree))
        .route("/{owner}/{repo}/blob/{*rest}", get(pages::code::blob))
        .route("/{owner}/{repo}/raw/{*rest}", get(pages::code::raw))
```

- [ ] **Step 9: Run the browsing tests**

Run: `cargo test -p starforged --test web_code`
Expected: 2 passed.

- [ ] **Step 10: Full suite, lint, format, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates Cargo.lock
git commit -m "feat: browse repositories — trees, files, raw content, and README rendering"
```

---

### Task 12: Commit history and diffs

**Files:**
- Create: `crates/starforged-git/src/diff.rs`; Modify: `crates/starforged-git/src/lib.rs` (add `pub mod diff;`)
- Modify: `crates/starforged-core/src/content.rs` (add `diff`)
- Create: `crates/starforged-web/src/pages/history.rs`, `crates/starforged-web/templates/commits.html`, `crates/starforged-web/templates/commit.html`; Modify: `crates/starforged-web/src/pages/mod.rs`, `crates/starforged-web/src/lib.rs`
- Test: unit tests in `diff.rs`; `crates/starforged/tests/web_history.rs`

**Interfaces:**
- Consumes: `command::run`, `GitError` (Task 5); `Core::{repo_for, resolve, log, commit}`, `read::CommitInfo` (Task 11); `MaybeUser`, `nav`, `format_time`, `encode_path` (Tasks 8, 11).
- Produces:
  - `starforged_git::diff::{FileStatus, LineKind, DiffLine { kind, old_line, new_line, text }, Hunk { header, lines }, FileDiff { old_path, new_path, status, binary, hunks }, CommitDiff { files, truncated }, parse(text, max_lines) -> CommitDiff, commit_diff(repo, commit_id, max_lines) -> Result<CommitDiff, GitError>}`; `FileDiff::display_path()`.
  - `starforged_core::content::MAX_DIFF_LINES` (10 000); `Core::diff(&RepoAccess, commit_id) -> CoreResult<CommitDiff>`.
  - Routes: `GET /{owner}/{repo}/commits/{*ref}` (50 per page, `?page=N`) and `GET /{owner}/{repo}/commit/{id}` (full object id only).

- [ ] **Step 1: Write the failing diff tests**

Add `pub mod diff;` to `crates/starforged-git/src/lib.rs`.

`crates/starforged-git/src/diff.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,3 @@
 fn a() {}
-fn b() {}
+fn b() -> u8 { 1 }
 fn c() {}
diff --git a/docs/a b.txt b/docs/a b.txt
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/docs/a b.txt\t
@@ -0,0 +1 @@
+hello
\\ No newline at end of file
diff --git a/old.txt b/old.txt
deleted file mode 100644
index 4444444..0000000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
--- not a header
diff --git a/a.txt b/c.txt
similarity index 100%
rename from a.txt
rename to c.txt
diff --git a/img.png b/img.png
new file mode 100644
index 0000000..5555555
Binary files /dev/null and b/img.png differ
";

    #[test]
    fn parses_every_kind_of_file_change() {
        let diff = parse(SAMPLE, 1000);
        assert!(!diff.truncated);
        let summary: Vec<(FileStatus, &str, bool)> =
            diff.files.iter().map(|f| (f.status, f.display_path(), f.binary)).collect();
        assert_eq!(
            summary,
            vec![
                (FileStatus::Modified, "src/lib.rs", false),
                (FileStatus::Added, "docs/a b.txt", false),
                (FileStatus::Deleted, "old.txt", false),
                (FileStatus::Renamed, "c.txt", false),
                (FileStatus::Added, "img.png", true),
            ]
        );
        assert_eq!(diff.files[3].old_path.as_deref(), Some("a.txt"));
        assert_eq!(diff.files[2].new_path, None);

        let lines = &diff.files[0].hunks[0].lines;
        let shape: Vec<(LineKind, Option<u32>, Option<u32>, &str)> =
            lines.iter().map(|l| (l.kind, l.old_line, l.new_line, l.text.as_str())).collect();
        assert_eq!(
            shape,
            vec![
                (LineKind::Context, Some(1), Some(1), "fn a() {}"),
                (LineKind::Removed, Some(2), None, "fn b() {}"),
                (LineKind::Added, None, Some(2), "fn b() -> u8 { 1 }"),
                (LineKind::Context, Some(3), Some(3), "fn c() {}"),
            ]
        );
        let added = &diff.files[1].hunks[0].lines;
        assert_eq!((added[0].kind, added[0].new_line), (LineKind::Added, Some(1)));
        assert_eq!(added[1].kind, LineKind::NoNewline);
        let removed = &diff.files[2].hunks[0].lines;
        assert_eq!((removed[0].kind, removed[0].text.as_str()), (LineKind::Removed, "-- not a header"));
    }

    #[test]
    fn truncates_after_max_lines() {
        let diff = parse(SAMPLE, 2);
        assert!(diff.truncated);
        let total: usize = diff.files.iter().flat_map(|f| &f.hunks).map(|h| h.lines.len()).sum();
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn commit_diff_runs_git_and_refuses_non_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
                .args(args)
                .current_dir(p)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8(out.stdout).unwrap()
        };
        git(&["init", "-q", "-b", "main", "."]);
        std::fs::write(p.join("a.txt"), "one\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "root"]);
        std::fs::write(p.join("a.txt"), "one\ntwo\n").unwrap();
        git(&["commit", "-qam", "second"]);
        let head = git(&["rev-parse", "HEAD"]).trim().to_owned();
        let root = git(&["rev-parse", "HEAD~1"]).trim().to_owned();
        let repo = p.join(".git");

        let second = commit_diff(&repo, &head, 100).await.unwrap();
        assert_eq!(second.files[0].status, FileStatus::Modified);
        assert_eq!(second.files[0].hunks[0].lines.last().unwrap().text, "two");
        let first = commit_diff(&repo, &root, 100).await.unwrap();
        assert_eq!(first.files[0].status, FileStatus::Added);
        assert!(commit_diff(&repo, "--output=/tmp/x", 100).await.is_err());
    }
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-git diff`
Expected: compile errors.

- [ ] **Step 3: Implement `diff.rs`**

Insert at the top of `crates/starforged-git/src/diff.rs`:

```rust
//! Commit diffs via `git show` (rename detection; merges diff against their first parent) and a
//! unified-diff parser for rendering.

use std::ffi::OsStr;
use std::path::Path;

use crate::command::{GitError, run};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    Added,
    Deleted,
    Modified,
    Renamed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Context,
    Added,
    Removed,
    NoNewline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: LineKind,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
    /// The line without its leading `+`, `-`, or space.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub header: String,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub status: FileStatus,
    pub binary: bool,
    pub hunks: Vec<Hunk>,
}

impl FileDiff {
    pub fn display_path(&self) -> &str {
        self.new_path.as_deref().or(self.old_path.as_deref()).unwrap_or("")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitDiff {
    pub files: Vec<FileDiff>,
    /// More than `max_lines` diff lines existed; the rest were dropped.
    pub truncated: bool,
}

/// Diff of `commit_id` against its first parent (or the empty tree for a root commit).
pub async fn commit_diff(repo: &Path, commit_id: &str, max_lines: usize) -> Result<CommitDiff, GitError> {
    if commit_id.is_empty() || !commit_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(GitError::Failed { command: "show".into(), stderr: format!("not an object id: {commit_id}") });
    }
    let out = run([
        OsStr::new("-c"),
        OsStr::new("core.quotePath=false"),
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("show"),
        OsStr::new("--format="),
        OsStr::new("--patch"),
        OsStr::new("--find-renames"),
        OsStr::new("--diff-merges=first-parent"),
        OsStr::new("--no-color"),
        OsStr::new("--no-ext-diff"),
        OsStr::new("--no-textconv"),
        OsStr::new(commit_id),
    ])
    .await?;
    Ok(parse(&String::from_utf8_lossy(&out), max_lines))
}

/// Parses `git diff`/`git show` patch output, keeping at most `max_lines` diff lines.
pub fn parse(text: &str, max_lines: usize) -> CommitDiff {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut kept = 0_usize;
    let mut truncated = false;
    let (mut old_no, mut new_no) = (0_u32, 0_u32);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let (old, new) = split_diff_git(rest);
            files.push(FileDiff { old_path: Some(old), new_path: Some(new), status: FileStatus::Modified, binary: false, hunks: Vec::new() });
            continue;
        }
        let Some(file) = files.last_mut() else { continue };
        if file.hunks.is_empty() {
            if line.starts_with("new file mode") {
                file.status = FileStatus::Added;
                file.old_path = None;
                continue;
            }
            if line.starts_with("deleted file mode") {
                file.status = FileStatus::Deleted;
                file.new_path = None;
                continue;
            }
            if let Some(path) = line.strip_prefix("rename from ") {
                file.status = FileStatus::Renamed;
                file.old_path = Some(path.to_owned());
                continue;
            }
            if let Some(path) = line.strip_prefix("rename to ") {
                file.status = FileStatus::Renamed;
                file.new_path = Some(path.to_owned());
                continue;
            }
            if line.starts_with("Binary files ") {
                file.binary = true;
                continue;
            }
            if let Some(path) = line.strip_prefix("--- ") {
                if path != "/dev/null" {
                    file.old_path = Some(strip_side(path, "a/"));
                }
                continue;
            }
            if let Some(path) = line.strip_prefix("+++ ") {
                if path != "/dev/null" {
                    file.new_path = Some(strip_side(path, "b/"));
                }
                continue;
            }
        }
        if line.starts_with("@@ ") {
            (old_no, new_no) = hunk_starts(line);
            file.hunks.push(Hunk { header: line.to_owned(), lines: Vec::new() });
            continue;
        }
        let Some(hunk) = file.hunks.last_mut() else { continue };
        if kept >= max_lines {
            truncated = true;
            continue;
        }
        let (kind, old_line, new_line, body) = match line.as_bytes().first() {
            Some(b'+') => {
                new_no += 1;
                (LineKind::Added, None, Some(new_no - 1), &line[1..])
            }
            Some(b'-') => {
                old_no += 1;
                (LineKind::Removed, Some(old_no - 1), None, &line[1..])
            }
            Some(b' ') => {
                old_no += 1;
                new_no += 1;
                (LineKind::Context, Some(old_no - 1), Some(new_no - 1), &line[1..])
            }
            Some(b'\\') => (LineKind::NoNewline, None, None, line),
            _ => continue,
        };
        hunk.lines.push(DiffLine { kind, old_line, new_line, text: body.to_owned() });
        kept += 1;
    }
    CommitDiff { files, truncated }
}

/// `a/<old> b/<new>` → (old, new). Exact for paths without " b/"; `---`/`+++` lines refine it.
fn split_diff_git(rest: &str) -> (String, String) {
    match rest.rfind(" b/") {
        Some(at) => (strip_side(&rest[..at], "a/"), rest[at + 3..].to_owned()),
        None => (rest.to_owned(), rest.to_owned()),
    }
}

/// Drops the `a/`/`b/` prefix and the trailing tab git adds after paths containing spaces.
fn strip_side(path: &str, prefix: &str) -> String {
    path.strip_prefix(prefix).unwrap_or(path).trim_end_matches('\t').to_owned()
}

/// First old and new line numbers from `@@ -a,b +c,d @@`.
fn hunk_starts(header: &str) -> (u32, u32) {
    let mut old = 0;
    let mut new = 0;
    for part in header.split(' ').skip(1) {
        if let Some(range) = part.strip_prefix('-') {
            old = range.split(',').next().and_then(|n| n.parse().ok()).unwrap_or(0);
        } else if let Some(range) = part.strip_prefix('+') {
            new = range.split(',').next().and_then(|n| n.parse().ok()).unwrap_or(0);
            break;
        }
    }
    (old, new)
}
```

Run: `cargo test -p starforged-git diff`
Expected: 3 passed.

- [ ] **Step 4: Add `Core::diff`**

Append to `crates/starforged-core/src/content.rs` (and add `use starforged_git::diff::CommitDiff;` to its imports):

```rust
/// Diff lines rendered per commit before truncating.
pub const MAX_DIFF_LINES: usize = 10_000;

impl Core {
    /// The diff of commit `commit_id` against its first parent.
    pub async fn diff(&self, access: &RepoAccess, commit_id: &str) -> CoreResult<CommitDiff> {
        let repo = self.repo_path(access.repo.id);
        Ok(starforged_git::diff::commit_diff(&repo, commit_id, MAX_DIFF_LINES).await?)
    }
}
```

- [ ] **Step 5: Write the failing history tests**

`crates/starforged/tests/web_history.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_pages_and_commit_diffs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url("alice", "proj", Some(&s.token(&alice, &[Scope::RepoWrite]).await));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n"), ("b.txt", b"new file\n")], "second change").await;
    let change = git_ok(&work, &["rev-parse", "HEAD"]).await.trim().to_owned();
    for i in 0..55 {
        git_ok(&work, &["commit", "-q", "--allow-empty", "-m", &format!("empty {i}")]).await;
    }
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let client = s.browser();

    let first_page = get_text(&client, &s.url("/alice/proj/commits/main")).await;
    assert!(first_page.contains("empty 54"));
    assert!(first_page.contains(r#"href="?page=2""#));
    assert!(!first_page.contains("initial commit"));
    let second_page = get_text(&client, &s.url("/alice/proj/commits/main?page=2")).await;
    let newer = second_page.find("second change").expect("second change listed");
    let older = second_page.find("initial commit").expect("initial commit listed");
    assert!(newer < older, "newest first");
    assert!(second_page.contains(&format!(r#"href="/alice/proj/commit/{change}""#)));

    let diff = get_text(&client, &s.url(&format!("/alice/proj/commit/{change}"))).await;
    assert!(diff.contains("second change"));
    assert!(
        diff.contains(r#"<tr class="add"><td class="ln"></td><td class="ln">2</td><td><pre>two</pre></td></tr>"#),
        "{diff}"
    );
    assert!(diff.contains(r#"<span class="badge">added</span> b.txt"#), "{diff}");

    let zeros = "0".repeat(40);
    assert_eq!(client.get(s.url(&format!("/alice/proj/commit/{zeros}"))).send().await.unwrap().status(), 404);
    assert_eq!(client.get(s.url("/alice/proj/commit/HEAD")).send().await.unwrap().status(), 404);
    assert_eq!(client.get(s.url("/alice/proj/commits/main/a.txt")).send().await.unwrap().status(), 404);
}
```

Run: `cargo test -p starforged --test web_history`
Expected: FAIL — the history routes return 404 for everything.

- [ ] **Step 6: Implement the history pages**

`crates/starforged-web/src/pages/history.rs`:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use starforged_git::diff::{FileStatus, LineKind};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, format_time, nav};

pub const PER_PAGE: usize = 50;

#[derive(Deserialize)]
pub struct PageQuery {
    page: Option<usize>,
}

pub struct CommitRow {
    id: String,
    short_id: String,
    summary: String,
    author: String,
    when: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "commits.html")]
pub struct CommitsPage {
    nav_user: Option<NavUser>,
    owner: String,
    name: String,
    ref_name: String,
    commits: Vec<CommitRow>,
    page: usize,
    has_next: bool,
}

pub struct LineView {
    class: &'static str,
    old: String,
    new: String,
    text: String,
}

pub struct HunkView {
    header: String,
    lines: Vec<LineView>,
}

pub struct FileView {
    status: &'static str,
    path: String,
    binary: bool,
    hunks: Vec<HunkView>,
}

#[derive(Template, WebTemplate)]
#[template(path = "commit.html")]
pub struct CommitPage {
    nav_user: Option<NavUser>,
    owner: String,
    name: String,
    id: String,
    summary: String,
    body: String,
    author: String,
    when: String,
    parents: Vec<String>,
    files: Vec<FileView>,
    truncated: bool,
}

pub async fn commits(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
    Query(query): Query<PageQuery>,
) -> Result<CommitsPage, WebError> {
    let access = state.core.repo_for(session.as_ref().map(|s| &s.user), &owner, &repo).await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    if !resolved.path.is_empty() {
        return Err(WebError::NotFound);
    }
    let page = query.page.unwrap_or(1).max(1);
    let mut commits = state.core.log(&access, &resolved.commit_id, (page - 1).saturating_mul(PER_PAGE), PER_PAGE + 1).await?;
    let has_next = commits.len() > PER_PAGE;
    commits.truncate(PER_PAGE);
    Ok(CommitsPage {
        nav_user: nav(session.as_ref()),
        owner: access.repo.owner,
        name: access.repo.name,
        ref_name: resolved.ref_name,
        commits: commits
            .into_iter()
            .map(|c| CommitRow {
                short_id: c.short_id().to_owned(),
                author: c.author_name.clone(),
                when: format_time(c.author_time),
                summary: c.summary,
                id: c.id,
            })
            .collect(),
        page,
        has_next,
    })
}

pub async fn commit(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> Result<CommitPage, WebError> {
    let access = state.core.repo_for(session.as_ref().map(|s| &s.user), &owner, &repo).await?;
    let info = state.core.commit(&access, &id).await?;
    let diff = state.core.diff(&access, &info.id).await?;
    let files = diff
        .files
        .into_iter()
        .map(|file| FileView {
            status: match file.status {
                FileStatus::Added => "added",
                FileStatus::Deleted => "deleted",
                FileStatus::Modified => "modified",
                FileStatus::Renamed => "renamed",
            },
            path: match (file.status, &file.old_path) {
                (FileStatus::Renamed, Some(old)) => format!("{old} → {}", file.display_path()),
                _ => file.display_path().to_owned(),
            },
            binary: file.binary,
            hunks: file
                .hunks
                .into_iter()
                .map(|hunk| HunkView {
                    header: hunk.header,
                    lines: hunk
                        .lines
                        .into_iter()
                        .map(|line| LineView {
                            class: match line.kind {
                                LineKind::Context => "ctx",
                                LineKind::Added => "add",
                                LineKind::Removed => "del",
                                LineKind::NoNewline => "nonl",
                            },
                            old: line.old_line.map(|n| n.to_string()).unwrap_or_default(),
                            new: line.new_line.map(|n| n.to_string()).unwrap_or_default(),
                            text: line.text,
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect();
    let body = info.message.split_once('\n').map(|(_, rest)| rest.trim().to_owned()).unwrap_or_default();
    Ok(CommitPage {
        nav_user: nav(session.as_ref()),
        owner: access.repo.owner,
        name: access.repo.name,
        summary: info.summary,
        body,
        author: info.author_name,
        when: format_time(info.author_time),
        parents: info.parents,
        id: info.id,
        files,
        truncated: diff.truncated,
    })
}
```

`crates/starforged-web/templates/commits.html`:

```html
{% extends "base.html" %}
{% block title %}Commits · {{ owner }}/{{ name }}{% endblock %}
{% block content %}
<h1><a href="/{{ owner }}">{{ owner }}</a> / <a href="/{{ owner }}/{{ name }}">{{ name }}</a> · Commits on <span class="badge">{{ ref_name }}</span></h1>
<ol class="commits">
{% for c in commits %}
<li><a href="/{{ owner }}/{{ name }}/commit/{{ c.id }}"><code>{{ c.short_id }}</code></a> {{ c.summary }} <span class="muted">{{ c.author }} · {{ c.when }}</span></li>
{% endfor %}
</ol>
<p class="pager">{% if page > 1 %}<a href="?page={{ page - 1 }}">Newer</a> {% endif %}{% if has_next %}<a href="?page={{ page + 1 }}">Older</a>{% endif %}</p>
{% endblock %}
```

`crates/starforged-web/templates/commit.html`:

```html
{% extends "base.html" %}
{% block title %}{{ summary }} · {{ owner }}/{{ name }}{% endblock %}
{% block content %}
<h1><a href="/{{ owner }}">{{ owner }}</a> / <a href="/{{ owner }}/{{ name }}">{{ name }}</a></h1>
<h2>{{ summary }}</h2>
{% if !body.is_empty() %}<pre class="message">{{ body }}</pre>{% endif %}
<p class="muted">{{ author }} · {{ when }} · <code>{{ id }}</code>{% for p in parents %} · parent <a href="/{{ owner }}/{{ name }}/commit/{{ p }}"><code>{{ p }}</code></a>{% endfor %}</p>
{% if truncated %}<p class="notice">This diff is large; only the first lines are shown.</p>{% endif %}
{% for f in files %}
<section class="file">
<h3><span class="badge">{{ f.status }}</span> {{ f.path }}</h3>
{% if f.binary %}
<p class="muted">Binary file</p>
{% else %}
<table class="diff"><tbody>
{% for h in f.hunks %}
<tr class="hunk"><td colspan="3">{{ h.header }}</td></tr>
{% for l in h.lines %}<tr class="{{ l.class }}"><td class="ln">{{ l.old }}</td><td class="ln">{{ l.new }}</td><td><pre>{{ l.text }}</pre></td></tr>
{% endfor %}
{% endfor %}
</tbody></table>
{% endif %}
</section>
{% endfor %}
{% endblock %}
```

Add `pub mod history;` to `crates/starforged-web/src/pages/mod.rs` and these routes to `page_routes`:

```rust
        .route("/{owner}/{repo}/commits/{*rest}", get(pages::history::commits))
        .route("/{owner}/{repo}/commit/{id}", get(pages::history::commit))
```

- [ ] **Step 7: Run the history tests**

Run: `cargo test -p starforged --test web_history`
Expected: 1 passed.

- [ ] **Step 8: Full suite, lint, format, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates
git commit -m "feat: commit history and diff pages"
```

---

### Task 13: REST API — `/api/v1` user, repositories, collaborators

**Files:**
- Create: `crates/starforged-api/Cargo.toml`, `crates/starforged-api/src/lib.rs`, `crates/starforged-api/src/error.rs`, `crates/starforged-api/src/auth.rs`, `crates/starforged-api/src/user.rs`, `crates/starforged-api/src/repos.rs`
- Modify: `crates/starforged/src/serve.rs` (`build`), `crates/starforged/Cargo.toml`
- Test: `crates/starforged/tests/api.rs`

**Interfaces:**
- Consumes: `Core::{authenticate_token, create_repo, repo_for, collaborators, set_collaborator, remove_collaborator}`, `tokens::{grants, Scope}`, `Permission`, `Visibility`, `RepoAccess` (Tasks 4–5).
- Produces:
  - `starforged_api::{router(Core, base_url: String) -> axum::Router, ApiState}`; routes are relative and nested at `/api/v1` by `serve::build`.
  - `starforged_api::error::ApiError::{Unauthenticated, Forbidden(String), NotFound, Invalid(String), Conflict(String), Internal(String)}` → `{"error": {"code", "message"}}` with 401/403/404/422/409/500. 401 adds `WWW-Authenticate: Bearer`.
  - `starforged_api::auth::ApiAuth(Option<TokenAuth>)` with `require(Scope)` and `reader()`.
  - Endpoints:
    - `GET /user` → `{id, handle, display_name, is_admin}`.
    - `POST /user/repos` `{name, description?, visibility? = "private"}` → 201 + repository JSON (`repo:write`).
    - `GET /repos/{owner}/{repo}` → repository JSON `{id, owner, name, full_name, description, visibility, default_branch, clone_url, permission, created_at}`. Anonymous for readable repositories; a token needs `repo:read`.
    - `GET /repos/{owner}/{repo}/collaborators` → `[{handle, permission}]` (`repo:write`, repository admin).
    - `PUT /repos/{owner}/{repo}/collaborators/{handle}` `{permission}` → 204, and `DELETE` → 204 (same requirements).

- [ ] **Step 1: Write the failing API test**

Add to `crates/starforged/Cargo.toml` `[dev-dependencies]`:

```toml
serde_json.workspace = true
```

`crates/starforged/tests/api.rs`:

```rust
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_repositories_and_collaborators() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;
    let read = s.token(&alice, &[Scope::RepoRead]).await;
    let bob_read = s.token(&bob, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();
    let api = |path: &str| s.url(&format!("/api/v1{path}"));

    let anonymous = client.get(api("/user")).send().await.unwrap();
    assert_eq!(anonymous.status(), 401);
    assert_eq!(anonymous.headers()["www-authenticate"], "Bearer");
    assert_eq!(anonymous.json::<Value>().await.unwrap()["error"]["code"], "unauthenticated");
    assert_eq!(client.get(api("/user")).bearer_auth("sfp_bogus").send().await.unwrap().status(), 401);
    let me: Value = client.get(api("/user")).bearer_auth(&write).send().await.unwrap().json().await.unwrap();
    assert_eq!(me["handle"], "alice");

    let forbidden = client.post(api("/user/repos")).bearer_auth(&read).json(&json!({"name": "proj"})).send().await.unwrap();
    assert_eq!(forbidden.status(), 403);
    let created = client.post(api("/user/repos")).bearer_auth(&write).json(&json!({"name": "proj"})).send().await.unwrap();
    assert_eq!(created.status(), 201);
    let repo: Value = created.json().await.unwrap();
    assert_eq!(repo["full_name"], "alice/proj");
    assert_eq!(repo["visibility"], "private");
    assert_eq!(repo["permission"], "admin");
    assert_eq!(repo["clone_url"], format!("{}/alice/proj.git", s.base));
    let duplicate = client.post(api("/user/repos")).bearer_auth(&write).json(&json!({"name": "PROJ"})).send().await.unwrap();
    assert_eq!(duplicate.status(), 409);
    let malformed = client
        .post(api("/user/repos"))
        .bearer_auth(&write)
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 422);
    assert_eq!(malformed.json::<Value>().await.unwrap()["error"]["code"], "invalid");

    assert_eq!(client.get(api("/repos/alice/proj")).send().await.unwrap().status(), 404);
    assert_eq!(client.get(api("/repos/alice/proj")).bearer_auth(&bob_read).send().await.unwrap().status(), 404);

    let grant = client
        .put(api("/repos/alice/proj/collaborators/bob"))
        .bearer_auth(&write)
        .json(&json!({"permission": "triage"}))
        .send()
        .await
        .unwrap();
    assert_eq!(grant.status(), 204);
    let seen: Value = client.get(api("/repos/alice/proj")).bearer_auth(&bob_read).send().await.unwrap().json().await.unwrap();
    assert_eq!(seen["permission"], "triage");
    let list: Value = client.get(api("/repos/alice/proj/collaborators")).bearer_auth(&write).send().await.unwrap().json().await.unwrap();
    assert_eq!(list, json!([{"handle": "bob", "permission": "triage"}]));
    let bad_level = client
        .put(api("/repos/alice/proj/collaborators/bob"))
        .bearer_auth(&write)
        .json(&json!({"permission": "owner"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_level.status(), 422);
    assert_eq!(client.delete(api("/repos/alice/proj/collaborators/bob")).bearer_auth(&write).send().await.unwrap().status(), 204);
    assert_eq!(client.delete(api("/repos/alice/proj/collaborators/bob")).bearer_auth(&write).send().await.unwrap().status(), 404);

    let unknown = client.get(api("/nope")).send().await.unwrap();
    assert_eq!(unknown.status(), 404);
    assert_eq!(unknown.json::<Value>().await.unwrap()["error"]["code"], "not_found");
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p starforged --test api`
Expected: FAIL — `/api/v1/user` is not routed (the web router answers 404 with HTML).

- [ ] **Step 3: Create the API crate**

`crates/starforged-api/Cargo.toml`:

```toml
[package]
name = "starforged-api"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true

[dependencies]
axum.workspace = true
serde.workspace = true
serde_json.workspace = true
starforged-core = { path = "../starforged-core" }
tracing.workspace = true
```

`crates/starforged-api/src/lib.rs`:

```rust
//! starforged-api: the JSON REST API under `/api/v1` (spec §10.4). A thin layer over `starforged-core`.

pub mod auth;
pub mod error;
mod repos;
mod user;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post, put};
use starforged_core::Core;

use crate::error::ApiError;

#[derive(Clone)]
pub struct ApiState {
    pub core: Core,
    /// Public URL without a trailing slash, for `clone_url`.
    pub base_url: Arc<str>,
}

/// Routes relative to `/api/v1`; the caller nests them there.
pub fn router(core: Core, base_url: String) -> Router {
    Router::new()
        .route("/user", get(user::show))
        .route("/user/repos", post(repos::create))
        .route("/repos/{owner}/{repo}", get(repos::show))
        .route("/repos/{owner}/{repo}/collaborators", get(repos::list_collaborators))
        .route(
            "/repos/{owner}/{repo}/collaborators/{handle}",
            put(repos::set_collaborator).delete(repos::remove_collaborator),
        )
        .fallback(|| async { ApiError::NotFound })
        .with_state(ApiState { core, base_url: Arc::from(base_url) })
}
```

`crates/starforged-api/src/error.rs`:

```rust
//! The JSON error envelope: `{"error": {"code": "...", "message": "..."}}`.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use starforged_core::CoreError;

#[derive(Debug)]
pub enum ApiError {
    Unauthenticated,
    Forbidden(String),
    NotFound,
    Invalid(String),
    Conflict(String),
    Internal(String),
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> ApiError {
        match err {
            CoreError::NotFound => ApiError::NotFound,
            CoreError::Forbidden => ApiError::Forbidden("permission denied".into()),
            CoreError::Unauthenticated => ApiError::Unauthenticated,
            CoreError::Invalid(message) => ApiError::Invalid(message),
            CoreError::Conflict(message) => ApiError::Conflict(message),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated", "a valid token is required".to_owned()),
            ApiError::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_owned()),
            ApiError::Invalid(message) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid", message),
            ApiError::Conflict(message) => (StatusCode::CONFLICT, "conflict", message),
            ApiError::Internal(message) => {
                tracing::error!(error = %message, "api request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error".to_owned())
            }
        };
        let mut response = (status, Json(json!({ "error": { "code": code, "message": message } }))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
```

`crates/starforged-api/src/auth.rs`:

```rust
//! Bearer-token authentication.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use starforged_core::accounts::User;
use starforged_core::tokens::{self, Scope, TokenAuth};

use crate::ApiState;
use crate::error::ApiError;

/// The caller's token when `Authorization: Bearer …` was sent; a header with a bad token is rejected.
pub struct ApiAuth(pub Option<TokenAuth>);

impl FromRequestParts<ApiState> for ApiAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &ApiState) -> Result<Self, Self::Rejection> {
        let Some(value) = parts.headers.get(header::AUTHORIZATION) else { return Ok(ApiAuth(None)) };
        let token = value
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("token ")))
            .ok_or(ApiError::Unauthenticated)?;
        Ok(ApiAuth(Some(state.core.authenticate_token(token.trim()).await?)))
    }
}

impl ApiAuth {
    /// The authenticated caller, who must hold `scope`.
    pub fn require(&self, scope: Scope) -> Result<&TokenAuth, ApiError> {
        let auth = self.0.as_ref().ok_or(ApiError::Unauthenticated)?;
        if tokens::grants(&auth.scopes, scope) {
            Ok(auth)
        } else {
            Err(ApiError::Forbidden(format!("this token lacks the {} scope", scope.as_str())))
        }
    }

    /// For read endpoints: anonymous callers are fine, but a token must carry `repo:read`.
    pub fn reader(&self) -> Result<Option<&User>, ApiError> {
        match &self.0 {
            None => Ok(None),
            Some(_) => Ok(Some(&self.require(Scope::RepoRead)?.user)),
        }
    }
}
```

`crates/starforged-api/src/user.rs`:

```rust
use axum::Json;
use serde::Serialize;

use crate::auth::ApiAuth;
use crate::error::ApiError;

#[derive(Serialize)]
pub struct UserJson {
    id: i64,
    handle: String,
    display_name: String,
    is_admin: bool,
}

pub async fn show(auth: ApiAuth) -> Result<Json<UserJson>, ApiError> {
    let auth = auth.0.ok_or(ApiError::Unauthenticated)?;
    let user = auth.user;
    Ok(Json(UserJson { id: user.id, handle: user.handle, display_name: user.display_name, is_admin: user.is_admin }))
}
```

`crates/starforged-api/src/repos.rs`:

```rust
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::{CreateRepo, RepoAccess};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;

#[derive(Serialize)]
pub struct RepoJson {
    id: i64,
    owner: String,
    name: String,
    full_name: String,
    description: String,
    visibility: &'static str,
    default_branch: String,
    clone_url: String,
    permission: &'static str,
    created_at: i64,
}

fn repo_json(state: &ApiState, access: RepoAccess) -> RepoJson {
    let repo = access.repo;
    RepoJson {
        clone_url: format!("{}/{}/{}.git", state.base_url, repo.owner, repo.name),
        full_name: repo.full_name(),
        id: repo.id,
        description: repo.description,
        visibility: repo.visibility.as_str(),
        default_branch: repo.default_branch,
        permission: access.permission.as_str(),
        created_at: repo.created_at,
        owner: repo.owner,
        name: repo.name,
    }
}

#[derive(Deserialize)]
pub struct CreateRepoBody {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "private")]
    visibility: String,
}

fn private() -> String {
    "private".to_owned()
}

pub async fn create(
    State(state): State<ApiState>,
    auth: ApiAuth,
    body: Result<Json<CreateRepoBody>, JsonRejection>,
) -> Result<(StatusCode, Json<RepoJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let visibility = Visibility::parse(&body.visibility)
        .ok_or_else(|| ApiError::Invalid("visibility must be public, internal, or private".into()))?;
    let repo = state.core.create_repo(&auth.user, CreateRepo { name: body.name, description: body.description, visibility }).await?;
    Ok((StatusCode::CREATED, Json(repo_json(&state, RepoAccess { repo, permission: Permission::Admin }))))
}

pub async fn show(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<RepoJson>, ApiError> {
    let access = state.core.repo_for(auth.reader()?, &owner, &repo).await?;
    Ok(Json(repo_json(&state, access)))
}

#[derive(Serialize)]
pub struct CollaboratorJson {
    handle: String,
    permission: &'static str,
}

pub async fn list_collaborators(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<CollaboratorJson>>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let collaborators = state.core.collaborators(&auth.user, &owner, &repo).await?;
    Ok(Json(collaborators.into_iter().map(|c| CollaboratorJson { handle: c.handle, permission: c.permission.as_str() }).collect()))
}

#[derive(Deserialize)]
pub struct SetCollaboratorBody {
    permission: String,
}

pub async fn set_collaborator(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, handle)): Path<(String, String, String)>,
    body: Result<Json<SetCollaboratorBody>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let permission = Permission::parse(&body.permission)
        .ok_or_else(|| ApiError::Invalid("permission must be read, triage, write, maintain, or admin".into()))?;
    state.core.set_collaborator(&auth.user, &owner, &repo, &handle, permission).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_collaborator(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, handle)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state.core.remove_collaborator(&auth.user, &owner, &repo, &handle).await?;
    Ok(StatusCode::NO_CONTENT)
}
```

- [ ] **Step 4: Mount the API**

Add to `crates/starforged/Cargo.toml` `[dependencies]`:

```toml
starforged-api = { path = "../starforged-api" }
```

In `crates/starforged/src/serve.rs`, replace the body of `build` with:

```rust
    let core = open_core(config, hook_exe).await?;
    let web = starforged_web::router(
        core.clone(),
        starforged_web::WebSettings { base_url: config.server.base_url.clone(), secure_cookies: config.secure_cookies() },
    );
    let api = starforged_api::router(core.clone(), config.server.base_url.clone());
    let router = Router::new().route("/healthz", get(|| async { "ok" })).nest("/api/v1", api).merge(web);
    Ok(App { router, core })
```

and update its doc comment to `/// The whole application: \`/healthz\`, \`/api/v1\`, web pages, and git smart HTTP.`

- [ ] **Step 5: Run the API test**

Run: `cargo test -p starforged --test api`
Expected: 1 passed.

- [ ] **Step 6: Full suite, lint, format, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates Cargo.lock
git commit -m "feat(api): /api/v1 user, repositories, and collaborators with bearer tokens"
```

---

### Task 14: End-to-end check with the real binary, and the README

**Files:**
- Create: `crates/starforged/tests/e2e_binary.rs`, `README.md`
- Test: `crates/starforged/tests/e2e_binary.rs`

**Interfaces:**
- Consumes: every CLI command (`init`, `admin user create`, `admin token create`, `serve`), `/healthz`, `/api/v1/user/repos`, git smart HTTP, the repository home page, and the harness helpers `work_repo` and `git_ok`.
- Produces: proof that the shipped binary works end to end: its own hooks, its own SQLite file, and its own process.

- [ ] **Step 1: Write the end-to-end test**

`crates/starforged/tests/e2e_binary.rs`:

```rust
mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use common::*;

/// Kills the server when the test ends, even on failure.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn starforged(config: &Path, args: &[&str], stdin: Option<&str>) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "starforged {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_serves_a_repository_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    let data = tmp.path().join("data");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let addr = format!("127.0.0.1:{port}");
    starforged(&config, &["init", "--data-dir", data.to_str().unwrap(), "--base-url", &base, "--http-addr", &addr], None);
    starforged(&config, &["admin", "user", "create", "--handle", "alice", "--password-stdin"], Some("correct horse battery\n"));
    let token = starforged(&config, &["admin", "token", "create", "--user", "alice", "--name", "e2e"], None).trim().to_owned();

    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_starforged"))
            .arg("--config")
            .arg(&config)
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::new();
    let mut healthy = false;
    for _ in 0..100 {
        if client.get(format!("{base}/healthz")).send().await.is_ok_and(|r| r.status().is_success()) {
            healthy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(healthy, "starforged serve did not become healthy");

    let created = client
        .post(format!("{base}/api/v1/user/repos"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"name": "demo", "visibility": "public"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    let work = work_repo(tmp.path(), "work", &[("README.md", "# Demo\n")]).await;
    git_ok(&work, &["push", "-q", &format!("http://git:{token}@{addr}/alice/demo.git"), "main"]).await;
    let home = client.get(format!("{base}/alice/demo")).send().await.unwrap().text().await.unwrap();
    assert!(home.contains("<h1>Demo</h1>"), "{home}");
    git_ok(tmp.path(), &["clone", "-q", &format!("{base}/alice/demo.git"), "copy"]).await;
    assert_eq!(std::fs::read_to_string(tmp.path().join("copy/README.md")).unwrap(), "# Demo\n");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p starforged --test e2e_binary`
Expected: 1 passed. Every feature it touches was built in Tasks 1–13, so this test should pass immediately; if it fails, the failure is a real integration bug (e.g. hook paths or config loading in the spawned binary) — fix the code, not the test.

- [ ] **Step 3: Write `README.md`**

````markdown
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

Open http://127.0.0.1:3000, sign in, create a token under **Tokens** and a repository under **New repository**, then:

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

Any key can be overridden with an environment variable such as `STARFORGE__SERVER__HTTP_ADDR` or
`STARFORGE__DATABASE__URL`. `STARFORGE_CONFIG` sets the config file path.

## API

`/api/v1` accepts `Authorization: Bearer <token>`: `GET /user`, `POST /user/repos`, `GET /repos/{owner}/{repo}`,
and `GET`/`PUT`/`DELETE /repos/{owner}/{repo}/collaborators[/{handle}]`. Errors use
`{"error": {"code", "message"}}`.

## Development

```bash
scripts/check.sh                      # fmt, clippy, tests on SQLite
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17 via podman or docker
```

## License

See `LICENSE.md`: the server is AGPL-3.0-or-later; the CLI and trace format (from M1) are MIT OR Apache-2.0.
````

- [ ] **Step 4: Run the full check on both databases**

Run: `STARFORGE_TEST_PG=1 scripts/check.sh`
Expected: fmt and clippy clean; the whole workspace passes on SQLite and again on Postgres.

- [ ] **Step 5: Commit**

```bash
git add README.md crates/starforged/tests/e2e_binary.rs
git commit -m "test: end-to-end check of the starforged binary; add README"
```

---

## Spec Coverage (M0)

| Spec requirement (M0 row of §14) | Task |
|---|---|
| Workspace and crate layout | 1, 2, 3, 5, 7, 13 |
| Config and `init` (§12) | 1 |
| Schema and migrations on SQLite and Postgres (§12) | 2 |
| Local accounts (§9) and personal access tokens (§6.1) | 3, 4, 8, 9 |
| User-owned repositories with collaborators and permission levels (§6.1) | 5, 9, 10, 13 |
| Push and pull over smart HTTP, protocol v2 (§8.1); branch/tag ref namespace (§8.2) | 6, 7 |
| Code, history, commit, and diff browsing (§10.1) | 11, 12 |
| Audit log records (§6.5) | 4, 5, 8 |
| Security headers, sanitized Markdown, sandboxed raw files, CSRF (§11.1, §9) | 8, 11 |
| Git version check, hermetic git environment (§5.5) | 5, 7 |
| End-to-end proof with the shipped binary | 14 |
