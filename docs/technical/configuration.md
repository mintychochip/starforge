# Configuration

<!-- ste-sources
crates/starforged/src/config.rs
crates/starforged/src/init.rs
crates/starforged/src/admin.rs
crates/starforged-core/src/lib.rs
crates/starforged-core/src/mail.rs
crates/starforged-core/src/crypto.rs
crates/starforged-core/src/sandboxes.rs
crates/starforged-core/src/ci_usage.rs
crates/starforged-core/src/ci.rs
-->

## Purpose

This page defines configuration for the `starforged` server. Readers change configuration values and debug configuration failures. The code in `Config::load` reads, overrides, and validates values.

## Scope

This page covers keys, precedence, derived values, secrets, and validation. Procedures for operators live in [the administration configuration guide](../admin/configuration.md).

## How it works

`Config::load` reads the TOML file from a path. The path comes from the `--config` option or `STARFORGE_CONFIG`. The default path is `starforged.toml` in the startup directory. `Config::load` parses the file with `toml::from_str`. `Config::apply_env` then applies environment overrides. `Config::validate` runs before any database connection.

`admin::open_core` receives the validated `Config`. The server loads configuration once at start. A restart applies each change. No hot reload exists. `init::run` writes a fresh file and data directory. It refuses to overwrite an existing file.

It generates a random `secret_key` with 32 bytes. It creates `repos`, `tmp`, and `run` directories. It writes the file with mode `0600` on Unix. It creates the SSH host key with `ensure_host_key`.

### Precedence

| Order | Source | Effect |
|---|---|---|
| 1 | TOML file | Base values for all keys |
| 2 | `STARFORGE__<SECTION>__<KEY>` environment | Overrides file values |
| 3 | `Config::validate` | Rejects invalid values before connect |

The code ignores variables without the `STARFORGE__` prefix. The prefix is case-sensitive and must use uppercase. The section and key remainder is case-insensitive. Unknown keys with the prefix cause a fatal error.

Booleans accept only `true`, `1`, `false`, or `0`. List keys accept comma-separated values. The code drops empty list entries.

Nested keys use one `__` per level.
The code accepts `STARFORGE__SANDBOX__LOCAL__SOCKET`.
The code accepts `STARFORGE__CI__LIMITS__MINUTES_PER_MONTH`.
The code rejects an unknown nested key as fatal.

`STARFORGE_CONFIG` selects the file path.

### Keys

| Section | Key | Type | Default | Effect |
|---|---|---|---|---|
| `server` | `http_addr` | string | none, required | Socket address for HTTP |
| `server` | `base_url` | string | none, required | Public origin for links |
| `database` | `url` | string | empty, SQLite | Engine URL or empty value |
| `database` | `auto_migrate` | bool | `true` | Run migrations at start |
| `storage` | `data_dir` | path | none, required | Root for local data |
| `storage` | `index_dir` | path | `index` | Search index directory |
| `security` | `secret_key` | string | none, required | Key for sealed secrets |
| `registration` | `mode` | string | `invite` | Sign-up mode: `invite`, `open`, `domains`, or `sso` |
| `registration` | `allowed_domains` | list | empty | Domains in `domains` mode |
| `mail` | `url` | string | empty, no email | Mail transport URL |
| `mail` | `from` | string | empty | Sender mailbox address |
| `sessions` | `blob_dir` | path | `data/blobs` | Blob store root |
| `sessions` | `max_segment_bytes` | number | 16 MiB | Maximum segment bytes |
| `sessions` | `max_repo_bytes` | number | 20 GiB | Maximum bytes per repository |
| `sessions` | `max_user_bytes` | number | 5 GiB | Maximum bytes per uploader |
| `sessions` | `max_hourly_bytes` | number | 500 MiB | Maximum bytes per hour |
| `sessions` | `max_decompressed_bytes` | number | 256 MiB | Maximum decompressed bytes |
| `sessions` | `site_redact_rules` | string | none | Operator redact rules |
| `webhooks` | `allow_loopback` | bool | `false` | Test-only loopback delivery |
| `git` | `allowed_ref_namespaces` | list | empty | Extra push namespaces |
| `remotes` | `allow_file_urls` | bool | `false` | Test-only file URLs |
| `github` | `api_url` | string | `https://api.github.com` | GitHub API base URL |
| `oidc` | `enabled` | bool | `false` | Offer single sign-on |
| `oidc` | `issuer` | string | empty | Provider issuer URL |
| `oidc` | `client_id` | string | empty | Provider client identifier |
| `oidc` | `client_secret` | string | empty | Provider client secret |
| `oidc` | `scopes` | list | `openid,email,profile` | Requested OIDC scopes |
| `oidc` | `button_label` | string | `Sign in with SSO` | Sign-in page label |
| `oidc` | `auto_create` | bool | `false` | Create accounts on first sign-in |
| `oidc` | `link_by_email` | bool | `true` | Link sign-ins by email |
| `limits` | `login_per_ip_per_minute` | number | 10 | Sign-in attempts per IP |
| `limits` | `login_per_account_per_hour` | number | 20 | Sign-ins per account |
| `limits` | `api_per_token_per_hour` | number | 5000 | API calls per token |
| `limits` | `refs_for_new_changes_per_hour` | number | 30 | New changes per hour |
| `limits` | `max_push_bytes` | number | 0, disabled | Maximum bytes in one push |
| `limits` | `max_repo_bytes` | number | 0, disabled | Maximum repository bytes before refusal |
| `limits` | `git_per_ip_per_minute` | number | 0, disabled | Git requests per IP per minute |
| `audit` | `retention_days` | number | 0, keep forever | Audit row retention in days |
| `backup` | `dir` | path | empty, off | Directory for scheduled backups |
| `backup` | `interval_hours` | number | 0, off | Hours between scheduled backups |
| `backup` | `keep` | number | 7 | Backups to keep when enabled |
| `ssh` | `enabled` | bool | `true` | Start SSH listener |
| `ssh` | `listen` | string | `0.0.0.0:2222` | SSH socket address |
| `ssh` | `host_key_path` | path | `ssh_host_ed25519_key` | Host key file path |
| `ssh` | `public_host` | string | empty, from base URL | Host in SSH clone URLs |
| `ssh` | `public_port` | number | 2222 | Port in SSH clone URLs |
| `ssh` | `idle_timeout_secs` | number | 300 | Idle timeout per connection |
| `ssh` | `max_connection_secs` | number | 3600 | Total timeout per connection |
| `ssh` | `max_connections_per_user` | number | 10 | Active connections per user |
| `log` | `format` | string | `text` | Log output format |
| `log` | `level` | string | `info` | Log level filter |
| `metrics` | `token` | string | none, disabled | Bearer token for metrics |
| `sandbox` | `provider` | string | `local` | Sandbox provider: `local` or `e2b` |
| `sandbox` | `default_ttl_secs` | number | 3600 | Default sandbox lifetime in seconds |
| `sandbox.local` | `socket` | path | `/run/starforge/sandboxd.sock` | Sandbox daemon Unix socket |
| `sandbox.local` | `token_file` | path | `/run/starforge/sandboxd.token` | Sandbox daemon token file |
| `sandbox.local.egress` | `allowlist` | list | empty | Hosts the sandbox can reach |
| `sandbox.e2b` | `api_url` | string | `https://api.e2b.dev` | E2B API base URL |
| `sandbox.e2b` | `api_key` | string | empty | E2B API key |
| `sandbox.limits` | `max_concurrent_per_user` | number | 0, disabled | Concurrent sandboxes per user |
| `sandbox.limits` | `max_concurrent_per_repo` | number | 0, disabled | Concurrent sandboxes per repository |
| `sandbox.limits` | `sandbox_seconds_per_hour` | number | 0, disabled | Sandbox seconds per user per hour |
| `ci.limits` | `minutes_per_month` | number | 0, disabled | Native runner minutes per month |
| `ci.limits` | `artifact_bytes` | number | 0, disabled | Unexpired artifact bytes per repository |
| `ci.depot` | `api_url` | string | `https://api.depot.dev` | Depot API base URL |
| `ci.depot` | `api_token` | string | empty, disabled | Depot organization token |

Missing sections take the defaults above. Old files keep working without new sections. A `limits.*` value of `0` disables that control. A session `*_bytes` quota of `0` rejects every upload. A `sandbox.limits.*` value of `0` disables that control. A `ci.limits.*` value of `0` disables that control.

`audit.retention_days` of `0` keeps every row. Scheduled backups need a non-empty `backup.dir` and a positive `backup.interval_hours`. `backup.enabled` reports both conditions. `Config::validate` rejects `backup.keep` of `0` for enabled backups.

The `sandbox.provider` override accepts `local` or `e2b` only. An unknown provider value stops startup. Number overrides must parse as non-negative counts. An empty `ci.depot.api_token` disables the Depot supplier. An empty `sandbox.e2b.api_key` leaves the E2B provider without an API key. `Config::validate` checks no `sandbox.*` or `ci.*` value beyond environment parsing.

### Derived values

| Value | Derivation | Use |
|---|---|---|
| Database URL | Empty `database.url` gives `sqlite://<data_dir>/starforge.db?mode=rwc` | Database connection |
| `repos_dir` | `<data_dir>/repos` | Bare repositories |
| `tmp_dir` | `<data_dir>/tmp` | Scratch space |
| Blob directory | Absolute path stays verbatim, relative path joins `data_dir` | Blob store |
| Index directory | Absolute path stays verbatim, relative path joins `data_dir` | Search index |
| Host key path | Absolute path stays verbatim, relative path joins `data_dir` | SSH listener |
| Secure cookies | `true` when `base_url` starts with `https://` | Cookie flag |
| SSH clone base | `ssh://git@<host>:<port>` | Clone URLs on pages |

`public_host` wins over the host in `base_url`. IPv6 hosts appear in brackets. The code omits the SSH clone base for disabled SSH.

### Secrets

`security.secret_key` seals webhook secrets. `security.secret_key` derives the mirror credential key. The webhook key uses the key directly. The credential box uses HKDF from the key.

The key also seals TOTP secrets with the webhook key. The key also seals CI secrets through `CiSecretBox`. `CiSecretBox` uses HKDF info `ci-secrets-v1` and XChaCha20-Poly1305.

A repository admin can set two per-repository CI secret policies. The policies are `ci_allow_secrets_on_refs_for` and `ci_env_secrets`. Both policies default to off. The admin sets them with `PATCH /api/v1/repos/{owner}/{repo}`. The server-wide `[ci]` table stays unchanged.

Loss of `secret_key` makes sealed webhook secrets unreadable. Loss of `secret_key` makes sealed mirror credentials unreadable. Loss of `secret_key` makes sealed TOTP secrets unreadable. TOTP codes stop working after loss. Recovery codes still work after loss, because recovery codes store SHA-256 hashes.

Loss of `secret_key` makes sealed CI secrets unreadable. Web sessions do not depend on the key, because web sessions store only a hash of a random token. Loss of `secret_key` does not sign anyone out. A replacement has the same effect. Webhook deliveries fail until operators reset the secrets.

Mirror synchronization fails until operators reset credentials. TOTP sign-in fails until operators reset TOTP secrets. CI secret resolution fails until operators reset CI secrets. `Debug` output redacts `secret_key`. `Debug` output redacts mail credentials.

`Debug` output redacts OIDC client secrets. `Debug` output redacts metrics tokens. `Debug` output redacts `sandbox.e2b.api_key`. `Debug` output redacts `ci.depot.api_token`.

## Interfaces

`Config::load` takes a path and returns `Config`. `Config::apply_env` takes environment pairs. `Config::validate` returns an error for bad values. `Config::database_url` returns the database URL. `Config::repos_dir` returns the repositories path. `Config::tmp_dir` returns the scratch path.

`Config::blob_dir` returns the resolved blob path. `Config::index_dir` returns the resolved index path. `Config::ssh_host_key_path` returns the resolved host key path. `Config::secure_cookies` returns the cookie flag. `Config::ssh_clone_base` returns the clone base. `Config::mailer` returns the optional mailer.

`Config::registration_settings` returns registration settings. `Config::oidc_settings` returns OIDC settings. `admin::open_core` connects and builds `Core`. `Core::new` receives a `CoreConfig` struct. `CoreConfig` carries paths, quotas, and mailer. `CoreConfig` carries webhook and credential keys.

`CoreConfig` carries OIDC, limits, and SSH data. `CoreConfig` carries test-only loopback flags.

## Failure behavior

Invalid values stop the process before any connection. Unparsable TOML stops the process. Unknown `STARFORGE__*` keys stop the process. Missing files stop the process.

`validate` checks the base URL origin rule when the value parses as a URL. An unparsable `base_url` passes validation. Set a full URL such as `https://forge.example.com`.

`validate` checks the secret key format first, then the other rules.

`validate` checks the log format and level. `validate` checks the metrics token. `validate` checks registration settings. `validate` checks mail settings. `validate` checks git namespaces. `validate` checks OIDC settings.

Each check returns a fatal error message. Operators fix the file and restart the server.

### Validation rules

| Rule | Rejection |
|---|---|
| `secret_key` has 64 hex characters | Fatal error |
| `base_url` is an origin without path | Fatal error |
| `base_url` has no query or fragment | Fatal error |
| `log.format` is `text` or `json` | Fatal error |
| `log.level` is not empty | Fatal error |
| `metrics.token` is not blank | Fatal error |
| `registration.mode` is `invite`, `open`, `domains`, or `sso` | Fatal error |
| `domains` mode has allowed domains | Fatal error |
| `domains` mode has mail settings | Fatal error |
| Mail URL uses a known scheme | Fatal error |
| `tls=none` targets loopback only | Fatal error |
| Git namespaces avoid protected prefixes | Fatal error |
| OIDC issuer is present when enabled | Fatal error |
| OIDC issuer uses HTTPS or loopback HTTP | Fatal error |
| OIDC client identifier is present when enabled | Fatal error |
| `backup.keep` is at least 1 when backups are enabled | Fatal error |

The code lowercases domains before comparison. The code strips leading `@` characters from domains. Git namespaces must start with `refs/`. Git namespaces must end with `/`. A namespace must not equal, contain, or sit inside `refs/heads/`, `refs/tags/`, `refs/for/`, or `refs/trails/`.

Mail URLs accept `file:///`, `smtp://`, or `smtps://`. File URLs need an absolute path. `smtp://` uses STARTTLS by default. `smtps://` uses implicit TLS. When `mail.url` is not empty, the sender `from` must parse as a mailbox.

### Test-only keys

`remotes.allow_file_urls` admits file URLs for imports and mirrors. `webhooks.allow_loopback` admits loopback delivery targets. OIDC accepts loopback HTTP issuers in tests. Mail accepts `tls=none` for loopback hosts. Production values keep all four flags off.

## Verification

Unit tests cover environment overrides in `config.rs`. Tests reject unknown override keys. Tests check empty database URL handling. Tests check secret key and origin validation. Tests check mail URL validation rules. Tests check domain rules and namespace rules.

Tests check `Debug` redaction for secrets. Tests check session defaults and quotas. Tests check path resolution for blob directories. Tests check init-generated file round trips. Integration tests check private files from `init`. Run the checker on this page before commit.

## Related

Read [storage and database](storage-and-database.md) for layout and schema. Read [security](security.md) for trust boundaries and secret handling. Read [operations](operations.md) for startup and health checks.
