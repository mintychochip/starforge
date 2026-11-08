# Configuration

`starforged init` writes `starforged.toml`:

| Key | Meaning |
|---|---|
| `server.http_addr` | Address to bind, e.g. `127.0.0.1:3000` |
| `server.base_url` | Public URL of the server without a trailing slash; `https://` turns on secure cookies. Must be an origin like `https://forge.example.com` — a path prefix, query, or fragment (e.g. `https://example.com/forge`) is refused because Starforge cannot be served under a path prefix |
| `database.url` | Empty for SQLite in the data directory, or a `postgres://` URL |
| `database.auto_migrate` | Migrate the schema at startup (default `true`) |
| `storage.data_dir` | Repositories, SQLite database, and runtime files |
| `security.secret_key` | 64 hex characters; losing it makes sealed webhook secrets and mirror credentials unreadable |
| `registration.mode` | Who can sign up: `invite` (default; invite links only), `open`, `domains`, or `sso` (no sign-up forms; accounts arrive only through single sign-on) |
| `registration.allowed_domains` | Email domains that `domains` mode accepts, e.g. `["example.com"]` |
| `oidc.enabled` | Whether single sign-on is offered on the sign-in page (default `false`) |
| `oidc.issuer` | Provider issuer URL (`https://`, or `http://` only for loopback providers such as tests) |
| `oidc.client_id` | The client id registered with the provider |
| `oidc.client_secret` | The client secret (never logged or rendered) |
| `oidc.scopes` | Requested scopes (default `["openid", "email", "profile"]`) |
| `oidc.button_label` | Sign-in page button text (default `"Sign in with SSO"`) |
| `oidc.auto_create` | Create a password-less account on first sign-in when no account matches (default `false`) |
| `oidc.link_by_email` | Link first sign-ins by a provider-verified email that exactly matches one locally verified email (default `true`) |
| `mail.url` | Empty for no email; `smtp://user:pass@host:587` (STARTTLS), `smtps://user:pass@host:465`, or `file:///dir` (writes `.eml` files) |
| `mail.from` | Sender, e.g. `Starforge <forge@example.com>` |
| `ssh.enabled` | Whether the SSH listener starts (default `true`) |
| `ssh.listen` | Address the SSH server binds (default `0.0.0.0:2222`) |
| `ssh.host_key_path` | Host key file; generated with mode `0600` on first start or by `starforged init` (relative paths resolve against `storage.data_dir`) |
| `ssh.public_host` | Host shown in SSH clone URLs; empty takes the host from `server.base_url` |
| `ssh.public_port` | Port shown in SSH clone URLs (default `2222`) |
| `ssh.idle_timeout_secs` | Idle timeout per SSH connection (default `300`) |
| `ssh.max_connection_secs` | Total timeout per SSH connection (default `3600`) |
| `ssh.max_connections_per_user` | Concurrent SSH connections per user (per deploy key) (default `10`) |
| `log.format` | Log output: `text` (default) or `json` (one JSON object per line) |
| `log.level` | `EnvFilter` string for log verbosity (default `info`) |
| `metrics.token` | Bearer token protecting `GET /metrics`; unset disables the endpoint (404) |
| `limits.login_per_ip_per_minute` | Sign-in attempts per client IP per minute (default `10`; `0` disables) |
| `limits.login_per_account_per_hour` | Failed sign-ins per normalized login name per hour (default `20`; `0` disables) |
| `limits.api_per_token_per_hour` | API requests per token per hour (default `5000`; `0` disables) |
| `limits.refs_for_new_changes_per_hour` | New `refs/for` changes per user per hour (default `30`; `0` disables) |
| `remotes.allow_file_urls` | Test-only: admit `file://`/local-path remotes and loopback hosts for the import/mirror URL policy (default `false`; never set in production) |
| `sandbox.provider` | Sandbox provider: `local` (rootless containers via `starforge-sandboxd`, default) or `e2b` (remote cloud) |
| `sandbox.local.socket` | Unix socket the local sandbox daemon listens on (default `/run/starforge/sandboxd.sock`) |
| `sandbox.local.token_file` | Daemon auth token file, mode `0600`; rotates on restart (default `/run/starforge/sandboxd.token`) |
| `sandbox.local.egress.proxy_listen` | Address the egress proxy listens on (default `127.0.0.1:8888`) |
| `sandbox.local.egress.ca_dir` | Directory holding per-sandbox CA keys, destroyed with the sandbox (default `/run/starforge/sandbox-ca`) |
| `sandbox.local.egress.allowlist` | Hosts the egress proxy (and therefore the sandbox) may reach (default `[]`) |
| `sandbox.e2b.api_url` | Base URL of the E2B-shaped gateway (default `https://api.e2b.dev`; the adapter is not compatible with real E2B) |
| `sandbox.e2b.api_key` | E2B API key (never logged or rendered) |
| `sandbox.limits.max_concurrent_per_user` | Concurrent sandboxes per user (default `0`; `0` disables) |
| `sandbox.limits.max_concurrent_per_repo` | Concurrent sandboxes per repository (default `0`; `0` disables) |
| `sandbox.limits.sandbox_seconds_per_hour` | Sandbox-seconds per user per hour (default `0`; `0` disables) |
| `sandbox.default_ttl_secs` | Default sandbox lifetime cap in seconds when a request does not carry `timeout_s` (default `3600`) |

### CI (M6, opt-in)

The CI control plane (runners, jobs, artifacts, secrets) is configured per
repository through `.starforge/ci.toml` and the APIs; see
[User: CI](../user/ci.md) and [CI administration](ci.md). The server-wide
`[ci]` section holds the usage quotas for native runners and the external CI
suppliers whose usage Starforge reads:

| Key | Meaning |
|---|---|
| `ci.limits.minutes_per_month` | Native runner minutes per repository per calendar month (UTC). A run queued after the month's minutes are used up is refused with an `error` check naming the reset date (default `0`; `0` disables) |
| `ci.limits.artifact_bytes` | Bytes of unexpired CI artifacts per repository; an upload that would exceed it is refused (default `0`; `0` disables) |
| `ci.depot.api_url` | Base URL of the Depot API (default `https://api.depot.dev`) |
| `ci.depot.api_token` | Depot organization token, used only to read linked repositories' usage (never logged or rendered; empty disables the Depot supplier) |

Two secret policies are fixed in this release, not settings: `refs/for`
runs never resolve repository secrets, and secret values never enter the
job environment (only the egress proxy's headers).

Any key can be overridden with an environment variable such as `STARFORGE__SERVER__HTTP_ADDR` or
`STARFORGE__DATABASE__URL`. `STARFORGE_CONFIG` sets the config file path.

Every key above is overridable as `STARFORGE__<SECTION>__<KEY>` (upper-cased, e.g. `STARFORGE__SERVER__HTTP_ADDR`). `STARFORGE_CONFIG` sets the config file path. Full key list also includes the sections below: `sessions.*`, `webhooks.allow_loopback`, `git.allowed_ref_namespaces`, `github.api_url`, `storage.index_dir`, `log.*`, `metrics.token`, `limits.*`, `sandbox.*`, `ci.*` (nested keys use one `__` per level, e.g. `STARFORGE__SANDBOX__LOCAL__SOCKET`, `STARFORGE__CI__LIMITS__MINUTES_PER_MONTH`).

Abuse controls (spec §11.6) are all configurable under `[limits]`; every key is
also overridable as `STARFORGE__LIMITS__*`. Setting any limit to `0` disables it.
The session-upload volume and storage quotas keep their own `[sessions]` keys
(500 MiB/hour upload volume, 5 GiB per user, 20 GiB per repository, 16 MiB per
segment) and their existing errors.

| Limit | Config key | Default | What it counts |
|---|---|---|---|
| Sign-in attempts | `limits.login_per_ip_per_minute` | `10` | Attempts from one client IP per fixed 1-minute window (in-memory) |
| Failed sign-ins | `limits.login_per_account_per_hour` | `20` | `auth.login_failed` rows for the normalized login name in the last hour (database) |
| API requests | `limits.api_per_token_per_hour` | `5000` | Requests per token per fixed 1-hour window (in-memory) |
| New `refs/for` changes | `limits.refs_for_new_changes_per_hour` | `30` | `agit` changes created by the user in all repositories in the last hour (database) |

**Client IP.** The login limiter, the login page, and the audit writer all use
the same address: the TCP peer (`ConnectInfo`) of the HTTP connection. An
`X-Forwarded-For` header is never trusted, so a client cannot spoof its
address; only a reverse proxy in front of a single server can see the proxied
address, and behind one the limiter and the audit log see the proxy, not the
client. The per-account limit counts failures for existing and non-existing
login names identically (by the normalized name), so probing unknown names is
limited the same way.

**Response shapes.** Over the API limit: `429` with the error envelope
`{"error": {"code": "rate_limited", "message": "rate limit exceeded"}}`,
`Retry-After`, and on every token-authenticated API response (when the limit is
enabled) `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`
(unix seconds). When the limit is disabled no `X-RateLimit-*` headers are sent.
Over a sign-in limit: the sign-in page re-renders with `429` and a generic
message; failed attempts while limited are still audited
(`auth.login_rate_limited`). Over the `refs/for` budget: the push of that ref
is refused with a `remote: starforge: …` message naming the limit; updating
an existing topic is still accepted. API `429`s are never audited (too noisy)
and are logged at `info` with the token id, never the token. The in-memory
windows reset on restart, which a single-process deployment accepts.

