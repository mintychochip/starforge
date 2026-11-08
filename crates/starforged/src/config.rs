//! `starforged.toml`: loading, `STARFORGE__SECTION__KEY` environment overrides, and derived paths (spec §12).

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use starforged_core::mail::Mailer;
use starforged_core::registration::{Registration, RegistrationMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub registration: RegistrationConfig,
    #[serde(default)]
    pub mail: MailConfig,
    /// Session ingest tuning (spec §5.3, §6.3). Missing section defaults cleanly so old
    /// `starforged.toml` files keep working.
    #[serde(default)]
    pub sessions: SessionsConfig,
    /// Webhook delivery tuning. Missing section defaults cleanly (loopback denied).
    #[serde(default)]
    pub webhooks: WebhooksConfig,
    /// Push policy tuning. Missing section defaults cleanly (no extra namespaces).
    #[serde(default)]
    pub git: GitConfig,
    /// Import/mirror tuning. Missing section defaults cleanly (test-only
    /// file-URL flag off).
    #[serde(default)]
    pub remotes: RemotesConfig,
    /// GitHub import tuning. Missing section defaults cleanly
    /// (`https://api.github.com`).
    #[serde(default)]
    pub github: GithubConfig,
    /// OIDC single sign-on (spec §9, plan D4). Missing section defaults
    /// cleanly (disabled).
    #[serde(default)]
    pub oidc: OidcConfig,
    /// Abuse controls (spec §11.6). Missing section defaults cleanly; `0`
    /// disables a limit.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Git over SSH (M3c). Missing section defaults cleanly (listener on
    /// 0.0.0.0:2222, host key under the data dir).
    #[serde(default)]
    pub ssh: SshConfig,
    /// Logging (plan M5b D1). Missing section defaults cleanly (text, info).
    #[serde(default)]
    pub log: LogConfig,
    /// Prometheus metrics (plan M5b D6). Missing section defaults cleanly
    /// (no token: `/metrics` answers 404).
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Sandbox provider (plan M6b B1). Missing section defaults cleanly
    /// (`local`, 3600 s default TTL).
    #[serde(default)]
    pub sandbox: starforged_core::sandboxes::SandboxConfig,
    /// CI usage (`[ci]`): native-runner quotas (`[ci.limits]`, all
    /// `0`-disabled) and the Depot supplier (`[ci.depot]`). Missing section
    /// defaults to no limits and no external supplier.
    #[serde(default)]
    pub ci: starforged_core::ci_usage::CiConfig,
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
        DatabaseConfig {
            url: String::new(),
            auto_migrate: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_index_dir() -> PathBuf {
    PathBuf::from("index")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    /// Search index directory (spec §5.3). An absolute `index_dir` is used
    /// verbatim; a relative one resolves against `storage.data_dir` (like
    /// `sessions.blob_dir` does, see [`Config::index_dir`]).
    #[serde(default = "default_index_dir")]
    pub index_dir: PathBuf,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// 64 hex characters (32 bytes). Seals webhook secrets, mirror and
    /// GitHub-import credentials, CI secrets, and TOTP secrets: losing it
    /// makes them unreadable. Web sessions and recovery codes do not depend
    /// on it.
    pub secret_key: String,
}

impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailConfig {
    /// Empty: no email. Otherwise `smtp://`, `smtps://`, or `file:///dir` (forge-basics design §3).
    #[serde(default)]
    pub url: String,
    /// Sender mailbox, e.g. `Starforge <forge@example.com>`.
    #[serde(default)]
    pub from: String,
}

impl std::fmt::Debug for MailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = if self.url.is_empty() { "" } else { "<set>" };
        f.debug_struct("MailConfig")
            .field("url", &url)
            .field("from", &self.from)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationConfig {
    /// `invite` (default), `open`, or `domains` (forge-basics design §4.1).
    #[serde(default = "default_registration_mode")]
    pub mode: String,
    /// Email domains that `domains` mode accepts, e.g. `["example.com"]`.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_registration_mode() -> String {
    "invite".into()
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        RegistrationConfig {
            mode: default_registration_mode(),
            allowed_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionsConfig {
    /// Content-addressed blob root (spec §5.3). An absolute `blob_dir` is used
    /// verbatim; a relative one resolves against `storage.data_dir` (so
    /// `blob_dir = "data/blobs"` with `data_dir = "/srv/starforge"` stores
    /// blobs under `/srv/starforge/data/blobs`), matching how `repos_dir` and
    /// `tmp_dir` are derived. See [`Config::blob_dir`] for the resolved path.
    #[serde(default = "default_blob_dir")]
    pub blob_dir: PathBuf,
    /// Rejects session segment bodies larger than this (spec §6.3).
    #[serde(default = "default_max_segment_bytes")]
    pub max_segment_bytes: u64,
    /// Rejects segment uploads past this per-repository stored total (spec §7.7).
    #[serde(default = "default_max_repo_bytes")]
    pub max_repo_bytes: u64,
    /// Rejects segment uploads past this per-uploader stored total (spec §7.7).
    #[serde(default = "default_max_user_bytes")]
    pub max_user_bytes: u64,
    /// Rejects segment uploads past this per-uploader rolling-hour volume (spec §7.7).
    #[serde(default = "default_max_hourly_bytes")]
    pub max_hourly_bytes: u64,
    /// Rejects segment bodies whose decompressed event JSONL exceeds this
    /// (default 256 MiB, spec §6.3): the server never materializes more than
    /// `limit + 1` bytes per segment, so a decompression bomb cannot OOM it.
    #[serde(default = "default_max_decompressed_bytes")]
    pub max_decompressed_bytes: u64,
    /// Operator redact rules in `.starforge/redact.toml` grammar, merged last
    /// (operator wins over repo rules). Default: unset, meaning no site rules.
    #[serde(default)]
    pub site_redact_rules: Option<String>,
}

fn default_blob_dir() -> PathBuf {
    PathBuf::from("data/blobs")
}

fn default_max_segment_bytes() -> u64 {
    starforged_core::DEFAULT_MAX_SEGMENT_BYTES
}

fn default_max_repo_bytes() -> u64 {
    starforged_core::DEFAULT_MAX_REPO_BYTES
}

fn default_max_user_bytes() -> u64 {
    starforged_core::DEFAULT_MAX_USER_BYTES
}

fn default_max_hourly_bytes() -> u64 {
    starforged_core::DEFAULT_MAX_HOURLY_BYTES
}

fn default_max_decompressed_bytes() -> u64 {
    starforged_core::DEFAULT_MAX_DECOMPRESSED_BYTES
}

impl Default for SessionsConfig {
    fn default() -> Self {
        SessionsConfig {
            blob_dir: default_blob_dir(),
            max_segment_bytes: default_max_segment_bytes(),
            max_repo_bytes: default_max_repo_bytes(),
            max_user_bytes: default_max_user_bytes(),
            max_hourly_bytes: default_max_hourly_bytes(),
            max_decompressed_bytes: default_max_decompressed_bytes(),
            site_redact_rules: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhooksConfig {
    /// Test-only escape hatch for the delivery SSRF gate: when true, webhook
    /// delivery may target loopback addresses (the integration suite's
    /// in-process receiver). Always false in production; every other
    /// non-global address is denied regardless.
    #[serde(default)]
    pub allow_loopback: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitConfig {
    /// Ref namespaces clients may push into (spec §8.2), e.g.
    /// `allowed_ref_namespaces = ["refs/notes/"]`. Each entry must start
    /// with `refs/` and end with `/`, and must neither equal nor overlap
    /// `refs/heads/`, `refs/tags/`, `refs/for/`, or `refs/trails/`.
    /// Pushes there need write plus a write-scoped token and are never
    /// subject to branch protection. Empty by default.
    #[serde(default)]
    pub allowed_ref_namespaces: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotesConfig {
    /// Test-only escape hatch for the outbound remote URL policy (M4b):
    /// when true, `file://`/local-path remotes and loopback hosts are
    /// admitted (the import/mirror integration suite). Always false in
    /// production.
    #[serde(default)]
    pub allow_file_urls: bool,
}

fn default_login_per_ip_per_minute() -> u64 {
    10
}

fn default_login_per_account_per_hour() -> u64 {
    20
}

fn default_api_per_token_per_hour() -> u64 {
    5000
}

fn default_refs_for_new_changes_per_hour() -> u64 {
    30
}

/// Abuse controls (spec §11.6). Every limit is `0`-disables: an operator
/// can turn any single limit off without touching the others.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Login attempts per client IP per minute.
    #[serde(default = "default_login_per_ip_per_minute")]
    pub login_per_ip_per_minute: u64,
    /// Failed logins per normalized login name per hour.
    #[serde(default = "default_login_per_account_per_hour")]
    pub login_per_account_per_hour: u64,
    /// API requests per token per hour.
    #[serde(default = "default_api_per_token_per_hour")]
    pub api_per_token_per_hour: u64,
    /// New `refs/for` changes per user per hour.
    #[serde(default = "default_refs_for_new_changes_per_hour")]
    pub refs_for_new_changes_per_hour: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            login_per_ip_per_minute: default_login_per_ip_per_minute(),
            login_per_account_per_hour: default_login_per_account_per_hour(),
            api_per_token_per_hour: default_api_per_token_per_hour(),
            refs_for_new_changes_per_hour: default_refs_for_new_changes_per_hour(),
        }
    }
}

fn default_ssh_listen() -> String {
    "0.0.0.0:2222".into()
}

fn default_ssh_host_key() -> PathBuf {
    PathBuf::from("ssh_host_ed25519_key")
}

/// Git over SSH (M3c, spec §8.1). Missing section defaults cleanly and every
/// knob is overridable by `STARFORGE__SSH__*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConfig {
    /// Whether the SSH listener starts (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Socket address the SSH server binds (default `0.0.0.0:2222`).
    #[serde(default = "default_ssh_listen")]
    pub listen: String,
    /// Host key file; generated with mode `0600` on first start or by
    /// `starforged init`. Relative paths resolve against `storage.data_dir`.
    #[serde(default = "default_ssh_host_key")]
    pub host_key_path: PathBuf,
    /// Host for SSH clone URLs; empty takes the host from `server.base_url`.
    #[serde(default)]
    pub public_host: String,
    /// Port for SSH clone URLs (default 2222).
    #[serde(default = "default_ssh_port")]
    pub public_port: u16,
    /// Idle timeout in seconds (default 300).
    #[serde(default = "default_ssh_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Total timeout in seconds (default 3600).
    #[serde(default = "default_ssh_max_connection_secs")]
    pub max_connection_secs: u64,
    /// Concurrent connections per user (per deploy key) (default 10).
    #[serde(default = "default_ssh_max_connections_per_user")]
    pub max_connections_per_user: usize,
}

fn default_ssh_port() -> u16 {
    2222
}

fn default_ssh_idle_timeout_secs() -> u64 {
    300
}

fn default_ssh_max_connection_secs() -> u64 {
    3600
}

fn default_ssh_max_connections_per_user() -> usize {
    10
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            enabled: true,
            listen: default_ssh_listen(),
            host_key_path: default_ssh_host_key(),
            public_host: String::new(),
            public_port: default_ssh_port(),
            idle_timeout_secs: default_ssh_idle_timeout_secs(),
            max_connection_secs: default_ssh_max_connection_secs(),
            max_connections_per_user: default_ssh_max_connections_per_user(),
        }
    }
}

fn default_log_format() -> String {
    "text".into()
}

fn default_log_level() -> String {
    "info".into()
}

/// The `[log]` section (plan M5b D1): `format` is `text` or `json`,
/// `level` is an `EnvFilter` string. Overridable by `STARFORGE__LOG__*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            format: default_log_format(),
            level: default_log_level(),
        }
    }
}

/// The `[metrics]` section (plan M5b D6): `token` protects `/metrics`.
/// `None` (or empty) disables the endpoint (404). Never rendered in
/// `Debug`. Overridable by `STARFORGE__METRICS__TOKEN`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub token: Option<String>,
}

impl std::fmt::Debug for MetricsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsConfig")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}
fn default_github_api_url() -> String {
    "https://api.github.com".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubConfig {
    /// Base URL of the GitHub API for metadata imports (M4c, spec §8.6),
    /// e.g. `https://api.github.com` or a GitHub Enterprise origin. The
    /// host is checked with the webhook SSRF rules; loopback is denied
    /// except behind the test-only flags.
    #[serde(default = "default_github_api_url")]
    pub api_url: String,
}

impl Default for GithubConfig {
    fn default() -> Self {
        GithubConfig {
            api_url: default_github_api_url(),
        }
    }
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}

fn default_oidc_button_label() -> String {
    "Sign in with SSO".into()
}

/// The `[oidc]` section (plan D4). `client_secret` never renders in
/// `Debug`. Overridable by `STARFORGE__OIDC__*`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The provider issuer: HTTPS, or HTTP only for loopback (tests).
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_oidc_button_label")]
    pub button_label: String,
    #[serde(default)]
    pub auto_create: bool,
    #[serde(default = "default_true")]
    pub link_by_email: bool,
}

impl Default for OidcConfig {
    fn default() -> OidcConfig {
        OidcConfig {
            enabled: false,
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: default_oidc_scopes(),
            button_label: default_oidc_button_label(),
            auto_create: false,
            link_by_email: true,
        }
    }
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("enabled", &self.enabled)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &if self.client_secret.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .field("scopes", &self.scopes)
            .field("button_label", &self.button_label)
            .field("auto_create", &self.auto_create)
            .field("link_by_email", &self.link_by_email)
            .finish()
    }
}

impl Config {
    /// Reads `path`, applies environment overrides, and validates.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.apply_env(std::env::vars())?;
        config.validate()?;
        Ok(config)
    }

    /// Applies `STARFORGE__<SECTION>__<KEY>` overrides; other variables are ignored.
    pub fn apply_env(
        &mut self,
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> anyhow::Result<()> {
        for (key, value) in vars {
            let Some(rest) = key.strip_prefix("STARFORGE__") else {
                continue;
            };
            match rest.to_ascii_lowercase().as_str() {
                "server__http_addr" => self.server.http_addr = value,
                "server__base_url" => self.server.base_url = value,
                "database__url" => self.database.url = value,
                "database__auto_migrate" => self.database.auto_migrate = parse_bool(&key, &value)?,
                "storage__data_dir" => self.storage.data_dir = PathBuf::from(value),
                "storage__index_dir" => self.storage.index_dir = PathBuf::from(value),
                "security__secret_key" => self.security.secret_key = value,
                "mail__url" => self.mail.url = value,
                "mail__from" => self.mail.from = value,
                "registration__mode" => self.registration.mode = value,
                "registration__allowed_domains" => {
                    self.registration.allowed_domains = value
                        .split(',')
                        .map(str::trim)
                        .filter(|d| !d.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                "sessions__blob_dir" => self.sessions.blob_dir = PathBuf::from(value),
                "sessions__max_segment_bytes" => {
                    self.sessions.max_segment_bytes = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative byte count"))?;
                }
                "sessions__max_repo_bytes" => {
                    self.sessions.max_repo_bytes = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative byte count"))?;
                }
                "sessions__max_user_bytes" => {
                    self.sessions.max_user_bytes = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative byte count"))?;
                }
                "sessions__max_hourly_bytes" => {
                    self.sessions.max_hourly_bytes = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative byte count"))?;
                }
                "sessions__max_decompressed_bytes" => {
                    self.sessions.max_decompressed_bytes = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative byte count"))?;
                }
                "sessions__site_redact_rules" => {
                    self.sessions.site_redact_rules = if value.trim().is_empty() {
                        None
                    } else {
                        Some(value)
                    };
                }
                "webhooks__allow_loopback" => {
                    self.webhooks.allow_loopback = parse_bool(&key, &value)?;
                }
                "remotes__allow_file_urls" => {
                    self.remotes.allow_file_urls = parse_bool(&key, &value)?;
                }
                "github__api_url" => self.github.api_url = value,
                "git__allowed_ref_namespaces" => {
                    self.git.allowed_ref_namespaces = value
                        .split(',')
                        .map(str::trim)
                        .filter(|d| !d.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                "limits__login_per_ip_per_minute" => {
                    self.limits.login_per_ip_per_minute = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "limits__login_per_account_per_hour" => {
                    self.limits.login_per_account_per_hour = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "limits__api_per_token_per_hour" => {
                    self.limits.api_per_token_per_hour = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "limits__refs_for_new_changes_per_hour" => {
                    self.limits.refs_for_new_changes_per_hour = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "oidc__enabled" => self.oidc.enabled = parse_bool(&key, &value)?,
                "oidc__issuer" => self.oidc.issuer = value,
                "oidc__client_id" => self.oidc.client_id = value,
                "oidc__client_secret" => self.oidc.client_secret = value,
                "oidc__scopes" => {
                    self.oidc.scopes = value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                "oidc__button_label" => self.oidc.button_label = value,
                "oidc__auto_create" => self.oidc.auto_create = parse_bool(&key, &value)?,
                "oidc__link_by_email" => self.oidc.link_by_email = parse_bool(&key, &value)?,
                "ssh__enabled" => self.ssh.enabled = parse_bool(&key, &value)?,
                "ssh__listen" => self.ssh.listen = value,
                "ssh__host_key_path" => self.ssh.host_key_path = PathBuf::from(value),
                "ssh__public_host" => self.ssh.public_host = value,
                "ssh__public_port" => {
                    self.ssh.public_port = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a port number"))?;
                }
                "ssh__idle_timeout_secs" => {
                    self.ssh.idle_timeout_secs = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "ssh__max_connection_secs" => {
                    self.ssh.max_connection_secs = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "ssh__max_connections_per_user" => {
                    self.ssh.max_connections_per_user = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "log__format" => self.log.format = value,
                "log__level" => self.log.level = value,
                "metrics__token" => {
                    self.metrics.token = if value.trim().is_empty() {
                        None
                    } else {
                        Some(value)
                    };
                }
                "sandbox__provider" => {
                    self.sandbox.provider = match value.to_ascii_lowercase().as_str() {
                        "local" => starforged_core::sandboxes::SandboxProviderKind::Local,
                        "e2b" => starforged_core::sandboxes::SandboxProviderKind::E2b,
                        _ => bail!("{key} must be \"local\" or \"e2b\""),
                    };
                }
                "sandbox__default_ttl_secs" => {
                    self.sandbox.default_ttl_secs = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "sandbox__local__socket" => {
                    self.sandbox.local.socket = PathBuf::from(value);
                }
                "sandbox__local__token_file" => {
                    self.sandbox.local.token_file = PathBuf::from(value);
                }
                "sandbox__local__egress__proxy_listen" => {
                    self.sandbox.local.egress.proxy_listen = value;
                }
                "sandbox__local__egress__ca_dir" => {
                    self.sandbox.local.egress.ca_dir = PathBuf::from(value);
                }
                "sandbox__local__egress__allowlist" => {
                    self.sandbox.local.egress.allowlist = value
                        .split(',')
                        .map(str::trim)
                        .filter(|h| !h.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                "sandbox__e2b__api_url" => self.sandbox.e2b.api_url = value,
                "sandbox__e2b__api_key" => self.sandbox.e2b.api_key = value,
                "sandbox__limits__max_concurrent_per_user" => {
                    self.sandbox.limits.max_concurrent_per_user = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "sandbox__limits__max_concurrent_per_repo" => {
                    self.sandbox.limits.max_concurrent_per_repo = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "sandbox__limits__sandbox_seconds_per_hour" => {
                    self.sandbox.limits.sandbox_seconds_per_hour = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "ci__limits__minutes_per_month" => {
                    self.ci.limits.minutes_per_month = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "ci__limits__artifact_bytes" => {
                    self.ci.limits.artifact_bytes = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{key} must be a non-negative count"))?;
                }
                "ci__depot__api_url" => self.ci.depot.api_url = value,
                "ci__depot__api_token" => self.ci.depot.api_token = value,
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
        // Every route is mounted at the origin root and discovery advertises
        // `api_url = base_url`, so a path prefix would silently produce
        // broken links. A lone trailing `/` is a valid empty path.
        if let Ok(url) = url::Url::parse(&self.server.base_url) {
            let not_origin = !matches!(url.path(), "" | "/")
                || url.query().is_some()
                || url.fragment().is_some();
            if not_origin {
                bail!(
                    "server.base_url must be an origin like https://forge.example.com (Starforge cannot be served under a path prefix)"
                );
            }
        }
        if !matches!(self.log.format.as_str(), "text" | "json") {
            bail!("log.format must be \"text\" or \"json\"");
        }
        if self.log.level.trim().is_empty() {
            bail!("log.level must not be empty");
        }
        if let Some(token) = &self.metrics.token
            && token.trim().is_empty()
        {
            bail!("metrics.token must not be blank");
        }
        self.registration_settings()?;
        self.mailer()?;
        starforged_git::refpolicy::validate_allowed_namespaces(&self.git.allowed_ref_namespaces)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if self.oidc.enabled {
            if self.oidc.issuer.trim().is_empty() {
                bail!("oidc.enabled needs oidc.issuer");
            }
            if !starforged_core::oidc::url_allowed(&self.oidc.issuer) {
                bail!("oidc.issuer must be https (http is only allowed for loopback)");
            }
            if self.oidc.client_id.trim().is_empty() {
                bail!("oidc.enabled needs oidc.client_id");
            }
        }
        Ok(())
    }

    /// The `[oidc]` section as core settings.
    pub fn oidc_settings(&self) -> starforged_core::oidc::OidcConfig {
        starforged_core::oidc::OidcConfig {
            enabled: self.oidc.enabled,
            issuer: self.oidc.issuer.clone(),
            client_id: self.oidc.client_id.clone(),
            client_secret: self.oidc.client_secret.clone(),
            scopes: self.oidc.scopes.clone(),
            button_label: self.oidc.button_label.clone(),
            auto_create: self.oidc.auto_create,
            link_by_email: self.oidc.link_by_email,
        }
    }

    /// The `[registration]` section as core settings, with domains lowercased.
    pub fn registration_settings(&self) -> anyhow::Result<Registration> {
        let mode = RegistrationMode::parse(&self.registration.mode).with_context(|| {
            format!(
                "registration.mode must be \"invite\", \"open\", \"domains\", or \"sso\", not {:?}",
                self.registration.mode
            )
        })?;
        let allowed_domains: Vec<String> = self
            .registration
            .allowed_domains
            .iter()
            .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        if mode == RegistrationMode::Domains {
            if allowed_domains.is_empty() {
                bail!("registration.mode = \"domains\" needs registration.allowed_domains");
            }
            if self.mail.url.trim().is_empty() {
                bail!(
                    "registration.mode = \"domains\" needs [mail], because addresses must be verified"
                );
            }
        }
        Ok(Registration {
            mode,
            allowed_domains,
        })
    }

    pub fn database_url(&self) -> String {
        if self.database.url.is_empty() {
            format!(
                "sqlite://{}?mode=rwc",
                self.storage.data_dir.join("starforge.db").display()
            )
        } else {
            self.database.url.clone()
        }
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.storage.data_dir.join("repos")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.storage.data_dir.join("tmp")
    }

    /// Resolved content-addressed blob root: an absolute
    /// `sessions.blob_dir` is used verbatim, a relative one resolves against
    /// `storage.data_dir`, matching how [`Config::repos_dir`] and
    /// [`Config::tmp_dir`] are derived.
    pub fn blob_dir(&self) -> PathBuf {
        if self.sessions.blob_dir.is_absolute() {
            self.sessions.blob_dir.clone()
        } else {
            self.storage.data_dir.join(&self.sessions.blob_dir)
        }
    }

    /// Resolved search index directory: an absolute `storage.index_dir` is
    /// used verbatim, a relative one resolves against `storage.data_dir`
    /// (the same rule as [`Config::blob_dir`]). Defaults to `index`.
    pub fn index_dir(&self) -> PathBuf {
        if self.storage.index_dir.is_absolute() {
            self.storage.index_dir.clone()
        } else {
            self.storage.data_dir.join(&self.storage.index_dir)
        }
    }

    /// Cookies carry `Secure` when the public URL is HTTPS.
    pub fn secure_cookies(&self) -> bool {
        self.server.base_url.starts_with("https://")
    }

    /// The `[mail]` section as a mailer; `None` when `mail.url` is empty.
    pub fn mailer(&self) -> anyhow::Result<Option<Mailer>> {
        Ok(Mailer::from_config(&self.mail.url, &self.mail.from)?)
    }

    /// Resolved SSH host key file: an absolute `ssh.host_key_path` is used
    /// verbatim; a relative one resolves against `storage.data_dir`.
    pub fn ssh_host_key_path(&self) -> PathBuf {
        if self.ssh.host_key_path.is_absolute() {
            self.ssh.host_key_path.clone()
        } else {
            self.storage.data_dir.join(&self.ssh.host_key_path)
        }
    }

    /// The `ssh://` clone address prefix (`ssh://git@<host>:<port>`) for the
    /// repository page (D6): `ssh.public_host` defaults to the host from
    /// `server.base_url`. `None` when SSH is disabled.
    pub fn ssh_clone_base(&self) -> Option<String> {
        if !self.ssh.enabled {
            return None;
        }
        let host = if self.ssh.public_host.trim().is_empty() {
            let Ok(url) = url::Url::parse(&self.server.base_url) else {
                return None;
            };
            match url.host() {
                Some(url::Host::Domain(domain)) => domain.to_owned(),
                Some(url::Host::Ipv4(ip)) => ip.to_string(),
                Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
                None => return None,
            }
        } else {
            self.ssh.public_host.clone()
        };
        Some(format!("ssh://git@{host}:{}", self.ssh.public_port))
    }
}

fn parse_bool(key: &str, value: &str) -> anyhow::Result<bool> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => bail!("{key} must be true or false"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            server: ServerConfig {
                http_addr: "127.0.0.1:3000".into(),
                base_url: "http://127.0.0.1:3000".into(),
            },
            database: DatabaseConfig::default(),
            storage: StorageConfig {
                data_dir: PathBuf::from("/srv/starforge"),
                index_dir: PathBuf::from("index"),
            },
            security: SecurityConfig {
                secret_key: "ab".repeat(32),
            },
            registration: RegistrationConfig::default(),
            mail: MailConfig::default(),
            sessions: SessionsConfig::default(),
            webhooks: WebhooksConfig::default(),
            git: GitConfig::default(),
            remotes: RemotesConfig::default(),
            github: GithubConfig::default(),
            limits: LimitsConfig::default(),
            oidc: OidcConfig::default(),
            ssh: SshConfig::default(),
            log: LogConfig::default(),
            metrics: MetricsConfig::default(),
            sandbox: starforged_core::sandboxes::SandboxConfig::default(),
            ci: starforged_core::ci_usage::CiConfig::default(),
        }
    }

    #[test]
    fn env_overrides_apply_and_ignore_other_variables() {
        let mut config = sample();
        config
            .apply_env([
                (
                    "STARFORGE__SERVER__HTTP_ADDR".to_owned(),
                    "0.0.0.0:80".to_owned(),
                ),
                (
                    "STARFORGE__DATABASE__URL".to_owned(),
                    "postgres://db/starforge".to_owned(),
                ),
                (
                    "STARFORGE__DATABASE__AUTO_MIGRATE".to_owned(),
                    "false".to_owned(),
                ),
                (
                    "STARFORGE_CONFIG".to_owned(),
                    "/etc/starforged.toml".to_owned(),
                ),
                ("HOME".to_owned(), "/root".to_owned()),
            ])
            .unwrap();
        assert_eq!(config.server.http_addr, "0.0.0.0:80");
        assert_eq!(config.database.url, "postgres://db/starforge");
        assert!(!config.database.auto_migrate);
    }

    #[test]
    fn index_dir_defaults_under_the_data_dir_and_overrides() {
        assert_eq!(sample().index_dir(), PathBuf::from("/srv/starforge/index"));
        let mut config = sample();
        config
            .apply_env([(
                "STARFORGE__STORAGE__INDEX_DIR".to_owned(),
                "/elsewhere/idx".to_owned(),
            )])
            .unwrap();
        assert_eq!(config.index_dir(), PathBuf::from("/elsewhere/idx"));
    }

    #[test]
    fn unknown_overrides_are_rejected() {
        let err = sample()
            .apply_env([("STARFORGE__SERVER__PORT".to_owned(), "1".to_owned())])
            .unwrap_err();
        assert!(err.to_string().contains("STARFORGE__SERVER__PORT"));
    }

    #[test]
    fn empty_database_url_means_sqlite_in_the_data_dir() {
        assert_eq!(
            sample().database_url(),
            "sqlite:///srv/starforge/starforge.db?mode=rwc"
        );
        assert_eq!(sample().repos_dir(), PathBuf::from("/srv/starforge/repos"));
    }

    #[test]
    fn validation_checks_secret_key_and_base_url() {
        assert!(sample().validate().is_ok());
        let mut short_key = sample();
        short_key.security.secret_key = "abc".into();
        assert!(short_key.validate().is_err());
        // A trailing slash is an empty path and stays accepted.
        let mut slash = sample();
        slash.server.base_url = "http://x/".into();
        assert!(slash.validate().is_ok());
        let mut https = sample();
        https.server.base_url = "https://forge.example.com".into();
        assert!(https.secure_cookies());
        assert!(!sample().secure_cookies());
    }

    #[test]
    fn base_url_must_be_an_origin() {
        for good in ["http://127.0.0.1:3000", "https://h/"] {
            let mut config = sample();
            config.server.base_url = good.into();
            assert!(config.validate().is_ok(), "{good}");
        }
        for bad in ["https://h/forge", "https://h/?x=1", "https://h/#frag"] {
            let mut config = sample();
            config.server.base_url = bad.into();
            let err = config.validate().unwrap_err().to_string();
            assert!(
                err.contains("server.base_url must be an origin"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn mail_settings_are_validated() {
        let mut config = sample();
        assert!(config.mailer().unwrap().is_none());
        config
            .apply_env([
                (
                    "STARFORGE__MAIL__URL".to_owned(),
                    "smtp://mail.example.com?tls=none".to_owned(),
                ),
                (
                    "STARFORGE__MAIL__FROM".to_owned(),
                    "Starforge <forge@example.com>".to_owned(),
                ),
            ])
            .unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("loopback")
        );
        config.mail.url = "smtps://user:pw@mail.example.com".into();
        assert!(config.validate().is_ok());
        assert!(config.mailer().unwrap().is_some());
        config.mail.from = "not a mailbox".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn registration_settings_are_validated() {
        let mut config = sample();
        assert_eq!(
            config.registration_settings().unwrap(),
            Registration::default()
        );
        config
            .apply_env([
                (
                    "STARFORGE__REGISTRATION__MODE".to_owned(),
                    "domains".to_owned(),
                ),
                (
                    "STARFORGE__REGISTRATION__ALLOWED_DOMAINS".to_owned(),
                    " Example.com, @corp.example ".to_owned(),
                ),
            ])
            .unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("needs [mail]")
        );
        config.mail = MailConfig {
            url: "file:///tmp/starforge-mail".into(),
            from: "Starforge <forge@example.com>".into(),
        };
        assert_eq!(
            config.registration_settings().unwrap().allowed_domains,
            vec!["example.com".to_owned(), "corp.example".to_owned()]
        );
        assert!(config.validate().is_ok());
        config.registration.allowed_domains.clear();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("allowed_domains")
        );
        config.registration.mode = "everyone".into();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("registration.mode")
        );
    }

    #[test]
    fn debug_output_hides_mail_credentials() {
        let mut config = sample();
        config.mail.url = "smtps://mailuser:hunter2secret@mail.example.com".into();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("hunter2secret"), "{rendered}");
        assert!(!rendered.contains("mailuser"), "{rendered}");
    }

    #[test]
    fn debug_output_hides_the_secret_key() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains(&"ab".repeat(32)), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn sessions_section_defaults_and_overrides() {
        fn bare_toml() -> String {
            format!(
                "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"http://127.0.0.1:3000\"\n\
                 [storage]\ndata_dir = \"/srv/starforge\"\n\
                 [security]\nsecret_key = \"{}\"\n",
                "ab".repeat(32)
            )
        }
        // A config file without `[sessions]` keeps working with defaults.
        let without: Config = toml::from_str(&bare_toml()).unwrap();
        assert_eq!(without.sessions, SessionsConfig::default());
        assert_eq!(without.sessions.blob_dir, PathBuf::from("data/blobs"));
        assert_eq!(
            without.sessions.max_segment_bytes,
            starforged_core::DEFAULT_MAX_SEGMENT_BYTES
        );
        assert_eq!(starforged_core::DEFAULT_MAX_SEGMENT_BYTES, 16 * 1024 * 1024);
        // Quota defaults (spec §7.7): 20 GiB/repo, 5 GiB/user, 500 MiB/user/hour.
        assert_eq!(without.sessions.max_repo_bytes, 20 * 1024 * 1024 * 1024);
        assert_eq!(without.sessions.max_user_bytes, 5 * 1024 * 1024 * 1024);
        assert_eq!(without.sessions.max_hourly_bytes, 500 * 1024 * 1024);
        assert_eq!(
            without.sessions.max_repo_bytes,
            starforged_core::DEFAULT_MAX_REPO_BYTES
        );
        assert_eq!(
            without.sessions.max_user_bytes,
            starforged_core::DEFAULT_MAX_USER_BYTES
        );
        assert_eq!(
            without.sessions.max_hourly_bytes,
            starforged_core::DEFAULT_MAX_HOURLY_BYTES
        );
        assert!(without.validate().is_ok());

        // Explicit values parse and validate.
        let explicit: Config = toml::from_str(&format!(
            "{bare}[sessions]\nblob_dir = \"/var/lib/blobs\"\nmax_segment_bytes = 1024\n",
            bare = bare_toml()
        ))
        .unwrap();
        assert_eq!(explicit.sessions.blob_dir, PathBuf::from("/var/lib/blobs"));
        assert_eq!(explicit.sessions.max_segment_bytes, 1024);
        assert!(explicit.validate().is_ok());

        // Quota fields parse from TOML and environment.
        let quotas: Config = toml::from_str(&format!(
            "{bare}[sessions]\nmax_repo_bytes = 1\nmax_user_bytes = 2\nmax_hourly_bytes = 3\n",
            bare = bare_toml()
        ))
        .unwrap();
        assert_eq!(quotas.sessions.max_repo_bytes, 1);
        assert_eq!(quotas.sessions.max_user_bytes, 2);
        assert_eq!(quotas.sessions.max_hourly_bytes, 3);
        let mut config = sample();
        config
            .apply_env([(
                "STARFORGE__SESSIONS__MAX_REPO_BYTES".to_owned(),
                "4096".to_owned(),
            )])
            .unwrap();
        assert_eq!(config.sessions.max_repo_bytes, 4096);

        // Environment overrides apply, including rejection of a bad byte count.
        let mut config = sample();
        config
            .apply_env([
                (
                    "STARFORGE__SESSIONS__BLOB_DIR".to_owned(),
                    "/tmp/blobs".to_owned(),
                ),
                (
                    "STARFORGE__SESSIONS__MAX_SEGMENT_BYTES".to_owned(),
                    "2048".to_owned(),
                ),
            ])
            .unwrap();
        assert_eq!(config.sessions.blob_dir, PathBuf::from("/tmp/blobs"));
        assert_eq!(config.sessions.max_segment_bytes, 2048);
        let bad = sample()
            .apply_env([(
                "STARFORGE__SESSIONS__MAX_SEGMENT_BYTES".to_owned(),
                "lots".to_owned(),
            )])
            .unwrap_err();
        assert!(bad.to_string().contains("byte count"), "{bad:?}");
    }

    #[test]
    fn relative_blob_dir_resolves_under_data_dir() {
        let mut config = sample();
        config.sessions.blob_dir = PathBuf::from("data/blobs");
        assert_eq!(
            config.blob_dir(),
            PathBuf::from("/srv/starforge/data/blobs")
        );
    }

    #[test]
    fn absolute_blob_dir_is_kept_verbatim() {
        let mut config = sample();
        config.sessions.blob_dir = PathBuf::from("/var/lib/blobs");
        assert_eq!(config.blob_dir(), PathBuf::from("/var/lib/blobs"));
    }

    #[test]
    fn git_namespaces_default_empty_and_validate() {
        let config = sample();
        assert!(config.git.allowed_ref_namespaces.is_empty());
        assert!(config.validate().is_ok());
        // A config file without `[git]` keeps working with defaults.
        let bare =
            "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"http://127.0.0.1:3000\"\n\
            [storage]\ndata_dir = \"/srv/starforge\"\n\
            [security]\nsecret_key = \""
                .to_owned()
                + &"ab".repeat(32)
                + "\"\n";
        let without: Config = toml::from_str(&bare).unwrap();
        assert_eq!(without.git, GitConfig::default());
        assert!(without.validate().is_ok());

        // Explicit values parse and validate.
        let explicit: Config = toml::from_str(&format!(
            "{bare}[git]\nallowed_ref_namespaces = [\"refs/notes/\", \"refs/keys/\"]\n"
        ))
        .unwrap();
        assert_eq!(
            explicit.git.allowed_ref_namespaces,
            vec!["refs/notes/", "refs/keys/"]
        );
        assert!(explicit.validate().is_ok());

        // Each entry must start with `refs/`, end with `/`, and stay clear
        // of the reserved namespaces.
        for bad in [
            "notes/",
            "refs/notes",
            "refs/",
            "refs/heads/",
            "refs/tags/",
            "refs/for/",
            "refs/trails/",
            "refs/heads/evil/",
            "refs/tags/v1/",
        ] {
            let mut config = sample();
            config.git.allowed_ref_namespaces = vec![bad.into()];
            let err = config.validate().unwrap_err().to_string();
            assert!(err.contains(bad), "{bad:?}: {err}");
        }

        // The environment override splits on commas like allowed_domains.
        let mut config = sample();
        config
            .apply_env([(
                "STARFORGE__GIT__ALLOWED_REF_NAMESPACES".to_owned(),
                "refs/notes/, refs/keys/".to_owned(),
            )])
            .unwrap();
        assert_eq!(
            config.git.allowed_ref_namespaces,
            vec!["refs/notes/", "refs/keys/"]
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn init_generated_config_resolves_blobs_under_data_dir() {
        let data = tempfile::tempdir().unwrap();
        let config_path = data.path().join("starforged.toml");
        let returned = crate::init::run(&crate::init::InitOptions {
            config_path: &config_path,
            data_dir: data.path(),
            base_url: "http://127.0.0.1:3000",
            http_addr: "127.0.0.1:3000",
        })
        .unwrap();
        let loaded = Config::load(&config_path).unwrap();
        assert_eq!(loaded.storage.data_dir, returned.storage.data_dir);
        assert!(loaded.blob_dir().starts_with(&loaded.storage.data_dir));
        assert_eq!(loaded.blob_dir(), returned.blob_dir());
    }

    #[test]
    fn sandbox_defaults_and_empty_section() {
        use starforged_core::sandboxes::SandboxProviderKind;
        let config = sample();
        assert_eq!(config.sandbox.provider, SandboxProviderKind::Local);
        assert_eq!(config.sandbox.default_ttl_secs, 3600);
        assert_eq!(
            config.sandbox.local.socket,
            PathBuf::from("/run/starforge/sandboxd.sock")
        );
        // An empty `[sandbox]` section deserializes to the same defaults.
        let text = r#"
server.http_addr = "127.0.0.1:3000"
server.base_url = "http://127.0.0.1:3000"
storage.data_dir = "/srv/starforge"
security.secret_key = "abababababababababababababababababababababababababababababababababab"

[sandbox]
"#;
        let loaded: Config = toml::from_str(text).unwrap();
        assert_eq!(loaded.sandbox, config.sandbox);
    }

    #[test]
    fn ci_section_defaults_parses_and_env_overrides() {
        let config = sample();
        assert_eq!(config.ci.limits.minutes_per_month, 0);
        assert_eq!(config.ci.depot.api_url, "https://api.depot.dev");
        assert!(config.ci.depot.api_token.is_empty());
        // A partial `[ci]` section keeps the defaults for missing keys.
        let text = r#"
server.http_addr = "127.0.0.1:3000"
server.base_url = "http://127.0.0.1:3000"
storage.data_dir = "/srv/starforge"
security.secret_key = "abababababababababababababababababababababababababababababababababab"

[ci.limits]
minutes_per_month = 600
artifact_bytes = 1048576

[ci.depot]
api_token = "sf-test-depot-token"
"#;
        let loaded: Config = toml::from_str(text).unwrap();
        assert_eq!(loaded.ci.limits.minutes_per_month, 600);
        assert_eq!(loaded.ci.limits.artifact_bytes, 1_048_576);
        assert_eq!(loaded.ci.depot.api_url, "https://api.depot.dev");
        assert_eq!(loaded.ci.depot.api_token, "sf-test-depot-token");
        assert!(
            !format!("{:?}", loaded.ci).contains("sf-test-depot-token"),
            "the token stays out of Debug"
        );

        let mut config = sample();
        config
            .apply_env([
                (
                    "STARFORGE__CI__LIMITS__MINUTES_PER_MONTH".to_owned(),
                    "90".to_owned(),
                ),
                (
                    "STARFORGE__CI__DEPOT__API_URL".to_owned(),
                    "http://127.0.0.1:9".to_owned(),
                ),
            ])
            .unwrap();
        assert_eq!(config.ci.limits.minutes_per_month, 90);
        assert_eq!(config.ci.depot.api_url, "http://127.0.0.1:9");
        assert!(
            config
                .apply_env([(
                    "STARFORGE__CI__LIMITS__ARTIFACT_BYTES".to_owned(),
                    "-1".to_owned()
                )])
                .is_err()
        );
    }

    #[test]
    fn sandbox_env_overrides_apply() {
        use starforged_core::sandboxes::SandboxProviderKind;
        let mut config = sample();
        config
            .apply_env([
                ("STARFORGE__SANDBOX__PROVIDER".to_owned(), "e2b".to_owned()),
                (
                    "STARFORGE__SANDBOX__DEFAULT_TTL_SECS".to_owned(),
                    "600".to_owned(),
                ),
                (
                    "STARFORGE__SANDBOX__LOCAL__SOCKET".to_owned(),
                    "/tmp/sbx.sock".to_owned(),
                ),
                (
                    "STARFORGE__SANDBOX__LOCAL__EGRESS__ALLOWLIST".to_owned(),
                    "crates.io, docs.rs".to_owned(),
                ),
                (
                    "STARFORGE__SANDBOX__E2B__API_URL".to_owned(),
                    "https://api.e2b.example".to_owned(),
                ),
                (
                    "STARFORGE__SANDBOX__LIMITS__MAX_CONCURRENT_PER_USER".to_owned(),
                    "3".to_owned(),
                ),
            ])
            .unwrap();
        assert_eq!(config.sandbox.provider, SandboxProviderKind::E2b);
        assert_eq!(config.sandbox.default_ttl_secs, 600);
        assert_eq!(config.sandbox.local.socket, PathBuf::from("/tmp/sbx.sock"));
        assert_eq!(
            config.sandbox.local.egress.allowlist,
            vec!["crates.io".to_owned(), "docs.rs".to_owned()]
        );
        assert_eq!(config.sandbox.e2b.api_url, "https://api.e2b.example");
        assert_eq!(config.sandbox.limits.max_concurrent_per_user, 3);
    }

    #[test]
    fn sandbox_provider_env_rejects_unknown_values() {
        let err = sample()
            .apply_env([(
                "STARFORGE__SANDBOX__PROVIDER".to_owned(),
                "firecracker".to_owned(),
            )])
            .unwrap_err();
        assert!(err.to_string().contains("STARFORGE__SANDBOX__PROVIDER"));
    }
}
