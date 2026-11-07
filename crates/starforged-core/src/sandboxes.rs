//! Sandbox provider trait and `[sandbox]` configuration (plan M6b B1).
//!
//! The server owns the control plane; a [`SandboxProvider`] owns isolation.
//! v1 ships the local daemon provider and the E2B adapter behind this trait;
//! this module only declares the trait and the config — no provider
//! implementation yet.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use starforge_sandbox_protocol::{
    CreateSandboxRequest, ExecChunk, ExecRequest, FileOp, PortUrl, ProviderError, SandboxInfo,
};

pub use starforge_sandbox_protocol as protocol;

/// Which sandbox provider the server talks to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProviderKind {
    #[default]
    Local,
    E2b,
}

/// The `[sandbox]` section. Missing section (or any missing key) defaults
/// cleanly so old `starforged.toml` files keep working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Provider to use: `local` (rootless containers via `starforge-sandboxd`)
    /// or `e2b` (remote cloud).
    #[serde(default)]
    pub provider: SandboxProviderKind,
    /// Settings for the `local` provider.
    #[serde(default)]
    pub local: LocalSandboxConfig,
    /// Settings for the `e2b` provider.
    #[serde(default)]
    pub e2b: E2bSandboxConfig,
    /// Admission limits (all `0`-disabled).
    #[serde(default)]
    pub limits: SandboxLimits,
    /// Default sandbox lifetime cap in seconds when a request does not carry
    /// `timeout_s` (default 3600).
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            provider: SandboxProviderKind::default(),
            local: LocalSandboxConfig::default(),
            e2b: E2bSandboxConfig::default(),
            limits: SandboxLimits::default(),
            default_ttl_secs: default_ttl_secs(),
        }
    }
}

fn default_ttl_secs() -> u64 {
    3600
}

/// Settings for the `local` provider (the `starforge-sandboxd` daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSandboxConfig {
    /// Unix socket the sandbox daemon listens on.
    #[serde(default = "default_local_socket")]
    pub socket: PathBuf,
    /// File holding the daemon auth token (mode `0600`); rotates on restart.
    #[serde(default = "default_local_token_file")]
    pub token_file: PathBuf,
    /// Egress-proxy settings.
    #[serde(default)]
    pub egress: EgressConfig,
}

impl Default for LocalSandboxConfig {
    fn default() -> Self {
        Self {
            socket: default_local_socket(),
            token_file: default_local_token_file(),
            egress: EgressConfig::default(),
        }
    }
}

fn default_local_socket() -> PathBuf {
    PathBuf::from("/run/starforge/sandboxd.sock")
}

fn default_local_token_file() -> PathBuf {
    PathBuf::from("/run/starforge/sandboxd.token")
}

/// Egress-proxy settings for the local provider. The sandbox has no direct
/// egress; its outbound HTTPS goes through this proxy, which terminates TLS
/// with a per-sandbox CA and injects secret headers only for allowlisted
/// destinations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressConfig {
    /// Address the egress proxy listens on (inside the provider host).
    #[serde(default = "default_egress_proxy_listen")]
    pub proxy_listen: String,
    /// Directory holding per-sandbox CA keys (mode `0600`, destroyed with
    /// the sandbox).
    #[serde(default = "default_egress_ca_dir")]
    pub ca_dir: PathBuf,
    /// Hosts the proxy (and therefore the sandbox) may reach.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            proxy_listen: default_egress_proxy_listen(),
            ca_dir: default_egress_ca_dir(),
            allowlist: Vec::new(),
        }
    }
}

fn default_egress_proxy_listen() -> String {
    "127.0.0.1:8888".to_owned()
}

fn default_egress_ca_dir() -> PathBuf {
    PathBuf::from("/run/starforge/sandbox-ca")
}

/// Settings for the `e2b` provider (a `reqwest` client; the API key is
/// sealed in config or a secret row).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2bSandboxConfig {
    /// Base URL of the E2B API.
    #[serde(default = "default_e2b_api_url")]
    pub api_url: String,
    /// E2B API key. Never logged or rendered in `Debug`.
    #[serde(default)]
    pub api_key: String,
}

impl std::fmt::Debug for E2bSandboxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E2bSandboxConfig")
            .field("api_url", &self.api_url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl Default for E2bSandboxConfig {
    fn default() -> Self {
        Self {
            api_url: default_e2b_api_url(),
            api_key: String::new(),
        }
    }
}

fn default_e2b_api_url() -> String {
    "https://api.e2b.dev".to_owned()
}

/// Admission limits for sandboxes. Every limit is `0`-disables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxLimits {
    /// Concurrent sandboxes per user (`0` = unlimited).
    #[serde(default)]
    pub max_concurrent_per_user: u64,
    /// Concurrent sandboxes per repository (`0` = unlimited).
    #[serde(default)]
    pub max_concurrent_per_repo: u64,
    /// Sandbox-seconds per user per hour (`0` = unlimited).
    #[serde(default)]
    pub sandbox_seconds_per_hour: u64,
}

/// A sandbox provider: the server-side seam over isolation backends.
///
/// Implementations are external to `starforged-core` (the local daemon
/// client and the E2B adapter). All methods take owned values so the trait
/// stays object-safe with [`Send`] futures.
pub trait SandboxProvider: Send + Sync {
    /// Create a sandbox. `idempotency_key` retries return the same sandbox.
    fn create(
        &self,
        request: CreateSandboxRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>>;
    /// Fetch one sandbox's state (and expiry).
    fn get(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>>;
    /// Kill a sandbox; killing a dead sandbox is a no-op.
    fn kill(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>>;
    /// Pause a running sandbox.
    fn pause(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>>;
    /// Resume a paused sandbox.
    fn resume(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>>;
    /// Reset a sandbox's lifetime cap, in seconds.
    fn set_timeout(
        &self,
        id: String,
        timeout_s: u64,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>>;
    /// Run one command; returns the streamed stdout/stderr chunks plus the
    /// terminal exit event.
    fn exec(
        &self,
        id: String,
        request: ExecRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExecChunk>, ProviderError>> + Send + '_>>;
    /// Read/write/list/delete one file. Returns file content for
    /// [`FileOp::Read`], a listing for [`FileOp::List`], and an empty string
    /// for writes and deletes.
    fn files(
        &self,
        id: String,
        op: FileOp,
    ) -> Pin<Box<dyn Future<Output = Result<String, ProviderError>> + Send + '_>>;
    /// A signed, short-lived URL for one sandbox port.
    fn port_url(
        &self,
        id: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortUrl, ProviderError>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        let config = SandboxConfig::default();
        assert_eq!(config.provider, SandboxProviderKind::Local);
        assert_eq!(
            config.local.socket,
            PathBuf::from("/run/starforge/sandboxd.sock")
        );
        assert_eq!(
            config.local.token_file,
            PathBuf::from("/run/starforge/sandboxd.token")
        );
        assert_eq!(config.local.egress.proxy_listen, "127.0.0.1:8888");
        assert!(config.local.egress.allowlist.is_empty());
        assert_eq!(config.e2b.api_url, "https://api.e2b.dev");
        assert_eq!(config.default_ttl_secs, 3600);
        assert_eq!(config.limits.max_concurrent_per_user, 0);
    }

    #[test]
    fn empty_table_deserializes_to_defaults() {
        let config: SandboxConfig = toml::from_str("").unwrap();
        assert_eq!(config, SandboxConfig::default());
    }

    #[test]
    fn full_table_deserializes() {
        let text = r#"
provider = "e2b"
default_ttl_secs = 600

[local]
socket = "/tmp/sbx.sock"
token_file = "/tmp/sbx.token"

[local.egress]
proxy_listen = "127.0.0.1:9000"
ca_dir = "/tmp/ca"
allowlist = ["crates.io"]

[e2b]
api_url = "https://api.e2b.example"
api_key = "secret-key"

[limits]
max_concurrent_per_user = 3
sandbox_seconds_per_hour = 1800
"#;
        let config: SandboxConfig = toml::from_str(text).unwrap();
        assert_eq!(config.provider, SandboxProviderKind::E2b);
        assert_eq!(config.default_ttl_secs, 600);
        assert_eq!(config.local.socket, PathBuf::from("/tmp/sbx.sock"));
        assert_eq!(config.local.egress.allowlist, vec!["crates.io".to_owned()]);
        assert_eq!(config.e2b.api_url, "https://api.e2b.example");
        assert_eq!(config.e2b.api_key, "secret-key");
        assert_eq!(config.limits.max_concurrent_per_user, 3);
        assert_eq!(config.limits.sandbox_seconds_per_hour, 1800);
    }

    #[test]
    fn api_key_never_renders_in_debug() {
        let config = E2bSandboxConfig {
            api_url: "https://api.e2b.dev".to_owned(),
            api_key: "super-secret".to_owned(),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
    }
}
