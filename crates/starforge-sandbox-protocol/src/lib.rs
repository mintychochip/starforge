//! Starforge sandbox provider wire types (plan M6b B1).
//!
//! These types are shared by the server (`starforged-core`) and by sandbox
//! provider implementations (the local `starforge-sandboxd` daemon and the
//! server-side E2B adapter). The crate is `MIT OR Apache-2.0` and must not
//! depend on any `starforged-*` crate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Egress policy for a sandbox. Outbound destinations are denied by default;
/// `allow_out` lists the only hosts a sandbox may reach, `deny_out` lists
/// hosts that stay denied even when an allowlist entry would otherwise match,
/// and `secret_headers` names the header the egress proxy injects (by host)
/// for a bound secret. Secret *values* never appear on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow_out: Vec<String>,
    #[serde(default)]
    pub deny_out: Vec<String>,
    #[serde(default)]
    pub secret_headers: BTreeMap<String, String>,
    /// The forge's own `host:port` as the server sees it (IPv6 bracketed,
    /// e.g. `[::1]:3000`). Only the server sets it, on the job sandbox
    /// create; the public sandbox API never accepts it from callers.
    /// The daemon treats it as the ONE allow entry that may resolve to
    /// a loopback/private address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge: Option<String>,
}

/// One secret header the egress proxy injects for an allowlisted host.
/// The value travels only from the server to the local daemon over the
/// trusted Unix socket; it never enters the sandbox. `Debug` redacts it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBindingWire {
    /// Exact destination host the header is bound to.
    pub host: String,
    /// Header name to inject (e.g. `Authorization`).
    pub header: String,
    /// Header value; never logged.
    pub value: String,
}

impl std::fmt::Debug for SecretBindingWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBindingWire")
            .field("host", &self.host)
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Create a sandbox (E2B-shaped, plan M6b B1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CreateSandboxRequest {
    /// Runtime to run on: `podman`, `gvisor`, `e2b`, `firecracker`, or `kata`.
    #[serde(default)]
    pub runtime: String,
    /// Image/template to boot, e.g. `docker.io/library/rust:1.85` or
    /// `starforge/rust`.
    #[serde(default)]
    pub template: String,
    /// Lifetime cap in seconds. `0` means "server default".
    #[serde(default)]
    pub timeout_s: u64,
    /// Requested CPUs (fractional allowed). `0` means provider default.
    #[serde(default)]
    pub cpu: f64,
    /// Requested memory in MiB. `0` means provider default.
    #[serde(default)]
    pub mem_mb: u64,
    /// Requested root disk in GiB. `0` means provider default.
    #[serde(default)]
    pub disk_gb: u64,
    /// Environment variables injected at create time.
    #[serde(default)]
    pub envs: BTreeMap<String, String>,
    /// Egress policy.
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Caller metadata (e.g. `job_id`, `trail_id`).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Idempotency key; a retry with the same key returns the same sandbox.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Secret header bindings the server resolved for a job sandbox. The
    /// public sandbox API does not accept this field; only the server's
    /// local provider fills it. Values never enter the sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_bindings: Vec<SecretBindingWire>,
    /// Set by the local daemon before it creates the container: whether
    /// egress is provisioned (the container then gets a network that can
    /// reach the host-side proxy). Not part of the public API.
    #[serde(default)]
    pub network_enabled: bool,
}

/// Lifecycle state of a sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    #[default]
    Creating,
    Running,
    Paused,
    Killed,
    Error,
}

/// A sandbox handle as returned by the provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub state: SandboxState,
    /// Runtime the sandbox is (or was) running on.
    pub runtime: String,
    /// Expiry as an RFC 3339 timestamp, if the provider reports one.
    pub expires_at: Option<String>,
    /// Provider that owns the sandbox (`local`, `e2b`, …).
    pub provider: String,
}

/// One command to run inside a sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Command and arguments (argv form; no shell is assumed).
    #[serde(default)]
    pub command: Vec<String>,
    /// Working directory inside the sandbox. `None` uses the sandbox default.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Extra environment for this exec, merged over the create-time envs.
    #[serde(default)]
    pub envs: BTreeMap<String, String>,
    /// Per-exec timeout in seconds. `0` means "sandbox default".
    #[serde(default)]
    pub timeout_s: u64,
}

/// One chunk of exec output (or the terminal exit event).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stream", rename_all = "snake_case")]
pub enum ExecChunk {
    Stdout { data: String },
    Stderr { data: String },
    Exit { code: i32 },
}

/// A file operation inside a sandbox. Paths are relative to the sandbox
/// workspace; the provider rejects absolute paths and `..` escapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FileOp {
    Read { path: String },
    Write { path: String, content: String },
    List { path: String },
    Delete { path: String },
}

/// A signed, short-lived URL exposing one sandbox port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortUrl {
    pub url: String,
    /// Port the URL targets, if the provider reports it.
    #[serde(default)]
    pub port: u16,
    /// Expiry as an RFC 3339 timestamp, if the provider reports one.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// An error from a sandbox provider.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("{code}: {message}")]
pub struct ProviderError {
    /// Machine-readable code, e.g. `not_found`, `capacity`, `timeout`.
    pub code: String,
    /// Human-readable detail (never contains secrets).
    pub message: String,
    /// Whether the caller may retry.
    #[serde(default)]
    pub retryable: bool,
}

impl ProviderError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn retryable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trips<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).unwrap();
        let back: T = serde_json::from_str(&json).unwrap();
        assert_eq!(value, &back);
    }

    #[test]
    fn create_sandbox_request_round_trips() {
        let request = CreateSandboxRequest {
            runtime: "podman".to_owned(),
            template: "docker.io/library/rust:1.85".to_owned(),
            timeout_s: 1800,
            cpu: 2.0,
            mem_mb: 4096,
            disk_gb: 10,
            envs: BTreeMap::from([("RUST_BACKTRACE".to_owned(), "1".to_owned())]),
            network: NetworkPolicy {
                allow_out: vec!["crates.io".to_owned()],
                deny_out: vec!["evil.example".to_owned()],
                secret_headers: BTreeMap::from([(
                    "api.github.com".to_owned(),
                    "Authorization".to_owned(),
                )]),
                forge: None,
            },
            metadata: BTreeMap::from([("job_id".to_owned(), "42".to_owned())]),
            idempotency_key: Some("key-1".to_owned()),
            secret_bindings: vec![SecretBindingWire {
                host: "api.github.com".to_owned(),
                header: "Authorization".to_owned(),
                value: "sf-secret-value".to_owned(),
            }],
            network_enabled: true,
        };
        round_trips(&request);
        let debug = format!("{request:?}");
        assert!(!debug.contains("sf-secret-value"), "debug: {debug}");
        assert!(debug.contains("<redacted>"), "debug: {debug}");
    }

    #[test]
    fn create_sandbox_request_minimal_defaults() {
        let json = r#"{"runtime":"e2b","template":"starforge/rust"}"#;
        let request: CreateSandboxRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.runtime, "e2b");
        assert_eq!(request.timeout_s, 0);
        assert!(request.envs.is_empty());
        assert!(request.metadata.is_empty());
        assert_eq!(request.idempotency_key, None);
    }

    #[test]
    fn sandbox_info_round_trips() {
        let info = SandboxInfo {
            id: "sbx_1".to_owned(),
            state: SandboxState::Running,
            runtime: "podman".to_owned(),
            expires_at: Some("2026-11-06T12:00:00Z".to_owned()),
            provider: "local".to_owned(),
        };
        round_trips(&info);
    }

    #[test]
    fn sandbox_state_serde_names() {
        for (state, name) in [
            (SandboxState::Creating, "creating"),
            (SandboxState::Running, "running"),
            (SandboxState::Paused, "paused"),
            (SandboxState::Killed, "killed"),
            (SandboxState::Error, "error"),
        ] {
            round_trips(&state);
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{name}\"")
            );
        }
    }

    #[test]
    fn exec_request_and_chunks_round_trip() {
        let request = ExecRequest {
            command: vec!["cargo".to_owned(), "test".to_owned()],
            cwd: Some("/workspace".to_owned()),
            envs: BTreeMap::from([("CI".to_owned(), "1".to_owned())]),
            timeout_s: 60,
        };
        round_trips(&request);

        round_trips(&ExecChunk::Stdout {
            data: "ok\n".to_owned(),
        });
        round_trips(&ExecChunk::Stderr {
            data: "warn\n".to_owned(),
        });
        round_trips(&ExecChunk::Exit { code: 0 });
        round_trips(&ExecChunk::Exit { code: 1 });
    }

    #[test]
    fn file_op_round_trips() {
        round_trips(&FileOp::Read {
            path: "src/lib.rs".to_owned(),
        });
        round_trips(&FileOp::Write {
            path: "a.txt".to_owned(),
            content: "hello".to_owned(),
        });
        round_trips(&FileOp::List {
            path: ".".to_owned(),
        });
        round_trips(&FileOp::Delete {
            path: "a.txt".to_owned(),
        });
    }

    #[test]
    fn port_url_round_trips() {
        let url = PortUrl {
            url: "https://sbx-1.example.com:8080".to_owned(),
            port: 8080,
            expires_at: Some("2026-11-06T12:05:00Z".to_owned()),
        };
        round_trips(&url);
    }

    #[test]
    fn provider_error_round_trips() {
        let err = ProviderError::retryable("capacity", "provider is busy");
        round_trips(&err);
        assert_eq!(err.to_string(), "capacity: provider is busy");
        assert!(err.retryable);

        let plain = ProviderError::new("not_found", "no such sandbox");
        round_trips(&plain);
        assert!(!plain.retryable);
    }
}
