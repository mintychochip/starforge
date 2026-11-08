//! Sandbox provider trait, `[sandbox]` configuration, and the service
//! layer over them (plan M6b B1/B4).
//!
//! The server owns the control plane; a [`SandboxProvider`] owns isolation.
//! v1 ships the local daemon provider (Unix-socket client) and the E2B
//! adapter (`sandboxes_e2b`). [`Core`] methods below enforce
//! `sandbox:run` + `repo_for`, owner/admin/job authorization, network
//! policy, quotas, and audit around the provider calls.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use percent_encoding::percent_encode;
use starforged_db::now;
use starforged_db::sandboxes as db_sandboxes;

use crate::CoreError;
use crate::accounts::User;
use crate::ci::JobPrincipal;
use crate::{Core, CoreResult};
use serde::{Deserialize, Serialize};
pub use starforge_sandbox_protocol as protocol;
pub use starforge_sandbox_protocol::{
    CreateSandboxRequest, ExecChunk, ExecRequest, FileOp, NetworkPolicy, PortUrl, ProviderError,
    SandboxInfo, SandboxState,
};

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
/// destinations. The proxy listen address and the CA directory are
/// `starforge-sandboxd` flags (`--egress-listen`, `--egress-ca-dir`), not
/// server config: the daemon is a separate process and reads only its own
/// flags.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressConfig {
    /// Hosts the proxy (and therefore the sandbox) may reach.
    #[serde(default)]
    pub allowlist: Vec<String>,
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

/// Runtimes the create path accepts in v1. `firecracker` and `kata` are
/// reserved names for later adapters: creating one is refused (422).
pub const KNOWN_RUNTIMES: [&str; 5] = ["podman", "gvisor", "e2b", "firecracker", "kata"];

/// Max total exec output bytes kept for one exec call (stream cap).
pub const MAX_EXEC_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Max one file's content bytes for a write/read through the API.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// One sandbox as the control plane reports it (the API's JSON view).
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxView {
    pub id: String,
    pub state: String,
    pub provider: String,
    pub runtime: String,
    pub template: String,
    pub cpu: f64,
    pub mem_mb: i64,
    pub disk_gb: i64,
    pub owner_id: i64,
    pub repo_id: i64,
    pub job_id: Option<i64>,
    pub ca_fingerprint: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: Option<i64>,
}

/// One row of the runtime capability table (M6b B6): a runtime name, whether
/// the create path can serve it today, whether the name is reserved for a
/// later adapter, and a human-readable note on what backs it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeInfo {
    pub name: &'static str,
    pub available: bool,
    pub reserved: bool,
    pub detail: &'static str,
}

/// One sandbox row for the site-admin page: the control-plane view plus the
/// repository owner's handle and name (so a job link can be built).
#[derive(Debug, Clone, PartialEq)]
pub struct AdminSandbox {
    pub view: SandboxView,
    pub owner: String,
    pub repo: String,
}

/// Who a sandbox call acts for: the PAT user (owner/admin) or the job
/// execution (`JobAuth`). A job caller sees only its own job's sandbox;
/// a user sees sandboxes they own (site admins see everything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxCaller {
    pub user_id: i64,
    pub is_admin: bool,
    pub job_id: Option<i64>,
}

impl SandboxCaller {
    pub fn user(user: &User) -> Self {
        Self {
            user_id: user.id,
            is_admin: user.is_admin,
            job_id: None,
        }
    }

    pub fn job(principal: &JobPrincipal) -> Self {
        Self {
            user_id: principal.user_id,
            is_admin: false,
            job_id: Some(principal.job_id),
        }
    }
}

fn state_str(state: SandboxState) -> &'static str {
    match state {
        SandboxState::Creating => "creating",
        SandboxState::Running => "running",
        SandboxState::Paused => "paused",
        SandboxState::Killed => "killed",
        SandboxState::Error => "error",
    }
}

fn view_of(row: &db_sandboxes::SandboxRow) -> SandboxView {
    SandboxView {
        id: row.external_id.clone(),
        state: row.state.clone(),
        provider: row.provider.clone(),
        runtime: row.runtime.clone(),
        template: row.template.clone(),
        cpu: row.cpu,
        mem_mb: row.mem_mb,
        disk_gb: row.disk_gb,
        owner_id: row.owner_id,
        repo_id: row.repo_id,
        job_id: row.job_id,
        ca_fingerprint: row.ca_fingerprint.clone(),
        created_at: row.created_at,
        expires_at: row.expires_at,
        last_seen_at: row.last_seen_at,
    }
}

/// Maps a provider error onto the control plane's error vocabulary.
fn provider_err(err: ProviderError) -> CoreError {
    match err.code.as_str() {
        "not_found" => CoreError::NotFound,
        "invalid" => CoreError::Invalid(err.message),
        "capacity" | "too_large" => CoreError::RateLimited,
        "unauthorized" => CoreError::Unauthenticated,
        _ => CoreError::Internal(format!("sandbox provider: {}: {}", err.code, err.message)),
    }
}

/// Validates a sandbox-relative path: non-empty (unless `allow_empty`
/// for a listing root), no absolute prefix, no `..` segment, no NUL.
/// Returns the normalized path (`.` for an empty listing root).
fn validate_sandbox_path(path: &str, allow_empty: bool) -> CoreResult<String> {
    if path.is_empty() {
        if allow_empty {
            return Ok(".".to_owned());
        }
        return Err(CoreError::Invalid("path must not be empty".into()));
    }
    if path.len() > 4096 {
        return Err(CoreError::Invalid("path is too long".into()));
    }
    if path.contains('\0') || path.starts_with('/') || path.starts_with('\\') {
        return Err(CoreError::Invalid(format!(
            "path '{path}' must be relative"
        )));
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(CoreError::Invalid(format!("path '{path}' is malformed")));
        }
        if segment == ".." {
            return Err(CoreError::Invalid(format!(
                "path '{path}' must not escape the sandbox workspace"
            )));
        }
    }
    Ok(path.to_owned())
}

/// Encodes one path segment or query value for the provider wire.
/// Only non-unreserved bytes are encoded (RFC 3986): never `-_~.`,
/// so ordinary handles (`sbx-1`) reach the provider unchanged.
pub(crate) fn encode(value: &str) -> String {
    const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    percent_encode(value.as_bytes(), UNRESERVED).to_string()
}

/// The `local` provider: an HTTP client over the sandbox daemon's Unix
/// socket (`Authorization: Bearer <token>`, token read from the token
/// file on every call so a daemon restart's rotation is picked up).
#[derive(Debug, Clone)]
pub struct LocalSandboxProvider {
    socket: PathBuf,
    token_file: PathBuf,
}

impl LocalSandboxProvider {
    pub fn new(socket: PathBuf, token_file: PathBuf) -> Self {
        Self { socket, token_file }
    }

    fn token(&self) -> Result<String, ProviderError> {
        std::fs::read_to_string(&self.token_file)
            .map(|t| t.trim().to_owned())
            .map_err(|e| {
                ProviderError::retryable("unavailable", format!("reading daemon token: {e}"))
            })
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<(u16, Vec<u8>), ProviderError> {
        let token = self.token()?;
        let body_bytes = body
            .map(|b| serde_json::to_vec(b).expect("JSON"))
            .unwrap_or_default();
        let mut stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|e| {
                ProviderError::retryable("unavailable", format!("connecting to sandboxd: {e}"))
            })?;
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body_bytes.len(),
        );
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(unavailable)?;
        stream.write_all(&body_bytes).await.map_err(unavailable)?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.map_err(unavailable)?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| ProviderError::new("unavailable", "malformed daemon response"))?;
        let head_str = String::from_utf8_lossy(&raw[..split]).into_owned();
        let status: u16 = head_str
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ProviderError::new("unavailable", "malformed daemon status"))?;
        let mut body_out = raw[split + 4..].to_vec();
        if head_str
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            body_out = decode_chunked(&body_out);
        }
        Ok((status, body_out))
    }

    async fn json<T>(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, ProviderError>
    where
        T: serde::de::DeserializeOwned,
    {
        let (status, bytes) = self.request(method, path, body).await?;
        if status >= 400 {
            if let Ok(err) = serde_json::from_slice::<ProviderError>(&bytes) {
                return Err(err);
            }
            return Err(ProviderError::new(
                "internal",
                format!("sandboxd answered {status}"),
            ));
        }
        if bytes.is_empty() {
            return Err(ProviderError::new("internal", "empty sandboxd response"));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| ProviderError::new("internal", format!("decoding sandboxd response: {e}")))
    }
}

fn unavailable(e: std::io::Error) -> ProviderError {
    ProviderError::retryable("unavailable", e.to_string())
}

fn decode_chunked(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") {
        let Ok(size) =
            usize::from_str_radix(std::str::from_utf8(&rest[..nl]).unwrap_or("0").trim(), 16)
        else {
            break;
        };
        if size == 0 {
            break;
        }
        let start = nl + 2;
        if start + size > rest.len() {
            break;
        }
        out.extend_from_slice(&rest[start..start + size]);
        rest = &rest[start + size + 2..];
    }
    out
}

impl SandboxProvider for LocalSandboxProvider {
    fn create(
        &self,
        request: CreateSandboxRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let body = serde_json::to_value(&request).expect("JSON");
            self.json("POST", "/sandboxes", Some(&body)).await
        })
    }

    fn get(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json("GET", &format!("/sandboxes/{}", encode(&id)), None)
                .await
        })
    }

    fn kill(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let (status, bytes) = self
                .request("DELETE", &format!("/sandboxes/{}", encode(&id)), None)
                .await?;
            if status >= 400 {
                if let Ok(err) = serde_json::from_slice::<ProviderError>(&bytes) {
                    return Err(err);
                }
                return Err(ProviderError::new(
                    "internal",
                    format!("sandboxd answered {status}"),
                ));
            }
            Ok(())
        })
    }

    fn pause(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json("POST", &format!("/sandboxes/{}/pause", encode(&id)), None)
                .await
        })
    }

    fn resume(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json("POST", &format!("/sandboxes/{}/resume", encode(&id)), None)
                .await
        })
    }

    fn set_timeout(
        &self,
        id: String,
        timeout_s: u64,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let body = serde_json::json!({ "timeout_s": timeout_s });
            self.json(
                "POST",
                &format!("/sandboxes/{}/timeout", encode(&id)),
                Some(&body),
            )
            .await
        })
    }

    fn exec(
        &self,
        id: String,
        request: ExecRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExecChunk>, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let body = serde_json::to_value(&request).expect("JSON");
            self.json(
                "POST",
                &format!("/sandboxes/{}/exec", encode(&id)),
                Some(&body),
            )
            .await
        })
    }

    fn files(
        &self,
        id: String,
        op: FileOp,
    ) -> Pin<Box<dyn Future<Output = Result<String, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            match op {
                FileOp::Read { path } => {
                    let body: serde_json::Value = self
                        .json(
                            "GET",
                            &format!("/sandboxes/{}/files?path={}", encode(&id), encode(&path)),
                            None,
                        )
                        .await?;
                    let content = body["content"].as_str().ok_or_else(|| {
                        ProviderError::new("internal", "file read has no content")
                    })?;
                    let bytes =
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, content)
                            .map_err(|e| {
                                ProviderError::new(
                                    "internal",
                                    format!("decoding file content: {e}"),
                                )
                            })?;
                    String::from_utf8(bytes).map_err(|e| {
                        ProviderError::new("internal", format!("file content is not text: {e}"))
                    })
                }
                FileOp::List { path } => {
                    let body: serde_json::Value = self
                        .json(
                            "GET",
                            &format!(
                                "/sandboxes/{}/files?path={}&op=list",
                                encode(&id),
                                encode(&path)
                            ),
                            None,
                        )
                        .await?;
                    let entries = body["entries"].as_array().ok_or_else(|| {
                        ProviderError::new("internal", "file list has no entries")
                    })?;
                    Ok(entries
                        .iter()
                        .filter_map(|e| e.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"))
                }
                FileOp::Write { path, content } => {
                    let bytes = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        content.as_bytes(),
                    );
                    let body = serde_json::json!({ "path": path, "content": bytes });
                    let _: serde_json::Value = self
                        .json(
                            "PUT",
                            &format!("/sandboxes/{}/files", encode(&id)),
                            Some(&body),
                        )
                        .await?;
                    Ok(String::new())
                }
                FileOp::Delete { path } => {
                    let (status, bytes) = self
                        .request(
                            "DELETE",
                            &format!("/sandboxes/{}/files?path={}", encode(&id), encode(&path)),
                            None,
                        )
                        .await?;
                    if status >= 400 {
                        if let Ok(err) = serde_json::from_slice::<ProviderError>(&bytes) {
                            return Err(err);
                        }
                        return Err(ProviderError::new(
                            "internal",
                            format!("sandboxd answered {status}"),
                        ));
                    }
                    Ok(String::new())
                }
            }
        })
    }

    fn port_url(
        &self,
        id: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortUrl, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json(
                "GET",
                &format!("/sandboxes/{}/ports/{}/url", encode(&id), port),
                None,
            )
            .await
        })
    }
}

impl Core {
    /// The provider for one create: `runtime = "e2b"` selects the E2B
    /// adapter; every other runtime uses the configured provider
    /// (`local` Unix-socket client or the E2B adapter).
    fn sandbox_provider(&self, runtime: &str) -> Box<dyn SandboxProvider> {
        let cfg = &self.config().sandbox;
        if runtime == "e2b" || cfg.provider == SandboxProviderKind::E2b {
            Box::new(crate::sandboxes_e2b::E2bSandboxProvider::new(
                cfg.e2b.api_url.clone(),
                cfg.e2b.api_key.clone(),
            ))
        } else {
            Box::new(LocalSandboxProvider::new(
                cfg.local.socket.clone(),
                cfg.local.token_file.clone(),
            ))
        }
    }

    fn provider_name(runtime: &str, cfg: &SandboxConfig) -> String {
        if runtime == "e2b" || cfg.provider == SandboxProviderKind::E2b {
            "e2b".to_owned()
        } else {
            "local".to_owned()
        }
    }

    /// Owner/admin/job authorization for one sandbox row.
    async fn authorize_sandbox(
        &self,
        row: &db_sandboxes::SandboxRow,
        caller: SandboxCaller,
    ) -> CoreResult<()> {
        if caller.is_admin || row.owner_id == caller.user_id {
            return Ok(());
        }
        if row
            .job_id
            .is_some_and(|job_id| Some(job_id) == caller.job_id)
        {
            return Ok(());
        }
        Err(CoreError::Forbidden)
    }

    async fn sandbox_row(
        &self,
        id: &str,
        caller: SandboxCaller,
    ) -> CoreResult<db_sandboxes::SandboxRow> {
        let row = db_sandboxes::sandbox_by_external_id(self.db(), id)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.authorize_sandbox(&row, caller).await?;
        Ok(row)
    }

    /// Creates a sandbox for `owner/repo` on behalf of `user`. The
    /// caller must already hold the `sandbox:run` scope (enforced by
    /// the API layer); this checks repo readability (`repo_for`),
    /// network policy, quotas, and idempotency, then delegates isolation
    /// to the provider and records the plan row.
    pub async fn create_sandbox(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        job_id: Option<i64>,
        req: CreateSandboxRequest,
    ) -> CoreResult<SandboxView> {
        let caller = SandboxCaller::user(user);
        let access = self.repo_for(Some(user), owner, repo).await?;
        self.create_sandbox_inner(caller, access.repo.id, job_id, req)
            .await
    }

    /// Creates a sandbox for the job's own repo (the `JobAuth` path).
    /// The job was authorized at creation; the user it acts for is the
    /// job's creator, so quotas and ownership land on them.
    pub async fn create_sandbox_for_job(
        &self,
        principal: &JobPrincipal,
        req: CreateSandboxRequest,
    ) -> CoreResult<SandboxView> {
        let caller = SandboxCaller::job(principal);
        self.create_sandbox_inner(caller, principal.repo_id, Some(principal.job_id), req)
            .await
    }

    async fn create_sandbox_inner(
        &self,
        caller: SandboxCaller,
        repo_id: i64,
        job_id: Option<i64>,
        req: CreateSandboxRequest,
    ) -> CoreResult<SandboxView> {
        let runtime = req.runtime.trim().to_ascii_lowercase();
        let runtime = if runtime.is_empty() {
            "podman"
        } else {
            runtime.as_str()
        };
        if !KNOWN_RUNTIMES.contains(&runtime) {
            return Err(CoreError::Invalid(format!("unknown runtime '{runtime}'")));
        }
        if runtime == "firecracker" || runtime == "kata" {
            return Err(CoreError::Invalid(format!(
                "runtime '{runtime}' is not available yet"
            )));
        }
        // Network policy: the caller cannot widen egress. A secret-header
        // binding is honored only for a host the sandbox may reach, and
        // no host may be both allowed and denied.
        for host in &req.network.allow_out {
            if req.network.deny_out.contains(host) {
                return Err(CoreError::Invalid(format!(
                    "host '{host}' is both allowed and denied"
                )));
            }
        }
        let cfg_allowlist = &self.config().sandbox.local.egress.allowlist;
        for host in req.network.secret_headers.keys() {
            if !req.network.allow_out.contains(host) && !cfg_allowlist.contains(host) {
                return Err(CoreError::Invalid(format!(
                    "secret header for '{host}' requires the host to be allow-listed"
                )));
            }
        }
        // Idempotent replay returns the original sandbox.
        if let Some(key) = req.idempotency_key.as_deref().filter(|k| !k.is_empty()) {
            let existing =
                db_sandboxes::sandbox_by_idempotency(self.db(), caller.user_id, key).await?;
            if let Some(existing) = existing {
                self.authorize_sandbox(&existing, caller).await?;
                return Ok(view_of(&existing));
            }
        }
        let now_ts = now();
        let ttl = if req.timeout_s == 0 {
            self.config().sandbox.default_ttl_secs
        } else {
            req.timeout_s
        };
        if ttl == 0 {
            return Err(CoreError::Invalid("timeout_s must not be 0".into()));
        }
        // Quotas: concurrent sandboxes per user/repo, sandbox-seconds
        // per user per hour. `0` disables a limit.
        let limits = &self.config().sandbox.limits;
        let window_start = now_ts - now_ts.rem_euclid(3600);
        if limits.max_concurrent_per_user > 0
            && db_sandboxes::count_active_by_owner(self.db(), caller.user_id).await?
                >= limits.max_concurrent_per_user as i64
        {
            return Err(CoreError::RateLimited);
        }
        if limits.max_concurrent_per_repo > 0
            && db_sandboxes::count_active_by_repo(self.db(), repo_id).await?
                >= limits.max_concurrent_per_repo as i64
        {
            return Err(CoreError::RateLimited);
        }
        if limits.sandbox_seconds_per_hour > 0 {
            let used =
                db_sandboxes::usage_seconds_since(self.db(), caller.user_id, window_start).await?;
            if used + ttl as i64 > limits.sandbox_seconds_per_hour as i64 {
                return Err(CoreError::RateLimited);
            }
        }
        let provider_name = Self::provider_name(runtime, &self.config().sandbox);
        let info = self
            .sandbox_provider(runtime)
            .create(req.clone())
            .await
            .map_err(provider_err)?;
        let metadata = serde_json::to_string(&req.metadata).unwrap_or_else(|_| "{}".into());
        let expires_at = now_ts + ttl as i64;
        let stored = match db_sandboxes::insert_sandbox(
            self.db(),
            &db_sandboxes::NewSandbox {
                provider: &provider_name,
                runtime,
                external_id: &info.id,
                job_id,
                owner_id: caller.user_id,
                repo_id,
                state: state_str(info.state),
                template: &req.template,
                cpu: req.cpu,
                mem_mb: req.mem_mb as i64,
                disk_gb: req.disk_gb as i64,
                idempotency_key: req.idempotency_key.as_deref(),
                ca_fingerprint: None,
                metadata: &metadata,
                created_at: now_ts,
                expires_at,
            },
        )
        .await
        {
            Ok(row) => row,
            Err(err) if err.is_unique_violation() => {
                let key = req.idempotency_key.clone().unwrap_or_default();
                db_sandboxes::sandbox_by_idempotency(self.db(), caller.user_id, &key)
                    .await?
                    .unwrap_or_else(|| db_sandboxes::SandboxRow {
                        id: 0,
                        provider: provider_name.clone(),
                        runtime: runtime.to_owned(),
                        external_id: info.id.clone(),
                        job_id,
                        owner_id: caller.user_id,
                        repo_id,
                        state: state_str(info.state).to_owned(),
                        template: req.template.clone(),
                        cpu: req.cpu,
                        mem_mb: req.mem_mb as i64,
                        disk_gb: req.disk_gb as i64,
                        idempotency_key: req.idempotency_key.clone(),
                        ca_fingerprint: None,
                        metadata,
                        created_at: now_ts,
                        expires_at,
                        last_seen_at: None,
                    })
            }
            Err(err) => return Err(err.into()),
        };
        db_sandboxes::record_usage(
            self.db(),
            caller.user_id,
            repo_id,
            window_start,
            ttl as i64,
            now_ts,
        )
        .await?;
        self.audit(
            Some(caller.user_id),
            "sandbox.create",
            &format!("sandbox:{}", info.id),
            &format!("runtime={runtime} template={}", req.template),
        )
        .await?;
        Ok(view_of(&stored))
    }

    /// Fetches one sandbox (provider state refresh) with owner/admin/job
    /// authorization.
    pub async fn get_sandbox(&self, caller: SandboxCaller, id: &str) -> CoreResult<SandboxView> {
        let row = self.sandbox_row(id, caller).await?;
        let info = self
            .sandbox_provider(&row.runtime)
            .get(id.to_owned())
            .await
            .map_err(provider_err)?;
        db_sandboxes::update_sandbox_state(self.db(), id, state_str(info.state), now()).await?;
        let mut view = view_of(&row);
        view.state = state_str(info.state).to_owned();
        view.last_seen_at = Some(now());
        Ok(view)
    }

    /// Kills a sandbox (idempotent) and audits the kill.
    pub async fn kill_sandbox(&self, caller: SandboxCaller, id: &str) -> CoreResult<SandboxView> {
        let row = self.sandbox_row(id, caller).await?;
        self.sandbox_provider(&row.runtime)
            .kill(id.to_owned())
            .await
            .map_err(provider_err)?;
        db_sandboxes::update_sandbox_state(self.db(), id, "killed", now()).await?;
        self.audit(
            Some(caller.user_id),
            "sandbox.kill",
            &format!("sandbox:{id}"),
            "",
        )
        .await?;
        let mut view = view_of(&row);
        view.state = "killed".to_owned();
        Ok(view)
    }

    /// Pauses a running sandbox.
    pub async fn pause_sandbox(&self, caller: SandboxCaller, id: &str) -> CoreResult<SandboxView> {
        let row = self.sandbox_row(id, caller).await?;
        let info = self
            .sandbox_provider(&row.runtime)
            .pause(id.to_owned())
            .await
            .map_err(provider_err)?;
        db_sandboxes::update_sandbox_state(self.db(), id, state_str(info.state), now()).await?;
        let mut view = view_of(&row);
        view.state = state_str(info.state).to_owned();
        Ok(view)
    }

    /// Resumes a paused sandbox.
    pub async fn resume_sandbox(&self, caller: SandboxCaller, id: &str) -> CoreResult<SandboxView> {
        let row = self.sandbox_row(id, caller).await?;
        let info = self
            .sandbox_provider(&row.runtime)
            .resume(id.to_owned())
            .await
            .map_err(provider_err)?;
        db_sandboxes::update_sandbox_state(self.db(), id, state_str(info.state), now()).await?;
        let mut view = view_of(&row);
        view.state = state_str(info.state).to_owned();
        Ok(view)
    }

    /// Resets a sandbox's lifetime cap and the stored expiry.
    pub async fn set_sandbox_timeout(
        &self,
        caller: SandboxCaller,
        id: &str,
        timeout_s: u64,
    ) -> CoreResult<SandboxView> {
        if timeout_s == 0 {
            return Err(CoreError::Invalid("timeout_s must not be 0".into()));
        }
        let row = self.sandbox_row(id, caller).await?;
        let info = self
            .sandbox_provider(&row.runtime)
            .set_timeout(id.to_owned(), timeout_s)
            .await
            .map_err(provider_err)?;
        db_sandboxes::update_sandbox_expires_at(self.db(), id, now() + timeout_s as i64).await?;
        let mut view = view_of(&row);
        view.state = state_str(info.state).to_owned();
        view.expires_at = now() + timeout_s as i64;
        Ok(view)
    }

    /// Runs one command, returning the streamed chunks (capped at
    /// [`MAX_EXEC_OUTPUT_BYTES`] with a truncation marker).
    pub async fn exec_sandbox(
        &self,
        caller: SandboxCaller,
        id: &str,
        req: ExecRequest,
    ) -> CoreResult<Vec<ExecChunk>> {
        if req.command.is_empty() {
            return Err(CoreError::Invalid("command must not be empty".into()));
        }
        if req.command.iter().any(|part| part.contains('\0')) {
            return Err(CoreError::Invalid("command argument contains NUL".into()));
        }
        let row = self.sandbox_row(id, caller).await?;
        let chunks = self
            .sandbox_provider(&row.runtime)
            .exec(id.to_owned(), req)
            .await
            .map_err(provider_err)?;
        let mut out = Vec::new();
        let mut total = 0usize;
        for chunk in chunks {
            let len = match &chunk {
                ExecChunk::Stdout { data } | ExecChunk::Stderr { data } => data.len(),
                ExecChunk::Exit { .. } => 0,
            };
            if total + len > MAX_EXEC_OUTPUT_BYTES {
                out.push(ExecChunk::Stderr {
                    data: format!(
                        "[starforge: sandbox exec output truncated at {MAX_EXEC_OUTPUT_BYTES} bytes]"
                    ),
                });
                break;
            }
            total += len;
            out.push(chunk);
        }
        Ok(out)
    }

    /// Reads/writes/lists/deletes one file. Paths are sandbox-relative;
    /// traversal is refused before the provider is ever called.
    pub async fn sandbox_file(
        &self,
        caller: SandboxCaller,
        id: &str,
        op: FileOp,
    ) -> CoreResult<String> {
        match &op {
            FileOp::Read { path } => {
                validate_sandbox_path(path, false)?;
            }
            FileOp::List { path } => {
                validate_sandbox_path(path, true)?;
            }
            FileOp::Write { path, content } => {
                validate_sandbox_path(path, false)?;
                if content.len() as u64 > MAX_FILE_BYTES {
                    return Err(CoreError::Invalid(format!(
                        "file content exceeds {MAX_FILE_BYTES} bytes"
                    )));
                }
            }
            FileOp::Delete { path } => {
                validate_sandbox_path(path, false)?;
            }
        }
        let row = self.sandbox_row(id, caller).await?;
        let content = self
            .sandbox_provider(&row.runtime)
            .files(id.to_owned(), op)
            .await
            .map_err(provider_err)?;
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err(CoreError::Invalid(format!(
                "file content exceeds {MAX_FILE_BYTES} bytes"
            )));
        }
        Ok(content)
    }

    /// A signed, short-lived URL for one sandbox port.
    pub async fn sandbox_port_url(
        &self,
        caller: SandboxCaller,
        id: &str,
        port: u16,
    ) -> CoreResult<PortUrl> {
        if port == 0 {
            return Err(CoreError::Invalid("port must not be 0".into()));
        }
        let row = self.sandbox_row(id, caller).await?;
        self.sandbox_provider(&row.runtime)
            .port_url(id.to_owned(), port)
            .await
            .map_err(provider_err)
    }

    /// The control plane's sandbox rows for one owner (newest first).
    pub async fn list_sandboxes(
        &self,
        caller: SandboxCaller,
        limit: i64,
    ) -> CoreResult<Vec<SandboxView>> {
        let _ = caller.is_admin;
        let rows =
            db_sandboxes::sandboxes_for_owner(self.db(), caller.user_id, limit.clamp(1, 200))
                .await?;
        Ok(rows.iter().map(view_of).collect())
    }

    /// The runtime capability table (M6b B6): which runtimes the create
    /// path can serve today. `podman`, `gvisor`, and `e2b` are available;
    /// `firecracker` and `kata` are reserved names for later adapters and a
    /// create naming one is refused (422) by [`Core::create_sandbox_inner`].
    pub fn sandbox_runtimes(&self) -> Vec<RuntimeInfo> {
        vec![
            RuntimeInfo {
                name: "podman",
                available: true,
                reserved: false,
                detail: "Rootless containers via the local sandbox daemon (default)",
            },
            RuntimeInfo {
                name: "gvisor",
                available: true,
                reserved: false,
                detail: "runsc (gVisor) via the local sandbox daemon (opt-in runtime)",
            },
            RuntimeInfo {
                name: "e2b",
                available: true,
                reserved: false,
                detail: "Remote cloud sandboxes via the E2B adapter",
            },
            RuntimeInfo {
                name: "firecracker",
                available: false,
                reserved: true,
                detail: "Reserved for a later provider adapter",
            },
            RuntimeInfo {
                name: "kata",
                available: false,
                reserved: true,
                detail: "Reserved for a later Kubernetes adapter",
            },
        ]
    }

    /// Every sandbox, newest first, for the site-admin page. Only site
    /// admins may list; ownership is irrelevant here (callers are
    /// [`RequireAdmin`]-gated in the web layer, this is defense in depth).
    pub async fn list_all_sandboxes(
        &self,
        admin: &User,
        limit: i64,
    ) -> CoreResult<Vec<AdminSandbox>> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        let rows = db_sandboxes::list_all_sandboxes(self.db(), limit.clamp(1, 200)).await?;
        Ok(rows
            .into_iter()
            .map(|(row, owner, repo)| AdminSandbox {
                view: view_of(&row),
                owner,
                repo,
            })
            .collect())
    }

    /// Kills one sandbox as a site admin (B5): admins may kill a sandbox
    /// they do not own, and the kill is audited like any other.
    pub async fn kill_sandbox_admin(&self, admin: &User, id: &str) -> CoreResult<SandboxView> {
        if !admin.is_admin {
            return Err(CoreError::Forbidden);
        }
        self.kill_sandbox(
            SandboxCaller {
                user_id: admin.id,
                is_admin: true,
                job_id: None,
            },
            id,
        )
        .await
    }

    /// Kills every sandbox past its expiry and records it `killed`
    /// (M6b B5). The hourly cleanup calls this; it is also safe to call
    /// directly. A provider that is unreachable does not pin the record:
    /// the best-effort kill failure is logged and the row is still marked
    /// killed, so a dead daemon cannot leak control-plane rows forever.
    pub async fn gc_expired_sandboxes(&self) -> CoreResult<Vec<String>> {
        let ids = db_sandboxes::expired_sandbox_ids(self.db(), now(), 100).await?;
        let mut killed = Vec::new();
        for id in ids {
            let Some(row) = db_sandboxes::sandbox_by_external_id(self.db(), &id).await? else {
                continue;
            };
            if let Err(err) = self.sandbox_provider(&row.runtime).kill(id.clone()).await {
                tracing::warn!(sandbox = %id, error = %err, "sandbox GC: provider kill failed; marking killed anyway");
            }
            db_sandboxes::update_sandbox_state(self.db(), &id, "killed", now()).await?;
            killed.push(id);
        }
        Ok(killed)
    }
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

    #[test]
    fn sandbox_paths_reject_traversal() {
        assert_eq!(validate_sandbox_path("a/b.txt", false).unwrap(), "a/b.txt");
        assert_eq!(validate_sandbox_path(".", true).unwrap(), ".");
        for bad in ["", "/etc/passwd", "../secret", "a/../b", "a//b", "a\0b"] {
            assert!(
                validate_sandbox_path(bad, false).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(validate_sandbox_path("", false).is_err());
        assert!(validate_sandbox_path("", true).is_ok());
    }

    #[tokio::test]
    async fn local_provider_reports_missing_socket() {
        let provider = LocalSandboxProvider::new(
            PathBuf::from("/nonexistent/sandboxd.sock"),
            PathBuf::from("/nonexistent/sandboxd.token"),
        );
        let err = provider.get("sbx-1".into()).await.unwrap_err();
        assert_eq!(err.code, "unavailable");
    }
}
