//! Starforge CI runner client/executor (plan M6d D4).
//!
//! The runner long-polls `POST /runners/jobs/request`, then per job: mints
//! the short-lived git credential, creates a sandbox through the server
//! sandbox API (using the per-job token), clones/checks out the commit in
//! the sandbox, runs the job commands, streams logs with `Content-Range`,
//! runs `starforge sync` in the sandbox, uploads artifacts
//! (authorize + PUT), and finishes with state/exit/checksum/session ULIDs.
//!
//! Secrets (runner token, job token, git credential) are never logged or
//! traced: every log chunk is scrubbed of known secret values before it is
//! sent. `Job-Status: canceled` and stale-fence `409` are handled by
//! killing the sandbox and stopping.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use starforge_sandbox_protocol::{CreateSandboxRequest, ExecChunk, ExecRequest, NetworkPolicy};

pub const FENCE_HEADER: &str = "x-starforge-fence";
pub const JOB_STATUS_HEADER: &str = "job-status";
/// Max log chunk sent per trace request.
pub const TRACE_CHUNK: usize = 64 * 1024;
/// Lease heartbeat interval; the server's claim lease is 60 seconds.
pub const HEARTBEAT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Server base URL, e.g. `https://forge.example.com` (no trailing slash).
    pub server_url: String,
    /// Runner auth token (`sfr_…`). Never logged.
    pub token: String,
    /// Runner labels offered on claim.
    pub labels: Vec<String>,
    /// Sandbox runtime for created sandboxes (e.g. `podman`, `e2b`).
    pub runtime: String,
    /// Max concurrent jobs.
    pub concurrency: usize,
    /// Long-poll claim timeout: how long one claim request waits server-side.
    pub poll_timeout: Duration,
    /// Git clone URL for the repo under test. Empty means "skip the
    /// clone/checkout step" (sandbox image pre-populates the worktree).
    pub repo_url: String,
}

impl RunnerConfig {
    pub fn new(server_url: &str, token: impl Into<String>) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_owned(),
            token: token.into(),
            labels: Vec::new(),
            runtime: "podman".to_owned(),
            concurrency: 1,
            poll_timeout: Duration::from_secs(50),
            repo_url: String::new(),
        }
    }

    /// Human-readable plan used by `--dry-run`. Contains no secrets.
    pub fn plan_text(&self) -> String {
        format!(
            "runner plan (dry run)\nserver: {}\nlabels: {}\nruntime: {}\nconcurrency: {}\npoll timeout: {}s\nsteps: claim -> git-credential -> create sandbox -> clone/checkout -> run commands -> trace logs -> starforge sync -> upload artifacts -> finish",
            self.server_url,
            if self.labels.is_empty() {
                "(none)".to_owned()
            } else {
                self.labels.join(",")
            },
            self.runtime,
            self.concurrency,
            self.poll_timeout.as_secs(),
        )
    }
}

/// CLI flags for `starforge runner` (clap `Args`).
#[derive(Debug, Clone, clap::Args)]
pub struct RunnerArgs {
    /// Starforge server URL.
    #[arg(long, env = "STARFORGE_SERVER")]
    pub server: String,
    /// Runner auth token (`sfr_…`).
    #[arg(long, env = "STARFORGE_RUNNER_TOKEN")]
    pub token: String,
    /// Runner label (repeatable).
    #[arg(long)]
    pub label: Vec<String>,
    /// Sandbox runtime.
    #[arg(long, default_value = "podman")]
    pub runtime: String,
    /// Max concurrent jobs.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=64))]
    pub concurrency: u64,
    /// Poll timeout in seconds.
    #[arg(long, default_value_t = 50)]
    pub poll_timeout: u64,
    /// Git clone URL for the repo under test (optional).
    #[arg(long, default_value = "")]
    pub repo_url: String,
}

impl From<&RunnerArgs> for RunnerConfig {
    fn from(a: &RunnerArgs) -> Self {
        Self {
            server_url: a.server.trim_end_matches('/').to_owned(),
            token: a.token.clone(),
            labels: a.label.clone(),
            runtime: a.runtime.clone(),
            concurrency: a.concurrency as usize,
            poll_timeout: Duration::from_secs(a.poll_timeout),
            repo_url: a.repo_url.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire types (mirror of the server API)
// ---------------------------------------------------------------------------

/// One job of `.starforge/ci.toml` (mirrors `starforged_core::ci_spec::CiJobSpec`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiJobSpec {
    pub name: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub runs_on: Vec<String>,
}

impl CiJobSpec {
    /// Parse `30m`/`1h`/`90s`/bare-seconds; `None` on parse failure.
    pub fn timeout_duration(&self) -> Option<Duration> {
        self.timeout.as_deref().and_then(parse_timeout)
    }
}

pub fn parse_timeout(text: &str) -> Option<Duration> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // Split leading digits from the unit suffix ("30m", "90s", "1h", "120").
    let digit_len = text
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .map(|c| c.len_utf8())
        .sum::<usize>();
    if digit_len == 0 {
        return None;
    }
    let (digits, unit) = text.split_at(digit_len);
    let n: u64 = digits.parse().ok()?;
    match unit.trim() {
        "" | "s" => Some(Duration::from_secs(n)),
        "m" => Some(Duration::from_secs(n.saturating_mul(60))),
        "h" => Some(Duration::from_secs(n.saturating_mul(3600))),
        _ => None,
    }
}

/// A claimed job (`POST /runners/jobs/request` → 201).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedJob {
    pub job_id: i64,
    pub job_name: String,
    pub commit_sha: String,
    pub spec: CiJobSpec,
    pub fence: String,
    pub job_token: String,
    pub deadline: String,
    pub lease_until: String,
}

#[derive(Debug, Serialize)]
struct FinishBody {
    state: String,
    exit_code: Option<i64>,
    checksum: Option<String>,
    session_ulids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GitCredentialBody {
    token: String,
    #[allow(dead_code)]
    token_id: i64,
}

/// One repository secret resolved for a claimed job. `Debug` redacts
/// `value`; secret values are never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSecret {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub header: String,
}

impl std::fmt::Debug for ResolvedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSecret")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("host", &self.host)
            .field("header", &self.header)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct ResolveSecretsBody {
    #[serde(default)]
    secrets: Vec<ResolvedSecret>,
}

#[derive(Debug, Serialize)]
struct AuthorizeArtifactBody<'a> {
    name: &'a str,
    size: i64,
    sha256: &'a str,
}

#[derive(Debug, Deserialize)]
struct AuthorizeArtifactResp {
    token: String,
}

#[derive(Debug, Serialize)]
struct CreateSandboxBody {
    #[serde(default)]
    owner: String,
    #[serde(default)]
    repo: String,
    job_id: Option<i64>,
    #[serde(flatten)]
    req: CreateSandboxRequest,
}

// ---------------------------------------------------------------------------
// Errors / outcomes
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("http {0}: {1}")]
    Http(StatusCode, String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("malformed response: {0}")]
    Malformed(String),
    #[error("stale fence (409)")]
    StaleFence,
    #[error("job not found (404)")]
    NotFound,
    #[error("sandbox provider: {0}")]
    Provider(String),
    #[error("timeout")]
    Timeout,
}

impl RunnerError {
    fn from_reqwest(err: reqwest::Error) -> Self {
        RunnerError::Transport(err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOutcome {
    Succeeded { exit_code: i64 },
    Failed { exit_code: i64 },
    TimedOut,
    Canceled,
    StaleFence,
    ProviderFailed(String),
    TransportFailed(String),
}

pub enum TraceResult {
    Accepted,
    Canceled,
}

// ---------------------------------------------------------------------------
// Sandbox provider seam
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit: i64,
}

pub trait SandboxProvider: Send + Sync {
    fn create(
        &self,
        job: &ClaimedJob,
        req: CreateSandboxRequest,
    ) -> impl Future<Output = Result<String, RunnerError>> + Send;
    fn exec(
        &self,
        job: &ClaimedJob,
        id: &str,
        req: ExecRequest,
    ) -> impl Future<Output = Result<ExecResult, RunnerError>> + Send;
    fn read_file(
        &self,
        job: &ClaimedJob,
        id: &str,
        path: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RunnerError>> + Send;
    fn list_files(
        &self,
        job: &ClaimedJob,
        id: &str,
        path: &str,
    ) -> impl Future<Output = Result<Vec<String>, RunnerError>> + Send;
    fn kill(&self, job: &ClaimedJob, id: &str) -> impl Future<Output = ()> + Send;
}

/// HTTP sandbox provider: talks to `POST /api/v1/sandboxes` (plus exec,
/// files, kill) with the per-job token.
pub struct HttpSandboxProvider {
    client: reqwest::Client,
    base: String,
}

impl HttpSandboxProvider {
    pub fn new(server_url: &str) -> Self {
        Self {
            client: Client::build(),
            base: format!("{}/api/v1", server_url.trim_end_matches('/')),
        }
    }
}

impl SandboxProvider for HttpSandboxProvider {
    async fn create(
        &self,
        job: &ClaimedJob,
        req: CreateSandboxRequest,
    ) -> Result<String, RunnerError> {
        let resp = self
            .client
            .post(format!("{}/sandboxes", self.base))
            .bearer_auth(&job.job_token)
            .json(&CreateSandboxBody {
                owner: String::new(),
                repo: String::new(),
                job_id: Some(job.job_id),
                req,
            })
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        let s = resp.status();
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RunnerError::Malformed(e.to_string()))?;
        if !s.is_success() {
            return Err(RunnerError::Provider(v.to_string()));
        }
        v.get("id")
            .and_then(|i| i.as_str())
            .map(str::to_owned)
            .ok_or_else(|| RunnerError::Malformed("sandbox create: no id".into()))
    }

    async fn exec(
        &self,
        job: &ClaimedJob,
        id: &str,
        req: ExecRequest,
    ) -> Result<ExecResult, RunnerError> {
        let resp = self
            .client
            .post(format!("{}/sandboxes/{id}/exec", self.base))
            .bearer_auth(&job.job_token)
            .json(&req)
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        if !resp.status().is_success() {
            return Err(RunnerError::Provider(format!("exec: {}", resp.status())));
        }
        let chunks: Vec<ExecChunk> = resp
            .json()
            .await
            .map_err(|e| RunnerError::Malformed(e.to_string()))?;
        let mut out = ExecResult::default();
        for c in chunks {
            match c {
                ExecChunk::Stdout { data } => out.stdout.push_str(&data),
                ExecChunk::Stderr { data } => out.stderr.push_str(&data),
                ExecChunk::Exit { code } => out.exit = code as i64,
            }
        }
        Ok(out)
    }

    async fn read_file(
        &self,
        job: &ClaimedJob,
        id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, RunnerError> {
        let url = format!(
            "{}/sandboxes/{id}/files?path={}",
            self.base,
            url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>()
        );
        let resp = self
            .client
            .get(url)
            .bearer_auth(&job.job_token)
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(RunnerError::Provider(format!(
                "read file: {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RunnerError::Malformed(e.to_string()))?;
        Ok(v.get("content")
            .and_then(|c| c.as_str())
            .map(|s| s.as_bytes().to_vec()))
    }

    async fn list_files(
        &self,
        job: &ClaimedJob,
        id: &str,
        path: &str,
    ) -> Result<Vec<String>, RunnerError> {
        let url = format!(
            "{}/sandboxes/{id}/files?path={}&op=list",
            self.base,
            url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>()
        );
        let resp = self
            .client
            .get(url)
            .bearer_auth(&job.job_token)
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        if !resp.status().is_success() {
            return Err(RunnerError::Provider(format!(
                "list files: {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RunnerError::Malformed(e.to_string()))?;
        Ok(v.get("entries")
            .and_then(|e| e.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn kill(&self, job: &ClaimedJob, id: &str) {
        let _ = self
            .client
            .delete(format!("{}/sandboxes/{id}", self.base))
            .bearer_auth(&job.job_token)
            .send()
            .await;
    }
}

// ---------------------------------------------------------------------------
// Server client
// ---------------------------------------------------------------------------

pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Client {
    pub fn build() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    pub fn new(server_url: &str, token: &str) -> Self {
        Self {
            http: Self::build(),
            base: format!("{}/api/v1", server_url.trim_end_matches('/')),
            token: token.to_owned(),
        }
    }

    /// Long-poll claim. `None` on 204.
    pub async fn request_job(&self, labels: &[String]) -> Result<Option<ClaimedJob>, RunnerError> {
        let resp = self
            .http
            .post(format!("{}/runners/jobs/request", self.base))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "labels": labels }))
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        if resp.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if resp.status() == StatusCode::CONFLICT {
            return Err(RunnerError::StaleFence);
        }
        if !resp.status().is_success() {
            let s = resp.status();
            return Err(RunnerError::Http(s, resp.text().await.unwrap_or_default()));
        }
        resp.json::<ClaimedJob>()
            .await
            .map(Some)
            .map_err(|e| RunnerError::Malformed(e.to_string()))
    }

    pub async fn git_credential(&self, job_id: i64, fence: &str) -> Result<String, RunnerError> {
        let resp = self
            .http
            .post(format!("{}/ci/jobs/{job_id}/git-credential", self.base))
            .bearer_auth(&self.token)
            .header(FENCE_HEADER, fence)
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        self.check_fence(resp.status()).await?;
        resp.json::<GitCredentialBody>()
            .await
            .map(|b| b.token)
            .map_err(|e| RunnerError::Malformed(e.to_string()))
    }

    /// Resolves the claimed job's repository secrets. The response body
    /// carries secret values and is never logged.
    pub async fn resolve_secrets(
        &self,
        job_id: i64,
        fence: &str,
    ) -> Result<Vec<ResolvedSecret>, RunnerError> {
        let resp = self
            .http
            .post(format!("{}/runners/jobs/{job_id}/secrets", self.base))
            .bearer_auth(&self.token)
            .header(FENCE_HEADER, fence)
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        if resp.status() == StatusCode::CONFLICT {
            return Err(RunnerError::StaleFence);
        }
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(RunnerError::NotFound);
        }
        if !resp.status().is_success() {
            let s = resp.status();
            return Err(RunnerError::Http(s, resp.text().await.unwrap_or_default()));
        }
        resp.json::<ResolveSecretsBody>()
            .await
            .map(|b| b.secrets)
            .map_err(|e| RunnerError::Malformed(e.to_string()))
    }

    pub async fn trace(
        &self,
        job_id: i64,
        fence: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Result<TraceResult, RunnerError> {
        let end = offset + bytes.len() as u64;
        let range = format!("bytes {offset}-{}/*", end.saturating_sub(1));
        let resp = self
            .http
            .patch(format!("{}/runners/jobs/{job_id}/trace", self.base))
            .bearer_auth(&self.token)
            .header(FENCE_HEADER, fence)
            .header(reqwest::header::CONTENT_RANGE, range)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        if resp.status() == StatusCode::CONFLICT {
            return Err(RunnerError::StaleFence);
        }
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(RunnerError::NotFound);
        }
        if !resp.status().is_success() {
            let s = resp.status();
            return Err(RunnerError::Http(s, resp.text().await.unwrap_or_default()));
        }
        if resp
            .headers()
            .get(JOB_STATUS_HEADER)
            .and_then(|v| v.to_str().ok())
            == Some("canceled")
        {
            return Ok(TraceResult::Canceled);
        }
        Ok(TraceResult::Accepted)
    }

    /// Renews the claim lease. Called every [`HEARTBEAT_SECS`] while a job
    /// runs, so a quiet command cannot let the lease expire.
    pub async fn heartbeat(&self, job_id: i64, fence: &str) -> Result<(), RunnerError> {
        let resp = self
            .http
            .post(format!("{}/runners/jobs/{job_id}/heartbeat", self.base))
            .bearer_auth(&self.token)
            .header(FENCE_HEADER, fence)
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        self.check_fence(resp.status()).await
    }

    pub async fn finish(
        &self,
        job_id: i64,
        fence: &str,
        state: &str,
        exit_code: Option<i64>,
        checksum: Option<String>,
        session_ulids: Vec<String>,
    ) -> Result<(), RunnerError> {
        let resp = self
            .http
            .put(format!("{}/runners/jobs/{job_id}", self.base))
            .bearer_auth(&self.token)
            .header(FENCE_HEADER, fence)
            .json(&FinishBody {
                state: state.to_owned(),
                exit_code,
                checksum,
                session_ulids,
            })
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        self.check_fence(resp.status()).await
    }

    pub async fn authorize_artifact(
        &self,
        job_id: i64,
        fence: &str,
        name: &str,
        size: i64,
        sha256: &str,
    ) -> Result<String, RunnerError> {
        let resp = self
            .http
            .post(format!(
                "{}/runners/jobs/{job_id}/artifacts/authorize",
                self.base
            ))
            .bearer_auth(&self.token)
            .header(FENCE_HEADER, fence)
            .json(&AuthorizeArtifactBody { name, size, sha256 })
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        self.check_fence(resp.status()).await?;
        resp.json::<AuthorizeArtifactResp>()
            .await
            .map(|b| b.token)
            .map_err(|e| RunnerError::Malformed(e.to_string()))
    }

    pub async fn upload_artifact(
        &self,
        job_id: i64,
        name: &str,
        token: &str,
        bytes: &[u8],
        sha256: &str,
    ) -> Result<(), RunnerError> {
        let resp = self
            .http
            .put(format!(
                "{}/runners/jobs/{job_id}/artifacts/{name}",
                self.base
            ))
            .bearer_auth(token)
            .header("x-starforge-sha256", sha256)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(RunnerError::from_reqwest)?;
        if resp.status() == StatusCode::CONFLICT {
            return Err(RunnerError::StaleFence);
        }
        if !resp.status().is_success() {
            let s = resp.status();
            return Err(RunnerError::Http(s, resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    async fn check_fence(&self, status: StatusCode) -> Result<(), RunnerError> {
        match status {
            StatusCode::CONFLICT => Err(RunnerError::StaleFence),
            StatusCode::NOT_FOUND => Err(RunnerError::NotFound),
            s if s.is_success() => Ok(()),
            s => Err(RunnerError::Http(s, String::new())),
        }
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// The `owner/repo` part of a clone URL, for `starforge.repo`.
fn repo_full_name(repo_url: &str) -> Option<String> {
    let url = url::Url::parse(repo_url).ok()?;
    let path = url.path().trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// Single-quote a shell argument.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Egress allowlist for a job sandbox: the server and repo hosts, plus the
/// host of every bound secret (with the header the proxy injects for it).
fn network_policy(server_url: &str, repo_url: &str, resolved: &[ResolvedSecret]) -> NetworkPolicy {
    let mut allow_out: Vec<String> = Vec::new();
    let mut secret_headers: BTreeMap<String, String> = BTreeMap::new();
    for url in [server_url, repo_url] {
        if url.is_empty() {
            continue;
        }
        if let Some(host) = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            && !allow_out.contains(&host)
        {
            allow_out.push(host);
        }
    }
    for secret in resolved {
        if secret.host.is_empty() {
            continue;
        }
        if !allow_out.contains(&secret.host) {
            allow_out.push(secret.host.clone());
        }
        secret_headers.insert(secret.host.clone(), secret.header.clone());
    }
    NetworkPolicy {
        allow_out,
        deny_out: Vec::new(),
        secret_headers,
    }
}

pub struct Executor<P: SandboxProvider> {
    pub config: RunnerConfig,
    pub client: Client,
    pub provider: P,
    /// Session ULIDs discovered by the most recent `starforge sync` exec.
    pub sync_ulids: std::sync::Mutex<Vec<String>>,
}

impl<P: SandboxProvider> Executor<P> {
    pub fn new(config: RunnerConfig, provider: P) -> Self {
        let client = Client::new(&config.server_url, &config.token);
        Self {
            config,
            client,
            provider,
            sync_ulids: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn sandbox_request(
        &self,
        job: &ClaimedJob,
        resolved: &[ResolvedSecret],
    ) -> CreateSandboxRequest {
        let template = job
            .spec
            .template
            .clone()
            .or_else(|| job.spec.image.clone())
            .unwrap_or_default();
        let timeout_s = job
            .spec
            .timeout_duration()
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut envs = job.spec.env.clone();
        envs.insert("STARFORGE_TOKEN".to_owned(), job.job_token.clone());
        CreateSandboxRequest {
            runtime: self.config.runtime.clone(),
            template,
            timeout_s,
            cpu: 0.0,
            mem_mb: 0,
            disk_gb: 0,
            envs,
            network: network_policy(&self.config.server_url, &self.config.repo_url, resolved),
            metadata: BTreeMap::from([
                ("job_id".to_owned(), job.job_id.to_string()),
                ("commit_sha".to_owned(), job.commit_sha.clone()),
            ]),
            idempotency_key: Some(format!("job-{}-{}", job.job_id, job.commit_sha)),
            secret_bindings: Vec::new(),
            network_enabled: false,
        }
    }

    /// Scrub known secrets (and their URL-encoded form) from a log chunk.
    pub fn scrub(text: &str, secrets: &[String]) -> String {
        let mut out = text.to_owned();
        for s in secrets {
            if s.is_empty() || s.len() < 4 {
                continue;
            }
            out = out.replace(s.as_str(), "***");
            // URL-encoded variant of the secret.
            let url = url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            if url != *s {
                out = out.replace(&url, "***");
            }
        }
        out
    }

    async fn trace_all(
        &self,
        job: &ClaimedJob,
        offset: &mut u64,
        text: &str,
        secrets: &[String],
    ) -> Result<(), JobOutcome> {
        let scrubbed = Self::scrub(text, secrets);
        let bytes = scrubbed.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let end = (i + TRACE_CHUNK).min(bytes.len());
            match self
                .client
                .trace(job.job_id, &job.fence, *offset, &bytes[i..end])
                .await
            {
                Ok(TraceResult::Accepted) => {}
                Ok(TraceResult::Canceled) => return Err(JobOutcome::Canceled),
                Err(RunnerError::StaleFence) => return Err(JobOutcome::StaleFence),
                Err(e) => return Err(JobOutcome::TransportFailed(e.to_string())),
            }
            *offset += (end - i) as u64;
            i = end;
        }
        Ok(())
    }

    /// Execute one claimed job end to end.
    pub async fn execute_job(&self, job: ClaimedJob) -> JobOutcome {
        let timeout = job
            .spec
            .timeout_duration()
            .unwrap_or(Duration::from_secs(3600));
        let heartbeat = self.spawn_heartbeat(&job);
        let result = tokio::time::timeout(timeout, self.execute_inner(&job)).await;
        heartbeat.abort();
        match result {
            Ok(o) => o,
            Err(_) => {
                // Best effort: kill + finish failed.
                let _ = self.provider.kill(&job, "job").await;
                let _ = self
                    .client
                    .finish(job.job_id, &job.fence, "failed", None, None, Vec::new())
                    .await;
                JobOutcome::TimedOut
            }
        }
    }

    /// Keeps the claim lease alive while a job runs. Log traces renew the
    /// lease too, but a command that is quiet for more than the 60-second
    /// lease would otherwise let the reaper requeue the job. The task stops
    /// on a stale fence or a missing job, and is aborted when the job ends.
    fn spawn_heartbeat(&self, job: &ClaimedJob) -> tokio::task::JoinHandle<()> {
        let server_url = self.config.server_url.clone();
        let token = self.config.token.clone();
        let job_id = job.job_id;
        let fence = job.fence.clone();
        tokio::spawn(async move {
            let client = Client::new(&server_url, &token);
            let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
            interval.tick().await; // the first tick is immediate
            loop {
                interval.tick().await;
                match client.heartbeat(job_id, &fence).await {
                    Ok(()) => {}
                    Err(RunnerError::StaleFence | RunnerError::NotFound) => break,
                    Err(_) => {}
                }
            }
        })
    }

    async fn execute_inner(&self, job: &ClaimedJob) -> JobOutcome {
        let mut secrets: Vec<String> = vec![self.config.token.clone(), job.job_token.clone()];
        let mut offset: u64 = 0;

        // 1. Git credential.
        let git_token = match self.client.git_credential(job.job_id, &job.fence).await {
            Ok(t) => t,
            Err(RunnerError::StaleFence) => return JobOutcome::StaleFence,
            Err(e) => return JobOutcome::TransportFailed(e.to_string()),
        };
        secrets.push(git_token.clone());

        // 1b. Repository secrets for this job.
        let resolved = match self.client.resolve_secrets(job.job_id, &job.fence).await {
            Ok(v) => v,
            Err(RunnerError::StaleFence) => return JobOutcome::StaleFence,
            Err(RunnerError::NotFound) => {
                return JobOutcome::TransportFailed("job not found".into());
            }
            Err(e) => return JobOutcome::TransportFailed(e.to_string()),
        };
        for secret in &resolved {
            if !secret.value.is_empty() {
                secrets.push(secret.value.clone());
            }
        }

        // 2. Create sandbox.
        let sandbox_id = match self
            .provider
            .create(job, self.sandbox_request(job, &resolved))
            .await
        {
            Ok(id) => id,
            Err(e) => {
                let _ = self
                    .client
                    .finish(job.job_id, &job.fence, "failed", None, None, Vec::new())
                    .await;
                return JobOutcome::ProviderFailed(e.to_string());
            }
        };

        // 3. Clone / checkout.
        if !self.config.repo_url.is_empty() {
            let url = self.config.repo_url.replace(
                "https://",
                &format!("https://{}@x-access-token:", git_token),
            );
            let cmd = format!(
                "git clone --depth 1 {url} /workspace && cd /workspace && git fetch --depth 1 origin {} && git checkout {}",
                job.commit_sha, job.commit_sha
            );
            match self
                .run_cmd(job, &sandbox_id, &cmd, &mut offset, &secrets)
                .await
            {
                Ok(exit) if exit != 0 => {
                    self.kill_sandbox(job, &sandbox_id).await;
                    return self.finish_failed(job, exit).await;
                }
                Ok(_) => {}
                Err(o) => {
                    self.kill_sandbox(job, &sandbox_id).await;
                    return o;
                }
            }
        }

        // 3b. Point `starforge sync` at the server and repository. The
        // worktree may be pre-populated (no clone), so this is best effort.
        let mut config_cmd = format!(
            "git config starforge.server {}",
            shell_quote(&self.config.server_url)
        );
        if let Some(repo) = repo_full_name(&self.config.repo_url) {
            config_cmd.push_str(&format!(
                " && git config starforge.repo {}",
                shell_quote(&repo)
            ));
        }
        config_cmd.push_str(" 2>/dev/null || true");
        if let Err(o) = self
            .run_cmd(job, &sandbox_id, &config_cmd, &mut offset, &secrets)
            .await
        {
            self.kill_sandbox(job, &sandbox_id).await;
            return o;
        }

        // 4. Run commands.
        let mut exit_code: i64 = 0;
        for cmd in &job.spec.commands {
            match self
                .run_cmd(job, &sandbox_id, cmd, &mut offset, &secrets)
                .await
            {
                Ok(exit) => {
                    exit_code = exit;
                    if exit != 0 {
                        break;
                    }
                }
                Err(o) => {
                    self.kill_sandbox(job, &sandbox_id).await;
                    return o;
                }
            }
        }

        // 5. starforge sync in the sandbox.
        let mut session_ulids: Vec<String> = Vec::new();
        if exit_code == 0 {
            match self
                .run_cmd(job, &sandbox_id, "starforge sync", &mut offset, &secrets)
                .await
            {
                Ok(sync_exit) => {
                    if sync_exit == 0 {
                        // ULIDs were already traced (scrubbed) as part of
                        // the sync output; re-derive from the last exec.
                        session_ulids = self
                            .sync_ulids
                            .lock()
                            .map(|g| g.clone())
                            .unwrap_or_default();
                    }
                }
                Err(o) => {
                    self.kill_sandbox(job, &sandbox_id).await;
                    return o;
                }
            }
        }

        // 6. Artifacts.
        let mut checksum_hasher = Sha256::new();
        if exit_code == 0 {
            for glob in &job.spec.artifacts {
                for (name, bytes) in self.harvest(job, &sandbox_id, glob).await {
                    checksum_hasher.update(&bytes);
                    let sha = hex::encode(Sha256::digest(&bytes));
                    match self
                        .client
                        .authorize_artifact(job.job_id, &job.fence, &name, bytes.len() as i64, &sha)
                        .await
                    {
                        Ok(atok) => {
                            if let Err(e) = self
                                .client
                                .upload_artifact(job.job_id, &name, &atok, &bytes, &sha)
                                .await
                            {
                                tracing::warn!("artifact upload failed: {e}");
                            }
                        }
                        Err(RunnerError::StaleFence) => {
                            self.kill_sandbox(job, &sandbox_id).await;
                            return JobOutcome::StaleFence;
                        }
                        Err(e) => tracing::warn!("artifact authorize failed: {e}"),
                    }
                }
            }
        }
        let checksum = hex::encode(checksum_hasher.finalize());

        // 7. Kill + finish.
        self.kill_sandbox(job, &sandbox_id).await;
        let state = if exit_code == 0 {
            "succeeded"
        } else {
            "failed"
        };
        match self
            .client
            .finish(
                job.job_id,
                &job.fence,
                state,
                Some(exit_code),
                Some(checksum),
                session_ulids,
            )
            .await
        {
            Ok(()) => {
                if exit_code == 0 {
                    JobOutcome::Succeeded { exit_code }
                } else {
                    JobOutcome::Failed { exit_code }
                }
            }
            Err(RunnerError::StaleFence) => JobOutcome::StaleFence,
            Err(e) => JobOutcome::TransportFailed(e.to_string()),
        }
    }

    /// Run one command, trace its output, return the exit code.
    async fn kill_sandbox(&self, job: &ClaimedJob, id: &str) {
        self.provider.kill(job, id).await;
    }

    async fn run_cmd(
        &self,
        job: &ClaimedJob,
        sandbox_id: &str,
        cmd: &str,
        offset: &mut u64,
        secrets: &[String],
    ) -> Result<i64, JobOutcome> {
        let req = ExecRequest {
            command: vec!["sh".to_owned(), "-c".to_owned(), cmd.to_owned()],
            cwd: Some("/workspace".to_owned()),
            envs: BTreeMap::new(),
            timeout_s: job
                .spec
                .timeout_duration()
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let res = match self.provider.exec(job, sandbox_id, req).await {
            Ok(r) => r,
            Err(e) => return Err(JobOutcome::ProviderFailed(e.to_string())),
        };
        if res.stdout.contains("starforge sync") || cmd.contains("starforge sync") {
            // Collect candidate session ULIDs from sync output.
            let mut v = Vec::new();
            for w in res.stdout.split_whitespace() {
                let w = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
                if w.len() == 26 && w.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    v.push(w.to_owned());
                }
            }
            if let Ok(mut g) = self.sync_ulids.lock() {
                *g = v;
            }
        }
        self.trace_all(job, offset, &res.stdout, secrets).await?;
        if !res.stderr.is_empty() {
            self.trace_all(job, offset, &res.stderr, secrets).await?;
        }
        Ok(res.exit)
    }

    async fn finish_failed(&self, job: &ClaimedJob, exit: i64) -> JobOutcome {
        match self
            .client
            .finish(
                job.job_id,
                &job.fence,
                "failed",
                Some(exit),
                None,
                Vec::new(),
            )
            .await
        {
            Ok(()) => JobOutcome::Failed { exit_code: exit },
            Err(RunnerError::StaleFence) => JobOutcome::StaleFence,
            Err(e) => JobOutcome::TransportFailed(e.to_string()),
        }
    }

    /// Harvest files matching a (possibly glob) artifact pattern.
    async fn harvest(
        &self,
        job: &ClaimedJob,
        sandbox_id: &str,
        glob: &str,
    ) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        if !glob.contains('*') {
            if let Ok(Some(bytes)) = self.provider.read_file(job, sandbox_id, glob).await {
                out.push((glob.to_owned(), bytes));
            }
            return out;
        }
        let base = glob.split('*').next().unwrap_or("");
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(".");
        let dir = if dir.is_empty() { "." } else { dir };
        if let Ok(entries) = self.provider.list_files(job, sandbox_id, dir).await {
            for e in entries {
                let full = if dir == "." {
                    e.clone()
                } else {
                    format!("{dir}/{e}")
                };
                if glob_match(glob, &full)
                    && let Ok(Some(bytes)) = self.provider.read_file(job, sandbox_id, &full).await
                {
                    out.push((full, bytes));
                }
            }
        }
        out
    }

    /// Claim loop: poll claims and execute them until `poll_timeout`
    /// elapses without a job, or `stop` is set.
    pub async fn run_until_idle(
        &self,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, RunnerError> {
        let mut done = 0u64;
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match self.client.request_job(&self.config.labels).await? {
                Some(job) => {
                    let _ = self.execute_job(job).await;
                    done += 1;
                }
                None => break,
            }
        }
        Ok(done)
    }
}

/// Simple glob match supporting `*` and `**`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // `**/` matches any number of path segments (including zero).
    if let Some(rest) = pattern.strip_prefix("**/") {
        if glob_match(rest, text) {
            return true;
        }
        if text.len() > 1 {
            return glob_match(pattern, &text[1..]);
        }
        return text.len() == 1 && glob_match(pattern, "");
    }
    if let Some(star) = pattern.find('*') {
        let double = pattern[star..].starts_with("**");
        let pre = &pattern[..star];
        let post = if double {
            &pattern[star + 2..]
        } else {
            &pattern[star + 1..]
        };
        if !text.starts_with(pre) {
            return false;
        }
        let rest = &text[pre.len()..];
        if double {
            // `**` matches any characters, including `/`.
            return (0..=rest.len()).any(|i| glob_match(post, &rest[i..]));
        }
        // Single `*` matches any characters except `/`.
        return (0..=rest.len()).any(|i| !rest[..i].contains('/') && glob_match(post, &rest[i..]));
    }
    pattern == text
}
// ---------------------------------------------------------------------------
// Fake sandbox provider (tests / dry-run)
// ---------------------------------------------------------------------------

/// In-memory sandbox provider used by tests and `--dry-run` planning.
#[derive(Debug, Default)]
pub struct FakeSandboxProvider {
    /// `(command-substring, stdout, exit)` scripted exec results.
    pub script: Vec<(String, String, i64)>,
    /// Files served by `read_file` / `list_files`.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Artificial exec delay (timeout tests).
    pub delay: Duration,
    /// Set when a sandbox is killed.
    pub killed: std::sync::Mutex<Vec<String>>,
    /// Created sandbox ids.
    pub created: std::sync::Mutex<Vec<String>>,
    /// Create requests, in order (for tests that inspect the policy).
    pub requests: std::sync::Mutex<Vec<CreateSandboxRequest>>,
}

impl FakeSandboxProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_script(mut self, cmd: &str, stdout: &str, exit: i64) -> Self {
        self.script.push((cmd.to_owned(), stdout.to_owned(), exit));
        self
    }

    pub fn with_file(mut self, path: &str, bytes: &[u8]) -> Self {
        self.files.insert(path.to_owned(), bytes.to_vec());
        self
    }

    pub fn was_killed(&self) -> bool {
        self.killed.lock().map(|k| !k.is_empty()).unwrap_or(false)
    }
}

impl SandboxProvider for FakeSandboxProvider {
    async fn create(
        &self,
        _job: &ClaimedJob,
        req: CreateSandboxRequest,
    ) -> Result<String, RunnerError> {
        let id = format!(
            "sbx-fake-{}",
            self.created.lock().map(|c| c.len()).unwrap_or(0)
        );
        if let Ok(mut c) = self.created.lock() {
            c.push(id.clone());
        }
        if let Ok(mut r) = self.requests.lock() {
            r.push(req);
        }
        Ok(id)
    }

    async fn exec(
        &self,
        _job: &ClaimedJob,
        _id: &str,
        req: ExecRequest,
    ) -> Result<ExecResult, RunnerError> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let joined = req.command.join(" ");
        for (needle, stdout, exit) in &self.script {
            if joined.contains(needle.as_str()) {
                return Ok(ExecResult {
                    stdout: stdout.clone(),
                    stderr: String::new(),
                    exit: *exit,
                });
            }
        }
        Ok(ExecResult {
            stdout: format!("$ {joined}\nok\n"),
            stderr: String::new(),
            exit: 0,
        })
    }

    async fn read_file(
        &self,
        _job: &ClaimedJob,
        _id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, RunnerError> {
        Ok(self.files.get(path).cloned())
    }

    async fn list_files(
        &self,
        _job: &ClaimedJob,
        _id: &str,
        path: &str,
    ) -> Result<Vec<String>, RunnerError> {
        let prefix = if path == "." {
            String::new()
        } else {
            format!("{path}/")
        };
        Ok(self
            .files
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(str::to_owned))
            .filter(|k| !k.contains('/'))
            .collect())
    }

    async fn kill(&self, _job: &ClaimedJob, id: &str) {
        if let Ok(mut k) = self.killed.lock() {
            k.push(id.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_parses_units() {
        assert_eq!(parse_timeout("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_timeout("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_timeout("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_timeout("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_timeout("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_timeout("bogus"), None);
    }

    #[test]
    fn scrub_removes_secrets() {
        let secrets = vec!["sfr_supersecret".to_owned()];
        let out = Executor::<FakeSandboxProvider>::scrub("token is sfr_supersecret ok", &secrets);
        assert!(!out.contains("sfr_supersecret"));
        assert!(out.contains("***"));
    }

    #[test]
    fn glob_matches() {
        assert!(glob_match("target/nextest/**", "target/nextest/a/b.txt"));
        assert!(glob_match("**/a.txt", "x/y/a.txt"));
        assert!(glob_match("target/nextest/**", "target/nextest/a.txt"));
        assert!(glob_match("*.txt", "a.txt"));
        assert!(!glob_match("*.txt", "a/b.txt"));
        assert!(glob_match("out.bin", "out.bin"));
        assert!(!glob_match("out.bin", "other.bin"));
    }

    #[test]
    fn plan_text_has_no_secret() {
        let cfg = RunnerConfig::new("https://forge.example", "sfr_secret");
        let plan = cfg.plan_text();
        assert!(plan.contains("podman"));
        assert!(!plan.contains("sfr_secret"));
    }

    #[test]
    fn sandbox_request_allows_server_repo_and_secret_hosts() {
        let mut cfg = RunnerConfig::new("http://127.0.0.1:3000", "sfr_token");
        cfg.repo_url = "https://git.example.com/alice/proj".to_owned();
        let executor = Executor::new(cfg, FakeSandboxProvider::new());
        let job = ClaimedJob {
            job_id: 7,
            job_name: "test".to_owned(),
            commit_sha: "abc123".to_owned(),
            spec: CiJobSpec::default(),
            fence: "fence".to_owned(),
            job_token: "job_token".to_owned(),
            deadline: String::new(),
            lease_until: String::new(),
        };
        let resolved = vec![ResolvedSecret {
            name: "TOKEN".to_owned(),
            value: "v".to_owned(),
            host: "registry.example".to_owned(),
            header: "Authorization".to_owned(),
        }];
        let req = executor.sandbox_request(&job, &resolved);
        assert!(req.network.allow_out.iter().any(|h| h == "127.0.0.1"));
        assert!(req.network.allow_out.iter().any(|h| h == "git.example.com"));
        assert!(
            req.network
                .allow_out
                .iter()
                .any(|h| h == "registry.example")
        );
        assert_eq!(
            req.network
                .secret_headers
                .get("registry.example")
                .map(String::as_str),
            Some("Authorization")
        );
        assert!(req.network.deny_out.is_empty());
        assert!(req.secret_bindings.is_empty());
        assert!(!req.network_enabled);
    }

    #[test]
    fn resolved_secret_debug_redacts_value() {
        let secret = ResolvedSecret {
            name: "TOKEN".to_owned(),
            value: "supersecretvalue".to_owned(),
            host: "registry.example".to_owned(),
            header: "Authorization".to_owned(),
        };
        let debug = format!("{secret:?}");
        assert!(!debug.contains("supersecretvalue"));
        assert!(debug.contains("registry.example"));
    }
}
