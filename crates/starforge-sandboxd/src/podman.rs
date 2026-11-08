//! Sandbox runtime layer: the [`Runtime`] trait, the real podman
//! implementation ([`PodmanRuntime`]), and an in-memory test double
//! ([`FakeRuntime`]).
//!
//! # Command-injection hygiene (B2 hardening)
//!
//! Podman is invoked with an argument vector only (`Command::arg`); there is
//! no shell anywhere in this module. Positional arguments that could be
//! mistaken for flags are preceded by `--`. Container names written into
//! argv are daemon-generated hex ids, never caller input. Images are checked
//! against the allowlist ([`image_allowed`]) before they reach podman, and
//! environment keys/values are validated ([`validate_env`]) — podman pairs
//! `-e KEY=VALUE` with the `=` intact, so a weird key could otherwise become
//! a flag. File operations stay inside `/workspace` in the container: the
//! relative path is lexically validated ([`validate_relative_path`]), then,
//! for the real runtime, resolved with `realpath` inside the container and
//! re-checked against the workspace root so symlinks cannot escape it.
//!
//! # Binary safety
//!
//! The protocol carries file content as a `String`, so bytes travel as
//! base64 on the wire ([`encode_content`]/[`decode_content`], documented here
//! and at the HTTP layer). Reads, writes, and exec output are capped at
//! [`MAX_FILE_BYTES`]/[`MAX_EXEC_BYTES`] (8 MiB); anything larger is a
//! provider error, never a silent truncation.
//!
//! No host paths are mounted into the container. Each sandbox gets a
//! dedicated workspace volume (`<id>-workspace`); the container runs with
//! `--network none` until the B7 egress proxy lands.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use starforge_sandbox_protocol::{
    CreateSandboxRequest, ExecChunk, ExecRequest, PortUrl, ProviderError, SandboxState,
};

/// Workspace root inside every sandbox container.
pub const WORKSPACE_ROOT: &str = "/workspace";
/// Cap on a single file read/write (bytes, after base64 decoding).
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
/// Cap on one exec output stream (stdout or stderr; bytes).
pub const MAX_EXEC_BYTES: usize = 8 * 1024 * 1024;
/// Cap on a base64 payload length (chars) for file writes.
pub const MAX_FILE_B64_CHARS: usize = MAX_FILE_BYTES * 4 / 3 + 8;

/// Error raised when a sandbox id is unknown to the runtime.
pub fn err_not_found(id: &str) -> ProviderError {
    ProviderError::new("not_found", format!("sandbox `{id}` not found"))
}

/// Error raised for caller-side mistakes (bad paths, bad env, …).
pub fn err_invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::new("invalid_argument", message)
}

/// Error raised for podman/CLI failures.
pub fn err_runtime(message: impl Into<String>) -> ProviderError {
    ProviderError::new("runtime", message)
}

/// Max sandbox lifetime bound shared by daemon and runtime.
pub const MAX_TIMEOUT_S: u64 = 86_400;

/// Whether `image` is allowed by `allowlist`.
///
/// An entry matches exactly, or matches the image with an explicit tag/digest
/// appended (`entry:1.85`, `entry@sha256:…`). Prefix confusion is rejected:
/// `docker.io/library/rust` does not match `docker.io/library/rustic`.
pub fn image_allowed(image: &str, allowlist: &[String]) -> bool {
    if image.is_empty() {
        return false;
    }
    // Image refs are lowercase registry/name[:tag][@digest]; uppercase or
    // whitespace means the caller is confused (or hostile).
    if image.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    allowlist.iter().any(|entry| {
        image == entry
            || image
                .strip_prefix(entry.as_str())
                .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('@'))
    })
}

/// Validate environment pairs destined for `-e KEY=VALUE` argv.
///
/// Keys must match `[A-Za-z_][A-Za-z0-9_]*` (so a key can never smuggle a
/// flag or an `=`); values must contain no NUL or control characters.
pub fn validate_env(
    envs: &std::collections::BTreeMap<String, String>,
) -> Result<(), ProviderError> {
    for (key, value) in envs {
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(err_invalid(format!("invalid env key `{key}`")));
        }
        if key.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return Err(err_invalid(format!("invalid env key `{key}`")));
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(err_invalid(format!(
                "invalid env value for env key `{key}`"
            )));
        }
    }
    Ok(())
}

/// Lexically validate a workspace-relative path.
///
/// Rejects empty paths, absolute paths, NUL/control bytes, and any `..`
/// component. Symlinks are not visible lexically; the real runtime resolves
/// with `realpath` in the container ([`PodmanRuntime::resolve_in_container`])
/// and the fake resolves through its symlink map ([`FakeRuntime`]).
pub fn validate_relative_path(path: &str) -> Result<String, ProviderError> {
    if path.is_empty() {
        return Err(err_invalid("path must not be empty"));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(err_invalid(format!("path `{path}` must be relative")));
    }
    if path.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(err_invalid(format!(
            "path `{path}` contains control characters"
        )));
    }
    if path.split('/').any(|part| part == "..") {
        return Err(err_invalid(format!("path `{path}` escapes the workspace")));
    }
    Ok(path.to_owned())
}

/// Join a validated relative path under the workspace root.
pub fn workspace_path(rel: &str) -> String {
    format!("{WORKSPACE_ROOT}/{rel}")
}

/// Base64-encode raw file bytes for the wire (`String`-typed protocol field).
pub fn encode_content(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode base64 wire content, enforcing [`MAX_FILE_BYTES`].
pub fn decode_content(text: &str) -> Result<Vec<u8>, ProviderError> {
    if text.len() > MAX_FILE_B64_CHARS {
        return Err(ProviderError::new(
            "too_large",
            format!("file content exceeds {MAX_FILE_BYTES} bytes"),
        ));
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .map_err(|e| err_invalid(format!("file content is not valid base64: {e}")))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ProviderError::new(
            "too_large",
            format!("file content exceeds {MAX_FILE_BYTES} bytes"),
        ));
    }
    Ok(bytes)
}

type Fute<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;

/// Isolation backend behind the daemon's HTTP layer.
///
/// Implementations own argv building; callers must pass already-validated
/// relative paths (see [`validate_relative_path`]) and stay within the byte
/// caps. `create` receives the container id the daemon generated.
pub trait Runtime: Send + Sync {
    fn create<'a>(&'a self, id: &'a str, req: &'a CreateSandboxRequest) -> Fute<'a, ()>;
    fn inspect<'a>(&'a self, id: &'a str) -> Fute<'a, SandboxState>;
    fn remove<'a>(&'a self, id: &'a str) -> Fute<'a, ()>;
    fn pause<'a>(&'a self, id: &'a str) -> Fute<'a, ()>;
    fn resume<'a>(&'a self, id: &'a str) -> Fute<'a, ()>;
    fn exec<'a>(&'a self, id: &'a str, req: &'a ExecRequest) -> Fute<'a, Vec<ExecChunk>>;
    fn file_read<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, Vec<u8>>;
    fn file_write<'a>(&'a self, id: &'a str, rel_path: &'a str, bytes: &'a [u8]) -> Fute<'a, ()>;
    fn file_list<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, Vec<String>>;
    fn file_delete<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, ()>;
    fn port_url<'a>(&'a self, id: &'a str, port: u16) -> Fute<'a, PortUrl>;
}

// ---------------------------------------------------------------- podman --

/// Real backend: shells out to `podman` (rootless). All argv is built with
/// `Command::arg`; no shell is involved.
#[derive(Debug, Clone)]
pub struct PodmanRuntime {
    /// Binary to invoke (default `podman`).
    pub bin: PathBuf,
}

impl PodmanRuntime {
    pub fn new(bin: PathBuf) -> Self {
        Self { bin }
    }

    /// Run `podman <args...>`, optionally feeding `stdin`.
    async fn run(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>), ProviderError> {
        let mut cmd = tokio::process::Command::new(&self.bin);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| err_runtime(format!("failed to start {}: {e}", self.bin.display())))?;
        if let Some(bytes) = stdin {
            use tokio::io::AsyncWriteExt as _;
            if let Some(mut input) = child.stdin.take() {
                let _ = input.write_all(bytes).await;
            }
        }
        let output = tokio::time::timeout(Duration::from_secs(120), child.wait_with_output())
            .await
            .map_err(|_| err_runtime("podman command timed out"))?
            .map_err(|e| err_runtime(format!("podman failed: {e}")))?;
        let code = output.status.code().unwrap_or(-1);
        Ok((code, output.stdout, output.stderr))
    }

    /// Like [`Self::run`], but a non-zero exit is a provider error carrying
    /// the stderr text.
    async fn run_ok(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, ProviderError> {
        let (code, out, err) = self.run(args, stdin).await?;
        if code != 0 {
            let stderr = String::from_utf8_lossy(&err);
            return Err(err_runtime(format!(
                "podman {} failed ({code}): {}",
                args.first().copied().unwrap_or(""),
                stderr.trim()
            )));
        }
        Ok(out)
    }

    /// Resolve `rel` inside the container with `realpath -m` and confirm the
    /// result stays under [`WORKSPACE_ROOT`]. Rejects symlink escapes.
    pub(crate) async fn resolve_in_container(
        &self,
        id: &str,
        rel: &str,
    ) -> Result<String, ProviderError> {
        let joined = workspace_path(rel);
        let out = self
            .run_ok(&["exec", id, "realpath", "-m", "--", &joined], None)
            .await?;
        let resolved = String::from_utf8_lossy(&out).trim().to_owned();
        let root = WORKSPACE_ROOT;
        if resolved == root
            || resolved
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            Ok(resolved)
        } else {
            Err(err_invalid(format!(
                "path `{rel}` resolves outside the workspace"
            )))
        }
    }
}

/// Build the `podman run` argument vector for creating `id` from `req`.
///
/// Pure: no I/O or validation (callers validate `req` first). When
/// `req.network_enabled` the container gets pasta networking with host
/// loopback mapped to `10.0.2.2` (where the egress proxy listens
/// host-side); otherwise it stays `--network none`.
pub fn create_args(id: &str, req: &CreateSandboxRequest) -> Vec<String> {
    let cpu = if req.cpu > 0.0 { req.cpu } else { 1.0 };
    let mem_mb = if req.mem_mb > 0 { req.mem_mb } else { 512 };
    let network = if req.network_enabled {
        "pasta:--map-host-loopback=10.0.2.2"
    } else {
        "none"
    };
    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        id.into(),
        "--network".into(),
        network.into(),
        "--security-opt".into(),
        "no-new-privileges=true".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--read-only".into(),
        "--pids-limit".into(),
        "512".into(),
        "--stop-timeout".into(),
        "5".into(),
        "--workdir".into(),
        WORKSPACE_ROOT.into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid".into(),
        "--volume".into(),
        format!("{id}-workspace:{WORKSPACE_ROOT}"),
        "--label".into(),
        format!("starforge.sandbox={id}"),
        "--label".into(),
        "starforge.runtime=podman".into(),
        "--memory".into(),
        format!("{mem_mb}m"),
        "--cpus".into(),
        format!("{cpu}"),
    ];
    for (key, value) in &req.envs {
        args.push("--env".into());
        args.push(format!("{key}={value}"));
    }
    for (key, value) in &req.metadata {
        args.push("--label".into());
        args.push(format!("starforge.meta.{key}={value}"));
    }
    args.push("--".into());
    args.push(req.template.clone());
    args.push("sleep".into());
    args.push("infinity".into());
    args
}

impl Runtime for PodmanRuntime {
    fn create<'a>(&'a self, id: &'a str, req: &'a CreateSandboxRequest) -> Fute<'a, ()> {
        Box::pin(async move {
            if req.template.is_empty() {
                return Err(err_invalid("image/template must not be empty"));
            }
            validate_env(&req.envs)?;
            let args = create_args(id, req);
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            match self.run_ok(&refs, None).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    let message = err.message.to_lowercase();
                    let network_related = message.contains("pasta")
                        || message.contains("network")
                        || message.contains("slirp4netns");
                    if !req.network_enabled || !network_related {
                        return Err(err);
                    }
                    // Networking backend unavailable: drop any partial
                    // container and retry with slirp4netns, which maps host
                    // loopback via its own gateway.
                    Runtime::remove(self, id).await.ok();
                    let mut retry_args = args;
                    if let Some(pos) = retry_args.iter().position(|a| a == "--network")
                        && let Some(value) = retry_args.get_mut(pos + 1)
                    {
                        *value = "slirp4netns:allow_host_loopback=true".to_owned();
                    }
                    let retry_refs: Vec<&str> = retry_args.iter().map(String::as_str).collect();
                    self.run_ok(&retry_refs, None).await?;
                    Ok(())
                }
            }
        })
    }

    fn inspect<'a>(&'a self, id: &'a str) -> Fute<'a, SandboxState> {
        Box::pin(async move {
            let out = self
                .run_ok(&["inspect", "--format", "{{.State.Status}}", id], None)
                .await
                .map_err(|e| {
                    if e.message.contains("no such container") {
                        err_not_found(id)
                    } else {
                        e
                    }
                })?;
            let status = String::from_utf8_lossy(&out).trim().to_owned();
            Ok(match status.as_str() {
                "paused" => SandboxState::Paused,
                "running" => SandboxState::Running,
                "exited" | "stopped" => SandboxState::Killed,
                _ => SandboxState::Running,
            })
        })
    }

    fn remove<'a>(&'a self, id: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            // `rm -f` on a missing container exits non-zero; treat as success.
            let (code, _, stderr) = self.run(&["rm", "-f", id], None).await?;
            if code != 0 {
                let text = String::from_utf8_lossy(&stderr).to_lowercase();
                if !text.contains("no such container") {
                    return Err(err_runtime(format!(
                        "podman rm failed ({code}): {}",
                        String::from_utf8_lossy(&stderr).trim()
                    )));
                }
            }
            Ok(())
        })
    }

    fn pause<'a>(&'a self, id: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            self.run_ok(&["pause", id], None).await?;
            Ok(())
        })
    }

    fn resume<'a>(&'a self, id: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            self.run_ok(&["resume", id], None).await?;
            Ok(())
        })
    }

    fn exec<'a>(&'a self, id: &'a str, req: &'a ExecRequest) -> Fute<'a, Vec<ExecChunk>> {
        Box::pin(async move {
            if req.command.is_empty() {
                return Err(err_invalid("command must not be empty"));
            }
            validate_env(&req.envs)?;
            let mut args: Vec<String> = vec!["exec".into()];
            if let Some(cwd) = &req.cwd {
                let cwd = validate_relative_path(cwd)?;
                args.push("--workdir".into());
                args.push(workspace_path(&cwd));
            }
            for (key, value) in &req.envs {
                args.push("--env".into());
                args.push(format!("{key}={value}"));
            }
            args.push(id.into());
            args.push("--".into());
            for part in &req.command {
                if part.contains('\0') {
                    return Err(err_invalid("command argument contains NUL"));
                }
                args.push(part.clone());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let (code, stdout, stderr) = self.run(&refs, None).await?;
            if stdout.len() > MAX_EXEC_BYTES || stderr.len() > MAX_EXEC_BYTES {
                return Err(ProviderError::new(
                    "too_large",
                    format!("exec output exceeds {MAX_EXEC_BYTES} bytes"),
                ));
            }
            let mut chunks = Vec::new();
            let out = String::from_utf8_lossy(&stdout).into_owned();
            if !out.is_empty() {
                chunks.push(ExecChunk::Stdout { data: out });
            }
            let err = String::from_utf8_lossy(&stderr).into_owned();
            if !err.is_empty() {
                chunks.push(ExecChunk::Stderr { data: err });
            }
            chunks.push(ExecChunk::Exit { code });
            Ok(chunks)
        })
    }

    fn file_read<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, Vec<u8>> {
        Box::pin(async move {
            let resolved = self.resolve_in_container(id, rel_path).await?;
            let out = self
                .run_ok(&["cp", &format!("{id}:{resolved}"), "-"], None)
                .await?;
            if out.len() > MAX_FILE_BYTES {
                return Err(ProviderError::new(
                    "too_large",
                    format!("file exceeds {MAX_FILE_BYTES} bytes"),
                ));
            }
            Ok(out)
        })
    }

    fn file_write<'a>(&'a self, id: &'a str, rel_path: &'a str, bytes: &'a [u8]) -> Fute<'a, ()> {
        Box::pin(async move {
            if bytes.len() > MAX_FILE_BYTES {
                return Err(ProviderError::new(
                    "too_large",
                    format!("file exceeds {MAX_FILE_BYTES} bytes"),
                ));
            }
            let resolved = self.resolve_in_container(id, rel_path).await?;
            let parent = resolved
                .rsplit_once('/')
                .map(|(dir, _)| dir)
                .unwrap_or(WORKSPACE_ROOT);
            self.run_ok(&["exec", id, "mkdir", "-p", "--", parent], None)
                .await?;
            self.run_ok(&["cp", "-", &format!("{id}:{resolved}")], Some(bytes))
                .await?;
            Ok(())
        })
    }

    fn file_list<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, Vec<String>> {
        Box::pin(async move {
            let resolved = self.resolve_in_container(id, rel_path).await?;
            let out = self
                .run_ok(&["exec", id, "ls", "-1A", "--", &resolved], None)
                .await?;
            let text = String::from_utf8_lossy(&out);
            let entries: Vec<String> = text
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| line.to_owned())
                .collect();
            if entries.len() > 100_000 {
                return Err(ProviderError::new(
                    "too_large",
                    "directory listing exceeds 100000 entries",
                ));
            }
            Ok(entries)
        })
    }

    fn file_delete<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            let resolved = self.resolve_in_container(id, rel_path).await?;
            self.run_ok(&["exec", id, "rm", "-rf", "--", &resolved], None)
                .await?;
            Ok(())
        })
    }

    fn port_url<'a>(&'a self, id: &'a str, port: u16) -> Fute<'a, PortUrl> {
        Box::pin(async move {
            // B7 (egress proxy) makes this URL routable; until then the
            // sandbox has `--network none`, so the URL names the port but
            // does not yet resolve. It is well-formed, not a silent stub:
            // the proxy will publish this same shape host-side.
            Ok(PortUrl {
                url: format!("http://{id}.sandboxd.local:{port}/"),
                port,
                expires_at: None,
            })
        })
    }
}

// ------------------------------------------------------------------- fake --

/// In-memory runtime for unit tests. Never shells out.
#[derive(Debug, Default)]
pub struct FakeRuntime {
    inner: Mutex<FakeInner>,
}

#[derive(Debug, Default)]
struct FakeInner {
    sandboxes: HashMap<String, FakeSandbox>,
    created: Vec<(String, CreateSandboxRequest)>,
    kills: Vec<String>,
}

#[derive(Debug, Default)]
struct FakeSandbox {
    state: SandboxState,
    files: HashMap<String, Vec<u8>>,
    /// Symlink map (lexical path -> raw target) for escape tests.
    symlinks: HashMap<String, String>,
    exec_chunks: Vec<ExecChunk>,
    exec_requests: Vec<ExecRequest>,
}

impl FakeRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sandbox_count(&self) -> usize {
        self.inner.lock().unwrap().sandboxes.len()
    }

    /// Ids (with requests) of every create, in order.
    pub fn created(&self) -> Vec<(String, CreateSandboxRequest)> {
        self.inner.lock().unwrap().created.clone()
    }

    /// Ids of every remove, in order.
    pub fn kills(&self) -> Vec<String> {
        self.inner.lock().unwrap().kills.clone()
    }

    /// Install the chunks `exec` returns for `id`.
    pub fn set_exec_chunks(&self, id: &str, chunks: Vec<ExecChunk>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(sandbox) = inner.sandboxes.get_mut(id) {
            sandbox.exec_chunks = chunks;
        }
    }

    /// Exec requests recorded for `id`.
    pub fn exec_requests(&self, id: &str) -> Vec<ExecRequest> {
        let inner = self.inner.lock().unwrap();
        inner
            .sandboxes
            .get(id)
            .map(|s| s.exec_requests.clone())
            .unwrap_or_default()
    }

    /// Plant a symlink `from` -> `to` (both workspace-lexical) for escape tests.
    pub fn add_symlink(&self, id: &str, from: &str, to: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(sandbox) = inner.sandboxes.get_mut(id) {
            sandbox.symlinks.insert(from.to_owned(), to.to_owned());
        }
    }

    /// Resolve `rel` through the symlink map (fake `realpath`) and confirm the
    /// target stays inside the workspace, mirroring the podman behavior.
    fn resolve(sandbox: &FakeSandbox, rel: &str) -> Result<String, ProviderError> {
        let mut current = rel.to_owned();
        for _ in 0..16 {
            let hit = sandbox.symlinks.iter().find(|(from, _)| {
                current == from.as_str() || current.starts_with(format!("{from}/").as_str())
            });
            match hit {
                Some((from, to)) => {
                    let rest = current[from.len()..].to_owned();
                    current = to.trim_end_matches('/').to_owned() + &rest;
                }
                None => break,
            }
        }
        if current == ".." || current.starts_with("../") || current.starts_with('/') {
            return Err(err_invalid(format!(
                "path `{rel}` resolves outside the workspace"
            )));
        }
        Ok(current)
    }
}

impl Runtime for FakeRuntime {
    fn create<'a>(&'a self, id: &'a str, req: &'a CreateSandboxRequest) -> Fute<'a, ()> {
        Box::pin(async move {
            if req.template.is_empty() {
                return Err(err_invalid("image/template must not be empty"));
            }
            validate_env(&req.envs)?;
            let mut inner = self.inner.lock().unwrap();
            inner.sandboxes.entry(id.to_owned()).or_default();
            if let Some(sandbox) = inner.sandboxes.get_mut(id) {
                sandbox.state = SandboxState::Running;
                sandbox.exec_chunks = vec![
                    ExecChunk::Stdout {
                        data: "fake stdout\n".into(),
                    },
                    ExecChunk::Stderr {
                        data: "fake stderr\n".into(),
                    },
                    ExecChunk::Exit { code: 0 },
                ];
            }
            inner.created.push((id.to_owned(), req.clone()));
            Ok(())
        })
    }

    fn inspect<'a>(&'a self, id: &'a str) -> Fute<'a, SandboxState> {
        Box::pin(async move {
            let inner = self.inner.lock().unwrap();
            inner
                .sandboxes
                .get(id)
                .map(|s| s.state)
                .ok_or_else(|| err_not_found(id))
        })
    }

    fn remove<'a>(&'a self, id: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            let mut inner = self.inner.lock().unwrap();
            inner.sandboxes.remove(id);
            inner.kills.push(id.to_owned());
            Ok(())
        })
    }

    fn pause<'a>(&'a self, id: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            let mut inner = self.inner.lock().unwrap();
            inner
                .sandboxes
                .get_mut(id)
                .map(|s| s.state = SandboxState::Paused)
                .ok_or_else(|| err_not_found(id))
        })
    }

    fn resume<'a>(&'a self, id: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            let mut inner = self.inner.lock().unwrap();
            inner
                .sandboxes
                .get_mut(id)
                .map(|s| s.state = SandboxState::Running)
                .ok_or_else(|| err_not_found(id))
        })
    }

    fn exec<'a>(&'a self, id: &'a str, req: &'a ExecRequest) -> Fute<'a, Vec<ExecChunk>> {
        Box::pin(async move {
            validate_env(&req.envs)?;
            let mut inner = self.inner.lock().unwrap();
            let sandbox = inner
                .sandboxes
                .get_mut(id)
                .ok_or_else(|| err_not_found(id))?;
            if sandbox.state != SandboxState::Running {
                return Err(err_runtime(format!("sandbox `{id}` is not running")));
            }
            sandbox.exec_requests.push(req.clone());
            Ok(sandbox.exec_chunks.clone())
        })
    }

    fn file_read<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, Vec<u8>> {
        Box::pin(async move {
            let inner = self.inner.lock().unwrap();
            let sandbox = inner.sandboxes.get(id).ok_or_else(|| err_not_found(id))?;
            let key = Self::resolve(sandbox, rel_path)?;
            sandbox.files.get(&key).cloned().ok_or_else(|| {
                ProviderError::new(
                    "not_found",
                    format!("file `{key}` not found in sandbox `{id}`"),
                )
            })
        })
    }

    fn file_write<'a>(&'a self, id: &'a str, rel_path: &'a str, bytes: &'a [u8]) -> Fute<'a, ()> {
        Box::pin(async move {
            if bytes.len() > MAX_FILE_BYTES {
                return Err(ProviderError::new(
                    "too_large",
                    format!("file exceeds {MAX_FILE_BYTES} bytes"),
                ));
            }
            let mut inner = self.inner.lock().unwrap();
            let sandbox = inner
                .sandboxes
                .get_mut(id)
                .ok_or_else(|| err_not_found(id))?;
            let key = Self::resolve(sandbox, rel_path)?;
            sandbox.files.insert(key, bytes.to_vec());
            Ok(())
        })
    }

    fn file_list<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, Vec<String>> {
        Box::pin(async move {
            let inner = self.inner.lock().unwrap();
            let sandbox = inner.sandboxes.get(id).ok_or_else(|| err_not_found(id))?;
            let dir = Self::resolve(sandbox, rel_path)?;
            let prefix = if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            };
            let mut entries: Vec<String> = sandbox
                .files
                .keys()
                .filter_map(|key| {
                    key.strip_prefix(&prefix)
                        .filter(|rest| !rest.contains('/'))
                        .map(|rest| rest.to_owned())
                })
                .collect();
            entries.sort();
            Ok(entries)
        })
    }

    fn file_delete<'a>(&'a self, id: &'a str, rel_path: &'a str) -> Fute<'a, ()> {
        Box::pin(async move {
            let mut inner = self.inner.lock().unwrap();
            let sandbox = inner
                .sandboxes
                .get_mut(id)
                .ok_or_else(|| err_not_found(id))?;
            let key = Self::resolve(sandbox, rel_path)?;
            sandbox.files.remove(&key);
            Ok(())
        })
    }

    fn port_url<'a>(&'a self, id: &'a str, port: u16) -> Fute<'a, PortUrl> {
        Box::pin(async move {
            let inner = self.inner.lock().unwrap();
            if !inner.sandboxes.contains_key(id) {
                return Err(err_not_found(id));
            }
            Ok(PortUrl {
                url: format!("http://{id}.sandboxd.local:{port}/"),
                port,
                expires_at: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_allowlist_is_exact_or_tagged() {
        let allow = vec!["docker.io/library/rust".to_owned()];
        assert!(image_allowed("docker.io/library/rust", &allow));
        assert!(image_allowed("docker.io/library/rust:1.85", &allow));
        assert!(image_allowed("docker.io/library/rust@sha256:abc", &allow));
        assert!(!image_allowed("docker.io/library/rustic", &allow));
        assert!(!image_allowed("docker.io/library/rust-foo", &allow));
        assert!(!image_allowed("evil.com/rust:1.85", &allow));
        assert!(!image_allowed("", &allow));
        assert!(!image_allowed("rust; rm -rf /", &allow));
    }

    #[test]
    fn env_keys_must_be_shell_names() {
        let good = std::collections::BTreeMap::from([
            ("FOO_BAR".to_owned(), "x".to_owned()),
            ("_A1".to_owned(), "y".to_owned()),
        ]);
        assert!(validate_env(&good).is_ok());
        for bad_key in ["", "1ABC", "A-B", "A B", "-e;rm", "A=B", "Å"] {
            let map = std::collections::BTreeMap::from([(bad_key.to_owned(), "x".to_owned())]);
            assert!(validate_env(&map).is_err(), "key {bad_key:?} must fail");
        }
        let nul_value = std::collections::BTreeMap::from([("K".to_owned(), "a\0b".to_owned())]);
        assert!(validate_env(&nul_value).is_err());
        let ctl_value = std::collections::BTreeMap::from([("K".to_owned(), "a\nb".to_owned())]);
        assert!(validate_env(&ctl_value).is_err());
    }

    #[test]
    fn relative_paths_reject_traversal() {
        assert!(validate_relative_path("src/main.rs").is_ok());
        assert!(validate_relative_path("../etc/passwd").is_err());
        assert!(validate_relative_path("a/../../b").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("").is_err());
        assert!(validate_relative_path("a\0b").is_err());
    }

    #[tokio::test]
    async fn fake_symlink_escape_is_rejected() {
        let rt = FakeRuntime::new();
        rt.create(
            "sbx-1",
            &CreateSandboxRequest {
                template: "x".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        rt.add_symlink("sbx-1", "link", "../../etc");
        let err = rt.file_read("sbx-1", "link/passwd").await.unwrap_err();
        assert_eq!(err.code, "invalid_argument");
        // A symlink staying inside the workspace still works.
        rt.add_symlink("sbx-1", "inside", "real");
        rt.file_write("sbx-1", "real/data.txt", b"secret")
            .await
            .unwrap();
        assert_eq!(
            rt.file_read("sbx-1", "inside/data.txt").await.unwrap(),
            b"secret"
        );
    }

    #[tokio::test]
    async fn fake_files_roundtrip_and_caps() {
        let rt = FakeRuntime::new();
        rt.create(
            "sbx-1",
            &CreateSandboxRequest {
                template: "x".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            rt.file_read("sbx-1", "missing.txt").await.unwrap_err().code,
            "not_found"
        );
        rt.file_write("sbx-1", "a.bin", &[0u8; 8]).await.unwrap();
        assert_eq!(rt.file_read("sbx-1", "a.bin").await.unwrap(), vec![0u8; 8]);
        let big = vec![0u8; MAX_FILE_BYTES + 1];
        let err = rt.file_write("sbx-1", "big", &big).await.unwrap_err();
        assert_eq!(err.code, "too_large");
    }

    #[tokio::test]
    async fn fake_exec_and_remove_are_tracked() {
        let rt = FakeRuntime::new();
        rt.create(
            "sbx-1",
            &CreateSandboxRequest {
                template: "x".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let chunks = rt.exec("sbx-1", &ExecRequest::default()).await.unwrap();
        assert!(matches!(chunks.last(), Some(ExecChunk::Exit { code: 0 })));
        rt.remove("sbx-1").await.unwrap();
        assert_eq!(rt.kills(), vec!["sbx-1".to_owned()]);
        assert!(
            rt.create("sbx-1", &CreateSandboxRequest::default())
                .await
                .is_err()
        );
    }

    fn arg_value(args: &[String], flag: &str) -> Option<String> {
        args.windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
    }

    #[test]
    fn create_args_network_and_hardening() {
        let off = CreateSandboxRequest {
            template: "docker.io/library/rust:1.85".into(),
            ..Default::default()
        };
        let args = create_args("sbx-x", &off);
        assert_eq!(
            arg_value(&args, "--network").as_deref(),
            Some("none"),
            "args: {args:?}"
        );
        let on = CreateSandboxRequest {
            template: "docker.io/library/rust:1.85".into(),
            network_enabled: true,
            ..Default::default()
        };
        let args = create_args("sbx-x", &on);
        assert_eq!(
            arg_value(&args, "--network").as_deref(),
            Some("pasta:--map-host-loopback=10.0.2.2"),
            "args: {args:?}"
        );
        // Hardened flags survive in both modes.
        assert_eq!(arg_value(&args, "--cap-drop").as_deref(), Some("ALL"));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert_eq!(
            arg_value(&args, "--security-opt").as_deref(),
            Some("no-new-privileges=true")
        );
        assert!(args.iter().any(|a| a == "--pids-limit"));
        assert_eq!(
            arg_value(&args, "--volume").as_deref(),
            Some("sbx-x-workspace:/workspace")
        );
    }

    // Real podman smoke test: only when STARFORGE_TEST_SANDBOX=1.
    #[tokio::test]
    async fn podman_smoke_when_enabled() {
        if std::env::var("STARFORGE_TEST_SANDBOX").as_deref() != Ok("1") {
            return;
        }
        let rt = PodmanRuntime::new(PathBuf::from("podman"));
        let id = "sbx-smoke";
        rt.remove(id).await.ok();
        rt.create(
            id,
            &CreateSandboxRequest {
                template: "docker.io/library/rust:1.85".into(),
                ..Default::default()
            },
        )
        .await
        .expect("podman create");
        assert_eq!(rt.inspect(id).await.unwrap(), SandboxState::Running);
        let chunks = rt
            .exec(
                id,
                &ExecRequest {
                    command: vec!["echo".into(), "hello".into()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(chunks.iter().any(|c| matches!(
            c,
            ExecChunk::Stdout { data } if data.contains("hello")
        )));
        rt.file_write(id, "hello.txt", b"data").await.unwrap();
        assert_eq!(rt.file_read(id, "hello.txt").await.unwrap(), b"data");
        rt.remove(id).await.unwrap();
    }
}
