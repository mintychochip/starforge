//! The E2B provider adapter (plan M6b B3): the real E2B v2 API.
//!
//! Control plane: `POST /v2/sandboxes`, `GET`/`DELETE /sandboxes/{id}`,
//! and the pause/resume/timeout routes on `api.e2b.app` with `X-API-Key`.
//! Data plane (envd): `sandbox.e2b.app` with `E2b-Sandbox-Id`,
//! `E2b-Sandbox-Port` (49983), and `X-Access-Token` (the per-sandbox
//! `envdAccessToken` from the create response). Exec uses the Connect
//! protocol (`process.Process/Start`, server-streaming JSON frames); files
//! use the envd REST/JSON endpoints.
//!
//! The API key is never logged or rendered. Secret *values* never travel
//! here: the E2B path delivers repository secrets as environment variables
//! only with the repo's explicit `ci_env_secrets` opt-in, and the server
//! strips local-daemon secret bindings before calling the provider.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde_json::{Value, json};
use starforge_sandbox_protocol::{
    CreateSandboxRequest, ExecChunk, ExecRequest, FileOp, PortUrl, ProviderError, SandboxInfo,
    SandboxState,
};

use crate::sandboxes::{SandboxProvider, encode};

/// envd's port inside an E2B sandbox.
const ENVD_PORT: u16 = 49983;
/// Max exec output kept for one call (matches the local provider's cap).
const MAX_EXEC_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Per-sandbox data-plane credentials from the create response.
#[derive(Debug, Clone)]
struct E2bSandbox {
    envd_token: String,
    domain: String,
}

/// A sandbox provider talking to the real E2B v2 API.
#[derive(Clone)]
pub struct E2bSandboxProvider {
    client: reqwest::Client,
    api_url: String,
    sandbox_url: String,
    api_key: String,
    sandboxes: Arc<Mutex<HashMap<String, E2bSandbox>>>,
}

impl std::fmt::Debug for E2bSandboxProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E2bSandboxProvider")
            .field("api_url", &self.api_url)
            .field("sandbox_url", &self.sandbox_url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl E2bSandboxProvider {
    pub fn new(api_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let api_url = api_url.into().trim_end_matches('/').to_owned();
        let sandbox_url = derive_sandbox_url(&api_url);
        Self {
            client: reqwest::Client::builder()
                .build()
                .expect("reqwest client builder"),
            api_url,
            sandbox_url,
            api_key: api_key.into(),
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Override the envd host (tests and non-standard E2B deployments).
    pub fn with_sandbox_url(mut self, sandbox_url: impl Into<String>) -> Self {
        self.sandbox_url = sandbox_url.into().trim_end_matches('/').to_owned();
        self
    }

    async fn control(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        idempotency_key: Option<&str>,
    ) -> Result<(u16, Vec<u8>), ProviderError> {
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.api_url))
            .header("X-API-Key", &self.api_key);
        if let Some(key) = idempotency_key {
            req = req.header("Idempotency-Key", key);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProviderError::retryable("unavailable", format!("calling e2b: {e}")))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| {
                ProviderError::retryable("unavailable", format!("reading e2b response: {e}"))
            })?
            .to_vec();
        Ok((status, bytes))
    }

    async fn control_json<T>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        idempotency_key: Option<&str>,
    ) -> Result<T, ProviderError>
    where
        T: serde::de::DeserializeOwned,
    {
        let (status, bytes) = self.control(method, path, body, idempotency_key).await?;
        if status >= 400 {
            return Err(parse_error(status, &bytes));
        }
        if bytes.is_empty() {
            return Err(ProviderError::new("internal", "empty e2b response"));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| ProviderError::new("internal", format!("decoding e2b response: {e}")))
    }

    /// One envd request with the sandbox routing headers.
    async fn envd(
        &self,
        id: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
        content_type: &str,
        timeout_ms: Option<u64>,
    ) -> Result<(u16, Vec<u8>), ProviderError> {
        let token = self.token_for(id).await?;
        let req = self
            .client
            .request(method, format!("{}{path}", self.sandbox_url))
            .header("E2b-Sandbox-Id", id)
            .header("E2b-Sandbox-Port", ENVD_PORT.to_string())
            .header("X-Access-Token", token)
            .header("Connect-Protocol-Version", "1")
            .header(reqwest::header::CONTENT_TYPE, content_type);
        let mut req = match timeout_ms {
            Some(ms) => req.header("Connect-Timeout-Ms", ms.to_string()),
            None => req,
        };
        if let Some(body) = body {
            req = req.body(body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProviderError::retryable("unavailable", format!("calling envd: {e}")))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| {
                ProviderError::retryable("unavailable", format!("reading envd response: {e}"))
            })?
            .to_vec();
        Ok((status, bytes))
    }

    /// The envd access token for `id`, from the create cache or a
    /// `POST /sandboxes/{id}/connect` refresh. The provider is constructed
    /// per call, so the cache can be empty; the connect call also resumes a
    /// paused sandbox and returns a fresh token, so it is correct across a
    /// server restart and with several servers.
    async fn token_for(&self, id: &str) -> Result<String, ProviderError> {
        if let Some(token) = self
            .sandboxes
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.envd_token.clone())
        {
            return Ok(token);
        }
        let value: Value = self
            .control_json(
                reqwest::Method::POST,
                &format!("/sandboxes/{}/connect", encode(id)),
                None,
                None,
            )
            .await?;
        let token = value
            .get("envdAccessToken")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let domain = value
            .get("domain")
            .and_then(Value::as_str)
            .unwrap_or("e2b.app")
            .to_owned();
        self.sandboxes.lock().unwrap().insert(
            id.to_owned(),
            E2bSandbox {
                envd_token: token.clone(),
                domain,
            },
        );
        Ok(token)
    }

    fn sandbox_info(&self, id: &str, state: &str, timeout_s: u64) -> SandboxInfo {
        let state = match state {
            "paused" => SandboxState::Paused,
            "killed" | "stopped" | "expired" => SandboxState::Killed,
            "error" => SandboxState::Error,
            _ => SandboxState::Running,
        };
        SandboxInfo {
            id: id.to_owned(),
            state,
            runtime: "e2b".to_owned(),
            expires_at: (timeout_s > 0).then(|| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                format_rfc3339(now + timeout_s)
            }),
            provider: "e2b".to_owned(),
        }
    }
}

/// Derive the envd host from the control-plane URL: `api.e2b.app` →
/// `sandbox.e2b.app`; a non-`api.` host (a fake server or a private
/// deployment) is used unchanged.
fn derive_sandbox_url(api_url: &str) -> String {
    if let Some(rest) = api_url.strip_prefix("https://api.") {
        format!("https://sandbox.{rest}")
    } else if let Some(rest) = api_url.strip_prefix("http://api.") {
        format!("http://sandbox.{rest}")
    } else {
        api_url.to_owned()
    }
}

/// Format seconds since the epoch as an RFC 3339 UTC timestamp.
fn format_rfc3339(secs: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .map(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

fn parse_error(status: u16, bytes: &[u8]) -> ProviderError {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes)
        && let Some(message) = value.get("message").and_then(Value::as_str)
    {
        if value.get("error_code").and_then(Value::as_str) == Some("sandbox_capacity_unavailable") {
            return ProviderError::retryable("capacity", message);
        }
        let code = match status {
            404 => "not_found",
            401 | 403 => "unauthorized",
            409 => "conflict",
            413 => "too_large",
            429 => "capacity",
            503 | 504 => "unavailable",
            _ => "internal",
        };
        let error = ProviderError::new(code, message);
        return if matches!(status, 429 | 503 | 504) {
            ProviderError::retryable(error.code, error.message)
        } else {
            error
        };
    }
    let code = match status {
        404 => "not_found",
        401 | 403 => "unauthorized",
        409 => "conflict",
        413 => "too_large",
        429 => "capacity",
        503 | 504 => "unavailable",
        _ => "internal",
    };
    let message = format!("e2b answered {status}");
    if matches!(status, 429 | 503 | 504) {
        ProviderError::retryable(code, message)
    } else {
        ProviderError::new(code, message)
    }
}

/// One Connect frame: flags byte 0, four big-endian length bytes, JSON.
fn connect_frame(payload: &Value) -> Vec<u8> {
    let json = serde_json::to_vec(payload).expect("JSON");
    let mut out = Vec::with_capacity(5 + json.len());
    out.push(0);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    out
}

/// Decode a server-streaming Connect response into exec chunks. The final
/// frame (flags bit 2) carries an optional error object.
fn decode_start_stream(bytes: &[u8]) -> Result<Vec<ExecChunk>, ProviderError> {
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut offset = 0usize;
    let mut saw_end = false;
    while offset + 5 <= bytes.len() {
        let flags = bytes[offset];
        let len = u32::from_be_bytes([
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
        ]) as usize;
        offset += 5;
        if offset + len > bytes.len() {
            return Err(ProviderError::new("internal", "truncated e2b stream frame"));
        }
        let payload = &bytes[offset..offset + len];
        offset += len;
        let value: Value = serde_json::from_slice(payload)
            .map_err(|e| ProviderError::new("internal", format!("decoding e2b frame: {e}")))?;
        if flags & 2 != 0 {
            if let Some(error) = value.get("error") {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("e2b process failed");
                return Err(ProviderError::new("internal", message));
            }
            break;
        }
        let Some(event) = value.get("event") else {
            continue;
        };
        if let Some(data) = event.get("data") {
            for (key, stdout) in [("stdout", true), ("stderr", false)] {
                if let Some(encoded) = data.get(key).and_then(Value::as_str) {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|e| {
                            ProviderError::new("internal", format!("e2b {key} is not base64: {e}"))
                        })?;
                    total += bytes.len();
                    if total > MAX_EXEC_OUTPUT_BYTES {
                        return Err(ProviderError::new(
                            "too_large",
                            "e2b exec output is too large",
                        ));
                    }
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    out.push(if stdout {
                        ExecChunk::Stdout { data: text }
                    } else {
                        ExecChunk::Stderr { data: text }
                    });
                }
            }
        }
        if let Some(end) = event.get("end") {
            saw_end = true;
            // proto3 JSON omits zero-valued scalars, so a successful process
            // may carry no `exitCode` at all. `exited: true` with no error is
            // success; otherwise an absent code is a failure.
            let code = match end.get("exitCode").and_then(Value::as_i64) {
                Some(code) => code,
                None if end.get("exited").and_then(Value::as_bool) == Some(true)
                    && end.get("error").is_none() =>
                {
                    0
                }
                None => 1,
            };
            out.push(ExecChunk::Exit {
                code: code.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            });
        }
    }
    if offset != bytes.len() {
        // A trailing partial header is a truncated frame, not an end.
        return Err(ProviderError::new("internal", "truncated e2b stream frame"));
    }
    if !saw_end {
        // A stream that stops without an exit event cannot prove the
        // command succeeded; never report it as a zero exit.
        return Err(ProviderError::new(
            "internal",
            "e2b stream ended without an exit event",
        ));
    }
    Ok(out)
}

impl SandboxProvider for E2bSandboxProvider {
    fn create(
        &self,
        request: CreateSandboxRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let mut request = request;
            // Local-daemon-only field: never send secret values to E2B.
            request.secret_bindings.clear();
            let timeout = if request.timeout_s == 0 {
                300
            } else {
                request.timeout_s
            };
            // The Starforge default is deny-all; E2B's default is open.
            let mut network = json!({ "allowPublicTraffic": true });
            if !request.network.allow_out.is_empty() {
                network["allowOut"] = json!(request.network.allow_out);
            }
            if !request.network.deny_out.is_empty() {
                network["denyOut"] = json!(request.network.deny_out);
            }
            let mut body = json!({
                "templateID": request.template,
                "timeout": timeout,
                // Starforge is default-deny. E2B documents `false` as
                // `denyOut: 0.0.0.0/0`; `network.allowOut` entries still
                // take precedence, so the allowlist is the only egress.
                "allow_internet_access": false,
                "network": network,
            });
            if !request.envs.is_empty() {
                body["envVars"] = json!(request.envs);
            }
            if !request.metadata.is_empty() {
                body["metadata"] = json!(request.metadata);
            }
            let idempotency = request
                .idempotency_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .map(sanitize_idempotency_key);
            let created: Value = self
                .control_json(
                    reqwest::Method::POST,
                    "/v2/sandboxes",
                    Some(&body),
                    idempotency.as_deref(),
                )
                .await?;
            let id = created
                .get("sandboxID")
                .and_then(Value::as_str)
                .ok_or_else(|| ProviderError::new("internal", "e2b create has no sandboxID"))?
                .to_owned();
            let envd_token = created
                .get("envdAccessToken")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let domain = created
                .get("domain")
                .and_then(Value::as_str)
                .unwrap_or("e2b.app")
                .to_owned();
            self.sandboxes
                .lock()
                .unwrap()
                .insert(id.clone(), E2bSandbox { envd_token, domain });
            Ok(self.sandbox_info(&id, "running", timeout))
        })
    }

    fn get(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let value: Value = self
                .control_json(
                    reqwest::Method::GET,
                    &format!("/sandboxes/{}", encode(&id)),
                    None,
                    None,
                )
                .await?;
            let state = value
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or("running");
            Ok(self.sandbox_info(&id, state, 0))
        })
    }

    fn kill(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let (status, bytes) = self
                .control(
                    reqwest::Method::DELETE,
                    &format!("/sandboxes/{}", encode(&id)),
                    None,
                    None,
                )
                .await?;
            self.sandboxes.lock().unwrap().remove(&id);
            if status >= 400 && status != 404 {
                return Err(parse_error(status, &bytes));
            }
            Ok(())
        })
    }

    fn pause(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let _: Value = self
                .control_json(
                    reqwest::Method::POST,
                    &format!("/sandboxes/{}/pause", encode(&id)),
                    None,
                    None,
                )
                .await?;
            Ok(self.sandbox_info(&id, "paused", 0))
        })
    }

    fn resume(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let value: Value = self
                .control_json(
                    reqwest::Method::POST,
                    &format!("/sandboxes/{}/resume", encode(&id)),
                    None,
                    None,
                )
                .await?;
            let token = value
                .get("envdAccessToken")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if !token.is_empty()
                && let Some(entry) = self.sandboxes.lock().unwrap().get_mut(&id)
            {
                entry.envd_token = token;
            }
            Ok(self.sandbox_info(&id, "running", 0))
        })
    }

    fn set_timeout(
        &self,
        id: String,
        timeout_s: u64,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let body = json!({ "timeout": timeout_s });
            let _: Value = self
                .control_json(
                    reqwest::Method::POST,
                    &format!("/sandboxes/{}/timeout", encode(&id)),
                    Some(&body),
                    None,
                )
                .await?;
            Ok(self.sandbox_info(&id, "running", timeout_s))
        })
    }

    fn exec(
        &self,
        id: String,
        request: ExecRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExecChunk>, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            if request.command.is_empty() {
                return Err(ProviderError::new("invalid", "command must not be empty"));
            }
            let mut process = json!({
                "cmd": request.command[0],
                "args": &request.command[1..],
            });
            if !request.envs.is_empty() {
                process["envs"] = json!(request.envs);
            }
            if let Some(cwd) = &request.cwd {
                process["cwd"] = json!(cwd);
            }
            let payload = json!({ "process": process, "stdin": false });
            let timeout_ms = (request.timeout_s > 0).then(|| request.timeout_s * 1000);
            let (status, bytes) = self
                .envd(
                    &id,
                    reqwest::Method::POST,
                    "/process.Process/Start",
                    Some(connect_frame(&payload)),
                    "application/connect+json",
                    timeout_ms,
                )
                .await?;
            if status >= 400 {
                return Err(parse_error(status, &bytes));
            }
            decode_start_stream(&bytes)
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
                    let (status, bytes) = self
                        .envd(
                            &id,
                            reqwest::Method::GET,
                            &format!("/files?path={}", encode(&path)),
                            None,
                            "application/octet-stream",
                            None,
                        )
                        .await?;
                    if status == 404 {
                        return Err(ProviderError::new("not_found", "e2b file not found"));
                    }
                    if status >= 400 {
                        return Err(parse_error(status, &bytes));
                    }
                    String::from_utf8(bytes).map_err(|e| {
                        ProviderError::new("internal", format!("file content is not text: {e}"))
                    })
                }
                FileOp::List { path } => {
                    let body =
                        serde_json::to_vec(&json!({ "path": path, "depth": 1 })).expect("JSON");
                    let (status, bytes) = self
                        .envd(
                            &id,
                            reqwest::Method::POST,
                            "/filesystem.Filesystem/ListDir",
                            Some(body),
                            "application/json",
                            None,
                        )
                        .await?;
                    if status >= 400 {
                        return Err(parse_error(status, &bytes));
                    }
                    let value: Value = serde_json::from_slice(&bytes)
                        .map_err(|e| ProviderError::new("internal", format!("e2b list: {e}")))?;
                    let entries = value["entries"]
                        .as_array()
                        .ok_or_else(|| ProviderError::new("internal", "e2b list has no entries"))?;
                    Ok(entries
                        .iter()
                        .filter_map(|e| e.get("name").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n"))
                }
                FileOp::Write { path, content } => {
                    let (status, bytes) = self
                        .envd(
                            &id,
                            reqwest::Method::PUT,
                            &format!("/files?path={}", encode(&path)),
                            Some(content.into_bytes()),
                            "application/octet-stream",
                            None,
                        )
                        .await?;
                    if status >= 400 {
                        return Err(parse_error(status, &bytes));
                    }
                    Ok(String::new())
                }
                FileOp::Delete { path } => {
                    let body = serde_json::to_vec(&json!({ "path": path })).expect("JSON");
                    let (status, bytes) = self
                        .envd(
                            &id,
                            reqwest::Method::POST,
                            "/filesystem.Filesystem/Remove",
                            Some(body),
                            "application/json",
                            None,
                        )
                        .await?;
                    if status >= 400 {
                        return Err(parse_error(status, &bytes));
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
            let domain = {
                let guard = self.sandboxes.lock().unwrap();
                guard
                    .get(&id)
                    .map(|s| s.domain.clone())
                    .unwrap_or_else(|| "e2b.app".to_owned())
            };
            Ok(PortUrl {
                url: format!("https://{port}-{id}.{domain}/"),
                port,
                expires_at: None,
            })
        })
    }
}

/// E2B idempotency keys are 1-255 lowercase ASCII letters, digits, or
/// hyphens. A Starforge key may contain other characters; hash those to a
/// stable lowercase hex key.
fn sanitize_idempotency_key(key: &str) -> String {
    if !key.is_empty()
        && key.len() <= 255
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return key.to_owned();
    }
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use starforge_sandbox_protocol::{ExecChunk, NetworkPolicy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn frame(flags: u8, value: &Value) -> Vec<u8> {
        let json = serde_json::to_vec(value).unwrap();
        let mut out = vec![flags];
        out.extend_from_slice(&(json.len() as u32).to_be_bytes());
        out.extend_from_slice(&json);
        out
    }

    fn response(status: u16, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    async fn fake_e2b(listener: tokio::net::TcpListener, seen: Arc<Mutex<Vec<String>>>) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            seen.lock().unwrap().push(req.clone());
            let body: Vec<u8> = if req.starts_with("POST /v2/sandboxes ") {
                if req.contains("\"templateID\":\"missing\"") {
                    response(404, br#"{"code":404,"message":"template not found"}"#)
                } else if req.contains("\"templateID\":\"capacity\"") {
                    response(
                        503,
                        br#"{"code":503,"message":"no capacity","error_code":"sandbox_capacity_unavailable"}"#,
                    )
                } else {
                    response(
                        201,
                        br#"{"sandboxID":"sbx-1","envdAccessToken":"envd-tok","domain":"e2b.app"}"#,
                    )
                }
            } else if req.starts_with("POST /process.Process/Start ") {
                let mut out = frame(
                    0,
                    &json!({"event":{"data":{"stdout": base64::engine::general_purpose::STANDARD.encode("hi")}}}),
                );
                out.extend(frame(
                    0,
                    &json!({"event":{"data":{"stderr": base64::engine::general_purpose::STANDARD.encode("err")}}}),
                ));
                out.extend(frame(
                    0,
                    &json!({"event":{"end":{"exitCode":0,"exited":true}}}),
                ));
                out.extend(frame(2, &json!({})));
                response(200, &out)
            } else if req.starts_with("GET /files?path=") {
                response(200, b"content")
            } else if req.starts_with("PUT /files?path=") {
                response(200, b"")
            } else if req.starts_with("POST /filesystem.Filesystem/ListDir ") {
                response(200, br#"{"entries":[{"name":"a"},{"name":"b"}]}"#)
            } else if req.starts_with("POST /filesystem.Filesystem/Remove ") {
                response(200, b"{}")
            } else if req.starts_with("DELETE /sandboxes/sbx-1 ") {
                response(200, b"")
            } else if req.starts_with("POST /sandboxes/sbx-1/connect ") {
                response(
                    200,
                    br#"{"sandboxID":"sbx-1","envdAccessToken":"envd-tok-2","domain":"e2b.app"}"#,
                )
            } else if req.starts_with("GET /sandboxes/sbx-1 ") {
                response(200, br#"{"state":"running"}"#)
            } else if req.starts_with("POST /sandboxes/sbx-1/pause ") {
                response(200, b"{}")
            } else if req.starts_with("POST /sandboxes/sbx-1/resume ") {
                response(200, br#"{"envdAccessToken":"envd-tok"}"#)
            } else if req.starts_with("POST /sandboxes/sbx-1/timeout ") {
                response(200, b"{}")
            } else {
                response(404, b"{}")
            };
            let _ = stream.write_all(&body).await;
        }
    }

    async fn provider() -> (E2bSandboxProvider, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(fake_e2b(listener, Arc::clone(&seen)));
        let provider = E2bSandboxProvider::new(&base, "key").with_sandbox_url(&base);
        (provider, seen)
    }

    #[tokio::test]
    async fn create_exec_files_and_lifecycle_round_trip() {
        let (provider, seen) = provider().await;
        let info = provider
            .create(CreateSandboxRequest {
                template: "base".into(),
                timeout_s: 60,
                network: NetworkPolicy {
                    allow_out: vec!["example.com".into()],
                    ..Default::default()
                },
                envs: BTreeMap::from([("A".into(), "1".into())]),
                secret_bindings: vec![starforge_sandbox_protocol::SecretBindingWire {
                    host: "example.com".into(),
                    header: "Authorization".into(),
                    value: "secret-value".into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(info.id, "sbx-1");
        assert_eq!(info.state, SandboxState::Running);
        let create = seen.lock().unwrap()[0].to_lowercase();
        assert!(create.contains("x-api-key: key"), "{create}");
        assert!(create.contains("\"templateid\":\"base\""), "{create}");
        assert!(create.contains("\"allowout\""), "{create}");
        assert!(create.contains("\"allowpublictraffic\":true"), "{create}");
        assert!(
            create.contains("\"allow_internet_access\":false"),
            "default-deny: {create}"
        );
        assert!(
            !create.contains("secret-value"),
            "no secret values: {create}"
        );
        assert!(create.contains("\"envvars\""), "{create}");

        let chunks = provider
            .exec(
                "sbx-1".into(),
                ExecRequest {
                    command: vec!["echo".into(), "hi".into()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            chunks
                .iter()
                .any(|c| matches!(c, ExecChunk::Stdout { data } if data == "hi"))
        );
        assert!(
            chunks
                .iter()
                .any(|c| matches!(c, ExecChunk::Stderr { data } if data == "err"))
        );
        assert!(
            chunks
                .iter()
                .any(|c| matches!(c, ExecChunk::Exit { code: 0 }))
        );
        let exec = seen
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.starts_with("POST /process.Process/Start"))
            .unwrap()
            .to_lowercase();
        assert!(exec.contains("e2b-sandbox-id: sbx-1"), "{exec}");
        assert!(exec.contains("x-access-token: envd-tok"), "{exec}");
        assert!(exec.contains("connect-protocol-version: 1"), "{exec}");

        assert_eq!(
            provider
                .files(
                    "sbx-1".into(),
                    FileOp::Read {
                        path: "a.txt".into()
                    }
                )
                .await
                .unwrap(),
            "content"
        );
        assert_eq!(
            provider
                .files("sbx-1".into(), FileOp::List { path: ".".into() })
                .await
                .unwrap(),
            "a\nb"
        );
        provider
            .files(
                "sbx-1".into(),
                FileOp::Write {
                    path: "a.txt".into(),
                    content: "x".into(),
                },
            )
            .await
            .unwrap();
        provider
            .files(
                "sbx-1".into(),
                FileOp::Delete {
                    path: "a.txt".into(),
                },
            )
            .await
            .unwrap();

        provider.get("sbx-1".into()).await.unwrap();
        provider.pause("sbx-1".into()).await.unwrap();
        provider.resume("sbx-1".into()).await.unwrap();
        provider.set_timeout("sbx-1".into(), 30).await.unwrap();
        let url = provider.port_url("sbx-1".into(), 3000).await.unwrap();
        assert!(url.url.contains("3000-sbx-1.e2b.app"), "{}", url.url);
        provider.kill("sbx-1".into()).await.unwrap();
    }

    #[tokio::test]
    async fn a_fresh_provider_rehydrates_via_connect() {
        let (provider, seen) = provider().await;
        provider
            .create(CreateSandboxRequest {
                template: "base".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        // A second provider instance (as `Core::sandbox_provider` builds per
        // call) has an empty cache; it must connect and use the fresh token.
        let base = provider.sandbox_url.clone();
        let fresh = E2bSandboxProvider::new(&base, "key").with_sandbox_url(&base);
        let chunks = fresh
            .exec(
                "sbx-1".into(),
                ExecRequest {
                    command: vec!["echo".into(), "hi".into()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            chunks
                .iter()
                .any(|c| matches!(c, ExecChunk::Exit { code: 0 }))
        );
        let requests = seen.lock().unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with("POST /sandboxes/sbx-1/connect")),
            "connect must rehydrate: {requests:?}"
        );
        let exec = requests
            .iter()
            .find(|r| r.starts_with("POST /process.Process/Start"))
            .unwrap()
            .to_lowercase();
        assert!(exec.contains("x-access-token: envd-tok-2"), "{exec}");
    }

    #[test]
    fn terminal_error_frame_is_an_error() {
        let bytes = frame(
            2,
            &json!({"error":{"code":"invalid_argument","message":"boom"}}),
        );
        let err = decode_start_stream(&bytes).unwrap_err();
        assert!(err.message.contains("boom"), "{err:?}");
    }

    #[test]
    fn truncated_frame_is_an_error() {
        let err = decode_start_stream(&[0, 0, 0, 0, 10]).unwrap_err();
        assert!(err.message.contains("truncated"), "{err:?}");
    }

    #[test]
    fn stream_without_an_end_event_is_an_error() {
        let bytes = frame(
            0,
            &json!({"event":{"data":{"stdout": base64::engine::general_purpose::STANDARD.encode("hi")}}}),
        );
        let err = decode_start_stream(&bytes).unwrap_err();
        assert!(err.message.contains("without an exit event"), "{err:?}");
    }

    #[test]
    fn omitted_zero_exit_code_is_success() {
        let mut bytes = frame(
            0,
            &json!({"event":{"end":{"exited":true,"status":"exit status 0"}}}),
        );
        bytes.extend(frame(2, &json!({})));
        let chunks = decode_start_stream(&bytes).unwrap();
        assert!(
            chunks
                .iter()
                .any(|c| matches!(c, ExecChunk::Exit { code: 0 })),
            "{chunks:?}"
        );
    }

    #[test]
    fn partial_trailing_header_is_an_error() {
        let mut bytes = frame(
            0,
            &json!({"event":{"data":{"stdout": base64::engine::general_purpose::STANDARD.encode("hi")}}}),
        );
        bytes.extend_from_slice(&[0, 0, 0]);
        let err = decode_start_stream(&bytes).unwrap_err();
        assert!(err.message.contains("truncated"), "{err:?}");
    }

    #[test]
    fn non_zero_exit_is_preserved() {
        let mut bytes = frame(0, &json!({"event":{"end":{"exitCode":7,"exited":true}}}));
        bytes.extend(frame(2, &json!({})));
        let chunks = decode_start_stream(&bytes).unwrap();
        assert!(
            chunks
                .iter()
                .any(|c| matches!(c, ExecChunk::Exit { code: 7 }))
        );
    }

    #[tokio::test]
    async fn control_plane_errors_map_to_codes() {
        let (provider, _seen) = provider().await;
        let missing = provider
            .create(CreateSandboxRequest {
                template: "missing".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(missing.code, "not_found");
        let capacity = provider
            .create(CreateSandboxRequest {
                template: "capacity".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(capacity.code, "capacity");
        assert!(capacity.retryable);
    }

    #[test]
    fn idempotency_keys_are_sanitized() {
        assert_eq!(sanitize_idempotency_key("abc-123"), "abc-123");
        let hashed = sanitize_idempotency_key("Not A Valid Key");
        assert_eq!(hashed.len(), 64);
        assert!(hashed.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
