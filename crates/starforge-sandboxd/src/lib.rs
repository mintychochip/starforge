//! `starforge-sandboxd`: local sandbox provider daemon (plan M6b B2).
//!
//! HTTP control plane over a Unix socket, in front of a [`Runtime`]
//! (rootless podman by default; [`podman::FakeRuntime`] in tests). Every
//! request needs `Authorization: Bearer <token>`, where the token is read
//! from a `0600` token file the daemon rotates on each start; the listener
//! additionally drops connections whose `SO_PEERCRED` uid is not the daemon's
//! own uid (see `main.rs`).
//!
//! Endpoints (JSON, mirroring `starforge-sandbox-protocol`):
//!
//! - `POST /sandboxes` — create (allowlisted image, idempotency key, TTL).
//! - `GET /sandboxes/{id}` — state + expiry.
//! - `DELETE /sandboxes/{id}` — kill (idempotent).
//! - `POST /sandboxes/{id}/pause|resume|timeout` — lifecycle.
//! - `POST /sandboxes/{id}/exec` — returns the chunk array
//!   (`ExecChunk` values, `stream`-tagged).
//! - `GET /sandboxes/{id}/files` — `?path=` read, `?path=&op=list` listing.
//! - `PUT /sandboxes/{id}/files` — `{"path","content"}` write; `content` is
//!   base64 (see [`podman::MAX_FILE_BYTES`], 8 MiB).
//! - `DELETE /sandboxes/{id}/files` — `?path=` delete.
//! - `GET /sandboxes/{id}/ports/{port}/url` — port URL.
//!
//! Errors are [`ProviderError`] JSON with a status taken from the code.

pub mod podman;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use starforge_sandbox_protocol::{
    CreateSandboxRequest, ExecChunk, ExecRequest, PortUrl, ProviderError, SandboxInfo, SandboxState,
};

use podman::{
    MAX_FILE_B64_CHARS, MAX_TIMEOUT_S, Runtime, err_invalid, err_not_found, image_allowed,
    validate_env, validate_relative_path,
};

/// Daemon knobs.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Image allowlist (exact or `name:tag`/`name@digest` match).
    pub images: Vec<String>,
    /// TTL used when a create request carries `timeout_s = 0`.
    pub default_ttl_s: u64,
    /// Max concurrent sandboxes (`0` = unlimited).
    pub max_sandboxes: usize,
    /// Cap on one exec (seconds; `0` = no cap).
    pub exec_timeout_s: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            images: Vec::new(),
            default_ttl_s: 3600,
            max_sandboxes: 0,
            exec_timeout_s: 300,
        }
    }
}

#[derive(Debug)]
struct SandboxRecord {
    info: SandboxInfo,

    deadline_unix: i64,
}

/// Shared daemon state (cheap to clone).
#[derive(Clone)]
pub struct DaemonState {
    runtime: Arc<dyn Runtime>,
    token: String,
    config: DaemonConfig,
    sandboxes: Arc<Mutex<HashMap<String, SandboxRecord>>>,
    idempotency: Arc<Mutex<HashMap<String, String>>>,
}

impl DaemonState {
    pub fn new(runtime: Arc<dyn Runtime>, token: String, config: DaemonConfig) -> Self {
        Self {
            runtime,
            token,
            config,
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            idempotency: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn sandbox_count(&self) -> usize {
        self.sandboxes.lock().unwrap().len()
    }
}

/// Handler error: the wire [`ProviderError`] carried as JSON with a status.
#[derive(Debug, Clone)]
pub struct ApiError(pub ProviderError);

impl ApiError {
    fn unauthorized() -> Self {
        Self(ProviderError::new(
            "unauthorized",
            "missing or invalid bearer token",
        ))
    }

    fn too_large(message: impl Into<String>) -> Self {
        Self(ProviderError::new("too_large", message))
    }
}

impl From<ProviderError> for ApiError {
    fn from(err: ProviderError) -> Self {
        Self(err)
    }
}

fn status_for(code: &str) -> StatusCode {
    match code {
        "unauthorized" => StatusCode::UNAUTHORIZED,
        "not_found" => StatusCode::NOT_FOUND,
        "invalid_argument" => StatusCode::BAD_REQUEST,
        "image_not_allowed" => StatusCode::FORBIDDEN,
        "capacity" => StatusCode::TOO_MANY_REQUESTS,
        "timeout" => StatusCode::REQUEST_TIMEOUT,
        "too_large" => StatusCode::PAYLOAD_TOO_LARGE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = status_for(&self.0.code);
        (status, Json(&self.0)).into_response()
    }
}

/// Constant-time byte comparison for the bearer token.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Read `n` random bytes from `/dev/urandom` (daemon ids + token).
pub fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut file = std::fs::File::open("/dev/urandom")?;
    use std::io::Read as _;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Hex-encode `n` random bytes.
pub fn random_hex(n: usize) -> std::io::Result<String> {
    Ok(random_bytes(n)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ` (Hinnant civil-from-days; the daemon
/// takes no extra dependency for one envelope format).
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let (h, mi, s) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn record_info(record: &SandboxRecord) -> SandboxInfo {
    let mut info = record.info.clone();
    info.expires_at = Some(rfc3339(record.deadline_unix));
    info
}

/// Kill every sandbox whose deadline has passed. Returns killed ids.
pub async fn sweep_expired(state: &DaemonState, now_unix: i64) -> Vec<String> {
    let expired: Vec<String> = {
        let sandboxes = state.sandboxes.lock().unwrap();
        sandboxes
            .iter()
            .filter_map(|(id, record)| (record.deadline_unix <= now_unix).then_some(id.clone()))
            .collect()
    };
    let mut killed = Vec::new();
    for id in expired {
        let _ = state.runtime.remove(&id).await;
        state.sandboxes.lock().unwrap().remove(&id);
        killed.push(id);
    }
    killed
}

// -------------------------------------------------------------- middleware --

async fn auth_middleware(
    State(state): State<DaemonState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !ct_eq(token.as_bytes(), state.token.as_bytes()) {
        return Err(ApiError::unauthorized());
    }
    Ok(next.run(req).await)
}

// --------------------------------------------------------------- handlers --

async fn create_sandbox(
    State(state): State<DaemonState>,
    Json(req): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxInfo>, ApiError> {
    if !req.runtime.is_empty() && req.runtime != "podman" {
        return Err(ApiError(err_invalid(format!(
            "runtime `{}` is not available on this daemon (only `podman` is built in)",
            req.runtime
        ))));
    }
    if req.template.is_empty() {
        return Err(ApiError(err_invalid("image/template must not be empty")));
    }
    if !image_allowed(&req.template, &state.config.images) {
        return Err(ApiError(ProviderError::new(
            "image_not_allowed",
            format!("image `{}` is not on the allowlist", req.template),
        )));
    }
    validate_env(&req.envs)?;

    // Idempotency: a retry with the same key returns the original sandbox.
    if let Some(key) = &req.idempotency_key {
        let existing = state.idempotency.lock().unwrap().get(key).cloned();
        if let Some(existing) = existing {
            let sandboxes = state.sandboxes.lock().unwrap();
            if let Some(record) = sandboxes.get(&existing) {
                return Ok(Json(record_info(record)));
            }
        }
    }

    let ttl = if req.timeout_s == 0 {
        state.config.default_ttl_s
    } else if req.timeout_s > MAX_TIMEOUT_S {
        return Err(ApiError(err_invalid(format!(
            "timeout_s {} exceeds the {MAX_TIMEOUT_S}s cap",
            req.timeout_s
        ))));
    } else {
        req.timeout_s
    };

    if state.config.max_sandboxes > 0
        && state.sandboxes.lock().unwrap().len() >= state.config.max_sandboxes
    {
        return Err(ApiError(ProviderError::retryable(
            "capacity",
            "sandbox capacity reached",
        )));
    }

    let id = format!(
        "sbx-{}",
        random_hex(8).map_err(|e| ProviderError::new(
            "internal",
            format!("failed to generate sandbox id: {e}")
        ))?
    );
    state.runtime.create(&id, &req).await?;

    let now = now_unix();
    let record = SandboxRecord {
        info: SandboxInfo {
            id: id.clone(),
            state: SandboxState::Running,
            runtime: "podman".to_owned(),
            expires_at: Some(rfc3339(now + ttl as i64)),
            provider: "local".to_owned(),
        },
        deadline_unix: now + ttl as i64,
    };
    let info = record_info(&record);
    state.sandboxes.lock().unwrap().insert(id.clone(), record);
    if let Some(key) = &req.idempotency_key {
        state.idempotency.lock().unwrap().insert(key.clone(), id);
    }
    Ok(Json(info))
}

async fn get_sandbox(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    let sandboxes = state.sandboxes.lock().unwrap();
    sandboxes
        .get(&id)
        .map(|record| Json(record_info(record)))
        .ok_or_else(|| ApiError(err_not_found(&id)))
}

async fn delete_sandbox(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let known = state.sandboxes.lock().unwrap().remove(&id).is_some();
    if known {
        state.runtime.remove(&id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn pause_sandbox(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    state.runtime.pause(&id).await?;
    update_state(&state, &id, SandboxState::Paused)
}

async fn resume_sandbox(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    state.runtime.resume(&id).await?;
    update_state(&state, &id, SandboxState::Running)
}

fn update_state(
    state: &DaemonState,
    id: &str,
    new_state: SandboxState,
) -> Result<Json<SandboxInfo>, ApiError> {
    let mut sandboxes = state.sandboxes.lock().unwrap();
    let record = sandboxes
        .get_mut(id)
        .ok_or_else(|| ApiError(err_not_found(id)))?;
    record.info.state = new_state;
    Ok(Json(record_info(record)))
}

#[derive(Debug, Deserialize, Serialize)]
struct TimeoutBody {
    timeout_s: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct FileWriteBody {
    path: String,
    /// Base64-encoded bytes (the protocol carries content as `String`).
    content: String,
}

async fn set_sandbox_timeout(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(body): Json<TimeoutBody>,
) -> Result<Json<SandboxInfo>, ApiError> {
    if body.timeout_s > MAX_TIMEOUT_S {
        return Err(ApiError(err_invalid(format!(
            "timeout_s {} exceeds the {MAX_TIMEOUT_S}s cap",
            body.timeout_s
        ))));
    }
    let ttl = if body.timeout_s == 0 {
        state.config.default_ttl_s
    } else {
        body.timeout_s
    };
    let mut sandboxes = state.sandboxes.lock().unwrap();
    let record = sandboxes
        .get_mut(&id)
        .ok_or_else(|| ApiError(err_not_found(&id)))?;
    record.deadline_unix = now_unix() + ttl as i64;
    Ok(Json(record_info(record)))
}

async fn exec_sandbox(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<Vec<ExecChunk>>, ApiError> {
    require_known(&state, &id)?;
    if req.command.is_empty() {
        return Err(ApiError(err_invalid("command must not be empty")));
    }
    if req.command.iter().any(|part| part.contains('\0')) {
        return Err(ApiError(err_invalid("command argument contains NUL")));
    }
    if let Some(cwd) = &req.cwd {
        validate_relative_path(cwd)?;
    }
    validate_env(&req.envs)?;
    let cap = if state.config.exec_timeout_s == 0 {
        u64::MAX
    } else {
        state.config.exec_timeout_s
    };
    let timeout = if req.timeout_s == 0 {
        cap
    } else {
        req.timeout_s.min(cap)
    };
    // `u64::MAX` means uncapped; the duration alone could overflow the
    // tokio timer, so skip the wrapper when unbounded.
    let chunks = if timeout == u64::MAX {
        state.runtime.exec(&id, &req).await
    } else {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout),
            state.runtime.exec(&id, &req),
        )
        .await
        .map_err(|_| ProviderError::retryable("timeout", "exec timed out"))?
    };
    Ok(Json(chunks?))
}

#[derive(Debug, Deserialize, Serialize)]
struct FileGetQuery {
    path: String,
    #[serde(default)]
    op: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FileDeleteQuery {
    path: String,
}

async fn get_files(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Query(query): Query<FileGetQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_known(&state, &id)?;
    let path = validate_relative_path(&query.path)?;
    if query.op.as_deref() == Some("list") {
        let entries = state.runtime.file_list(&id, &path).await?;
        Ok(Json(serde_json::json!({
            "path": path,
            "entries": entries,
        }))
        .into_response())
    } else {
        let bytes = state.runtime.file_read(&id, &path).await?;
        if bytes.len() > podman::MAX_FILE_BYTES {
            return Err(ApiError::too_large("file read exceeds 8 MiB"));
        }
        Ok(Json(serde_json::json!({
            "path": path,
            "content": podman::encode_content(&bytes),
        }))
        .into_response())
    }
}

async fn put_file(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(body): Json<FileWriteBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_known(&state, &id)?;
    if body.content.len() > MAX_FILE_B64_CHARS {
        return Err(ApiError::too_large("file content exceeds 8 MiB"));
    }
    let path = validate_relative_path(&body.path)?;
    let bytes = podman::decode_content(&body.content)?;
    state.runtime.file_write(&id, &path, &bytes).await?;
    Ok(Json(serde_json::json!({ "path": path })).into_response())
}

async fn delete_file(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Query(query): Query<FileDeleteQuery>,
) -> Result<StatusCode, ApiError> {
    require_known(&state, &id)?;
    let path = validate_relative_path(&query.path)?;
    state.runtime.file_delete(&id, &path).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn port_url(
    State(state): State<DaemonState>,
    Path((id, port)): Path<(String, u16)>,
) -> Result<Json<PortUrl>, ApiError> {
    require_known(&state, &id)?;
    Ok(Json(state.runtime.port_url(&id, port).await?))
}

fn require_known(state: &DaemonState, id: &str) -> Result<(), ApiError> {
    if state.sandboxes.lock().unwrap().contains_key(id) {
        Ok(())
    } else {
        Err(ApiError(err_not_found(id)))
    }
}

/// Build the daemon router (Bearer auth applied to every route).
pub fn router(state: DaemonState) -> Router {
    Router::new()
        .route("/sandboxes", axum::routing::post(create_sandbox))
        .route(
            "/sandboxes/{id}",
            axum::routing::get(get_sandbox).delete(delete_sandbox),
        )
        .route("/sandboxes/{id}/pause", axum::routing::post(pause_sandbox))
        .route(
            "/sandboxes/{id}/resume",
            axum::routing::post(resume_sandbox),
        )
        .route(
            "/sandboxes/{id}/timeout",
            axum::routing::post(set_sandbox_timeout),
        )
        .route("/sandboxes/{id}/exec", axum::routing::post(exec_sandbox))
        .route(
            "/sandboxes/{id}/files",
            axum::routing::get(get_files)
                .put(put_file)
                .delete(delete_file),
        )
        .route(
            "/sandboxes/{id}/ports/{port}/url",
            axum::routing::get(port_url),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use podman::{FakeRuntime, MAX_FILE_BYTES};
    use tower::ServiceExt as _;

    fn test_state() -> DaemonState {
        let config = DaemonConfig {
            images: vec!["docker.io/library/rust".to_owned()],
            ..DaemonConfig::default()
        };
        DaemonState::new(
            Arc::new(FakeRuntime::new()),
            "test-token".to_owned(),
            config,
        )
    }

    async fn req(
        state: &DaemonState,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(axum::http::header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
        }
        let request = if let Some(body) = &body {
            builder.body(Body::from(body.to_string())).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let response = router(state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, value)
    }

    fn create_body(image: &str) -> serde_json::Value {
        serde_json::json!({ "template": image })
    }

    #[tokio::test]
    async fn unauthenticated_requests_are_rejected() {
        let state = test_state();
        let (status, body) = req(
            &state,
            "POST",
            "/sandboxes",
            None,
            Some(create_body("docker.io/library/rust")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "unauthorized");
        let (status, _) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("wrong"),
            Some(create_body("docker.io/library/rust")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_enforces_image_allowlist() {
        let state = test_state();
        let (status, body) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(create_body("evil.com/rust")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "image_not_allowed");
        let (status, body) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(create_body("docker.io/library/rust:1.85")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["id"].as_str().unwrap().starts_with("sbx-"));
        assert_eq!(body["state"], "running");
    }

    #[tokio::test]
    async fn create_is_idempotent_by_key() {
        let state = test_state();
        let body = serde_json::json!({
            "template": "docker.io/library/rust",
            "idempotency_key": "retry-1",
        });
        let (_, first) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(body.clone()),
        )
        .await;
        let (_, second) = req(&state, "POST", "/sandboxes", Some("test-token"), Some(body)).await;
        assert_eq!(first["id"], second["id"]);
        assert_eq!(state.sandbox_count(), 1);
    }

    #[tokio::test]
    async fn lifecycle_get_delete_unknown_id() {
        let state = test_state();
        let (status, _) = req(&state, "GET", "/sandboxes/nope", Some("test-token"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = req(
            &state,
            "DELETE",
            "/sandboxes/nope",
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn files_roundtrip_and_traversal() {
        let state = test_state();
        let (_, created) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(create_body("docker.io/library/rust")),
        )
        .await;
        let id = created["id"].as_str().unwrap();

        let content = podman::encode_content(b"hello world");
        let (status, _) = req(
            &state,
            "PUT",
            &format!("/sandboxes/{id}/files"),
            Some("test-token"),
            Some(serde_json::json!({ "path": "src/main.rs", "content": content })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, read) = req(
            &state,
            "GET",
            &format!("/sandboxes/{id}/files?path=src/main.rs"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            podman::decode_content(read["content"].as_str().unwrap()).unwrap(),
            b"hello world"
        );

        let (status, listing) = req(
            &state,
            "GET",
            &format!("/sandboxes/{id}/files?path=src&op=list"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listing["entries"][0], "main.rs");

        let (status, _) = req(
            &state,
            "GET",
            &format!("/sandboxes/{id}/files?path=../secret"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = req(
            &state,
            "GET",
            &format!("/sandboxes/{id}/files?path=/etc/passwd"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = req(
            &state,
            "PUT",
            &format!("/sandboxes/{id}/files"),
            Some("test-token"),
            Some(serde_json::json!({ "path": "a/../../b", "content": "AAAA" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let huge = "A".repeat(MAX_FILE_BYTES * 2);
        let (status, _) = req(
            &state,
            "PUT",
            &format!("/sandboxes/{id}/files"),
            Some("test-token"),
            Some(serde_json::json!({ "path": "big", "content": huge })),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        let (status, _) = req(
            &state,
            "DELETE",
            &format!("/sandboxes/{id}/files?path=src/main.rs"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn exec_returns_chunk_stream() {
        let state = test_state();
        let (_, created) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(create_body("docker.io/library/rust")),
        )
        .await;
        let id = created["id"].as_str().unwrap();
        let (status, chunks) = req(
            &state,
            "POST",
            &format!("/sandboxes/{id}/exec"),
            Some("test-token"),
            Some(serde_json::json!({ "command": ["echo", "hi"] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(chunks.as_array().unwrap().len(), 3);
        assert_eq!(chunks[0]["stream"], "stdout");
        assert_eq!(chunks[1]["stream"], "stderr");
        assert_eq!(chunks[2]["stream"], "exit");
        assert_eq!(chunks[2]["code"], 0);
    }

    #[tokio::test]
    async fn exec_rejects_bad_env_and_nul() {
        let state = test_state();
        let (_, created) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(create_body("docker.io/library/rust")),
        )
        .await;
        let id = created["id"].as_str().unwrap();
        let (status, _) = req(
            &state,
            "POST",
            &format!("/sandboxes/{id}/exec"),
            Some("test-token"),
            Some(serde_json::json!({
                "command": ["echo", "hi"],
                "envs": { "K; rm -rf /": "x" },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = req(
            &state,
            "POST",
            &format!("/sandboxes/{id}/exec"),
            Some("test-token"),
            Some(serde_json::json!({
                "command": ["echo", "a\u{0}b"],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ttl_sweep_kills_expired_and_delete_kills() {
        let state = test_state();
        let (_, created) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(serde_json::json!({ "template": "docker.io/library/rust", "timeout_s": 5 })),
        )
        .await;
        let id = created["id"].as_str().unwrap().to_owned();
        let killed = sweep_expired(&state, now_unix() + 10).await;
        assert_eq!(killed, vec![id.clone()]);
        let (status, _) = req(
            &state,
            "GET",
            &format!("/sandboxes/{id}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, created) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(create_body("docker.io/library/rust")),
        )
        .await;
        let id2 = created["id"].as_str().unwrap();
        let (status, _) = req(
            &state,
            "DELETE",
            &format!("/sandboxes/{id2}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn pause_resume_timeout_and_port_url() {
        let state = test_state();
        let (_, created) = req(
            &state,
            "POST",
            "/sandboxes",
            Some("test-token"),
            Some(create_body("docker.io/library/rust")),
        )
        .await;
        let id = created["id"].as_str().unwrap();
        let (status, paused) = req(
            &state,
            "POST",
            &format!("/sandboxes/{id}/pause"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(paused["state"], "paused");
        let (status, resumed) = req(
            &state,
            "POST",
            &format!("/sandboxes/{id}/resume"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resumed["state"], "running");
        let (status, timed) = req(
            &state,
            "POST",
            &format!("/sandboxes/{id}/timeout"),
            Some("test-token"),
            Some(serde_json::json!({ "timeout_s": 120 })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(timed["expires_at"].as_str().unwrap().contains('T'));
        let (status, url) = req(
            &state,
            "GET",
            &format!("/sandboxes/{id}/ports/8080/url"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(url["url"].as_str().unwrap().contains("8080"));
    }
}
