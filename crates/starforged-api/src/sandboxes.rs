//! Sandbox API (E2B-shaped, plan M6b B4): create/get/kill/pause/resume/
//! timeout/exec/files/port-URL for sandboxes behind one provider seam.
//!
//! Auth is [`SandboxAuth`]: a PAT holding `sandbox:run` (the `repo_for`
//! permission check runs in Core) or a job token (`JobAuth`). Ownership
//! and admin/job-runner authorization live in Core; every handler here
//! only translates HTTP to Core calls. File paths are validated in Core
//! (no absolute paths, no `..` escapes) before the provider is touched.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use starforged_core::ci::{JOB_TOKEN_PREFIX, JobPrincipal};
use starforged_core::limits::RateDecision;
use starforged_core::sandboxes::{
    CreateSandboxRequest, ExecChunk, ExecRequest, FileOp, NetworkPolicy, SandboxCaller, SandboxView,
};
use starforged_core::tokens::{self, Scope, TokenAuth};

use crate::ApiState;
use crate::auth::bearer_token;
use crate::error::ApiError;
use crate::time::rfc3339;

/// PAT with `sandbox:run`, or a CI job token, for sandbox routes.
pub enum SandboxAuth {
    Pat(TokenAuth),
    Job(JobPrincipal),
}

impl SandboxAuth {
    fn caller(&self) -> SandboxCaller {
        match self {
            SandboxAuth::Pat(auth) => SandboxCaller::user(&auth.user),
            SandboxAuth::Job(principal) => SandboxCaller::job(principal),
        }
    }
}

impl FromRequestParts<ApiState> for SandboxAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)
            .ok_or(ApiError::Unauthenticated)?
            .to_owned();
        if token.starts_with(JOB_TOKEN_PREFIX) {
            return Ok(SandboxAuth::Job(state.core.authenticate_job(&token).await?));
        }
        let auth = match parts.extensions.get::<TokenAuth>() {
            Some(auth) => auth.clone(),
            None => state.core.authenticate_token(&token).await?,
        };
        let decision = match parts.extensions.get::<RateDecision>() {
            Some(decision) => *decision,
            None => state.core.check_api_rate(auth.token_id),
        };
        if !decision.allowed {
            return Err(ApiError::RateLimited {
                retry_after: (decision.reset_at - starforged_core::limits::now_secs()).max(1),
                decision,
            });
        }
        if !tokens::grants(&auth.scopes, Scope::SandboxRun) {
            return Err(ApiError::Forbidden(format!(
                "this token lacks the {} scope",
                Scope::SandboxRun.as_str()
            )));
        }
        Ok(SandboxAuth::Pat(auth))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NetworkPolicyJson {
    #[serde(default)]
    pub allow_out: Vec<String>,
    #[serde(default)]
    pub deny_out: Vec<String>,
    #[serde(default)]
    pub secret_headers: BTreeMap<String, String>,
}

impl From<NetworkPolicyJson> for NetworkPolicy {
    fn from(value: NetworkPolicyJson) -> Self {
        Self {
            allow_out: value.allow_out,
            deny_out: value.deny_out,
            secret_headers: value.secret_headers,
            forge: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct CreateSandboxBody {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub job_id: Option<i64>,
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    pub timeout_s: u64,
    #[serde(default)]
    pub cpu: f64,
    #[serde(default)]
    pub mem_mb: u64,
    #[serde(default)]
    pub disk_gb: u64,
    #[serde(default)]
    pub envs: BTreeMap<String, String>,
    #[serde(default)]
    pub network: NetworkPolicyJson,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SandboxJson {
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
    pub created_at: String,
    pub expires_at: String,
}

fn sandbox_json(view: &SandboxView) -> SandboxJson {
    SandboxJson {
        id: view.id.clone(),
        state: view.state.clone(),
        provider: view.provider.clone(),
        runtime: view.runtime.clone(),
        template: view.template.clone(),
        cpu: view.cpu,
        mem_mb: view.mem_mb,
        disk_gb: view.disk_gb,
        owner_id: view.owner_id,
        repo_id: view.repo_id,
        job_id: view.job_id,
        created_at: rfc3339(view.created_at),
        expires_at: rfc3339(view.expires_at),
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct TimeoutBody {
    #[serde(default)]
    pub timeout_s: u64,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct ExecBody {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub envs: BTreeMap<String, String>,
    #[serde(default)]
    pub timeout_s: u64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(tag = "stream", rename_all = "snake_case")]
pub enum ExecChunkJson {
    Stdout { data: String },
    Stderr { data: String },
    Exit { code: i32 },
}

impl From<ExecChunk> for ExecChunkJson {
    fn from(chunk: ExecChunk) -> Self {
        match chunk {
            ExecChunk::Stdout { data } => ExecChunkJson::Stdout { data },
            ExecChunk::Stderr { data } => ExecChunkJson::Stderr { data },
            ExecChunk::Exit { code } => ExecChunkJson::Exit { code },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileQuery {
    pub path: String,
    #[serde(default)]
    pub op: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeleteFileQuery {
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FileJson {
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub entries: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct FileWriteBody {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub content: String,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct PortUrlJson {
    pub url: String,
    pub port: u16,
    pub expires_at: Option<String>,
}

/// `POST /api/v1/sandboxes` (201).
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes",
    request_body = CreateSandboxBody,
    responses(
        (status = 201, description = "Created sandbox", body = SandboxJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
        (status = 429, description = "Quota exceeded", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_sandbox(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    body: Result<Json<CreateSandboxBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<SandboxJson>), ApiError> {
    let body = body
        .map_err(|_| ApiError::BadRequest("malformed JSON body".into()))?
        .0;
    let request = CreateSandboxRequest {
        runtime: body.runtime,
        template: body.template,
        timeout_s: body.timeout_s,
        cpu: body.cpu,
        mem_mb: body.mem_mb,
        disk_gb: body.disk_gb,
        envs: body.envs,
        network: body.network.into(),
        metadata: body.metadata,
        idempotency_key: body.idempotency_key,
        secret_bindings: Vec::new(),
        network_enabled: false,
    };
    let view = match &auth {
        SandboxAuth::Pat(token_auth) => {
            if body.owner.trim().is_empty() || body.repo.trim().is_empty() {
                return Err(ApiError::Invalid("owner and repo are required".into()));
            }
            state
                .core
                .create_sandbox(
                    &token_auth.user,
                    &body.owner,
                    &body.repo,
                    body.job_id,
                    request,
                )
                .await?
        }
        SandboxAuth::Job(principal) => {
            state
                .core
                .create_sandbox_for_job(principal, request)
                .await?
        }
    };
    Ok((StatusCode::CREATED, Json(sandbox_json(&view))))
}

/// `GET /api/v1/sandboxes/{id}`.
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes/{id}",
    params(("id" = String, Path, description = "Sandbox provider handle")),
    responses(
        (status = 200, description = "Sandbox view", body = SandboxJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_sandbox(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
) -> Result<Json<SandboxJson>, ApiError> {
    let view = state.core.get_sandbox(auth.caller(), &id).await?;
    Ok(Json(sandbox_json(&view)))
}

/// `DELETE /api/v1/sandboxes/{id}` (kill; idempotent).
#[utoipa::path(
    delete,
    path = "/api/v1/sandboxes/{id}",
    params(("id" = String, Path, description = "Sandbox provider handle")),
    responses(
        (status = 200, description = "Killed sandbox view", body = SandboxJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn kill_sandbox(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
) -> Result<Json<SandboxJson>, ApiError> {
    let view = state.core.kill_sandbox(auth.caller(), &id).await?;
    Ok(Json(sandbox_json(&view)))
}

/// `POST /api/v1/sandboxes/{id}/pause`.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/pause",
    params(("id" = String, Path, description = "Sandbox provider handle")),
    responses(
        (status = 200, description = "Paused sandbox view", body = SandboxJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn pause_sandbox(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
) -> Result<Json<SandboxJson>, ApiError> {
    let view = state.core.pause_sandbox(auth.caller(), &id).await?;
    Ok(Json(sandbox_json(&view)))
}

/// `POST /api/v1/sandboxes/{id}/resume`.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/resume",
    params(("id" = String, Path, description = "Sandbox provider handle")),
    responses(
        (status = 200, description = "Resumed sandbox view", body = SandboxJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn resume_sandbox(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
) -> Result<Json<SandboxJson>, ApiError> {
    let view = state.core.resume_sandbox(auth.caller(), &id).await?;
    Ok(Json(sandbox_json(&view)))
}

/// `POST /api/v1/sandboxes/{id}/timeout`.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/timeout",
    params(("id" = String, Path, description = "Sandbox provider handle")),
    request_body = TimeoutBody,
    responses(
        (status = 200, description = "Sandbox view with new expiry", body = SandboxJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn set_sandbox_timeout(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
    body: Result<Json<TimeoutBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<SandboxJson>, ApiError> {
    let body = body
        .map_err(|_| ApiError::BadRequest("malformed JSON body".into()))?
        .0;
    let view = state
        .core
        .set_sandbox_timeout(auth.caller(), &id, body.timeout_s)
        .await?;
    Ok(Json(sandbox_json(&view)))
}

/// `POST /api/v1/sandboxes/{id}/exec` (JSON `ExecChunk` stream).
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/exec",
    params(("id" = String, Path, description = "Sandbox provider handle")),
    request_body = ExecBody,
    responses(
        (status = 200, description = "Exec output chunks", body = Vec<ExecChunkJson>),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn exec_sandbox(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
    body: Result<Json<ExecBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Vec<ExecChunkJson>>, ApiError> {
    let body = body
        .map_err(|_| ApiError::BadRequest("malformed JSON body".into()))?
        .0;
    let chunks = state
        .core
        .exec_sandbox(
            auth.caller(),
            &id,
            ExecRequest {
                command: body.command,
                cwd: body.cwd,
                envs: body.envs,
                timeout_s: body.timeout_s,
            },
        )
        .await?;
    Ok(Json(chunks.into_iter().map(ExecChunkJson::from).collect()))
}

/// `GET /api/v1/sandboxes/{id}/files?path=&op=` (read or list).
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes/{id}/files",
    params(
        ("id" = String, Path, description = "Sandbox provider handle"),
        ("path" = String, Query, description = "Workspace-relative path"),
        ("op" = Option<String>, Query, description = "Set to `list` for a listing"),
    ),
    responses(
        (status = 200, description = "File read or listing", body = FileJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_sandbox_file(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
) -> Result<Json<FileJson>, ApiError> {
    let op = if query.op.as_deref() == Some("list") {
        FileOp::List {
            path: query.path.clone(),
        }
    } else {
        FileOp::Read {
            path: query.path.clone(),
        }
    };
    let content = state.core.sandbox_file(auth.caller(), &id, op).await?;
    if query.op.as_deref() == Some("list") {
        let entries = if content.is_empty() {
            Vec::new()
        } else {
            content.split('\n').map(str::to_owned).collect()
        };
        Ok(Json(FileJson {
            path: query.path,
            content: None,
            entries: Some(entries),
        }))
    } else {
        Ok(Json(FileJson {
            path: query.path,
            content: Some(content),
            entries: None,
        }))
    }
}

/// `PUT /api/v1/sandboxes/{id}/files` (write).
#[utoipa::path(
    put,
    path = "/api/v1/sandboxes/{id}/files",
    params(("id" = String, Path, description = "Sandbox provider handle")),
    request_body = FileWriteBody,
    responses(
        (status = 200, description = "Write ack", body = FileJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn put_sandbox_file(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
    body: Result<Json<FileWriteBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<FileJson>, ApiError> {
    let body = body
        .map_err(|_| ApiError::BadRequest("malformed JSON body".into()))?
        .0;
    state
        .core
        .sandbox_file(
            auth.caller(),
            &id,
            FileOp::Write {
                path: body.path.clone(),
                content: body.content,
            },
        )
        .await?;
    Ok(Json(FileJson {
        path: body.path,
        content: None,
        entries: None,
    }))
}

/// `DELETE /api/v1/sandboxes/{id}/files?path=` (delete).
#[utoipa::path(
    delete,
    path = "/api/v1/sandboxes/{id}/files",
    params(
        ("id" = String, Path, description = "Sandbox provider handle"),
        ("path" = String, Query, description = "Workspace-relative path"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_sandbox_file(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path(id): Path<String>,
    Query(query): Query<DeleteFileQuery>,
) -> Result<StatusCode, ApiError> {
    state
        .core
        .sandbox_file(auth.caller(), &id, FileOp::Delete { path: query.path })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/sandboxes/{id}/ports/{port}/url` (signed, short-lived URL).
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes/{id}/ports/{port}/url",
    params(
        ("id" = String, Path, description = "Sandbox provider handle"),
        ("port" = u16, Path, description = "Sandbox port"),
    ),
    responses(
        (status = 200, description = "Port URL", body = PortUrlJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn sandbox_port_url(
    State(state): State<ApiState>,
    auth: SandboxAuth,
    Path((id, port)): Path<(String, u16)>,
) -> Result<Json<PortUrlJson>, ApiError> {
    let url = state
        .core
        .sandbox_port_url(auth.caller(), &id, port)
        .await?;
    Ok(Json(PortUrlJson {
        url: url.url,
        port: url.port,
        expires_at: url.expires_at,
    }))
}

/// One row of the runtime capability table (M6b B6).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct RuntimeJson {
    pub name: String,
    pub available: bool,
    /// Reserved names (`firecracker`, `kata`) report `available = false`:
    /// creating one is refused with 422 until its adapter ships.
    pub reserved: bool,
    pub detail: String,
}

/// `GET /api/v1/sandboxes/runtimes` response.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct RuntimesJson {
    pub runtimes: Vec<RuntimeJson>,
}

/// `GET /api/v1/sandboxes/runtimes`: the runtime capability table.
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes/runtimes",
    responses(
        (status = 200, description = "Runtime capability table", body = RuntimesJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_runtimes(
    State(state): State<ApiState>,
    _auth: SandboxAuth,
) -> Result<Json<RuntimesJson>, ApiError> {
    Ok(Json(RuntimesJson {
        runtimes: state
            .core
            .sandbox_runtimes()
            .into_iter()
            .map(|info| RuntimeJson {
                name: info.name.to_owned(),
                available: info.available,
                reserved: info.reserved,
                detail: info.detail.to_owned(),
            })
            .collect(),
    }))
}
