//! CI runner registration and CRUD routes (spec M6, task A2):
//! `POST /repos/{owner}/{repo}/runners/registration-token`,
//! `POST /runners/register`, `GET /repos/{owner}/{repo}/runners`,
//! `DELETE /runners/{id}`.
//!
//! The registration endpoint carries no `Authorization` header: the
//! registration token in the body is the credential.

use std::net::SocketAddr;

use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::ci::{FinishOutcome, RunnerView, TraceOutcome};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::ci_auth::RunnerAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegistrationTokenJson {
    /// The `sfrt_…` secret, shown once.
    pub token: String,
    pub expires_at: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateRegistrationTokenBody {
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterRunnerBody {
    pub registration_token: String,
    pub name: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegisteredRunnerJson {
    pub runner_id: i64,
    /// The `sfr_…` auth token, shown once.
    pub auth_token: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RunnerJson {
    pub id: i64,
    pub name: String,
    pub labels: Vec<String>,
    pub ephemeral: bool,
    pub version: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
}

fn runner_json(view: &RunnerView) -> RunnerJson {
    RunnerJson {
        id: view.id,
        name: view.name.clone(),
        labels: view.labels.clone(),
        ephemeral: view.ephemeral,
        version: view.version.clone(),
        last_seen_at: view.last_seen_at.map(crate::time::rfc3339),
        created_at: rfc3339(view.created_at),
    }
}

/// The secret-carrying responses (registration token, runner auth token)
/// must never be stored by a cache or intermediary.
fn no_store_headers() -> HeaderMap {
    HeaderMap::from_iter([
        (
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        ),
        (
            axum::http::header::PRAGMA,
            axum::http::HeaderValue::from_static("no-cache"),
        ),
    ])
}

/// `POST /repos/{owner}/{repo}/runners/registration-token` (201).
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/runners/registration-token",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = CreateRegistrationTokenBody,
    responses(
        (status = 201, description = "Minted registration token", body = RegistrationTokenJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_registration_token(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<CreateRegistrationTokenBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<RegistrationTokenJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let minted = state
        .core
        .create_runner_registration_token(&auth.user, &owner, &repo, &body.labels, body.ephemeral)
        .await?;
    Ok((
        StatusCode::CREATED,
        no_store_headers(),
        Json(RegistrationTokenJson {
            token: minted.secret,
            expires_at: rfc3339(minted.expires_at),
        }),
    ))
}

/// `POST /runners/register` (201).
#[utoipa::path(
    post,
    path = "/api/v1/runners/register",
    request_body = RegisterRunnerBody,
    responses(
        (status = 201, description = "Registered runner", body = RegisteredRunnerJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 429, description = "Rate limited", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
)]
pub async fn register_runner(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Result<Json<RegisterRunnerBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<RegisteredRunnerJson>), ApiError> {
    if !state
        .core
        .check_register_rate(&addr.ip().to_string())
        .allowed
    {
        return Err(starforged_core::CoreError::RateLimited.into());
    }
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let registered = state
        .core
        .register_runner(
            &body.registration_token,
            &body.name,
            &body.labels,
            &body.version,
            body.ephemeral,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        no_store_headers(),
        Json(RegisteredRunnerJson {
            runner_id: registered.runner_id,
            auth_token: registered.auth_secret,
        }),
    ))
}

/// `GET /repos/{owner}/{repo}/runners` (200).
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/runners",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Runners", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_runners(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let views = state
        .core
        .list_runners(Some(&auth.user), &owner, &repo)
        .await?;
    Ok(Json(
        json!({ "runners": views.iter().map(runner_json).collect::<Vec<_>>() }),
    ))
}

/// `DELETE /runners/{id}` (204).
#[utoipa::path(
    delete,
    path = "/api/v1/runners/{id}",
    params(("id" = i64, Path, description = "Runner id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn revoke_runner(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state.core.revoke_runner(&auth.user, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The job payload returned by a successful runner claim (201).
#[derive(Serialize, utoipa::ToSchema)]
pub struct ClaimedJobJson {
    pub job_id: i64,
    pub job_name: String,
    pub commit_sha: String,
    /// The parsed `.starforge/ci.toml` job spec.
    pub spec: serde_json::Value,
    /// The per-claim lease fence; present it as `X-Starforge-Fence`.
    pub fence: String,
    /// The per-job token (`sfj_…`), shown once.
    pub job_token: String,
    pub deadline: String,
    pub lease_until: String,
}

/// The finish report (`PUT /runners/jobs/{id}`).
#[derive(Deserialize, utoipa::ToSchema)]
pub struct FinishJobBody {
    /// Terminal state: `succeeded`, `failed`, or `error`.
    pub state: String,
    #[serde(default)]
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub session_ulids: Vec<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct FinishedJobJson {
    pub job_id: i64,
    pub state: String,
}

/// The git-credential payload (201); the token is shown once.
#[derive(Serialize, utoipa::ToSchema)]
pub struct GitCredentialJson {
    /// The short-lived `sfp_` git token, shown once.
    pub token: String,
    pub token_id: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CancelRunJson {
    pub job_id: i64,
    pub status: String,
}

/// Long-poll claim budget: at most 50 s (plan A3).
const CLAIM_POLL_BUDGET: Duration = Duration::from_secs(50);

fn fence_header(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get("x-starforge-fence")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ApiError::Invalid("missing X-Starforge-Fence header".into()))
}

fn no_store(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
}

/// `POST /runners/jobs/request` (201 claimed job, 204 none within 50 s).
#[utoipa::path(
    post,
    path = "/api/v1/runners/jobs/request",
    responses(
        (status = 201, description = "Claimed job", body = ClaimedJobJson),
        (status = 204, description = "No job available"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn request_job(
    State(state): State<ApiState>,
    RunnerAuth(runner): RunnerAuth,
) -> Result<Response, ApiError> {
    let start = Instant::now();
    loop {
        if let Some(claimed) = state.core.claim_ci_job(&runner).await? {
            let body = ClaimedJobJson {
                job_id: claimed.job_id,
                job_name: claimed.job_name,
                commit_sha: claimed.commit_sha,
                spec: serde_json::to_value(&claimed.spec).unwrap_or(Value::Null),
                fence: claimed.fence,
                job_token: claimed.job_token,
                deadline: rfc3339(claimed.deadline),
                lease_until: rfc3339(claimed.lease_until),
            };
            let mut response = (StatusCode::CREATED, Json(body)).into_response();
            no_store(response.headers_mut());
            return Ok(response);
        }
        if start.elapsed() >= CLAIM_POLL_BUDGET {
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Parses `Content-Range: bytes <start>-<inclusive end>/<total|*>` into
/// the half-open offsets the trace path stores.
fn parse_content_range(headers: &HeaderMap) -> Result<(i64, i64), ApiError> {
    let value = headers
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Invalid("missing Content-Range header".into()))?;
    let range = value
        .strip_prefix("bytes ")
        .ok_or_else(|| ApiError::Invalid("malformed Content-Range header".into()))?;
    let (offsets, _total) = range
        .split_once('/')
        .ok_or_else(|| ApiError::Invalid("malformed Content-Range header".into()))?;
    let (start, inclusive_end) = offsets
        .split_once('-')
        .ok_or_else(|| ApiError::Invalid("malformed Content-Range header".into()))?;
    let start: i64 = start
        .parse()
        .map_err(|_| ApiError::Invalid("malformed Content-Range header".into()))?;
    let inclusive_end: i64 = inclusive_end
        .parse()
        .map_err(|_| ApiError::Invalid("malformed Content-Range header".into()))?;
    if start < 0 || inclusive_end < start {
        return Err(ApiError::Invalid("malformed Content-Range header".into()));
    }
    Ok((start, inclusive_end + 1))
}

fn range_not_satisfiable() -> Response {
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        Json(json!({ "error": {
            "code": "range_not_satisfiable",
            "message": "the range does not continue the stored log",
            "details": Value::Null,
        } })),
    )
        .into_response()
}

/// `PATCH /runners/jobs/{id}/trace` (202 accepted, 416 range mismatch,
/// 409 stale fence; `Job-Status: canceled` when the job was canceled).
#[utoipa::path(
    patch,
    path = "/api/v1/runners/jobs/{id}/trace",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("X-Starforge-Fence" = String, Header, description = "Per-claim lease fence"),
        ("Content-Range" = String, Header, description = "Chunk range: bytes <start>-<end>/<total>"),
    ),
    responses(
        (status = 202, description = "Accepted"),
        (status = 200, description = "Job canceled", headers(("Job-Status" = String, description = "canceled"))),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Stale fence", body = crate::openapi::ApiErrorBody),
        (status = 413, description = "Log cap exceeded", body = crate::openapi::ApiErrorBody),
        (status = 416, description = "Range not satisfiable", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn trace_job(
    State(state): State<ApiState>,
    RunnerAuth(runner): RunnerAuth,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let fence = fence_header(&headers)?;
    let (start, end) = parse_content_range(&headers)?;
    match state
        .core
        .trace_ci_job(&runner, id, &fence, start, end, &body)
        .await?
    {
        TraceOutcome::Accepted => Ok(StatusCode::ACCEPTED.into_response()),
        TraceOutcome::RangeMismatch => Ok(range_not_satisfiable()),
        TraceOutcome::NotFound => Err(ApiError::NotFound),
        TraceOutcome::FenceMismatch => Err(ApiError::Conflict("stale runner fence".into())),
        TraceOutcome::PayloadTooLarge => {
            Err(ApiError::PayloadTooLarge("job log cap exceeded".into()))
        }
        TraceOutcome::Canceled => {
            let mut response = StatusCode::OK.into_response();
            response
                .headers_mut()
                .insert("job-status", header::HeaderValue::from_static("canceled"));
            Ok(response)
        }
    }
}

/// `POST /runners/jobs/{id}/heartbeat` (204; 409 stale fence or canceled).
#[utoipa::path(
    post,
    path = "/api/v1/runners/jobs/{id}/heartbeat",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("X-Starforge-Fence" = String, Header, description = "Per-claim lease fence"),
    ),
    responses(
        (status = 204, description = "Lease renewed"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Stale fence or canceled job", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn heartbeat_job(
    State(state): State<ApiState>,
    RunnerAuth(runner): RunnerAuth,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let fence = fence_header(&headers)?;
    state.core.heartbeat_ci_job(&runner, id, &fence).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /runners/jobs/{id}` (200 finished; `Job-Status: canceled` when
/// the job was canceled).
#[utoipa::path(
    put,
    path = "/api/v1/runners/jobs/{id}",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("X-Starforge-Fence" = String, Header, description = "Per-claim lease fence"),
    ),
    request_body = FinishJobBody,
    responses(
        (status = 200, description = "Finished", body = FinishedJobJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Stale fence", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn finish_job(
    State(state): State<ApiState>,
    RunnerAuth(runner): RunnerAuth,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Result<Json<FinishJobBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let fence = fence_header(&headers)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    match state
        .core
        .finish_ci_job(
            &runner,
            id,
            &fence,
            &body.state,
            body.exit_code,
            body.checksum.as_deref(),
            &body.session_ulids,
        )
        .await?
    {
        FinishOutcome::Finished => Ok((
            StatusCode::OK,
            Json(FinishedJobJson {
                job_id: id,
                state: body.state,
            }),
        )
            .into_response()),
        FinishOutcome::NotFound => Err(ApiError::NotFound),
        FinishOutcome::FenceMismatch => Err(ApiError::Conflict("stale runner fence".into())),
        FinishOutcome::Canceled => {
            let mut response = StatusCode::OK.into_response();
            response
                .headers_mut()
                .insert("job-status", header::HeaderValue::from_static("canceled"));
            Ok(response)
        }
    }
}

/// `POST /ci/jobs/{id}/git-credential` (201; secret shown once).
#[utoipa::path(
    post,
    path = "/api/v1/ci/jobs/{id}/git-credential",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("X-Starforge-Fence" = String, Header, description = "Per-claim lease fence"),
    ),
    responses(
        (status = 201, description = "Minted git credential", body = GitCredentialJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Stale fence", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn git_credential(
    State(state): State<ApiState>,
    RunnerAuth(runner): RunnerAuth,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let fence = fence_header(&headers)?;
    let minted = state
        .core
        .git_credential_for_runner(&runner, id, &fence)
        .await?;
    let mut response = (
        StatusCode::CREATED,
        Json(GitCredentialJson {
            token: minted.secret,
            token_id: minted.token_id,
        }),
    )
        .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

/// `POST /repos/{owner}/{repo}/ci/runs/{id}/cancel` (202).
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/ci/runs/{id}/cancel",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("id" = i64, Path, description = "CI job id"),
    ),
    responses(
        (status = 202, description = "Cancel requested", body = CancelRunJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn cancel_run(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<(StatusCode, Json<CancelRunJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .cancel_ci_job(&auth.user, &owner, &repo, id)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CancelRunJson {
            job_id: id,
            status: "cancel_requested".into(),
        }),
    ))
}

// ===== CI triggers, runs, artifacts, and secrets (M6c C1–C3) =====

/// Query of `GET /repos/{owner}/{repo}/ci/runs`.
#[derive(Deserialize, utoipa::IntoParams)]
pub struct ListRunsQuery {
    /// Maximum runs (1-200, default 50).
    pub limit: Option<i64>,
    /// Keyset cursor (accepted for interface stability; order is newest first).
    pub after: Option<String>,
}

/// Body of `POST /repos/{owner}/{repo}/ci/runs` (manual trigger).
#[derive(Deserialize, utoipa::ToSchema)]
pub struct TriggerRunBody {
    /// Ref to run at (default: the repository's default branch).
    pub r#ref: Option<String>,
    /// One job to run (default: every job in the spec).
    pub job: Option<String>,
}

/// One queued run of `POST /repos/{owner}/{repo}/ci/runs`.
#[derive(Serialize, utoipa::ToSchema)]
pub struct TriggeredRunJson {
    pub job_id: i64,
    pub job_name: String,
    pub commit_sha: String,
    pub state: String,
}

/// Response of `POST /repos/{owner}/{repo}/ci/runs` (201).
#[derive(Serialize, utoipa::ToSchema)]
pub struct TriggerRunsJson {
    /// Newly queued job ids (empty when every job was already queued).
    pub job_ids: Vec<i64>,
    pub runs: Vec<TriggeredRunJson>,
}

/// One CI run as listed by `GET /repos/{owner}/{repo}/ci/runs`.
#[derive(Serialize, utoipa::ToSchema)]
pub struct RunJson {
    pub job_id: i64,
    pub commit_sha: String,
    pub job_name: String,
    pub state: String,
    pub created_by: Option<i64>,
    pub created_at: String,
    pub finished_at: Option<String>,
}

/// Artifact metadata as listed in a run detail.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ArtifactJson {
    pub name: String,
    pub size: i64,
    pub blake3: String,
    pub sha256: Option<String>,
    pub expires_at: String,
}

/// Body of `POST /runners/jobs/{id}/artifacts/authorize`.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct AuthorizeArtifactBody {
    pub name: String,
    pub size: i64,
    pub sha256: String,
}

/// Response of `POST /runners/jobs/{id}/artifacts/authorize` (201).
#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthorizedArtifactJson {
    /// The one-time `sfa_…` token, shown once.
    pub token: String,
    pub expires_at: String,
}

/// Body of `POST /repos/{owner}/{repo}/ci/secrets` (create or rotate).
#[derive(Deserialize, utoipa::ToSchema)]
pub struct SecretBody {
    pub name: String,
    /// The plaintext value. It is sealed before storage and never logged
    /// or returned; responses carry metadata only.
    pub value: String,
    pub redact_in_sessions: Option<bool>,
}

/// Secret metadata (no value, ever).
#[derive(Serialize, utoipa::ToSchema)]
pub struct SecretJson {
    pub id: i64,
    pub name: String,
    pub redact_in_sessions: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// One resolved secret value (in memory only; the response carries
/// `Cache-Control: no-store` and the value never reaches logs or disk).
#[derive(Serialize, utoipa::ToSchema)]
pub struct ResolvedSecretJson {
    pub name: String,
    pub value: String,
}

/// Response of the secret-resolution route.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ResolvedSecretsJson {
    /// Empty under the trust rule (unprotected branch, unapproved Trail).
    pub secrets: Vec<ResolvedSecretJson>,
}

/// `POST /repos/{owner}/{repo}/ci/runs` (201; manual trigger).
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/ci/runs",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = TriggerRunBody,
    responses(
        (status = 201, description = "Runs queued", body = TriggerRunsJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn trigger_run(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<TriggerRunBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<TriggerRunsJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let ids = state
        .core
        .ci_trigger_manual(
            &auth.user,
            &owner,
            &repo,
            body.r#ref.as_deref(),
            body.job.as_deref(),
        )
        .await?;
    let mut runs = Vec::with_capacity(ids.len());
    for id in &ids {
        let detail = state
            .core
            .get_ci_run(Some(&auth.user), &owner, &repo, *id)
            .await?;
        runs.push(TriggeredRunJson {
            job_id: detail.run.job_id,
            job_name: detail.run.job_name,
            commit_sha: detail.run.commit_sha,
            state: detail.run.state,
        });
    }
    Ok((
        StatusCode::CREATED,
        Json(TriggerRunsJson { job_ids: ids, runs }),
    ))
}

/// `GET /repos/{owner}/{repo}/ci/runs` (200).
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/ci/runs",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("limit" = Option<i64>, Query, description = "Maximum runs (1-200, default 50)"),
    ),
    responses(
        (status = 200, description = "CI runs", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_runs(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    query: axum::extract::Query<ListRunsQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoRead)?;
    let limit = query.limit.unwrap_or(50);
    let runs = state
        .core
        .list_ci_runs(Some(&auth.user), &owner, &repo, limit)
        .await?;
    Ok(Json(json!({
        "runs": runs.into_iter().map(|run| RunJson {
            job_id: run.job_id,
            commit_sha: run.commit_sha,
            job_name: run.job_name,
            state: run.state,
            created_by: run.created_by,
            created_at: rfc3339(run.created_at),
            finished_at: run.finished_at.map(rfc3339),
        }).collect::<Vec<_>>(),
    })))
}

/// `GET /repos/{owner}/{repo}/ci/runs/{id}` (200).
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/ci/runs/{id}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("id" = i64, Path, description = "CI job id"),
    ),
    responses(
        (status = 200, description = "CI run detail", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_run(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoRead)?;
    let detail = state
        .core
        .get_ci_run(Some(&auth.user), &owner, &repo, id)
        .await?;
    let run = detail.run;
    Ok(Json(json!({
        "job_id": run.job_id,
        "commit_sha": run.commit_sha,
        "job_name": run.job_name,
        "state": run.state,
        "created_by": run.created_by,
        "created_at": rfc3339(run.created_at),
        "finished_at": run.finished_at.map(rfc3339),
        "artifacts": detail.artifacts.iter().map(|artifact| ArtifactJson {
            name: artifact.name.clone(),
            size: artifact.size,
            blake3: artifact.blake3.clone(),
            sha256: artifact.sha256.clone(),
            expires_at: rfc3339(artifact.expires_at),
        }).collect::<Vec<_>>(),
        "sessions": detail.sessions,
    })))
}

/// `POST /runners/jobs/{id}/artifacts/authorize` (201; one-time token).
#[utoipa::path(
    post,
    path = "/api/v1/runners/jobs/{id}/artifacts/authorize",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("X-Starforge-Fence" = String, Header, description = "Per-claim lease fence"),
    ),
    request_body = AuthorizeArtifactBody,
    responses(
        (status = 201, description = "Authorized", body = AuthorizedArtifactJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Stale fence", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn authorize_artifact(
    State(state): State<ApiState>,
    RunnerAuth(runner): RunnerAuth,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Result<Json<AuthorizeArtifactBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let fence = fence_header(&headers)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let token = state
        .core
        .authorize_artifact_upload(&runner, id, &fence, &body.name, body.size, &body.sha256)
        .await?;
    let mut response = (
        StatusCode::CREATED,
        Json(AuthorizedArtifactJson {
            token,
            expires_at: rfc3339(
                starforged_core::ci::now_secs() + starforged_core::ci::ARTIFACT_TOKEN_TTL_SECS,
            ),
        }),
    )
        .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

/// `PUT /runners/jobs/{id}/artifacts/{name}` (201; artifact token, raw bytes).
#[utoipa::path(
    put,
    path = "/api/v1/runners/jobs/{id}/artifacts/{*name}",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("name" = String, Path, description = "Artifact name"),
    ),
    responses(
        (status = 201, description = "Stored", body = ArtifactJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Artifact token already used", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 413, description = "Artifact too large", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn upload_artifact(
    State(state): State<ApiState>,
    Path((id, name)): Path<(i64, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<ArtifactJson>), ApiError> {
    let token = bearer_of(&headers).ok_or(ApiError::Unauthenticated)?;
    let sha256 = headers
        .get("x-starforge-sha256")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::Invalid("missing X-Starforge-Sha256 header".into()))?;
    if body.len() as i64 > starforged_core::ci::MAX_ARTIFACT_BYTES {
        return Err(ApiError::PayloadTooLarge(
            "artifact exceeds the 1 GiB cap".into(),
        ));
    }
    let artifact = state
        .core
        .upload_ci_artifact(&token, id, &name, &body, sha256)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(ArtifactJson {
            name: artifact.name,
            size: artifact.size,
            blake3: artifact.blake3,
            sha256: artifact.sha256,
            expires_at: rfc3339(artifact.expires_at),
        }),
    ))
}

/// `GET /runners/jobs/{id}/artifacts/{name}` (200; artifact or job token).
#[utoipa::path(
    get,
    path = "/api/v1/runners/jobs/{id}/artifacts/{*name}",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("name" = String, Path, description = "Artifact name"),
    ),
    responses(
        (status = 200, description = "Artifact bytes"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn download_artifact(
    State(state): State<ApiState>,
    Path((id, name)): Path<(i64, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer_of(&headers).ok_or(ApiError::Unauthenticated)?;
    let download = if token.starts_with(starforged_core::ci::ARTIFACT_TOKEN_PREFIX) {
        starforged_core::ci::ArtifactDownloadAuth::Token(token)
    } else {
        let principal = state.core.authenticate_job(&token).await?;
        starforged_core::ci::ArtifactDownloadAuth::Job(principal)
    };
    let (bytes, artifact) = state
        .core
        .download_ci_artifact(id, &name, &download)
        .await?;
    let mut response = axum::response::Response::new(axum::body::Body::from(bytes));
    no_store(response.headers_mut());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        "x-starforge-blake3",
        header::HeaderValue::from_str(&artifact.blake3)
            .unwrap_or_else(|_| header::HeaderValue::from_static("")),
    );
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

/// `POST /repos/{owner}/{repo}/ci/secrets` (201; create or rotate).
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/ci/secrets",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = SecretBody,
    responses(
        (status = 201, description = "Secret stored", body = SecretJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_secret(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<SecretBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<SecretJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .create_ci_secret(
            &auth.user,
            &owner,
            &repo,
            &body.name,
            &body.value,
            body.redact_in_sessions.unwrap_or(true),
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(SecretJson {
            id: view.id,
            name: view.name,
            redact_in_sessions: view.redact_in_sessions,
            created_at: rfc3339(view.created_at),
            updated_at: rfc3339(view.updated_at),
        }),
    ))
}

/// `GET /repos/{owner}/{repo}/ci/secrets` (200; names only).
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/ci/secrets",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Secrets", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_secrets(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let secrets = state
        .core
        .list_ci_secrets(&auth.user, &owner, &repo)
        .await?;
    Ok(Json(json!({
        "secrets": secrets.into_iter().map(|secret| SecretJson {
            id: secret.id,
            name: secret.name,
            redact_in_sessions: secret.redact_in_sessions,
            created_at: rfc3339(secret.created_at),
            updated_at: rfc3339(secret.updated_at),
        }).collect::<Vec<_>>(),
    })))
}

/// `DELETE /repos/{owner}/{repo}/ci/secrets/{name}` (204).
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/ci/secrets/{name}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("name" = String, Path, description = "Secret name"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_secret(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, name)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .delete_ci_secret(&auth.user, &owner, &repo, &name)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /runners/jobs/{id}/secrets` (200; resolve for egress injection).
#[utoipa::path(
    post,
    path = "/api/v1/runners/jobs/{id}/secrets",
    params(
        ("id" = i64, Path, description = "CI job id"),
        ("X-Starforge-Fence" = String, Header, description = "Per-claim lease fence"),
    ),
    responses(
        (status = 200, description = "Resolved secrets", body = ResolvedSecretsJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Stale fence", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn resolve_job_secrets(
    State(state): State<ApiState>,
    RunnerAuth(runner): RunnerAuth,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let fence = fence_header(&headers)?;
    let resolved = state
        .core
        .resolve_runner_job_secrets(&runner, id, &fence)
        .await?;
    let mut response = (
        StatusCode::OK,
        Json(ResolvedSecretsJson {
            secrets: resolved
                .into_iter()
                .map(|secret| ResolvedSecretJson {
                    name: secret.name,
                    value: secret.value,
                })
                .collect(),
        }),
    )
        .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

/// The `Authorization: Bearer …` credential of a request, if present.
fn bearer_of(headers: &HeaderMap) -> Option<String> {
    crate::auth::bearer_token(headers).map(str::to_owned)
}
