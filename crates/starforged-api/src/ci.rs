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
