//! Runner end-to-end tests (plan M6d D4): a fake axum server plus a
//! [`FakeSandboxProvider`] drive claim → execute → finish, including
//! failure, timeout, cancel, and stale-fence paths, plus secret scrubbing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use serde_json::{Value, json};
use starforge_runner::{
    CiJobSpec, ClaimedJob, Executor, FakeSandboxProvider, JobOutcome, RunnerConfig,
};

const RUNNER_TOKEN: &str = "sfr_test_runner_token";
const JOB_TOKEN: &str = "sfj_test_job_token";
const GIT_TOKEN: &str = "sfp_test_git_credential_secret";

#[derive(Default)]
struct Record {
    traces: Vec<Vec<u8>>,
    finishes: Vec<Value>,
    artifacts: Vec<(String, Vec<u8>)>,
}

type CacheUploads = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

#[derive(Clone, Default)]
struct FakeState {
    record: Arc<Mutex<Record>>,
    cancel_on_trace: bool,
    stale_on_finish: bool,
    secret: Option<Value>,
    /// Cache spec injected into the claimed job when set.
    cache_job: Option<Value>,
    /// Cache archive served by the download route; `None` answers 404.
    cache_blob: Option<Vec<u8>>,
    /// Cache saves observed by the upload route.
    cache_uploads: CacheUploads,
}

fn job_json() -> Value {
    json!({
        "job_id": 7,
        "job_name": "test",
        "commit_sha": "abc123",
        "spec": {
            "name": "test",
            "image": "starforge/rust",
            "commands": ["cargo test"],
            "timeout": "30s",
            "env": {},
            "secrets": [],
            "artifacts": ["out.bin"],
            "runs_on": []
        },
        "fence": "fence-1",
        "job_token": JOB_TOKEN,
        "deadline": "2026-11-07T00:00:00Z",
        "lease_until": "2026-11-07T00:00:00Z",
    })
}

async fn request_job(State(s): State<FakeState>) -> impl IntoResponse {
    let mut job = job_json();
    if let Some(cache) = &s.cache_job {
        job["spec"]["cache"] = cache.clone();
    }
    (StatusCode::CREATED, Json(job))
}

async fn download_cache(
    State(s): State<FakeState>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> impl IntoResponse {
    match &s.cache_blob {
        Some(bytes) => {
            let mut response = axum::response::Response::new(axum::body::Body::from(bytes.clone()));
            response.headers_mut().insert(
                "x-starforge-cache-key",
                query
                    .get("key")
                    .cloned()
                    .unwrap_or_default()
                    .parse()
                    .unwrap(),
            );
            response
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upload_cache(
    State(s): State<FakeState>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
    body: Bytes,
) -> impl IntoResponse {
    let key = query.get("key").cloned().unwrap_or_default();
    s.cache_uploads.lock().unwrap().push((key, body.to_vec()));
    (StatusCode::CREATED, Json(json!({ "key": "k", "size": 0 })))
}

async fn git_credential() -> impl IntoResponse {
    (
        StatusCode::CREATED,
        Json(json!({ "token": GIT_TOKEN, "token_id": 1 })),
    )
}

async fn secrets(State(s): State<FakeState>) -> impl IntoResponse {
    let secrets = s
        .secret
        .clone()
        .map(|secret| vec![secret])
        .unwrap_or_default();
    (StatusCode::OK, Json(json!({ "secrets": secrets })))
}

async fn trace(
    State(s): State<FakeState>,
    Path(_id): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    assert_eq!(
        headers
            .get("x-starforge-fence")
            .and_then(|v| v.to_str().ok()),
        Some("fence-1")
    );
    s.record.lock().unwrap().traces.push(body.to_vec());
    if s.cancel_on_trace {
        let mut r = StatusCode::OK.into_response();
        r.headers_mut()
            .insert("job-status", "canceled".parse().unwrap());
        return r;
    }
    StatusCode::ACCEPTED.into_response()
}

async fn finish(
    State(s): State<FakeState>,
    Path(_id): Path<i64>,
    body: Json<Value>,
) -> impl IntoResponse {
    s.record.lock().unwrap().finishes.push(body.0.clone());
    if s.stale_on_finish {
        return StatusCode::CONFLICT.into_response();
    }
    StatusCode::OK.into_response()
}

async fn authorize() -> impl IntoResponse {
    (
        StatusCode::CREATED,
        Json(json!({ "token": "sfa_artifact", "expires_at": "2026-11-07T00:00:00Z" })),
    )
}

async fn upload(
    State(s): State<FakeState>,
    Path((_id, name)): Path<(i64, String)>,
    body: Bytes,
) -> impl IntoResponse {
    s.record
        .lock()
        .unwrap()
        .artifacts
        .push((name, body.to_vec()));
    (
        StatusCode::CREATED,
        Json(json!({ "name": "out.bin", "size": 5 })),
    )
}

fn app(state: FakeState) -> Router {
    Router::new()
        .route("/api/v1/runners/jobs/request", post(request_job))
        .route("/api/v1/ci/jobs/{id}/git-credential", post(git_credential))
        .route("/api/v1/runners/jobs/{id}/secrets", post(secrets))
        .route("/api/v1/runners/jobs/{id}/trace", patch(trace))
        .route("/api/v1/runners/jobs/{id}", put(finish))
        .route(
            "/api/v1/runners/jobs/{id}/artifacts/authorize",
            post(authorize),
        )
        .route("/api/v1/runners/jobs/{id}/artifacts/{*name}", put(upload))
        .route(
            "/api/v1/runners/jobs/{id}/cache",
            get(download_cache).put(upload_cache),
        )
        .with_state(state)
}

async fn serve(state: FakeState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state)).await.unwrap();
    });
    format!("http://{addr}")
}

fn claimed() -> ClaimedJob {
    serde_json::from_value(job_json()).unwrap()
}

fn claimed_cached() -> ClaimedJob {
    let mut job = job_json();
    job["spec"]["cache"] = json!({
        "key": "k",
        "paths": ["target"],
        "restore_keys": ["k-"],
        "save": true
    });
    serde_json::from_value(job).unwrap()
}

fn config(server: &str) -> RunnerConfig {
    RunnerConfig::new(server, RUNNER_TOKEN)
}

#[tokio::test]
async fn claim_execute_finish_succeeds() {
    let state = FakeState::default();
    let server = serve(state.clone()).await;
    let exec = Executor::new(
        config(&server),
        FakeSandboxProvider::new()
            .with_script("cargo test", "running 1 test: ok\n", 0)
            .with_script("starforge sync", "uploaded 01ARZ3NDEKTSV4RRFFQ69G5FAV\n", 0)
            .with_file("out.bin", b"hello"),
    );
    let outcome = exec.execute_job(claimed()).await;
    assert!(
        matches!(outcome, JobOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    let rec = state.record.lock().unwrap();
    let log = rec.traces.concat();
    assert!(String::from_utf8_lossy(&log).contains("running 1 test"));
    assert_eq!(rec.finishes.len(), 1);
    assert_eq!(rec.finishes[0]["state"], "succeeded");
    assert_eq!(rec.finishes[0]["exit_code"], 0);
    assert!(rec.finishes[0]["checksum"].is_string());
    assert_eq!(rec.artifacts.len(), 1);
    assert_eq!(rec.artifacts[0].1, b"hello");
    // Session ULIDs reported from `starforge sync` output.
    assert_eq!(
        rec.finishes[0]["session_ulids"][0],
        "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    );
    // No secrets in any traced log bytes.
    let all = String::from_utf8_lossy(&log).into_owned();
    for secret in [RUNNER_TOKEN, JOB_TOKEN, GIT_TOKEN] {
        assert!(!all.contains(secret), "secret leaked into logs");
    }
}

#[tokio::test]
async fn failure_finishes_failed() {
    let state = FakeState::default();
    let server = serve(state.clone()).await;
    let exec = Executor::new(
        config(&server),
        FakeSandboxProvider::new().with_script("cargo test", "test FAILED\n", 1),
    );
    let outcome = exec.execute_job(claimed()).await;
    assert!(
        matches!(outcome, JobOutcome::Failed { exit_code: 1 }),
        "{outcome:?}"
    );
    let rec = state.record.lock().unwrap();
    assert_eq!(rec.finishes[0]["state"], "failed");
    assert_eq!(rec.finishes[0]["exit_code"], 1);
}

#[tokio::test]
async fn timeout_finishes_failed() {
    let state = FakeState::default();
    let mut job = claimed();
    job.spec.timeout = Some("1s".to_owned());
    let server = serve(state.clone()).await;
    let mut provider = FakeSandboxProvider::new();
    provider.delay = std::time::Duration::from_secs(5);
    let exec = Executor::new(config(&server), provider);
    let outcome = exec.execute_job(job).await;
    assert!(matches!(outcome, JobOutcome::TimedOut), "{outcome:?}");
    let rec = state.record.lock().unwrap();
    assert_eq!(rec.finishes[0]["state"], "failed");
}

#[tokio::test]
async fn cancel_kills_sandbox_and_never_succeeds() {
    let state = FakeState {
        cancel_on_trace: true,
        ..Default::default()
    };
    let server = serve(state.clone()).await;
    let exec = Executor::new(config(&server), FakeSandboxProvider::new());
    let outcome = exec.execute_job(claimed()).await;
    assert!(matches!(outcome, JobOutcome::Canceled), "{outcome:?}");
    assert!(exec.provider.was_killed());
    let rec = state.record.lock().unwrap();
    assert!(rec.finishes.iter().all(|f| f["state"] != "succeeded"));
}

#[tokio::test]
async fn stale_fence_on_finish_is_reported() {
    let state = FakeState {
        stale_on_finish: true,
        ..Default::default()
    };
    let server = serve(state.clone()).await;
    let exec = Executor::new(config(&server), FakeSandboxProvider::new());
    let outcome = exec.execute_job(claimed()).await;
    assert!(matches!(outcome, JobOutcome::StaleFence), "{outcome:?}");
}

#[tokio::test]
async fn resolved_secret_is_scrubbed_and_bound_to_the_sandbox() {
    let state = FakeState {
        secret: Some(json!({
            "name": "TOKEN",
            "value": "super-secret",
            "host": "registry.example",
            "header": "Authorization",
        })),
        ..Default::default()
    };
    let server = serve(state.clone()).await;
    let exec = Executor::new(
        config(&server),
        FakeSandboxProvider::new().with_script("cargo test", "leaking super-secret\n", 0),
    );
    let outcome = exec.execute_job(claimed()).await;
    assert!(
        matches!(outcome, JobOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    let req = exec.provider.requests.lock().unwrap()[0].clone();
    assert_eq!(req.envs.get("STARFORGE_TOKEN"), Some(&JOB_TOKEN.to_owned()));
    assert_eq!(
        req.network.secret_headers.get("registry.example"),
        Some(&"Authorization".to_owned())
    );
    assert!(
        req.network
            .allow_out
            .iter()
            .any(|h| h == "registry.example"),
        "allow_out: {:?}",
        req.network.allow_out
    );
    let rec = state.record.lock().unwrap();
    let log = String::from_utf8_lossy(&rec.traces.concat()).into_owned();
    assert!(
        !log.contains("super-secret"),
        "secret leaked into logs: {log}"
    );
    assert!(log.contains("***"), "the value was scrubbed: {log}");
}

#[tokio::test]
async fn claim_loop_polls_server() {
    let state = FakeState::default();
    let server = serve(state.clone()).await;
    let exec = Executor::new(config(&server), FakeSandboxProvider::new());
    let job = exec.client.request_job(&[]).await.unwrap().unwrap();
    assert_eq!(job.job_id, 7);
    assert_eq!(job.spec.commands, vec!["cargo test"]);
}

#[test]
fn cli_exposes_runner_subcommand() {
    use clap::CommandFactory;
    let mut cmd = starforge_cli::cli::Cli::command();
    let mut help = Vec::new();
    cmd.write_long_help(&mut help).unwrap();
    let help = String::from_utf8(help).unwrap();
    assert!(help.contains("runner"), "help missing runner:\n{help}");
}

#[tokio::test]
async fn runner_dry_run_prints_plan_without_network() {
    // No server is started: dry-run must not touch the network.
    let args = starforge_runner::RunnerArgs {
        server: "http://127.0.0.1:1".to_owned(),
        sandbox_server: String::new(),
        token: RUNNER_TOKEN.to_owned(),
        label: vec![],
        runtime: "podman".to_owned(),
        concurrency: 1,
        poll_timeout: 50,
        repo_url: String::new(),
    };
    let code = starforge_cli::commands::runner::run(args, true).await;
    assert_eq!(code, 0);
}

#[test]
fn scrub_never_logs_secrets() {
    let secrets = vec![GIT_TOKEN.to_owned(), JOB_TOKEN.to_owned()];
    let out = starforge_runner::Executor::<FakeSandboxProvider>::scrub(
        &format!("clone https://{GIT_TOKEN}@host https://{JOB_TOKEN}@host"),
        &secrets,
    );
    assert!(!out.contains(GIT_TOKEN));
    assert!(!out.contains(JOB_TOKEN));
}

#[allow(dead_code)]
fn spec() -> CiJobSpec {
    CiJobSpec {
        name: "test".to_owned(),
        image: Some("starforge/rust".to_owned()),
        template: None,
        commands: vec!["cargo test".to_owned()],
        timeout: Some("30s".to_owned()),
        env: BTreeMap::new(),
        secrets: vec![],
        artifacts: vec!["out.bin".to_owned()],
        runs_on: vec![],
        cache: None,
    }
}

/// Restore writes the archive in 8 MiB chunks; save concatenates the split
/// parts and uploads them.
#[tokio::test]
async fn cache_restore_and_save_use_the_raw_file_api() {
    let blob: Vec<u8> = (0..(20 * 1024 * 1024 + 7))
        .map(|i| (i % 251) as u8)
        .collect();
    let state = FakeState {
        cache_job: Some(json!({
            "key": "k",
            "paths": ["target"],
            "restore_keys": ["k-"],
            "save": true
        })),
        cache_blob: Some(blob.clone()),
        ..Default::default()
    };
    let server = serve(state.clone()).await;
    let provider = FakeSandboxProvider::new()
        .with_script("cargo test", "ok\n", 0)
        .with_script("starforge sync", "ok\n", 0)
        .with_file(".starforge-cache.part-aa", b"save-a")
        .with_file(".starforge-cache.part-ab", b"save-b");
    let exec = Executor::new(config(&server), provider);
    let outcome = exec.execute_job(claimed_cached()).await;
    assert!(
        matches!(outcome, JobOutcome::Succeeded { .. }),
        "{outcome:?}"
    );

    let uploads = state.cache_uploads.lock().unwrap().clone();
    assert_eq!(uploads.len(), 1, "{uploads:?}");
    assert_eq!(uploads[0].0, "k");
    assert_eq!(uploads[0].1, b"save-asave-b");
}
