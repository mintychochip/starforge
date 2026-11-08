//! Phase 4: a job sandbox create resolves the job spec's bound secrets
//! server-side. The secret value must reach the sandbox provider only as a
//! `SecretValue` egress binding — never the runner, the provider request's
//! `Debug`, or the audit detail — the forge `host:port` is allow-listed, and
//! missing/unbound/untrusted secrets fail the create with the exact message.

mod common;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::sandboxes::{CreateSandboxRequest, SandboxConfig, SandboxProviderKind};
use starforged_core::tokens::Scope;
use starforged_db::ci::NewCiJob;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "Sk-live\"9f3A\\!@#-leak-check-7f3a2b";
const BIND_HOST: &str = "api.example.com";
const BIND_HEADER: &str = "Authorization";

const CI_TOML: &str = r#"version = 1

[triggers]
push = ["main", "release/*"]
trail = ["opened", "updated"]

[[job]]
name = "test"
image = "example.test/image:1"
commands = ["true"]
timeout = "30m"
secrets = ["MY_SECRET"]
artifacts = ["out/**"]
"#;

async fn api(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "PATCH" => client.patch(url),
        "DELETE" => client.delete(url),
        _ => unreachable!(),
    };
    let req = if token.is_empty() {
        req
    } else {
        req.bearer_auth(token)
    };
    let resp = req.json(&body.unwrap_or(json!({}))).send().await.unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    let value = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, value)
}

async fn register_runner(s: &TestServer, pat: &str) -> String {
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/runners/registration-token"),
        pat,
        Some(json!({ "labels": [], "ephemeral": false })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/register"),
        "",
        Some(json!({
            "registration_token": value["token"],
            "name": "runner-1",
            "labels": [],
            "version": "test",
            "ephemeral": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value["auth_token"].as_str().unwrap().to_owned()
}

/// Claims the oldest due job for the runner; returns (job_id, fence, job_token).
async fn claim(s: &TestServer, runner: &str) -> (i64, String, String) {
    let resp = s
        .browser()
        .post(s.url("/api/v1/runners/jobs/request"))
        .bearer_auth(runner)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    (
        body["job_id"].as_i64().unwrap(),
        body["fence"].as_str().unwrap().to_owned(),
        body["job_token"].as_str().unwrap().to_owned(),
    )
}

/// A recording fake E2B provider (create/get/kill only).
async fn spawn_fake_e2b(recorded: Arc<Mutex<Vec<CreateSandboxRequest>>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse().ok())
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let line = text.lines().next().unwrap_or_default().to_owned();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_owned();
                let target = parts.next().unwrap_or_default().to_owned();
                let path = target.split('?').next().unwrap_or_default().to_owned();
                let body_text = text
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.to_owned())
                    .unwrap_or_default();
                let info = |st: &str| {
                    serde_json::json!({
                        "id": "sbx-1", "state": st, "runtime": "e2b",
                        "expires_at": null, "provider": "e2b",
                    })
                    .to_string()
                };
                let (status, resp_body): (u16, String) = if method == "POST" && path == "/sandboxes"
                {
                    if let Ok(req) = serde_json::from_str::<CreateSandboxRequest>(&body_text) {
                        recorded.lock().unwrap().push(req);
                    }
                    (200, info("running"))
                } else if method == "GET" && path == "/sandboxes/sbx-1" {
                    (200, info("running"))
                } else if method == "DELETE" && path == "/sandboxes/sbx-1" {
                    (204, String::new())
                } else {
                    (
                        404,
                        json!({"code": "not_found", "message": "no route", "retryable": false})
                            .to_string(),
                    )
                };
                let reason = match status {
                    200 => "OK",
                    204 => "No Content",
                    _ => "Not Found",
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len(),
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });
    url
}

async fn sandbox_server(recorded: Arc<Mutex<Vec<CreateSandboxRequest>>>) -> TestServer {
    let fake_url = spawn_fake_e2b(recorded).await;
    TestServer::start_with(move |config| {
        config.sandbox = SandboxConfig {
            provider: SandboxProviderKind::E2b,
            e2b: starforged_core::sandboxes::E2bSandboxConfig {
                api_url: fake_url.clone(),
                api_key: "test-key".to_owned(),
            },
            ..Default::default()
        };
    })
    .await
}

fn sandbox_body() -> Value {
    json!({
        "runtime": "e2b",
        "template": "starforge/rust",
        "timeout_s": 300,
    })
}

/// Polls until at least `n` jobs of the repo have job_name "test".
async fn wait_for_test_jobs(s: &TestServer, repo_id: i64, n: usize) -> Vec<i64> {
    let start = Instant::now();
    loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo_id, 100)
            .await
            .unwrap();
        let test: Vec<i64> = jobs
            .into_iter()
            .filter(|j| j.job_name == "test")
            .map(|j| j.id)
            .collect();
        if test.len() >= n {
            return test;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for {n} test jobs"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Inserts a queued job directly at `sha` naming `secrets` (no git push).
async fn insert_job(
    s: &TestServer,
    repo_id: i64,
    user_id: i64,
    sha: &str,
    name: &str,
    secrets: &[&str],
) -> i64 {
    let spec = json!({
        "name": name,
        "image": "example.test/image:1",
        "commands": ["true"],
        "secrets": secrets,
    })
    .to_string();
    let now_ts = starforged_db::now();
    starforged_db::ci::insert_ci_job(
        s.db(),
        &NewCiJob {
            repo_id,
            trail_id: None,
            change_id: None,
            revision_id: None,
            commit_sha: sha,
            base_sha: None,
            job_name: name,
            spec: &spec,
            run_at: 0,
            deadline: now_ts + 3600,
            created_by: Some(user_id),
            now: now_ts,
        },
    )
    .await
    .unwrap()
    .id
}

/// Pushes a second commit to main and returns the new tip sha.
async fn push_second_commit(s: &TestServer, pat: &str, work: &std::path::Path) -> String {
    commit_files(work, &[("second.txt", b"second\n")], "second commit").await;
    git_ok(
        work,
        &["push", "-q", &s.git_url("alice", "proj", Some(pat)), "main"],
    )
    .await;
    git_ok(work, &["rev-parse", "HEAD"]).await.trim().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_job_sandbox_forwards_bound_secret() {
    let recorded: Arc<Mutex<Vec<CreateSandboxRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let s = sandbox_server(recorded.clone()).await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;

    // A bound secret: the response exposes the binding, never the value.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({
            "name": "MY_SECRET",
            "value": SECRET,
            "bind_host": BIND_HOST,
            "bind_header": BIND_HEADER,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["bind_host"], BIND_HOST);
    assert_eq!(value["bind_header"], BIND_HEADER);
    assert!(!value.to_string().contains(SECRET), "create leaks: {value}");

    // Push the CI spec, protect main, push again: the second job is trusted.
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[(".starforge/ci.toml", CI_TOML), ("README.md", "# proj\n")],
    )
    .await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&pat)),
            "main",
        ],
    )
    .await;
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/gate-rules"),
        &pat,
        Some(json!({
            "pattern": "main",
            "required_approvals": 0,
            "dismiss_on_push": false,
            "block_on_request_changes": false,
            "required_contexts": [],
            "require_up_to_date": false,
            "require_threads_resolved": false,
            "require_session_evidence": false,
            "allowed_methods": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let _tip = push_second_commit(&s, &pat, &work).await;
    let jobs = wait_for_test_jobs(&s, repo.id, 2).await;
    let runner = register_runner(&s, &pat).await;
    // Claim both queued jobs: the protected-branch one is newest-first in
    // the list, but the claim takes the oldest due job. Claim the first
    // (unprotected) job away, then claim again for the protected one.
    let (first, _, _) = claim(&s, &runner).await;
    let (protected_job, _, job_token) = claim(&s, &runner).await;
    assert_ne!(first, protected_job);
    assert!(jobs.contains(&protected_job));

    // The job sandbox create forwards the bound secret server-side.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(sandbox_body()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["id"], "sbx-1");
    assert!(!value.to_string().contains(SECRET), "create leaks: {value}");

    // Clone the one recorded request out of the guard before awaiting.
    let request = {
        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 1, "provider saw exactly one create");
        requests[0].clone()
    };
    assert_eq!(request.network.secret_values.len(), 1);
    assert_eq!(request.network.secret_values[0].host, BIND_HOST);
    assert_eq!(request.network.secret_values[0].header, BIND_HEADER);
    assert_eq!(request.network.secret_values[0].value, SECRET);
    assert_eq!(
        request
            .network
            .secret_headers
            .get(BIND_HOST)
            .map(String::as_str),
        Some(BIND_HEADER)
    );
    let forge = s.base.trim_start_matches("http://").to_owned();
    assert!(
        request.network.allow_out.contains(&forge),
        "forge host:port {forge} in {:?}",
        request.network.allow_out
    );
    assert!(
        request.network.allow_out.contains(&BIND_HOST.to_owned()),
        "bind host in {:?}",
        request.network.allow_out
    );
    let debug = format!("{request:?}");
    assert!(
        !debug.contains(SECRET),
        "provider request Debug leaks the value: {debug}"
    );

    // The resolution is recorded for session redaction.
    assert_eq!(
        starforged_db::ci::job_secrets_for_job(s.db(), protected_job)
            .await
            .unwrap()
            .len(),
        1,
        "ci_job_secrets row exists"
    );

    // The audit detail names the secret but never carries its value.
    let details: Vec<String> = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE action = 'ci.job.secrets.resolve' AND target = $1",
    )
    .bind(format!("ci_job:{protected_job}"))
    .fetch_all(s.db().pool())
    .await
    .unwrap();
    assert_eq!(details.len(), 1, "resolution audited once");
    assert!(
        details[0].contains("MY_SECRET"),
        "audit names: {}",
        details[0]
    );
    assert!(
        !details[0].contains(SECRET),
        "audit detail leaks the value: {}",
        details[0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_unbound_caller_supplied_secrets_refused() {
    let recorded: Arc<Mutex<Vec<CreateSandboxRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let s = sandbox_server(recorded.clone()).await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;

    // A bound and an unbound secret.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({
            "name": "BOUND",
            "value": SECRET,
            "bind_host": BIND_HOST,
            "bind_header": BIND_HEADER,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({ "name": "UNBOUND", "value": SECRET })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["bind_host"], "");

    // Caller-supplied secret values are refused on the user path (the API
    // body cannot even carry them, so this goes through Core directly).
    let supplied = CreateSandboxRequest {
        runtime: "e2b".to_owned(),
        network: starforged_core::sandboxes::NetworkPolicy {
            secret_values: vec![starforged_core::sandboxes::SecretValue {
                host: BIND_HOST.to_owned(),
                header: BIND_HEADER.to_owned(),
                value: "caller-supplied".to_owned(),
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let err = s
        .core
        .create_sandbox(&alice, "alice", "proj", None, supplied)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, starforged_core::CoreError::Invalid(m) if m.contains("server and must not be supplied")),
        "caller-supplied values refused: {err:?}"
    );

    // An unprotected push job is untrusted: no secrets at all.
    let bound_toml = CI_TOML.replace("MY_SECRET", "BOUND");
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[
            (".starforge/ci.toml", bound_toml.as_str()),
            ("README.md", "# proj\n"),
        ],
    )
    .await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&pat)),
            "main",
        ],
    )
    .await;
    let _ = wait_for_test_jobs(&s, repo.id, 1).await;
    let runner = register_runner(&s, &pat).await;
    let (_, _, job_token) = claim(&s, &runner).await;
    let (status, body) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(sandbox_body()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["error"]["message"], "repository secrets are not available to this run",
        "{body}"
    );

    // Protect main, push again: new jobs at the protected tip are trusted.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/gate-rules"),
        &pat,
        Some(json!({
            "pattern": "main",
            "required_approvals": 0,
            "dismiss_on_push": false,
            "block_on_request_changes": false,
            "required_contexts": [],
            "require_up_to_date": false,
            "require_threads_resolved": false,
            "require_session_evidence": false,
            "allowed_methods": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let tip = push_second_commit(&s, &pat, &work).await;
    let _ = wait_for_test_jobs(&s, repo.id, 2).await;
    // Consume the protected-branch job so later claims land on inserted
    // jobs (claims are oldest-due first).
    let _ = claim(&s, &runner).await;

    // A trusted job naming a missing secret fails with the exact message.
    let missing_job = insert_job(&s, repo.id, alice.id, &tip, "missing", &["MISSING_SECRET"]).await;
    let (claimed, _, job_token) = claim(&s, &runner).await;
    assert_eq!(claimed, missing_job);
    let (status, body) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(sandbox_body()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["error"]["message"], "secret MISSING_SECRET does not exist for this repository",
        "{body}"
    );

    // A trusted job naming an unbound secret fails with its exact message.
    let unbound_job = insert_job(&s, repo.id, alice.id, &tip, "unbound", &["UNBOUND"]).await;
    let (claimed, _, job_token) = claim(&s, &runner).await;
    assert_eq!(claimed, unbound_job);
    let (status, body) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(sandbox_body()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["error"]["message"], "secret UNBOUND has no host binding",
        "{body}"
    );

    // No provider create was attempted for any refused create.
    assert!(
        recorded.lock().unwrap().is_empty(),
        "refused creates never reach the provider"
    );
}
