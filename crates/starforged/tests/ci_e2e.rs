//! CI end-to-end (M6c C5): push → job → scripted runner (claim/trace/
//! finish) → `ci/<job>` status → gate permits merge, covering the
//! artifact and secret paths in between.
mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::Digest as _;
use starforged_core::permission::Visibility;
use starforged_core::sandboxes::{CreateSandboxRequest, SandboxConfig, SandboxProviderKind};
use starforged_core::tokens::Scope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIND_HOST: &str = "registry.example.com";
const BIND_HEADER: &str = "Authorization";

const CI_TOML: &str = r#"version = 1

[triggers]
push = ["main"]
trail = ["opened", "updated"]

[[job]]
name = "test"
image = "example.test/image:1"
commands = ["true"]
timeout = "30m"
secrets = ["CARGO_REGISTRY_TOKEN"]
artifacts = ["out/**"]
"#;

async fn api(
    client: &Client,
    method: &str,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
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

async fn wait_for_job(s: &TestServer, repo_id: i64, except: Option<i64>) -> i64 {
    let start = Instant::now();
    loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo_id, 100)
            .await
            .unwrap();
        if let Some(job) = jobs
            .iter()
            .find(|job| job.job_name == "test" && Some(job.id) != except)
        {
            return job.id;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no CI job");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn claim(s: &TestServer, runner: &str) -> (i64, String, String) {
    let client = s.browser();
    let resp = client
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

/// The removed runner-secrets route must answer 404.
async fn assert_runner_secrets_route_gone(
    client: &Client,
    s: &TestServer,
    job_id: i64,
    runner: &str,
    fence: &str,
) {
    let resp = client
        .post(s.url(&format!("/api/v1/runners/jobs/{job_id}/secrets")))
        .bearer_auth(runner)
        .header("x-starforge-fence", fence)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "removed route must be gone"
    );
}

async fn trace(
    s: &TestServer,
    runner: &str,
    job_id: i64,
    fence: &str,
    offset: i64,
    bytes: &[u8],
) -> StatusCode {
    let end = offset + bytes.len() as i64;
    let resp = s
        .browser()
        .patch(s.url(&format!("/api/v1/runners/jobs/{job_id}/trace")))
        .bearer_auth(runner)
        .header("x-starforge-fence", fence)
        .header("content-range", format!("bytes {offset}-{}/", end - 1))
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    resp.status()
}

async fn finish(s: &TestServer, runner: &str, job_id: i64, fence: &str, state: &str) -> StatusCode {
    let resp = s
        .browser()
        .put(s.url(&format!("/api/v1/runners/jobs/{job_id}")))
        .bearer_auth(runner)
        .header("x-starforge-fence", fence)
        .json(&json!({ "state": state, "exit_code": 0, "session_ulids": [] }))
        .send()
        .await
        .unwrap();
    resp.status()
}

async fn wait_for_change(s: &TestServer, repo_id: i64, user_id: i64) {
    let start = Instant::now();
    loop {
        let found = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            user_id,
            "main",
            "e2e",
            None,
        )
        .await
        .unwrap();
        if found.is_some() {
            return;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no change");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_runner_status_gate_artifact_and_secret_paths() {
    let recorded: Arc<Mutex<Vec<CreateSandboxRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let s = sandbox_server(recorded.clone()).await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s
        .token(&alice, &[Scope::RepoWrite, Scope::TrailWrite])
        .await;
    let client = s.browser();

    // Seed the bound secret (sealed) and gate rule (protects `main`,
    // requiring `ci/test`) through the API.
    let secret_value = "cargo-registry-super-secret-value";
    let (status, value) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({
            "name": "CARGO_REGISTRY_TOKEN",
            "value": secret_value,
            "bind_host": BIND_HOST,
            "bind_header": BIND_HEADER,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["bind_host"], BIND_HOST);
    assert_eq!(value["bind_header"], BIND_HEADER);
    assert!(
        !value.to_string().contains(secret_value),
        "create leaks: {value}"
    );
    let sealed = starforged_db::ci::secret_by_name(s.db(), repo.id, "CARGO_REGISTRY_TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert!(sealed.sealed_value.starts_with("c1:"));
    assert!(!sealed.sealed_value.contains(secret_value));

    let (status, value) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/gate-rules"),
        &pat,
        Some(json!({
            "pattern": "main",
            "required_approvals": 0,
            "dismiss_on_push": false,
            "block_on_request_changes": false,
            "required_contexts": ["ci/test"],
            "require_up_to_date": false,
            "require_threads_resolved": false,
            "require_session_evidence": false,
            "allowed_methods": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");

    // Push the ci.toml on main: this enqueues the push job and writes the
    // pending check.
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
    let job_id = wait_for_job(&s, repo.id, None).await;
    let job = starforged_db::ci::ci_job_by_id(s.db(), job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.created_by, Some(alice.id));
    // The trigger inserts the job row, then writes its pending check: poll
    // for the check rather than racing the second statement.
    let start = Instant::now();
    loop {
        let checks = starforged_db::checks::latest_checks_for_sha(s.db(), repo.id, &job.commit_sha)
            .await
            .unwrap();
        if checks
            .iter()
            .any(|c| c.context == "ci/test" && c.state == "pending")
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no pending ci/test check: {checks:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The scripted runner: claim, sandbox, logs, artifact, finish.
    let runner = register_runner(&s, &pat).await;
    let (claimed, fence, job_token) = claim(&s, &runner).await;
    assert_eq!(claimed, job_id);

    // Secret path: the protected-branch job creates its sandbox, the
    // server resolves the sealed secret to the provider only, records
    // the resolution, and the value never reaches the spec, the sealed
    // row, the runner, or the logs.
    assert_runner_secrets_route_gone(&client, &s, job_id, &runner, &fence).await;
    let (status, value) = api(
        &client,
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(sandbox_body()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["id"], "sbx-1");
    assert!(
        !value.to_string().contains(secret_value),
        "create leaks: {value}"
    );
    {
        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 1, "provider saw exactly one create");
        let request = &requests[0];
        assert_eq!(request.network.secret_values.len(), 1);
        assert_eq!(request.network.secret_values[0].host, BIND_HOST);
        assert_eq!(request.network.secret_values[0].header, BIND_HEADER);
        assert_eq!(request.network.secret_values[0].value, secret_value);
        let forge = s.base.trim_start_matches("http://").to_owned();
        assert!(
            request.network.allow_out.contains(&forge),
            "forge host:port {forge} in {:?}",
            request.network.allow_out
        );
    }
    assert_eq!(
        starforged_db::ci::job_secrets_for_job(s.db(), job_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let spec = starforged_db::ci::ci_job_by_id(s.db(), job_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!spec.spec.contains(secret_value), "no value in spec");

    let log = b"running tests\nok\n";
    assert_eq!(
        trace(&s, &runner, job_id, &fence, 0, log).await,
        StatusCode::ACCEPTED
    );

    let bytes = b"e2e artifact payload\n";
    let sha256 = hex::encode(sha2::Sha256::digest(bytes));
    let authorize = s.url(&format!(
        "/api/v1/runners/jobs/{job_id}/artifacts/authorize"
    ));
    let resp = client
        .post(&authorize)
        .bearer_auth(&runner)
        .header("x-starforge-fence", &fence)
        .json(&json!({ "name": "out/result.bin", "size": bytes.len(), "sha256": sha256 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token = resp.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let resp = client
        .put(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .bearer_auth(&token)
        .header("x-starforge-sha256", &sha256)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = client
        .get(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .bearer_auth(&job_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), bytes);

    assert_eq!(
        finish(&s, &runner, job_id, &fence, "succeeded").await,
        StatusCode::OK
    );

    // `ci/test` is now success on the commit, and the job token is revoked.
    let checks = starforged_db::checks::latest_checks_for_sha(s.db(), repo.id, &job.commit_sha)
        .await
        .unwrap();
    assert!(
        checks
            .iter()
            .any(|c| c.context == "ci/test" && c.state == "success"),
        "{checks:?}"
    );
    assert!(s.core.authenticate_job(&job_token).await.is_err());

    // The run page shows the job (and no secret value ever leaks there).
    let (browser, _) = s.login("alice").await;
    let page = get_text(&browser, &s.url(&format!("/alice/proj/ci/{job_id}"))).await;
    assert!(page.contains("succeeded"), "{page}");
    assert!(page.contains("out/result.bin"), "{page}");
    assert!(page.contains("ok"), "{page}");
    assert!(!page.contains(secret_value), "secret must not leak: {page}");

    // A change revision on the same gate: a new commit pushed as
    // refs/for/main/e2e enqueues a Trail job (no secrets without approval).
    commit_files(&work, &[("feature.txt", b"feature\n")], "feature").await;
    let url = s.git_url("alice", "proj", Some(&pat));
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/e2e"]).await;
    wait_for_change(&s, repo.id, alice.id).await;
    let job2 = wait_for_job(&s, repo.id, Some(job_id)).await;
    let (claimed2, fence2, job_token2) = claim(&s, &runner).await;
    assert_eq!(claimed2, job2);
    assert_runner_secrets_route_gone(&client, &s, job2, &runner, &fence2).await;
    // The unapproved refs/for job is untrusted: its sandbox create fails
    // with the trust-rule message and never reaches the provider.
    let (status, body) = api(
        &client,
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token2,
        Some(sandbox_body()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["error"]["message"], "repository secrets are not available to this run",
        "{body}"
    );
    assert_eq!(
        recorded.lock().unwrap().len(),
        1,
        "only the trusted create reached the provider"
    );
    assert_eq!(
        trace(&s, &runner, job2, &fence2, 0, b"revision ok\n").await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        finish(&s, &runner, job2, &fence2, "succeeded").await,
        StatusCode::OK
    );

    // The gate requiring `ci/test` now passes on the change, and the merge
    // goes through.
    let report = s
        .core
        .evaluate_gates(Some(&alice), "alice", "proj", 1, 1)
        .await
        .unwrap();
    assert!(report.passed, "{report:?}");
    let resp = client
        .post(s.url("/api/v1/repos/alice/proj/trails/1/changes/1/merge"))
        .bearer_auth(&pat)
        .json(&json!({ "method": "merge" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "gate must permit merge");
}
