//! CI usage and quotas by supplier: native runners are metered per attempt
//! by Starforge and limited by `[ci.limits]` (monthly minutes when a run is
//! queued, artifact storage when an upload is authorized); a repository
//! linked to Depot reports the usage Depot's API attributes to it, with the
//! limits left to Depot.
mod common;

use std::time::{Duration, Instant};

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::Digest as _;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const CI_TOML: &str = r#"version = 1
[triggers]
push = ["main"]

[[job]]
name = "test"
image = "example.test/image:1"
commands = ["true"]
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
        "DELETE" => client.delete(url),
        _ => unreachable!(),
    };
    let req = req.bearer_auth(token);
    let req = match body {
        Some(body) => req.json(&body),
        None => req,
    };
    let resp = req.send().await.unwrap();
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

async fn claim(s: &TestServer, runner: &str) -> (i64, String) {
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/jobs/request"),
        runner,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    (
        value["job_id"].as_i64().unwrap(),
        value["fence"].as_str().unwrap().to_owned(),
    )
}

/// Pushes `main` with the CI spec and returns the work tree.
async fn push_ci(s: &TestServer, pat: &str, tmp: &std::path::Path) -> std::path::PathBuf {
    let work = work_repo(
        tmp,
        "work",
        &[(".starforge/ci.toml", CI_TOML), ("README.md", "# proj\n")],
    )
    .await;
    git_ok(
        &work,
        &["push", "-q", &s.git_url("alice", "proj", Some(pat)), "main"],
    )
    .await;
    work
}

async fn wait_for_jobs(s: &TestServer, repo_id: i64, count: usize) {
    let start = Instant::now();
    while starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo_id, 100)
        .await
        .unwrap()
        .len()
        < count
    {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for {count} CI job(s)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn supplier<'a>(usage: &'a Value, name: &str) -> &'a Value {
    usage["suppliers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["supplier"] == name)
        .unwrap_or_else(|| panic!("no {name} supplier in {usage}"))
}

fn metric<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == name)
        .unwrap_or_else(|| panic!("no {name} metric in {report}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_minutes_are_metered_per_attempt_and_the_quota_refuses_new_runs() {
    let s = TestServer::start_with(|c| c.ci.limits.minutes_per_month = 2).await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = push_ci(&s, &pat, tmp.path()).await;
    wait_for_jobs(&s, repo.id, 1).await;
    let runner = register_runner(&s, &pat).await;
    let (job_id, fence) = claim(&s, &runner).await;

    // The attempt ran for three minutes on the runner.
    sqlx::query("UPDATE ci_jobs SET claimed_at = claimed_at - 180 WHERE id = $1")
        .bind(job_id)
        .execute(s.db().pool())
        .await
        .unwrap();
    let resp = s
        .browser()
        .put(s.url(&format!("/api/v1/runners/jobs/{job_id}")))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .json(&json!({ "state": "succeeded", "exit_code": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, usage) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/ci/usage"),
        &pat,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{usage}");
    let native = supplier(&usage, "native");
    assert_eq!(native["enforced_by"], "starforge");
    let minutes = metric(native, "runner_minutes");
    let used = minutes["used"].as_f64().unwrap();
    assert!(
        (3.0..3.1).contains(&used),
        "three runner minutes: {minutes}"
    );
    assert_eq!(minutes["limit"], 2.0);
    assert_eq!(metric(native, "attempts")["used"], 1.0);
    assert_eq!(
        usage["suppliers"].as_array().unwrap().len(),
        1,
        "no supplier is linked"
    );

    // The month's minutes are used up: a new push queues nothing and says
    // why on the job's check.
    commit_files(&work, &[("more.txt", b"more\n")], "more").await;
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
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let start = Instant::now();
    let check = loop {
        let checks = starforged_db::checks::latest_checks_for_sha(s.db(), repo.id, &sha)
            .await
            .unwrap();
        if let Some(check) = checks.into_iter().find(|c| c.context == "ci/test") {
            break check;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for the quota check"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(check.state, "error");
    let description = check.description.unwrap_or_default();
    assert!(
        description.contains("CI minutes quota") && description.contains("resets on"),
        "{description}"
    );
    assert_eq!(
        starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
            .await
            .unwrap()
            .len(),
        1,
        "the refused push queued no job"
    );

    // A manual run is refused with the same reason.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/runs"),
        &pat,
        Some(json!({ "ref": "main" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{value}");
    assert!(value.to_string().contains("CI minutes quota"), "{value}");

    // Re-triggering the commit that already ran leaves its result alone: a
    // refusal never overwrites an existing check.
    let first = starforged_db::ci::ci_job_by_id(s.db(), job_id)
        .await
        .unwrap()
        .unwrap();
    let ids = s
        .core
        .ci_trigger_push(repo.id, "main", &first.commit_sha, Some(alice.id))
        .await
        .unwrap();
    assert!(ids.is_empty(), "the quota refuses the re-trigger");
    let checks = starforged_db::checks::latest_checks_for_sha(s.db(), repo.id, &first.commit_sha)
        .await
        .unwrap();
    let check = checks.iter().find(|c| c.context == "ci/test").unwrap();
    assert_eq!(check.state, "success", "{checks:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifact_storage_quota_refuses_an_upload_past_it() {
    let s = TestServer::start_with(|c| c.ci.limits.artifact_bytes = 20).await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    push_ci(&s, &pat, tmp.path()).await;
    wait_for_jobs(&s, repo.id, 1).await;
    let runner = register_runner(&s, &pat).await;
    let (job_id, fence) = claim(&s, &runner).await;
    let client = s.browser();
    // Authorizes `bytes` as `name` and returns the one-time upload token.
    let authorize = |name: &'static str, bytes: &'static [u8]| {
        let client = client.clone();
        let url = s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/authorize"
        ));
        let (runner, fence) = (runner.clone(), fence.clone());
        async move {
            let sha256 = hex::encode(sha2::Sha256::digest(bytes));
            client
                .post(url)
                .bearer_auth(&runner)
                .header("X-Starforge-Fence", &fence)
                .json(&json!({ "name": name, "size": bytes.len(), "sha256": sha256 }))
                .send()
                .await
                .unwrap()
        }
    };
    let upload = |name: &'static str, bytes: &'static [u8], token: String| {
        let client = client.clone();
        let url = s.url(&format!("/api/v1/runners/jobs/{job_id}/artifacts/{name}"));
        async move {
            client
                .put(url)
                .bearer_auth(&token)
                .header(
                    "X-Starforge-Sha256",
                    hex::encode(sha2::Sha256::digest(bytes)),
                )
                .body(bytes.to_vec())
                .send()
                .await
                .unwrap()
        }
    };
    let token_of = |resp: reqwest::Response| async move {
        assert_eq!(resp.status(), StatusCode::CREATED);
        resp.json::<Value>().await.unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    const FIFTEEN: &[u8] = b"fifteen bytes!\n";
    const TEN: &[u8] = b"ten bytes\n";
    const FIVE: &[u8] = b"five\n";

    // Nothing is stored yet, so three uploads authorize in parallel even
    // though together they exceed the twenty-byte quota.
    let a = token_of(authorize("out/a.bin", FIFTEEN).await).await;
    let b = token_of(authorize("out/b.bin", TEN).await).await;
    let c = token_of(authorize("out/c.bin", FIVE).await).await;

    // The bytes are checked again on arrival: fifteen fit, ten more do not,
    // and five more reach the quota exactly.
    assert_eq!(
        upload("out/a.bin", FIFTEEN, a).await.status(),
        StatusCode::CREATED
    );
    let refused = upload("out/b.bin", TEN, b).await;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = refused.text().await.unwrap();
    assert!(body.contains("artifact storage quota"), "{body}");
    assert_eq!(
        upload("out/c.bin", FIVE, c).await.status(),
        StatusCode::CREATED
    );
    // With the quota full, a new authorization is refused up front.
    let resp = authorize("out/d.bin", FIVE).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let (_, usage) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/ci/usage"),
        &pat,
        None,
    )
    .await;
    let stored = metric(supplier(&usage, "native"), "artifact_bytes");
    assert_eq!(stored["used"], 20.0);
    assert_eq!(stored["limit"], 20.0);
}

/// A fake Depot API: answers `UsageService.GetUsage` for the expected
/// organization token, and a Connect `unauthenticated` error otherwise.
async fn fake_depot(token: &'static str) -> String {
    let app = axum::Router::new().route(
        "/depot.core.v1.UsageService/GetUsage",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                let authorized = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    == Some(&format!("Bearer {token}"));
                let connect = headers
                    .get("connect-protocol-version")
                    .and_then(|v| v.to_str().ok())
                    == Some("1");
                let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                if !authorized || !connect || !request["startAt"].is_string() {
                    return (
                        axum::http::StatusCode::UNAUTHORIZED,
                        axum::Json(json!({"code": "unauthenticated", "message": "invalid token"})),
                    );
                }
                (
                    axum::http::StatusCode::OK,
                    axum::Json(json!({
                        "periodStart": request["startAt"],
                        "periodEnd": request["endAt"],
                        "depotCi": [
                            {"repo": "acme/app", "workflow": "CI", "runner": "depot-ubuntu-24.04",
                             "attemptCount": 3, "minutesElapsed": 10.5, "vcpuMinutesBilled": 42.0},
                            {"repo": "acme/app", "workflow": "Lint", "runner": "depot-ubuntu-24.04",
                             "attemptCount": 2, "minutesElapsed": 4.25, "vcpuMinutesBilled": 17.0},
                            {"repo": "acme/other", "workflow": "CI", "runner": "depot-ubuntu-24.04",
                             "attemptCount": 9, "minutesElapsed": 90.0, "vcpuMinutesBilled": 360.0}
                        ],
                        "githubActionsJobs": [
                            {"repo": "Acme/App", "total": {"jobCount": 4, "minutesElapsed": 7.0, "minutesBilled": 8.0}}
                        ],
                        "containerBuild": [
                            {"projectName": "builder", "buildCount": 5, "minutesBilled": 12.0}
                        ]
                    })),
                )
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn depot_link_reports_the_suppliers_usage_and_leaves_limits_to_it() {
    let depot = fake_depot("depot-org-token").await;
    let s = TestServer::start_with(|c| {
        c.ci.depot.api_url = depot.clone();
        c.ci.depot.api_token = "depot-org-token".into();
        // Native limits do not apply to the Depot report.
        c.ci.limits.minutes_per_month = 1;
    })
    .await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let pat = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let bob_pat = s.token(&bob, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let link_url = s.url("/api/v1/repos/alice/proj/ci/suppliers/depot");
    let usage_url = s.url("/api/v1/repos/alice/proj/ci/usage");

    // Linking needs Admin; viewing usage needs Maintain.
    let (status, _) = api(
        &s.browser(),
        "PUT",
        &link_url,
        &bob_pat,
        Some(json!({ "external_ref": "acme/app" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api(&s.browser(), "GET", &usage_url, &bob_pat, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Unknown suppliers and malformed names are refused.
    let (status, _) = api(
        &s.browser(),
        "PUT",
        &s.url("/api/v1/repos/alice/proj/ci/suppliers/github"),
        &pat,
        Some(json!({ "external_ref": "acme/app" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = api(
        &s.browser(),
        "PUT",
        &link_url,
        &pat,
        Some(json!({ "external_ref": "acme" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, link) = api(
        &s.browser(),
        "PUT",
        &link_url,
        &pat,
        Some(json!({ "external_ref": "acme/app" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{link}");
    assert_eq!(link["supplier"], "depot");
    assert_eq!(link["external_ref"], "acme/app");

    let (status, usage) = api(&s.browser(), "GET", &usage_url, &pat, None).await;
    assert_eq!(status, StatusCode::OK, "{usage}");
    let depot_report = supplier(&usage, "depot");
    assert_eq!(depot_report["enforced_by"], "depot");
    assert_eq!(depot_report["external_ref"], "acme/app");
    assert!(depot_report["error"].is_null(), "{depot_report}");
    // Only acme/app's rows count; GitHub Actions jobs match case-insensitively.
    assert_eq!(metric(depot_report, "depot_ci_vcpu_minutes")["used"], 59.0);
    assert_eq!(metric(depot_report, "depot_ci_minutes")["used"], 14.75);
    assert_eq!(metric(depot_report, "depot_ci_attempts")["used"], 5.0);
    assert_eq!(metric(depot_report, "github_actions_minutes")["used"], 8.0);
    assert_eq!(metric(depot_report, "github_actions_jobs")["used"], 4.0);
    // Depot's API exposes no limits: Starforge reports none and enforces none.
    for metric in depot_report["metrics"].as_array().unwrap() {
        assert!(metric["limit"].is_null(), "{metric}");
    }
    assert_eq!(supplier(&usage, "native")["enforced_by"], "starforge");

    // Unlinking removes the report; a second unlink is 404.
    let (status, _) = api(&s.browser(), "DELETE", &link_url, &pat, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, usage) = api(&s.browser(), "GET", &usage_url, &pat, None).await;
    assert_eq!(usage["suppliers"].as_array().unwrap().len(), 1);
    let (status, _) = api(&s.browser(), "DELETE", &link_url, &pat, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn depot_errors_are_reported_without_failing_the_usage_call() {
    let depot = fake_depot("the-real-token").await;
    let s = TestServer::start_with(|c| {
        c.ci.depot.api_url = depot.clone();
        c.ci.depot.api_token = "a-wrong-token".into();
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let (status, _) = api(
        &s.browser(),
        "PUT",
        &s.url("/api/v1/repos/alice/proj/ci/suppliers/depot"),
        &pat,
        Some(json!({ "external_ref": "acme/app" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, usage) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/ci/usage"),
        &pat,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a supplier failure is not fatal: {usage}"
    );
    let report = supplier(&usage, "depot");
    let error = report["error"].as_str().unwrap();
    assert!(error.contains("unauthenticated"), "{error}");
    assert!(
        !error.contains("a-wrong-token"),
        "the token never leaks: {error}"
    );
    assert!(report["metrics"].as_array().unwrap().is_empty());
    assert_eq!(supplier(&usage, "native")["enforced_by"], "starforge");
}
