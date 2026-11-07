//! CI triggers, artifacts, and secrets API tests (M6c C1–C3): a push
//! enqueues a job from the commit's `.starforge/ci.toml`, a manual
//! trigger reuses the same path, artifacts authorize/upload/download
//! under their one-time binding, and secrets resolve only under the
//! trust rule (protected branch / approved Trail; `refs/for` denied).
mod common;

use std::time::{Duration, Instant};

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::Digest as _;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

const CI_TOML: &str = r#"version = 1

[triggers]
push = ["main", "release/*"]
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
    client: &reqwest::Client,
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

/// Registers one runner on alice/proj and returns its auth token.
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

/// Polls until `pred` finds a CI job of the repo, then returns its id.
async fn wait_for_job(s: &TestServer, repo_id: i64, job_name: &str) -> i64 {
    let start = Instant::now();
    loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo_id, 100)
            .await
            .unwrap();
        if let Some(job) = jobs.iter().find(|job| job.job_name == job_name) {
            return job.id;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for CI job {job_name}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Claims one job with the runner; returns `(job_id, fence, job_token)`.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_enqueues_job_from_commit_spec_and_dedupes() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
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
    let job_id = wait_for_job(&s, repo.id, "test").await;
    let job = starforged_db::ci::ci_job_by_id(s.db(), job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.repo_id, repo.id);
    assert_eq!(job.created_by, Some(alice.id), "created_by is the pusher");
    // The pending check is visible on the commit.
    let checks = starforged_db::checks::latest_checks_for_sha(s.db(), repo.id, &job.commit_sha)
        .await
        .unwrap();
    assert!(
        checks
            .iter()
            .any(|c| c.context == "ci/test" && c.state == "pending")
    );

    // Pushing the same commit to another matching branch dedupes.
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&pat)),
            "HEAD:release/1.0",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
        .await
        .unwrap();
    assert_eq!(
        jobs.len(),
        1,
        "same (repo, commit, job) must dedupe: {jobs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_trigger_runs_list_and_detail() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let _repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
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
    wait_for_job(&s, _repo.id, "test").await;

    // Manual trigger of the same commit dedupes against the live job.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/runs"),
        &pat,
        Some(json!({ "ref": "main" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["job_ids"].as_array().unwrap().len(), 0, "{value}");

    // Unknown job is 422; unknown ref is 422.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/runs"),
        &pat,
        Some(json!({ "ref": "main", "job": "nope" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{value}");

    let (status, value) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/ci/runs"),
        &pat,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let runs = value["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    let job_id = runs[0]["job_id"].as_i64().unwrap();

    let (status, value) = api(
        &s.browser(),
        "GET",
        &s.url(&format!("/api/v1/repos/alice/proj/ci/runs/{job_id}")),
        &pat,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["job_name"], "test");

    // A run of another repository reads as 404.
    let bob = s.user("bob").await;
    let _other = s.repo(&bob, "proj", Visibility::Private).await;
    let bob_pat = s.token(&bob, &[Scope::RepoWrite]).await;
    let (status, value) = api(
        &s.browser(),
        "GET",
        &s.url(&format!("/api/v1/repos/bob/proj/ci/runs/{job_id}")),
        &bob_pat,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{value}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifacts_authorize_upload_download_and_reject() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let _repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
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
    wait_for_job(&s, _repo.id, "test").await;
    let runner = register_runner(&s, &pat).await;
    let (job_id, fence, job_token) = claim(&s, &runner).await;

    let bytes = b"hello artifact\n";
    let sha256 = hex::encode(sha2::Sha256::digest(bytes));
    let client = s.browser();
    let authorize = s.url(&format!(
        "/api/v1/runners/jobs/{job_id}/artifacts/authorize"
    ));
    // Traversal name is refused.
    let resp = client
        .post(&authorize)
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .json(&json!({ "name": "../evil", "size": 1, "sha256": sha256 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Oversize is refused.
    let resp = client
        .post(&authorize)
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .json(&json!({ "name": "out/a.bin", "size": (1_i64 << 30) + 1, "sha256": sha256 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // A name outside the job's artifact globs is forbidden.
    let resp = client
        .post(&authorize)
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .json(&json!({ "name": "elsewhere.bin", "size": 1, "sha256": sha256 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // A valid authorize mints a one-time token (no-store).
    let resp = client
        .post(&authorize)
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .json(&json!({ "name": "out/result.bin", "size": bytes.len(), "sha256": sha256 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let token = resp.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(token.starts_with("sfa_"));

    // The runner token itself cannot PUT artifacts.
    let resp = client
        .put(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .bearer_auth(&runner)
        .header("X-Starforge-Sha256", &sha256)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Mismatched sha256 is refused.
    let resp = client
        .put(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .bearer_auth(&token)
        .header("X-Starforge-Sha256", "0".repeat(64))
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // The bound upload succeeds.
    let resp = client
        .put(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .bearer_auth(&token)
        .header("X-Starforge-Sha256", &sha256)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let stored: Value = resp.json().await.unwrap();
    assert_eq!(stored["name"], "out/result.bin");
    // The token is one-time: a replay is a conflict.
    let resp = client
        .put(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .bearer_auth(&token)
        .header("X-Starforge-Sha256", &sha256)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Download with the job token returns the bytes.
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
    // An unknown caller is refused.
    let resp = client
        .get(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Expired artifacts read as missing.
    sqlx::query("UPDATE ci_artifacts SET expires_at = $1 WHERE job_id = $2")
        .bind(0_i64)
        .bind(job_id)
        .execute(s.db().pool())
        .await
        .unwrap();
    let resp = client
        .get(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/result.bin"
        )))
        .bearer_auth(&job_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secrets_crud_and_trust_rule() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let client = s.browser();

    // Create (sealed) and list (metadata only).
    let secret_value = "registry-token-super-secret";
    let (status, value) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({ "name": "CARGO_REGISTRY_TOKEN", "value": secret_value })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let sealed = starforged_db::ci::secret_by_name(s.db(), repo.id, "CARGO_REGISTRY_TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert!(sealed.sealed_value.starts_with("c1:"));
    assert!(
        !sealed.sealed_value.contains(secret_value),
        "no plaintext in DB"
    );
    let (status, value) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["secrets"].as_array().unwrap().len(), 1);
    let listed = value.to_string();
    assert!(
        !listed.contains(secret_value),
        "no plaintext in list: {listed}"
    );
    assert!(
        !listed.contains(&sealed.sealed_value),
        "no sealed value in list: {listed}"
    );

    // Unprotected push: the job resolves no secrets.
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
    let plain_job = wait_for_job(&s, repo.id, "test").await;
    let runner = register_runner(&s, &pat).await;
    let (claimed_plain, fence_plain, _) = claim(&s, &runner).await;
    assert_eq!(claimed_plain, plain_job);
    let resp = client
        .post(s.url(&format!("/api/v1/runners/jobs/{plain_job}/secrets")))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence_plain)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(
        resp.json::<Value>().await.unwrap()["secrets"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Protect main, push again: the job resolves the secret, and the
    // resolution is recorded for session redaction.
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
            "required_contexts": [],
            "require_up_to_date": false,
            "require_threads_resolved": false,
            "require_session_evidence": false,
            "allowed_methods": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    commit_files(&work, &[("second.txt", b"second\n")], "second commit").await;
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
    // Wait for the protected-branch job (a second "test" row).
    let protected_job = loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
            .await
            .unwrap();
        let test_jobs: Vec<_> = jobs.iter().filter(|j| j.job_name == "test").collect();
        if test_jobs.len() >= 2 {
            break test_jobs[0].id;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let (claimed, fence, _) = claim(&s, &runner).await;
    assert_eq!(claimed, protected_job);
    let resp = client
        .post(s.url(&format!("/api/v1/runners/jobs/{protected_job}/secrets")))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resolved: Value = resp.json().await.unwrap();
    let secrets = resolved["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["name"], "CARGO_REGISTRY_TOKEN");
    assert_eq!(secrets[0]["value"], secret_value);
    assert_eq!(
        starforged_db::ci::job_secrets_for_job(s.db(), protected_job)
            .await
            .unwrap()
            .len(),
        1,
        "resolution recorded in ci_job_secrets"
    );

    // Cross-repo: the same secret name in another repo never leaks into
    // this job's resolution (resolution scopes by the job's repo).
    let _other = s.repo(&alice, "other", Visibility::Private).await;
    let (status, value) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/other/ci/secrets"),
        &pat,
        Some(json!({ "name": "CARGO_REGISTRY_TOKEN", "value": "other-repo-value" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let resp = client
        .post(s.url(&format!("/api/v1/runners/jobs/{protected_job}/secrets")))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .send()
        .await
        .unwrap();
    let resolved: Value = resp.json().await.unwrap();
    assert_eq!(resolved["secrets"][0]["value"], secret_value);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refs_for_jobs_get_no_secrets_without_approval() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let client = s.browser();
    let (status, value) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({ "name": "CARGO_REGISTRY_TOKEN", "value": "trail-secret" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");

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
    commit_files(&work, &[("feature.txt", b"feature\n")], "feature").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&pat)),
            "HEAD:refs/for/main/topic",
        ],
    )
    .await;

    // The Trail job is queued against the change's revision.
    let start = Instant::now();
    let trail_job = loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
            .await
            .unwrap();
        if let Some(job) = jobs.iter().find(|job| job.change_id.is_some()) {
            break job.id;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for the Trail CI job"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // Cancel the older push job so the claim lands on the Trail job.
    let push_job = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.id != trail_job)
        .map(|job| job.id)
        .unwrap();
    assert!(
        starforged_db::ci::cancel_ci_job(s.db(), push_job, None, starforged_db::now())
            .await
            .unwrap()
    );
    let runner = register_runner(&s, &pat).await;
    let (claimed, fence, _) = claim(&s, &runner).await;
    assert_eq!(claimed, trail_job);
    let resp = client
        .post(s.url(&format!("/api/v1/runners/jobs/{trail_job}/secrets")))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resolved: Value = resp.json().await.unwrap();
    assert_eq!(
        resolved["secrets"].as_array().unwrap().len(),
        0,
        "unapproved refs/for runs get no secrets (ci.allow_secrets_on_refs_for is off)"
    );

    // Supersede: a second revision cancels the first revision's job.
    commit_files(&work, &[("feature2.txt", b"feature2\n")], "feature 2").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&pat)),
            "HEAD:refs/for/main/topic",
        ],
    )
    .await;
    let start = Instant::now();
    let superseded = loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
            .await
            .unwrap();
        let old = jobs.iter().find(|job| job.id == trail_job).unwrap();
        if old.state == "canceled" {
            break old.state.clone();
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for the supersede cancel"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(
        superseded, "canceled",
        "a new revision supersedes the old job"
    );
    let old = starforged_db::ci::ci_job_by_id(s.db(), trail_job)
        .await
        .unwrap()
        .unwrap();
    // The job state flips before the terminal check is written; poll for
    // the check with the same deadline instead of racing the trigger.
    let start = Instant::now();
    let check = loop {
        let checks = starforged_db::checks::latest_checks_for_sha(s.db(), repo.id, &old.commit_sha)
            .await
            .unwrap();
        if let Some(check) = checks
            .iter()
            .find(|c| c.context == format!("ci/{}", old.job_name))
            .cloned()
            && check.state == "error"
            && check.description.as_deref() == Some("superseded by a newer revision")
        {
            break check;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for the superseded check"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(check.state, "error");
    assert_eq!(
        check.description.as_deref(),
        Some("superseded by a newer revision")
    );
}
