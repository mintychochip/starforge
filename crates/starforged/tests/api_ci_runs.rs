//! CI triggers, artifacts, and secrets API tests (M6c C1–C3): a push
//! enqueues a job from the commit's `.starforge/ci.toml`, a manual
//! trigger reuses the same path, artifacts authorize/upload/download
//! under their one-time binding, and secrets resolve only under the
//! trust rule (protected branch / approved Trail; `refs/for` denied).
mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::Digest as _;
use starforged_core::permission::Visibility;
use starforged_core::sandboxes::SandboxProviderKind;
use starforged_core::tokens::Scope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

const CI_TOML: &str = r#"version = 1

[triggers]
push = ["main", "release/*"]
trail = ["opened", "updated"]

[[job]]
name = "test"
image = "example.test/image:1"
commands = ["true"]
timeout = "30m"
secrets = ["CARGO_REGISTRY_TOKEN", "HOSTLESS_TOKEN"]
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
    // The pending check is visible on the commit. The trigger inserts the
    // job row, then writes the check: poll rather than race it.
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
    // The hourly cleanup's artifact GC deletes the expired row and, once
    // its refcount is zero, the CAS blob.
    let artifact = starforged_db::ci::artifact_by_name(s.db(), job_id, "out/result.bin", -1)
        .await
        .unwrap()
        .expect("artifact row");
    let blob_hash = artifact.blake3.clone();
    let deleted = s.core.gc_expired_artifacts().await.unwrap();
    assert!(deleted.contains(&artifact.id), "deleted: {deleted:?}");
    assert!(
        starforged_db::ci::artifact_by_name(s.db(), job_id, "out/result.bin", -1)
            .await
            .unwrap()
            .is_none(),
        "expired artifact row is gone"
    );
    assert!(
        s.core
            .config()
            .blob_store
            .get_by_hash(&blob_hash)
            .await
            .is_err(),
        "unreferenced artifact blob is gone"
    );

    // A blob shared with a live session or CI log chunk must survive the
    // artifact GC: the CAS is shared across all three.
    let shared = b"shared artifact\n";
    let shared_sha = hex::encode(sha2::Sha256::digest(shared));
    let resp = client
        .post(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/authorize"
        )))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .json(&json!({
            "name": "out/second.bin",
            "size": shared.len(),
            "sha256": shared_sha,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let value: Value = resp.json().await.unwrap();
    let shared_token = value["token"].as_str().unwrap().to_owned();
    let resp = client
        .put(s.url(&format!(
            "/api/v1/runners/jobs/{job_id}/artifacts/out/second.bin"
        )))
        .bearer_auth(&shared_token)
        .header("X-Starforge-Sha256", &shared_sha)
        .body(shared.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let stored2: Value = resp.json().await.unwrap();
    let shared_hash = stored2["blake3"].as_str().unwrap().to_owned();
    starforged_db::sessions::blob_incref(s.db(), &shared_hash, shared.len() as i64, &shared_hash)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO ci_job_logs (job_id, start_offset, end_offset, blake3, created_at) \
         VALUES ($1, 0, 1, $2, $3)",
    )
    .bind(job_id)
    .bind(&shared_hash)
    .bind(starforged_db::now())
    .execute(s.db().pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE ci_artifacts SET expires_at = 0 WHERE job_id = $1 AND name = 'out/second.bin'",
    )
    .bind(job_id)
    .execute(s.db().pool())
    .await
    .unwrap();
    let deleted = s.core.gc_expired_artifacts().await.unwrap();
    assert!(!deleted.is_empty(), "deleted: {deleted:?}");
    assert!(
        starforged_db::ci::artifact_by_name(s.db(), job_id, "out/second.bin", -1)
            .await
            .unwrap()
            .is_none(),
        "expired shared artifact row is gone"
    );
    assert!(
        s.core
            .config()
            .blob_store
            .get_by_hash(&shared_hash)
            .await
            .is_ok(),
        "shared blob survives artifact GC"
    );
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
        Some(json!({ "name": "CARGO_REGISTRY_TOKEN", "value": secret_value, "host": "registry.example", "header": "Authorization" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["host"], "registry.example");
    assert_eq!(value["header"], "Authorization");
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
    assert_eq!(value["secrets"][0]["host"], "registry.example");
    assert_eq!(value["secrets"][0]["header"], "Authorization");
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
    assert_eq!(secrets[0]["host"], "registry.example");
    assert_eq!(secrets[0]["header"], "Authorization");
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

    // A non-admin (Write collaborator) cannot flip the policy.
    let bob = s.user("bob").await;
    let bob_pat = s.token(&bob, &[Scope::RepoWrite]).await;
    let (status, value) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/collaborators/bob"),
        &pat,
        Some(json!({ "permission": "write" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{value}");
    let (status, value) = api(
        &client,
        "PATCH",
        &s.url("/api/v1/repos/alice/proj"),
        &bob_pat,
        Some(json!({ "ci_allow_secrets_on_refs_for": true })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");

    // Admin opts the repo in; the same claimed job now resolves.
    let (status, value) = api(
        &client,
        "PATCH",
        &s.url("/api/v1/repos/alice/proj"),
        &pat,
        Some(json!({ "ci_allow_secrets_on_refs_for": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["ci_allow_secrets_on_refs_for"], true);
    let resp = client
        .post(s.url(&format!("/api/v1/runners/jobs/{trail_job}/secrets")))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resolved: Value = resp.json().await.unwrap();
    assert_eq!(resolved["secrets"].as_array().unwrap().len(), 1);
    assert_eq!(resolved["secrets"][0]["value"], "trail-secret");

    // Admin resets the opt-in; resolution goes back to empty.
    let (status, value) = api(
        &client,
        "PATCH",
        &s.url("/api/v1/repos/alice/proj"),
        &pat,
        Some(json!({ "ci_allow_secrets_on_refs_for": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["ci_allow_secrets_on_refs_for"], false);
    let resp = client
        .post(s.url(&format!("/api/v1/runners/jobs/{trail_job}/secrets")))
        .bearer_auth(&runner)
        .header("X-Starforge-Fence", &fence)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resolved: Value = resp.json().await.unwrap();
    assert_eq!(resolved["secrets"].as_array().unwrap().len(), 0);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_create_rejects_bad_host_and_header() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let _repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let client = s.browser();
    for body in [
        json!({ "name": "TOKEN", "value": "v", "host": "https://evil.example" }),
        json!({ "name": "TOKEN", "value": "v", "header": "Content-Length" }),
    ] {
        let (status, value) = api(
            &client,
            "POST",
            &s.url("/api/v1/repos/alice/proj/ci/secrets"),
            &pat,
            Some(body),
        )
        .await;
        assert!(
            status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST,
            "expected 422/400, got {status}: {value}"
        );
    }
}

/// A fake E2B gateway that records every `POST /sandboxes` body and
/// answers with one running sandbox.
async fn spawn_recording_e2b() -> (String, Arc<Mutex<Vec<Value>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let recorded = Arc::clone(&bodies);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let recorded = Arc::clone(&recorded);
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
                        let head = String::from_utf8_lossy(&buf[..end]);
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
                let text = String::from_utf8_lossy(&buf);
                let line = text.lines().next().unwrap_or_default();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                let body = text
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b)
                    .unwrap_or_default();
                if method == "POST" && target == "/v2/sandboxes" {
                    if let Ok(value) = serde_json::from_str::<Value>(body) {
                        recorded.lock().unwrap().push(value);
                    }
                    let resp = r#"{"sandboxID":"sbx-e2b-1","envdAccessToken":"envd-tok","domain":"e2b.app"}"#;
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                                resp.len(),
                                resp
                            )
                            .as_bytes(),
                        )
                        .await;
                } else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });
    (url, bodies)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_sandbox_delivers_secrets_only_to_e2b_with_the_repo_opt_in() {
    let (e2b_url, recorded) = spawn_recording_e2b().await;
    let s = TestServer::start_with(|config| {
        config.sandbox.provider = SandboxProviderKind::E2b;
        config.sandbox.e2b.api_url = e2b_url.clone();
        config.sandbox.e2b.api_key = "test-key".to_owned();
    })
    .await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let secret_value = "e2b-secret-value";
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({
            "name": "CARGO_REGISTRY_TOKEN",
            "value": secret_value,
            "host": "registry.example",
            "header": "Authorization",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({
            "name": "HOSTLESS_TOKEN",
            "value": "hostless-secret-value",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    // Protect main so the job is trusted for secret resolution.
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
    let job = wait_for_job(&s, repo.id, "test").await;
    let runner = register_runner(&s, &pat).await;
    let (claimed, _fence, job_token) = claim(&s, &runner).await;
    assert_eq!(claimed, job);

    // E2B without the repo opt-in: the server resolves and registers the
    // secret for redaction, but sends neither envs nor bindings.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(json!({ "template": "starforge/rust", "runtime": "e2b" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let first = recorded.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        starforged_db::ci::job_secrets_for_job(s.db(), job)
            .await
            .unwrap()
            .len(),
        2,
        "resolution is recorded for session redaction"
    );
    assert!(
        first.get("secret_bindings").is_none(),
        "E2B must never receive secret bindings: {first}"
    );
    assert!(
        first
            .get("envVars")
            .and_then(Value::as_object)
            .is_none_or(|envs| !envs.values().any(|v| v.as_str() == Some(secret_value))),
        "no env delivery without the opt-in: {first}"
    );

    // With the per-repo opt-in, the E2B provider gets the value as env.
    let (status, value) = api(
        &s.browser(),
        "PATCH",
        &s.url("/api/v1/repos/alice/proj"),
        &pat,
        Some(json!({ "ci_env_secrets": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(json!({
            "template": "starforge/rust",
            "runtime": "e2b",
            "idempotency_key": "second-sandbox",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let second = recorded.lock().unwrap().last().cloned().unwrap();
    assert_eq!(second["envVars"]["CARGO_REGISTRY_TOKEN"], secret_value);
    assert_eq!(second["envVars"]["HOSTLESS_TOKEN"], "hostless-secret-value");
    assert!(
        second.get("secret_bindings").is_none(),
        "E2B must never receive secret bindings: {second}"
    );
}

/// A fake local sandbox daemon over a Unix socket. It records every
/// `POST /sandboxes` body and answers with one running sandbox.
async fn spawn_recording_local_daemon(
    token: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    Arc<Mutex<Vec<Value>>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("sandboxd.sock");
    let token_file = dir.path().join("sandboxd.token");
    std::fs::write(&token_file, token).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&recorded);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let rec = Arc::clone(&rec);
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
                        let head = String::from_utf8_lossy(&buf[..end]);
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
                let text = String::from_utf8_lossy(&buf);
                let line = text.lines().next().unwrap_or_default();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                let body = text
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b)
                    .unwrap_or_default();
                if method == "POST" && target == "/sandboxes" {
                    if let Ok(value) = serde_json::from_str::<Value>(body) {
                        rec.lock().unwrap().push(value);
                    }
                    let resp = r#"{"id":"sbx-local-1","state":"running","runtime":"podman","expires_at":null,"provider":"local"}"#;
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                                resp.len(),
                                resp
                            )
                            .as_bytes(),
                        )
                        .await;
                } else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });
    (dir, socket, token_file, recorded)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_sandbox_sends_secret_bindings_to_the_local_daemon() {
    let (_dir, socket, token_file, recorded) = spawn_recording_local_daemon("daemon-token").await;
    let s = TestServer::start_with(|config| {
        config.sandbox.provider = SandboxProviderKind::Local;
        config.sandbox.local.socket = socket.clone();
        config.sandbox.local.token_file = token_file.clone();
    })
    .await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let secret_value = "local-secret-value";
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/secrets"),
        &pat,
        Some(json!({
            "name": "CARGO_REGISTRY_TOKEN",
            "value": secret_value,
            "host": "registry.example",
            "header": "Authorization",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
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
    let job = wait_for_job(&s, repo.id, "test").await;
    let runner = register_runner(&s, &pat).await;
    let (claimed, _fence, job_token) = claim(&s, &runner).await;
    assert_eq!(claimed, job);

    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &job_token,
        Some(json!({ "template": "example.test/image:1", "runtime": "podman" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let create = recorded.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        starforged_db::ci::job_secrets_for_job(s.db(), job)
            .await
            .unwrap()
            .len(),
        1,
        "resolution is recorded for session redaction"
    );
    let bindings = create["secret_bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1, "one binding: {create}");
    assert_eq!(bindings[0]["host"], "registry.example");
    assert_eq!(bindings[0]["header"], "Authorization");
    assert_eq!(bindings[0]["value"], secret_value);
    assert_eq!(
        create["network"]["secret_headers"]["registry.example"],
        "Authorization"
    );
    assert!(
        create["network"]["allow_out"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h == "registry.example"),
        "secret host is allowlisted: {create}"
    );
    assert!(
        !create["envs"]
            .as_object()
            .unwrap()
            .values()
            .any(|v| v.as_str() == Some(secret_value)),
        "local provider never gets the value in env: {create}"
    );

    // A PAT create may name a job, but only the JobAuth path resolves
    // secrets; the PAT path must bind nothing.
    let sandbox_pat = s
        .token(&alice, &[Scope::RepoWrite, Scope::SandboxRun])
        .await;
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &sandbox_pat,
        Some(json!({
            "owner": "alice",
            "repo": "proj",
            "job_id": job,
            "template": "example.test/image:1",
            "runtime": "podman",
            "idempotency_key": "pat-foreign-job",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let pat_create = recorded.lock().unwrap().last().cloned().unwrap();
    assert!(
        pat_create.get("secret_bindings").is_none()
            || pat_create["secret_bindings"].as_array().unwrap().is_empty(),
        "PAT create binds no secrets: {pat_create}"
    );
    assert!(
        !pat_create["envs"]
            .as_object()
            .unwrap()
            .values()
            .any(|v| v.as_str() == Some(secret_value)),
        "PAT create gets no secret env: {pat_create}"
    );
}

/// A matrix job expands into one job per combination on a push, each with
/// its own expanded name and matrix environment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_spec_enqueues_one_job_per_combination() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let spec = r#"
version = 1
[triggers]
push = ["main"]
[[job]]
name = "test"
image = "example.test/image:1"
commands = ["true"]
[job.matrix]
os = ["linux", "mac"]
"#;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[(".starforge/ci.toml", spec), ("README.md", "# proj\n")],
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
    let start = Instant::now();
    let jobs = loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
            .await
            .unwrap();
        if jobs.len() >= 2 {
            break jobs;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for the matrix jobs"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let names: Vec<&str> = jobs.iter().map(|job| job.job_name.as_str()).collect();
    assert!(names.iter().any(|n| n.starts_with("test-0-")), "{names:?}");
    assert!(names.iter().any(|n| n.starts_with("test-1-")), "{names:?}");
    for job in &jobs {
        let spec: serde_json::Value = serde_json::from_str(&job.spec).unwrap();
        assert!(spec.get("matrix").is_none(), "{spec}");
        assert!(
            matches!(spec["env"]["os"].as_str(), Some("linux" | "mac")),
            "{spec}"
        );
    }
}

/// A manual `--job NAME` selects the base job's combinations, never a
/// different job whose name starts with `NAME-`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_run_selects_the_base_job_not_a_prefixed_one() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let spec = r#"
version = 1
[triggers]
push = []
[[job]]
name = "test"
image = "example.test/image:1"
commands = ["true"]
[job.matrix]
os = ["linux", "mac"]
[[job]]
name = "test-fast"
image = "example.test/image:1"
commands = ["true"]
"#;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[(".starforge/ci.toml", spec), ("README.md", "# proj\n")],
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
    let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
        .await
        .unwrap();
    assert!(
        jobs.is_empty(),
        "manual-only spec enqueues nothing: {jobs:?}"
    );

    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/runs"),
        &pat,
        Some(json!({"ref": "main", "job": "test"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let names: Vec<&str> = value["runs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|run| run["job_name"].as_str())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names.iter().all(|name| name.starts_with("test-")),
        "{names:?}"
    );
    assert!(!names.contains(&"test-fast"), "{names:?}");

    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/ci/runs"),
        &pat,
        Some(json!({"ref": "main", "job": "test-fast"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let names: Vec<&str> = value["runs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|run| run["job_name"].as_str())
        .collect();
    assert_eq!(names, vec!["test-fast"], "{names:?}");
}

/// Raw-body request helper for the cache routes.
async fn api_bytes(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
    body: Option<Vec<u8>>,
) -> (StatusCode, Vec<u8>) {
    let req = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        _ => unreachable!(),
    };
    let req = req.bearer_auth(token);
    let req = match body {
        Some(bytes) => req.body(bytes),
        None => req,
    };
    let resp = req.send().await.unwrap();
    let status = resp.status();
    (status, resp.bytes().await.unwrap().to_vec())
}

/// A runner saves a cache entry and another job restores it by prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_round_trip_and_restore_keys() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let _repo = s.repo(&alice, "proj", Visibility::Private).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let spec = r#"
version = 1
[triggers]
push = ["main"]
[[job]]
name = "first"
image = "example.test/image:1"
commands = ["true"]
[job.cache]
key = "cargo-1.85"
paths = ["target"]
[[job]]
name = "second"
image = "example.test/image:1"
commands = ["true"]
[job.cache]
key = "cargo-2.0"
paths = ["target"]
restore_keys = ["cargo-"]
"#;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[(".starforge/ci.toml", spec), ("README.md", "# proj\n")],
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
    let runner = register_runner(&s, &pat).await;
    let (first, _fence, first_token) = claim(&s, &runner).await;
    let payload = b"\x1f\x8b\x08 cache-bytes";
    let (status, _) = api_bytes(
        &s.browser(),
        "PUT",
        &s.url(&format!(
            "/api/v1/runners/jobs/{first}/cache?key=cargo-1.85"
        )),
        &first_token,
        Some(payload.to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = api_bytes(
        &s.browser(),
        "GET",
        &s.url(&format!(
            "/api/v1/runners/jobs/{first}/cache?key=cargo-1.85"
        )),
        &first_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);

    // A key outside the spec is refused.
    let (status, _) = api_bytes(
        &s.browser(),
        "PUT",
        &s.url(&format!("/api/v1/runners/jobs/{first}/cache?key=other")),
        &first_token,
        Some(vec![1, 2, 3]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The second job's exact key misses; its restore prefix finds the entry.
    let (second, _fence, second_token) = claim(&s, &runner).await;
    let (status, _) = api_bytes(
        &s.browser(),
        "GET",
        &s.url(&format!(
            "/api/v1/runners/jobs/{second}/cache?key=cargo-2.0"
        )),
        &second_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = api_bytes(
        &s.browser(),
        "GET",
        &s.url(&format!(
            "/api/v1/runners/jobs/{second}/cache?key=cargo-2.0&restore=cargo-"
        )),
        &second_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);
}
