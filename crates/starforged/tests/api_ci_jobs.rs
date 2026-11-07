//! Runner job protocol API tests (M6a A3/A4/A5): a runner claims a queued
//! job under a lease fence, streams log chunks with Content-Range,
//! finishes the job (the `ci/<job>` check appears on the commit), and the
//! surrounding guarantees hold: stale fences and cross-runner calls are
//! rejected, label routing releases non-matching jobs, cancel wins, and a
//! revoked runner's credentials stop working.
mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn api_raw(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
    headers_extra: &[(&str, &str)],
    body: Option<Value>,
    raw_body: Option<&[u8]>,
) -> (StatusCode, reqwest::header::HeaderMap, Value) {
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
    let req = headers_extra
        .iter()
        .fold(req, |req, &(name, value)| req.header(name, value));
    let req = match (body, raw_body) {
        (Some(body), _) => req.json(&body),
        (None, Some(bytes)) => req.body(bytes.to_vec()),
        (None, None) => req.json(&json!({})),
    };
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap();
    let value = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, headers, value)
}

async fn api(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, _, value) = api_raw(client, method, url, token, &[], body, None).await;
    (status, value)
}

fn assert_no_store(headers: &reqwest::header::HeaderMap) {
    assert_eq!(
        headers.get(reqwest::header::CACHE_CONTROL).unwrap(),
        "no-store",
        "{headers:?}"
    );
    assert_eq!(
        headers.get(reqwest::header::PRAGMA).unwrap(),
        "no-cache",
        "{headers:?}"
    );
}

/// Registers one runner with the given labels and returns its auth token.
async fn register_runner(s: &TestServer, pat: &str, labels: &[&str]) -> String {
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/runners/registration-token"),
        pat,
        Some(json!({ "labels": labels, "ephemeral": false })),
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
            "labels": labels,
            "version": "test",
            "ephemeral": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value["auth_token"].as_str().unwrap().to_owned()
}

/// Queues one CI job directly in the database (the trigger path is M6c).
async fn queue_job(
    s: &TestServer,
    repo_id: i64,
    user_id: i64,
    name: &str,
    runs_on: &[&str],
) -> i64 {
    let spec = json!({
        "name": name,
        "image": "example.test/image:1",
        "commands": ["true"],
        "runs_on": runs_on,
    })
    .to_string();
    let now = starforged_db::now();
    starforged_db::ci::insert_ci_job(
        s.db(),
        &starforged_db::ci::NewCiJob {
            repo_id,
            trail_id: None,
            change_id: None,
            revision_id: None,
            commit_sha: SHA,
            base_sha: None,
            job_name: name,
            spec: &spec,
            run_at: 0,
            deadline: now + 3600,
            created_by: Some(user_id),
            now,
        },
    )
    .await
    .unwrap()
    .id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_trace_finish_round_trip() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let runner = register_runner(&s, &pat, &["linux"]).await;
    let job_id = queue_job(&s, repo.id, alice.id, "test", &[]).await;

    // Claim: 201 with fence + one-time job token, never cached.
    let (status, headers, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/jobs/request"),
        &runner,
        &[],
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_no_store(&headers);
    assert_eq!(value["job_id"], job_id);
    assert_eq!(value["job_name"], "test");
    assert!(value["job_token"].as_str().unwrap().starts_with("sfj_"));
    let fence = value["fence"].as_str().unwrap().to_owned();
    let job_token = value["job_token"].as_str().unwrap().to_owned();

    // The job token authenticates for this job.
    assert!(s.core.authenticate_job(&job_token).await.is_ok());

    // Trace: first chunk 202; exact retry 202; a gap is 416.
    let trace_url = s.url(&format!("/api/v1/runners/jobs/{job_id}/trace"));
    async fn trace(
        s: &TestServer,
        runner: &str,
        trace_url: &str,
        fence: &str,
        start: i64,
        end: i64,
    ) -> (StatusCode, reqwest::header::HeaderMap, Value) {
        let body: Vec<u8> = (start..end).map(|b| b'0' + (b % 10) as u8).collect();
        api_raw(
            &s.browser(),
            "PATCH",
            trace_url,
            runner,
            &[
                ("x-starforge-fence", fence),
                ("content-range", &format!("bytes {start}-{}/", end - 1)),
            ],
            None,
            Some(&body),
        )
        .await
    }
    assert_eq!(
        trace(&s, &runner, &trace_url, &fence, 0, 5).await.0,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        trace(&s, &runner, &trace_url, &fence, 0, 5).await.0,
        StatusCode::ACCEPTED,
        "idempotent retry"
    );
    assert_eq!(
        trace(&s, &runner, &trace_url, &fence, 9, 14).await.0,
        StatusCode::RANGE_NOT_SATISFIABLE
    );
    assert_eq!(
        trace(&s, &runner, &trace_url, &fence, 5, 8).await.0,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        starforged_db::ci::log_end_offset(s.db(), job_id)
            .await
            .unwrap(),
        8
    );

    // Stale fence: 409.
    let (status, _, _) = api_raw(
        &s.browser(),
        "PATCH",
        &trace_url,
        &runner,
        &[
            ("x-starforge-fence", "stale-fence"),
            ("content-range", "bytes 8-9/*"),
        ],
        None,
        Some(b"hi"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Finish: 200, writes ci/test success, revokes the job token.
    let (status, _, value) = api_raw(
        &s.browser(),
        "PUT",
        &s.url(&format!("/api/v1/runners/jobs/{job_id}")),
        &runner,
        &[("x-starforge-fence", fence.as_str())],
        Some(json!({ "state": "succeeded", "exit_code": 0, "session_ulids": [] })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(s.core.authenticate_job(&job_token).await.is_err());

    // A gate requiring ci/test now sees the check.
    let (_, value) = api(
        &s.browser(),
        "GET",
        &s.url(&format!("/api/v1/repos/alice/proj/statuses/{SHA}")),
        &pat,
        None,
    )
    .await;
    let text = value.to_string();
    assert!(text.contains("ci/test"), "{value}");
    assert!(text.contains("success"), "{value}");

    // Nothing left to claim (core-level: no 50 s long-poll wait).
    let principal = s.core.authenticate_runner(&runner).await.unwrap();
    assert!(s.core.claim_ci_job(&principal).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn label_routing_releases_nonmatching_jobs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let runner = register_runner(&s, &pat, &["linux"]).await;
    let gpu_job = queue_job(&s, repo.id, alice.id, "gpu-job", &["gpu"]).await;

    // A gpu-only job is not claimable by a linux runner; it stays queued.
    let principal = s.core.authenticate_runner(&runner).await.unwrap();
    assert!(s.core.claim_ci_job(&principal).await.unwrap().is_none());
    let row = starforged_db::ci::ci_job_by_id(s.db(), gpu_job)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "queued", "released back for another runner");

    // A linux job behind it claims fine, and the gpu job remains queued.
    let linux_job = queue_job(&s, repo.id, alice.id, "linux-job", &["linux"]).await;
    let claimed = s.core.claim_ci_job(&principal).await.unwrap().unwrap();
    assert_eq!(claimed.job_id, linux_job);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_runner_fence_is_rejected() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let runner_a = register_runner(&s, &pat, &["linux"]).await;
    let runner_b = register_runner(&s, &pat, &["linux"]).await;
    let job_id = queue_job(&s, repo.id, alice.id, "test", &[]).await;

    let (status, _, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/jobs/request"),
        &runner_a,
        &[],
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let fence = value["fence"].as_str().unwrap().to_owned();

    // Runner B presents runner A's fence: 409.
    let (status, _, _) = api_raw(
        &s.browser(),
        "PATCH",
        &s.url(&format!("/api/v1/runners/jobs/{job_id}/trace")),
        &runner_b,
        &[
            ("x-starforge-fence", fence.as_str()),
            ("content-range", "bytes 0-4/*"),
        ],
        None,
        Some(b"hello"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // And runner B cannot claim the already-claimed job (core-level).
    let principal_b = s.core.authenticate_runner(&runner_b).await.unwrap();
    assert!(s.core.claim_ci_job(&principal_b).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_wins_over_trace_and_finish() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let runner = register_runner(&s, &pat, &["linux"]).await;
    let job_id = queue_job(&s, repo.id, alice.id, "test", &[]).await;

    let (status, _, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/jobs/request"),
        &runner,
        &[],
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let fence = value["fence"].as_str().unwrap().to_owned();

    // The user requests cancel.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url(&format!("/api/v1/repos/alice/proj/ci/runs/{job_id}/cancel")),
        &pat,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");

    // The next trace reports Job-Status: canceled instead of appending.
    let (status, headers, _) = api_raw(
        &s.browser(),
        "PATCH",
        &s.url(&format!("/api/v1/runners/jobs/{job_id}/trace")),
        &runner,
        &[
            ("x-starforge-fence", fence.as_str()),
            ("content-range", "bytes 0-4/*"),
        ],
        None,
        Some(b"hello"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("job-status").unwrap(), "canceled");

    // A late finish is canceled too, and the job ends canceled.
    let (status, headers, _) = api_raw(
        &s.browser(),
        "PUT",
        &s.url(&format!("/api/v1/runners/jobs/{job_id}")),
        &runner,
        &[("x-starforge-fence", fence.as_str())],
        Some(json!({ "state": "succeeded", "exit_code": 0 })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("job-status").unwrap(), "canceled");
    let row = starforged_db::ci::ci_job_by_id(s.db(), job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "canceled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_credential_and_revoked_runner_credentials() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;
    let runner = register_runner(&s, &pat, &["linux"]).await;
    let job_id = queue_job(&s, repo.id, alice.id, "test", &[]).await;

    let (status, _, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/jobs/request"),
        &runner,
        &[],
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let fence = value["fence"].as_str().unwrap().to_owned();
    let job_token = value["job_token"].as_str().unwrap().to_owned();

    // Git credential: 201, shown once, authenticates as the user's PAT.
    let (status, headers, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url(&format!("/api/v1/ci/jobs/{job_id}/git-credential")),
        &runner,
        &[("x-starforge-fence", fence.as_str())],
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_no_store(&headers);
    let git_token = value["token"].as_str().unwrap().to_owned();
    assert!(git_token.starts_with("sfp_"));
    assert!(s.core.authenticate_token(&git_token).await.is_ok());

    // Stale fence: 409.
    let (status, _, _) = api_raw(
        &s.browser(),
        "POST",
        &s.url(&format!("/api/v1/ci/jobs/{job_id}/git-credential")),
        &runner,
        &[("x-starforge-fence", "stale-fence")],
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Revoking the runner requeues its job and kills both credentials.
    let (_, value) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/runners"),
        &pat,
        None,
    )
    .await;
    let runner_id = value["runners"][0]["id"].as_i64().unwrap();
    let (status, _) = api(
        &s.browser(),
        "DELETE",
        &s.url(&format!("/api/v1/runners/{runner_id}")),
        &pat,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(s.core.authenticate_runner(&runner).await.is_err());
    assert!(s.core.authenticate_job(&job_token).await.is_err());
    assert!(s.core.authenticate_token(&git_token).await.is_err());
    let row = starforged_db::ci::ci_job_by_id(s.db(), job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "queued", "job requeued for another runner");
}
