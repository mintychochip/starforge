//! CI web pages and the sandbox runtime matrix (M6b B5/B6, M6c C4): the
//! admin sandboxes list/kill, `GET /sandboxes/runtimes`, sandbox GC, the
//! run list/detail/logs/cancel pages, their auth/404 matrix, and escaping
//! of runner-supplied log text.
mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const CI_TOML: &str = r#"version = 1

[triggers]
push = ["main"]
trail = ["opened", "updated"]

[[job]]
name = "test"
image = "example.test/image:1"
commands = ["true"]
timeout = "30m"
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

async fn wait_for_job(s: &TestServer, repo_id: i64) -> i64 {
    let start = Instant::now();
    loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo_id, 100)
            .await
            .unwrap();
        if let Some(job) = jobs.iter().find(|job| job.job_name == "test") {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtimes_matrix_and_auth() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let sandbox = s.token(&alice, &[Scope::SandboxRun]).await;
    let wrong_scope = s.token(&alice, &[Scope::RepoWrite]).await;

    // No token → 401; token without `sandbox:run` → 403.
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/sandboxes/runtimes"),
        "",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/sandboxes/runtimes"),
        &wrong_scope,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, value) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/sandboxes/runtimes"),
        &sandbox,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let runtimes = value["runtimes"].as_array().unwrap();
    let by_name: HashMap<&str, &Value> = runtimes
        .iter()
        .map(|r| (r["name"].as_str().unwrap(), r))
        .collect();
    for name in ["podman", "gvisor", "e2b"] {
        let row = by_name[name];
        assert_eq!(row["available"], true, "{row}");
        assert_eq!(row["reserved"], false, "{row}");
    }
    for name in ["firecracker", "kata"] {
        let row = by_name[name];
        assert_eq!(row["available"], false, "{row}");
        assert_eq!(row["reserved"], true, "{row}");
    }
    // Creating with a reserved runtime is refused with 422.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &sandbox,
        Some(json!({
            "owner": "alice", "repo": "proj",
            "runtime": "firecracker", "template": "starforge/rust",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{value}");
}

/// A stateful fake E2B server (create/get/kill only — enough for the
/// admin list/kill round trip).
async fn spawn_fake_e2b() -> String {
    let state: Arc<Mutex<String>> = Arc::new(Mutex::new("running".to_owned()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let state = state.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
                let info = |st: &str| {
                    serde_json::json!({
                        "id": "sbx-1", "state": st, "runtime": "e2b",
                        "expires_at": null, "provider": "e2b",
                    })
                    .to_string()
                };
                let (status, resp_body): (u16, String) = if method == "POST" && path == "/sandboxes"
                {
                    (200, info("running"))
                } else if method == "GET" && path == "/sandboxes/sbx-1" {
                    (200, info(&state.lock().unwrap().clone()))
                } else if method == "DELETE" && path == "/sandboxes/sbx-1" {
                    *state.lock().unwrap() = "killed".to_owned();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_sandboxes_page_list_kill_and_auth() {
    let fake_url = spawn_fake_e2b().await;
    let s = TestServer::start_with(move |config| {
        config.sandbox = starforged_core::sandboxes::SandboxConfig {
            provider: starforged_core::sandboxes::SandboxProviderKind::E2b,
            e2b: starforged_core::sandboxes::E2bSandboxConfig {
                api_url: fake_url.clone(),
                api_key: "test-key".to_owned(),
            },
            ..Default::default()
        };
    })
    .await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    let _repo = s.repo(&alice, "proj", Visibility::Private).await;
    let sandbox = s.token(&alice, &[Scope::SandboxRun]).await;

    // Create one sandbox through the API.
    let (status, value) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &sandbox,
        Some(json!({
            "owner": "alice", "repo": "proj", "runtime": "e2b",
            "template": "starforge/rust", "timeout_s": 300,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["id"], "sbx-1");

    // An admin sees the list; kill it through the page form.
    s.core
        .create_user(starforged_core::accounts::CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let (admin, csrf) = s.login("root").await;
    let page = get_text(&admin, &s.url("/admin/sandboxes")).await;
    assert!(page.contains("sbx-1"), "{page}");
    assert!(page.contains("alice/proj"), "{page}");
    assert!(page.contains("/admin/sandboxes/sbx-1/kill"), "{page}");
    let resp = admin
        .post(s.url("/admin/sandboxes/sbx-1/kill"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers()["location"], "/admin/sandboxes");
    // Killed sandboxes read back as killed (and offer no Kill button).
    let row = starforged_db::sandboxes::sandbox_by_external_id(s.db(), "sbx-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "killed");
    let page = get_text(&admin, &s.url("/admin/sandboxes")).await;
    assert!(page.contains("killed"), "{page}");
    assert!(!page.contains("/admin/sandboxes/sbx-1/kill"), "{page}");

    // Unknown handle → 404.
    let resp = admin
        .post(s.url("/admin/sandboxes/nope/kill"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Anonymous and non-admin users get 404 (never a leak-shaped 403).
    let anon = s.browser();
    assert_eq!(
        anon.get(s.url("/admin/sandboxes"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let (alice, _) = s.login("alice").await;
    assert_eq!(
        alice
            .get(s.url("/admin/sandboxes"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gc_expired_sandboxes_marks_killed() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let now_ts = starforged_db::now();
    for (external_id, expires_at) in [("sbx-old", now_ts - 10), ("sbx-live", now_ts + 3600)] {
        starforged_db::sandboxes::insert_sandbox(
            s.db(),
            &starforged_db::sandboxes::NewSandbox {
                provider: "local",
                runtime: "podman",
                external_id,
                job_id: None,
                owner_id: alice.id,
                repo_id: repo.id,
                state: "running",
                template: "starforge/rust",
                cpu: 1.0,
                mem_mb: 512,
                disk_gb: 1,
                idempotency_key: None,
                ca_fingerprint: None,
                metadata: "{}",
                created_at: now_ts - 100,
                expires_at,
            },
        )
        .await
        .unwrap();
    }
    let killed = s.core.gc_expired_sandboxes().await.unwrap();
    assert_eq!(killed, vec!["sbx-old"]);
    let old = starforged_db::sandboxes::sandbox_by_external_id(s.db(), "sbx-old")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.state, "killed");
    let live = starforged_db::sandboxes::sandbox_by_external_id(s.db(), "sbx-live")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.state, "running");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ci_pages_matrix_cancel_and_escaping() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;

    // A public repo for the anonymous-200 case.
    let _pub = s.repo(&alice, "pub", Visibility::Public).await;

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
    let job_id = wait_for_job(&s, repo.id).await;
    let job = starforged_db::ci::ci_job_by_id(s.db(), job_id)
        .await
        .unwrap()
        .unwrap();

    // Auth matrix: anonymous on the private repo → 404; anonymous on the
    // public repo → 200 (empty list); unknown job → 404.
    let anon = s.browser();
    assert_eq!(
        anon.get(s.url("/alice/proj/ci"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let pub_list = anon.get(s.url("/alice/pub/ci")).send().await.unwrap();
    assert_eq!(pub_list.status(), 200);
    assert!(
        get_text(&anon, &s.url("/alice/pub/ci"))
            .await
            .contains("No CI runs yet.")
    );
    assert_eq!(
        anon.get(s.url("/alice/proj/ci/9999"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // A run of another repository reads as 404 (alice/proj id under bob's).
    let _bob_repo = s.repo(&bob, "proj", Visibility::Public).await;
    let (bob_browser, bob_csrf) = s.login("bob").await;
    assert_eq!(
        bob_browser
            .get(s.url(&format!("/bob/proj/ci/{job_id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Drive the job: attacker log text with HTML that must not render raw.
    let runner = register_runner(&s, &pat).await;
    let (claimed, fence, _) = claim(&s, &runner).await;
    assert_eq!(claimed, job_id);
    let log = b"building...\n<script>alert(1)</script>\ndone\n";
    assert_eq!(
        trace(&s, &runner, job_id, &fence, 0, log).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        finish(&s, &runner, job_id, &fence, "succeeded").await,
        StatusCode::OK
    );

    // Read-only collaborator: detail 200, but no cancel form; owner: form.
    let detail_url = s.url(&format!("/alice/proj/ci/{job_id}"));
    let bob_detail = get_text(&bob_browser, &detail_url).await;
    assert!(bob_detail.contains("test"), "{bob_detail}");
    assert!(bob_detail.contains("succeeded"), "{bob_detail}");
    assert!(bob_detail.contains(&job.commit_sha), "{bob_detail}");
    assert!(
        bob_detail.contains(&format!("/alice/proj/ci/{job_id}/logs")),
        "{bob_detail}"
    );
    assert!(
        bob_detail.contains("/alice/proj/settings/protection"),
        "{bob_detail}"
    );
    assert!(!bob_detail.contains("Cancel run"), "{bob_detail}");

    // Logs route: plain text with no-store headers.
    let logs_resp = bob_browser
        .get(s.url(&format!("/alice/proj/ci/{job_id}/logs")))
        .send()
        .await
        .unwrap();
    assert_eq!(logs_resp.status(), 200);
    assert_eq!(logs_resp.headers()["cache-control"], "no-store, private");
    let logs_text = logs_resp.text().await.unwrap();
    assert!(
        logs_text.contains("<script>alert(1)</script>"),
        "{logs_text}"
    );

    let (alice_browser, alice_csrf) = s.login("alice").await;
    let alice_detail = get_text(&alice_browser, &detail_url).await;
    // Escaping: the detail page shows the log escaped, never raw.
    assert!(
        alice_detail.contains("&#60;script&#62;") || alice_detail.contains("&lt;script&gt;"),
        "log must be escaped:\n{alice_detail}"
    );
    assert!(
        !alice_detail.contains("<script>alert"),
        "log must not render as HTML:\n{alice_detail}"
    );

    // A second job for the cancel flow.
    commit_files(&work, &[("second.txt", b"second\n")], "second").await;
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
    let job2 = loop {
        let jobs = starforged_db::ci::list_ci_jobs_for_repo(s.db(), repo.id, 100)
            .await
            .unwrap();
        if let Some(j) = jobs.iter().find(|j| j.id > job_id) {
            break j.id;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // Reader cancel → 403 (Write required); owner cancel → 303 redirect.
    let resp = bob_browser
        .post(s.url(&format!("/alice/proj/ci/{job2}/cancel")))
        .form(&[("_csrf", bob_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = alice_browser
        .post(s.url(&format!("/alice/proj/ci/{job2}/cancel")))
        .form(&[("_csrf", alice_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers()["location"], format!("/alice/proj/ci/{job2}"));
    // A cancel POST for an unknown job → 404.
    let resp = alice_browser
        .post(s.url("/alice/proj/ci/9999/cancel"))
        .form(&[("_csrf", alice_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ci_usage_page_is_for_maintainers() {
    let s = TestServer::start_with(|c| c.ci.limits.minutes_per_month = 600).await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();

    let (alice_browser, _) = s.login("alice").await;
    assert!(
        get_text(&alice_browser, &s.url("/alice/proj/ci"))
            .await
            .contains("/alice/proj/ci/usage")
    );
    let resp = alice_browser
        .get(s.url("/alice/proj/ci/usage"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let page = resp.text().await.unwrap();
    assert!(page.contains("runner_minutes"), "{page}");
    assert!(page.contains("limits enforced by starforge"), "{page}");
    assert!(
        page.contains("600 minutes"),
        "the native limit shows: {page}"
    );

    // A reader sees no link and cannot open the page.
    let (bob_browser, _) = s.login("bob").await;
    assert!(
        !get_text(&bob_browser, &s.url("/alice/proj/ci"))
            .await
            .contains("/alice/proj/ci/usage")
    );
    let status = bob_browser
        .get(s.url("/alice/proj/ci/usage"))
        .send()
        .await
        .unwrap()
        .status();
    assert!(status == 403 || status == 404, "{status}");
    // Anonymous visitors are sent to sign in.
    let status = s
        .browser()
        .get(s.url("/alice/proj/ci/usage"))
        .send()
        .await
        .unwrap()
        .status();
    assert_ne!(status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ci_secrets_settings_page_crud_and_auth() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let _bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();

    let (alice_browser, alice_csrf) = s.login("alice").await;
    let base = "/alice/proj/settings/ci-secrets";
    let page_url = s.url(base);

    let page = get_text(&alice_browser, &page_url).await;
    assert!(page.contains("CI secrets"), "{page}");
    assert!(
        page.contains(base),
        "settings nav links to the page: {page}"
    );
    assert!(
        page.contains("input type=\"password\""),
        "value input is a password field: {page}"
    );

    // Bad CSRF is refused and creates nothing.
    let resp = alice_browser
        .post(&page_url)
        .form(&[
            ("_csrf", "wrong"),
            ("name", "MY_TOKEN"),
            ("value", "v1-secret-value"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(
        !get_text(&alice_browser, &page_url)
            .await
            .contains("MY_TOKEN"),
    );

    // Create: 303 back to the list; the value never appears in any response.
    let resp = alice_browser
        .post(&page_url)
        .form(&[
            ("_csrf", alice_csrf.as_str()),
            ("name", "MY_TOKEN"),
            ("value", "v1-secret-value"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers()["location"], base);
    assert!(!resp.text().await.unwrap().contains("v1-secret-value"),);
    let page = get_text(&alice_browser, &page_url).await;
    assert!(page.contains("MY_TOKEN"), "{page}");
    assert!(
        !page.contains("v1-secret-value"),
        "value is never rendered: {page}"
    );

    // Rotate: same name, new value; still 303, neither value leaks.
    let resp = alice_browser
        .post(&page_url)
        .form(&[
            ("_csrf", alice_csrf.as_str()),
            ("name", "MY_TOKEN"),
            ("value", "v2-rotated-value"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers()["location"], base);
    let page = get_text(&alice_browser, &page_url).await;
    assert!(page.contains("MY_TOKEN"), "{page}");
    assert!(!page.contains("v1-secret-value"), "{page}");
    assert!(!page.contains("v2-rotated-value"), "{page}");

    // Write-only collaborator: same refusal as the other Admin settings pages (403).
    let (bob_browser, bob_csrf) = s.login("bob").await;
    let status = bob_browser.get(&page_url).send().await.unwrap().status();
    assert_eq!(status, 403, "Write-only GET: {status}");
    let resp = bob_browser
        .post(&page_url)
        .form(&[
            ("_csrf", bob_csrf.as_str()),
            ("name", "BOB_SECRET"),
            ("value", "bob-value"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "Write-only POST: {}", resp.status());
    let resp = bob_browser
        .post(s.url(&format!("{base}/MY_TOKEN/delete")))
        .form(&[("_csrf", bob_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "Write-only delete: {}", resp.status());
    // The secret survives the refused delete.
    assert!(
        get_text(&alice_browser, &page_url)
            .await
            .contains("MY_TOKEN")
    );

    // Delete: 303, then the name is gone from the list.
    let resp = alice_browser
        .post(s.url(&format!("{base}/MY_TOKEN/delete")))
        .form(&[("_csrf", alice_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers()["location"], base);
    let page = get_text(&alice_browser, &page_url).await;
    assert!(!page.contains("MY_TOKEN"), "{page}");
}
