//! Readiness, metrics, and JSON logs (plan M5b O4).

mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

const TOKEN: &str = "metrics-secret-token";

fn parse_counter(text: &str, prefix: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with(prefix))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
}

/// Every exposition line is either a `# TYPE` comment or
/// `name{labels} value` / `name value` with a numeric value.
fn assert_exposition_parses(text: &str) {
    assert!(!text.is_empty(), "empty exposition");
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let (head, value) = line
            .rsplit_once(' ')
            .unwrap_or_else(|| panic!("malformed exposition line: {line:?}"));
        value
            .parse::<f64>()
            .unwrap_or_else(|_| panic!("non-numeric value in line: {line:?}"));
        assert!(
            head.starts_with("starforged_"),
            "unexpected metric name in line: {line:?}"
        );
        if let Some(start) = head.find('{') {
            assert!(head.ends_with('}'), "unbalanced labels in line: {line:?}");
            assert!(start > 0, "labels without a name in line: {line:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_is_200_on_a_healthy_server() {
    let s = TestServer::start().await;
    let client = reqwest::Client::new();
    let response = client.get(s.url("/readyz")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(body.contains("\"ok\""), "healthy body: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_is_200_with_ssh_enabled_after_start() {
    // TestServer enables SSH by default; its serve_on sets SSH_LISTENING.
    let s = TestServer::start().await;
    assert!(!s.ssh_base.is_empty(), "SSH is enabled in TestServer");
    let client = reqwest::Client::new();
    let response = client.get(s.url("/readyz")).send().await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_is_503_naming_jobs_when_workers_stop() {
    let s = TestServer::start().await;
    let client = reqwest::Client::new();
    assert_eq!(
        client.get(s.url("/readyz")).send().await.unwrap().status(),
        200
    );
    s.core.set_worker_heartbeat_for_test(0);
    let response = client.get(s.url("/readyz")).send().await.unwrap();
    assert_eq!(response.status(), 503);
    let body = response.text().await.unwrap();
    assert!(body.contains("jobs"), "503 names the failing check: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_is_404_without_a_configured_token() {
    let s = TestServer::start().await;
    let client = reqwest::Client::new();
    let response = client.get(s.url("/metrics")).send().await.unwrap();
    assert_eq!(response.status(), 404);
    // Even a bearer token cannot enable an unconfigured endpoint.
    let response = client
        .get(s.url("/metrics"))
        .bearer_auth("anything")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_is_401_with_a_wrong_token() {
    let s = TestServer::start_with(|config| {
        config.metrics.token = Some(TOKEN.to_owned());
    })
    .await;
    let client = reqwest::Client::new();
    let response = client.get(s.url("/metrics")).send().await.unwrap();
    assert_eq!(response.status(), 401);
    let response = client
        .get(s.url("/metrics"))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_counters_move_after_web_git_and_jobs() {
    let s = TestServer::start_with(|config| {
        config.metrics.token = Some(TOKEN.to_owned());
    })
    .await;
    let client = reqwest::Client::new();
    let metrics_url = format!("{}/metrics", s.base);
    let before = client
        .get(&metrics_url)
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_exposition_parses(&before);

    // A web request moves the request counter and histogram.
    let _ = client.get(s.url("/login")).send().await.unwrap();
    // A git clone moves the git RPC counter.
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let tmp = tempfile::tempdir().unwrap();
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "clone1",
        ],
    )
    .await;
    // A job run moves the jobs counter.
    s.core
        .enqueue(&starforged_core::jobs::Job::HourlyCleanup)
        .await
        .unwrap();
    s.core.run_due_jobs().await.unwrap();

    let after = client
        .get(&metrics_url)
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_exposition_parses(&after);
    let http_before = parse_counter(
        &before,
        "starforged_http_requests_total{class=\"web\",status=\"2xx\"}",
    )
    .unwrap_or(0);
    let http_after = parse_counter(
        &after,
        "starforged_http_requests_total{class=\"web\",status=\"2xx\"}",
    )
    .expect("web counter present");
    assert!(
        http_after > http_before,
        "web counter moved: {http_before} -> {http_after}"
    );
    let git = parse_counter(
        &after,
        "starforged_git_rpc_total{service=\"upload-pack\",transport=\"http\"}",
    )
    .expect("git counter present");
    assert!(git >= 1, "git counter moved: {git}");
    let jobs = parse_counter(
        &after,
        "starforged_jobs_processed_total{kind=\"hourly_cleanup\",outcome=\"ok\"}",
    )
    .expect("job counter present");
    assert!(jobs >= 1, "job counter moved: {jobs}");
    assert!(
        after
            .contains("starforged_http_request_duration_seconds_bucket{class=\"web\",le=\"+Inf\"}")
    );
    assert!(after.contains("# TYPE starforged_http_requests_total counter"));
    assert!(after.contains("# TYPE starforged_http_request_duration_seconds histogram"));
    assert!(after.contains("# TYPE starforged_jobs_pending gauge"));
    assert!(after.contains("starforged_index_documents{kind=\"trails\"}"));
    assert!(after.contains("starforged_ssh_connections"));

    // No label carries a repository or user name, and the token never leaks.
    for line in after.lines() {
        if line.starts_with('#') {
            continue;
        }
        assert!(!line.contains("alice"), "label leaks the user name: {line}");
        assert!(
            !line.contains("proj"),
            "label leaks the repository name: {line}"
        );
    }
    assert!(!after.contains(TOKEN), "metrics leaked the token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_stays_ok() {
    let s = TestServer::start().await;
    let client = reqwest::Client::new();
    let response = client.get(s.url("/healthz")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert_eq!(body, "ok");
}

#[test]
fn json_logs_emit_valid_json_startup_line() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let tmp = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_starforged");
    let config = tmp.path().join("starforged.toml");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let init = Command::new(bin)
        .arg("--config")
        .arg(&config)
        .args(["init", "--data-dir"])
        .arg(tmp.path().join("data"))
        .args([
            "--base-url",
            &format!("http://127.0.0.1:{port}"),
            "--http-addr",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let mut child = Command::new(bin)
        .arg("--config")
        .arg(&config)
        .arg("serve")
        .env("STARFORGE__LOG__FORMAT", "json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines() {
            if tx.send(line.unwrap_or_default()).is_err() {
                break;
            }
        }
    });
    let mut startup: Option<String> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) if line.contains("starforged listening") => {
                startup = Some(line);
                break;
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let line = startup.expect("server startup log line");
    let value: serde_json::Value = serde_json::from_str(&line)
        .unwrap_or_else(|err| panic!("startup log line is not valid JSON ({err}): {line}"));
    assert!(
        value
            .get("fields")
            .and_then(|f| f.get("message"))
            .and_then(|m| m.as_str())
            .is_some_and(|m| m.contains("listening")),
        "JSON log line carries the message: {line}"
    );
}
