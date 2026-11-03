mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use common::*;

/// Kills the server when the test ends, even on failure.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn starforged(config: &Path, args: &[&str], stdin: Option<&str>) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "starforged {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_serves_a_repository_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    let data = tmp.path().join("data");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let base = format!("http://127.0.0.1:{port}");
    let addr = format!("127.0.0.1:{port}");
    starforged(
        &config,
        &[
            "init",
            "--data-dir",
            data.to_str().unwrap(),
            "--base-url",
            &base,
            "--http-addr",
            &addr,
        ],
        None,
    );
    starforged(
        &config,
        &[
            "admin",
            "user",
            "create",
            "--handle",
            "alice",
            "--password-stdin",
        ],
        Some("correct horse battery\n"),
    );
    let token = starforged(
        &config,
        &[
            "admin", "token", "create", "--user", "alice", "--name", "e2e",
        ],
        None,
    )
    .trim()
    .to_owned();

    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_starforged"))
            .arg("--config")
            .arg(&config)
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::new();
    let mut healthy = false;
    for _ in 0..100 {
        if client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            healthy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(healthy, "starforged serve did not become healthy");

    let created = client
        .post(format!("{base}/api/v1/user/repos"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"name": "demo", "visibility": "public"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    let work = work_repo(tmp.path(), "work", &[("README.md", "# Demo\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &format!("http://git:{token}@{addr}/alice/demo.git"),
            "main",
        ],
    )
    .await;
    let home = client
        .get(format!("{base}/alice/demo"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(home.contains("<h1>Demo</h1>"), "{home}");
    git_ok(
        tmp.path(),
        &["clone", "-q", &format!("{base}/alice/demo.git"), "copy"],
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("copy/README.md")).unwrap(),
        "# Demo\n"
    );
}
