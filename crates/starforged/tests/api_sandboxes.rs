//! Sandbox API tests (M6b B4): auth matrix, quota 429, lifecycle,
//! traversal, and idempotency, all over a fake E2B provider server.
mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::sandboxes::{SandboxConfig, SandboxLimits, SandboxProviderKind};
use starforged_core::tokens::Scope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn call(
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

/// A stateful fake E2B server: routes the adapter's paths, stores file
/// content, and tracks one sandbox's state (running/paused).
async fn spawn_fake_e2b() -> String {
    let files: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let state: Arc<Mutex<String>> = Arc::new(Mutex::new("running".to_owned()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let files = files.clone();
    let state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let files = files.clone();
            let state = state.clone();
            tokio::spawn(async move {
                // Read headers + content-length body.
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
                // Extract JSON body (after the blank line) when present.
                let body = text
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
                    (200, info("running"))
                } else if method == "GET" && path == "/sandboxes/sbx-1" {
                    (200, info(&state.lock().unwrap().clone()))
                } else if method == "DELETE" && path == "/sandboxes/sbx-1" {
                    *state.lock().unwrap() = "killed".to_owned();
                    (204, String::new())
                } else if method == "POST" && path == "/sandboxes/sbx-1/pause" {
                    *state.lock().unwrap() = "paused".to_owned();
                    (200, info("paused"))
                } else if method == "POST" && path == "/sandboxes/sbx-1/resume" {
                    *state.lock().unwrap() = "running".to_owned();
                    (200, info("running"))
                } else if method == "POST" && path == "/sandboxes/sbx-1/timeout" {
                    (200, info(&state.lock().unwrap().clone()))
                } else if method == "POST" && path == "/sandboxes/sbx-1/exec" {
                    (
                        200,
                        serde_json::to_string(&json!([
                            {"stream": "stdout", "data": "hello from exec"},
                            {"stream": "exit", "code": 0},
                        ]))
                        .unwrap(),
                    )
                } else if method == "GET" && path == "/sandboxes/sbx-1/files" {
                    let query = target.split('?').nth(1).unwrap_or_default();
                    let path_q: String = query
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("path=").map(percent_decode))
                        .unwrap_or_default();
                    if query.contains("op=list") {
                        (
                            200,
                            json!({"path": path_q, "entries": ["a.txt"]}).to_string(),
                        )
                    } else {
                        let content = files
                            .lock()
                            .unwrap()
                            .get(&path_q)
                            .cloned()
                            .unwrap_or_else(|| "hello".into());
                        (200, json!({"path": path_q, "content": content}).to_string())
                    }
                } else if method == "PUT" && path == "/sandboxes/sbx-1/files" {
                    let parsed: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                    let p = parsed["path"].as_str().unwrap_or_default().to_owned();
                    let c = parsed["content"].as_str().unwrap_or_default().to_owned();
                    files.lock().unwrap().insert(p.clone(), c);
                    (200, json!({"path": p}).to_string())
                } else if method == "DELETE" && path == "/sandboxes/sbx-1/files" {
                    let query = target.split('?').nth(1).unwrap_or_default();
                    let path_q: String = query
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("path=").map(percent_decode))
                        .unwrap_or_default();
                    files.lock().unwrap().remove(&path_q);
                    (204, String::new())
                } else if method == "GET" && path == "/sandboxes/sbx-1/ports/8080/url" {
                    (
                        200,
                        json!({"url": "https://sbx-1.fake:8080", "port": 8080, "expires_at": null})
                            .to_string(),
                    )
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
                    404 => "Not Found",
                    _ => "Error",
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

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn sandbox_server(limits: SandboxLimits) -> TestServer {
    let fake_url = spawn_fake_e2b().await;
    TestServer::start_with(move |config| {
        config.sandbox = SandboxConfig {
            provider: SandboxProviderKind::E2b,
            e2b: starforged_core::sandboxes::E2bSandboxConfig {
                api_url: fake_url.clone(),
                api_key: "test-key".to_owned(),
            },
            limits,
            ..Default::default()
        };
    })
    .await
}

fn create_body(idempotency_key: Option<&str>) -> Value {
    let mut body = json!({
        "owner": "alice",
        "repo": "proj",
        "runtime": "e2b",
        "template": "starforge/rust",
        "timeout_s": 300,
    });
    if let Some(key) = idempotency_key {
        body["idempotency_key"] = json!(key);
    }
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_exec_kill_round_trip_and_auth_matrix() {
    let s = sandbox_server(SandboxLimits::default()).await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::SandboxRun]).await;
    let wrong_scope = s.token(&alice, &[Scope::RepoRead]).await;
    let bob_token = s.token(&bob, &[Scope::SandboxRun]).await;

    // No token → 401; wrong scope → 403.
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        "",
        Some(create_body(None)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &wrong_scope,
        Some(create_body(None)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Create → 201.
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &token,
        Some(create_body(None)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["id"], "sbx-1");
    assert_eq!(body["state"], "running");
    assert_eq!(body["runtime"], "e2b");

    // Blob: another user without access gets 403 on get.
    let (status, body) = call(
        &s.browser(),
        "GET",
        &s.url("/api/v1/sandboxes/sbx-1"),
        &bob_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Exec → chunks with a terminal exit event.
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes/sbx-1/exec"),
        &token,
        Some(json!({"command": ["echo", "hello from exec"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let chunks = body.as_array().unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0]["stream"], "stdout");
    assert_eq!(chunks[1]["stream"], "exit");
    assert_eq!(chunks[1]["code"], 0);

    // Empty command → 422.
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes/sbx-1/exec"),
        &token,
        Some(json!({"command": []})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Pause/resume/timeout.
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes/sbx-1/pause"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "paused");
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes/sbx-1/resume"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "running");
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes/sbx-1/timeout"),
        &token,
        Some(json!({"timeout_s": 600})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Port URL.
    let (status, body) = call(
        &s.browser(),
        "GET",
        &s.url("/api/v1/sandboxes/sbx-1/ports/8080/url"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["url"].as_str().unwrap().contains("sbx-1"));

    // Kill → state killed.
    let (status, body) = call(
        &s.browser(),
        "DELETE",
        &s.url("/api/v1/sandboxes/sbx-1"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "killed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_quota_returns_429() {
    let s = sandbox_server(SandboxLimits {
        max_concurrent_per_user: 1,
        ..Default::default()
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::SandboxRun]).await;

    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &token,
        Some(create_body(None)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &token,
        Some(create_body(None)),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotency_and_file_traversal() {
    let s = sandbox_server(SandboxLimits::default()).await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::SandboxRun]).await;

    // Same idempotency key → same sandbox id.
    let (status, first) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &token,
        Some(create_body(Some("key-1"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, second) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &token,
        Some(create_body(Some("key-1"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    assert_eq!(first["id"], second["id"]);

    // Traversal → 422 before the provider is touched.
    let id = first["id"].as_str().unwrap();
    for bad in ["../escape", "/etc/passwd", "a/../b"] {
        let (status, body) = call(
            &s.browser(),
            "PUT",
            &s.url(&format!("/api/v1/sandboxes/{id}/files")),
            &token,
            Some(json!({"path": bad, "content": "x"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
    }
    let (status, body) = call(
        &s.browser(),
        "GET",
        &s.url(&format!("/api/v1/sandboxes/{id}/files?path=..%2Fescape")),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // File write/read/list/delete round trip.
    let (status, body) = call(
        &s.browser(),
        "PUT",
        &s.url(&format!("/api/v1/sandboxes/{id}/files")),
        &token,
        Some(json!({"path": "a.txt", "content": "hello"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(
        &s.browser(),
        "GET",
        &s.url(&format!("/api/v1/sandboxes/{id}/files?path=a.txt")),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["content"], "hello");
    let (status, body) = call(
        &s.browser(),
        "GET",
        &s.url(&format!("/api/v1/sandboxes/{id}/files?path=.&op=list")),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entries"][0], "a.txt");
    let (status, body) = call(
        &s.browser(),
        "DELETE",
        &s.url(&format!("/api/v1/sandboxes/{id}/files?path=a.txt")),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Secret-header binding for a non-allow-listed host → 422.
    let mut body = create_body(None);
    body["network"] =
        json!({"allow_out": [], "secret_headers": {"registry.example": "Authorization"}});
    let (status, body) = call(
        &s.browser(),
        "POST",
        &s.url("/api/v1/sandboxes"),
        &token,
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}
