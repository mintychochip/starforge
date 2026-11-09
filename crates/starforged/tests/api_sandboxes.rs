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
    let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
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
                // Extract the body (after the blank line) when present. The
                // bytes stay raw for the binary file route; JSON handlers
                // use the lossy text.
                let body_start = buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|end| end + 4)
                    .unwrap_or(buf.len());
                let body_bytes = buf[body_start..].to_vec();
                let body = text
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.to_owned())
                    .unwrap_or_default();
                let (status, resp_body): (u16, Vec<u8>) =
                    if method == "POST" && path == "/v2/sandboxes" {
                        (
                            201,
                            br#"{"sandboxID":"sbx-1","envdAccessToken":"envd-tok","domain":"fake"}"#
                                .to_vec(),
                        )
                    } else if method == "POST" && path == "/sandboxes/sbx-1/connect" {
                        (
                            200,
                            br#"{"sandboxID":"sbx-1","envdAccessToken":"envd-tok","domain":"fake"}"#
                                .to_vec(),
                        )
                    } else if method == "GET" && path == "/sandboxes/sbx-1" {
                        (
                            200,
                            json!({
                                "state": state.lock().unwrap().clone(),
                                "envdAccessToken": "envd-tok",
                                "domain": "fake",
                            })
                            .to_string()
                            .into_bytes(),
                        )
                    } else if method == "DELETE" && path == "/sandboxes/sbx-1" {
                        *state.lock().unwrap() = "killed".to_owned();
                        (204, Vec::new())
                    } else if method == "POST" && path == "/sandboxes/sbx-1/pause" {
                        *state.lock().unwrap() = "paused".to_owned();
                        (200, b"{}".to_vec())
                    } else if method == "POST" && path == "/sandboxes/sbx-1/resume" {
                        *state.lock().unwrap() = "running".to_owned();
                        (200, br#"{"envdAccessToken":"envd-tok"}"#.to_vec())
                    } else if method == "POST" && path == "/sandboxes/sbx-1/timeout" {
                        (200, b"{}".to_vec())
                    } else if method == "POST" && path == "/process.Process/Start" {
                        // Connect frames: one stdout event, one end event, a
                        // terminal frame. "hello from exec" is base64 below.
                        let stdout =
                            json!({"event":{"data":{"stdout":"aGVsbG8gZnJvbSBleGVj"}}}).to_string();
                        let end = json!({"event":{"end":{"exitCode":0,"exited":true}}}).to_string();
                        let mut out = Vec::new();
                        for payload in [stdout, end] {
                            out.push(0);
                            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                            out.extend_from_slice(payload.as_bytes());
                        }
                        out.push(2);
                        out.extend_from_slice(&2u32.to_be_bytes());
                        out.extend_from_slice(b"{}");
                        (200, out)
                    } else if method == "GET" && path == "/files" {
                        let query = target.split('?').nth(1).unwrap_or_default();
                        let path_q: String = query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix("path=").map(percent_decode))
                            .unwrap_or_default();
                        let content = files
                            .lock()
                            .unwrap()
                            .get(&path_q)
                            .cloned()
                            .unwrap_or_else(|| b"hello".to_vec());
                        (200, content)
                    } else if method == "PUT" && path == "/files" {
                        let query = target.split('?').nth(1).unwrap_or_default();
                        let path_q: String = query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix("path=").map(percent_decode))
                            .unwrap_or_default();
                        files.lock().unwrap().insert(path_q, body_bytes.clone());
                        (200, b"{}".to_vec())
                    } else if method == "POST" && path == "/filesystem.Filesystem/ListDir" {
                        (200, br#"{"entries":[{"name":"a.txt"}]}"#.to_vec())
                    } else if method == "POST" && path == "/filesystem.Filesystem/Remove" {
                        let parsed: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                        let p = parsed["path"].as_str().unwrap_or_default().to_owned();
                        files.lock().unwrap().remove(&p);
                        (200, b"{}".to_vec())
                    } else {
                        (404, br#"{"code":404,"message":"no route"}"#.to_vec())
                    };
                let reason = match status {
                    200 => "OK",
                    201 => "Created",
                    204 => "No Content",
                    404 => "Not Found",
                    _ => "Error",
                };
                let mut resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len(),
                )
                .into_bytes();
                resp.extend_from_slice(&resp_body);
                let _ = stream.write_all(&resp).await;
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

    // Raw binary write/read (cache archives, binary artifacts).
    let raw = vec![0u8, 159, 146, 150, 255, 0];
    let resp = s
        .browser()
        .put(s.url(&format!("/api/v1/sandboxes/{id}/files/raw?path=blob.bin")))
        .bearer_auth(&token)
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = s
        .browser()
        .get(s.url(&format!("/api/v1/sandboxes/{id}/files/raw?path=blob.bin")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().to_vec(), raw);
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
