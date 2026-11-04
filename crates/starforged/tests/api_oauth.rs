mod common;

use common::*;
use serde_json::Value;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

const ULID_OAUTH: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA0";

fn meta_body(ulid: &str) -> Value {
    serde_json::json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "oauth session",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {},
        "parent_id": null,
        "usage": {},
        "files_touched": [],
        "redaction": {},
        "capture": {"mode": "discovery"},
    })
}

async fn device_code(client: &reqwest::Client, s: &TestServer) -> Value {
    let response = client
        .post(s.url("/api/v1/oauth/device/code"))
        .form(&[("client_id", "starforge-cli"), ("scope", "session:upload")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.json::<Value>().await.unwrap()
}

async fn poll(
    client: &reqwest::Client,
    s: &TestServer,
    device_code: &str,
) -> (reqwest::StatusCode, Value) {
    let response = client
        .post(s.url("/api/v1/oauth/token"))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", "starforge-cli"),
        ])
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json::<Value>().await.unwrap())
}

async fn approve(
    browser: &reqwest::Client,
    s: &TestServer,
    user_code: &str,
    decision: &str,
) -> reqwest::Response {
    let page = get_text(browser, &s.url("/oauth/device")).await;
    let csrf = extract_input(&page, "_csrf");
    browser
        .post(s.url("/oauth/device/approve"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("user_code", user_code),
            ("decision", decision),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_flow_happy_path() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let client = reqwest::Client::new();

    // Code request returns every field the CLI parses.
    let code = device_code(&client, &s).await;
    for field in [
        "device_code",
        "user_code",
        "verification_uri",
        "verification_uri_complete",
        "expires_in",
        "interval",
    ] {
        assert!(code.get(field).is_some(), "missing {field} in {code}");
    }
    assert_eq!(code["expires_in"], 900);
    assert_eq!(code["interval"], 5);
    let device_code = code["device_code"].as_str().unwrap().to_owned();
    let user_code = code["user_code"].as_str().unwrap().to_owned();
    assert!(
        code["verification_uri"]
            .as_str()
            .unwrap()
            .contains(&format!("/oauth/device?user_code={user_code}")),
        "unexpected verification_uri: {code}"
    );

    // Polling before approval pends.
    let (status, body) = poll(&client, &s, &device_code).await;
    assert_eq!(status, 400);
    assert_eq!(body, serde_json::json!({"error": "authorization_pending"}));

    // The browser approval page shows the code, and approving works.
    let (browser, _) = s.login("alice").await;
    let page = get_text(&browser, code["verification_uri"].as_str().unwrap()).await;
    assert!(
        page.contains(&user_code),
        "approval page lacks the user code"
    );
    let approved = approve(&browser, &s, &user_code, "approve").await;
    assert_eq!(approved.status(), 200);
    assert!(
        approved
            .text()
            .await
            .unwrap()
            .to_lowercase()
            .contains("approv"),
        "approval page shows no success banner"
    );

    // Polling after approval grants a token pair …
    let (status, body) = poll(&client, &s, &device_code).await;
    assert_eq!(status, 200, "token poll failed: {body}");
    let access = body["access_token"].as_str().unwrap().to_owned();
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(body["token_type"], "Bearer");

    // … which carries the session:upload scope end to end.
    let put = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_OAUTH}")))
        .bearer_auth(&access)
        .json(&meta_body(ULID_OAUTH))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "upload with device token failed");

    // Replaying a consumed code expires instead of granting again.
    let (status, body) = poll(&client, &s, &device_code).await;
    assert_eq!(status, 400);
    assert_eq!(body, serde_json::json!({"error": "expired_token"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_flow_deny_path() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = reqwest::Client::new();

    let code = device_code(&client, &s).await;
    let device_code = code["device_code"].as_str().unwrap();
    let user_code = code["user_code"].as_str().unwrap();

    let (browser, _) = s.login("alice").await;
    let denied = approve(&browser, &s, user_code, "deny").await;
    assert_eq!(denied.status(), 200);

    let (status, body) = poll(&client, &s, device_code).await;
    assert_eq!(status, 400);
    assert_eq!(body, serde_json::json!({"error": "access_denied"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_flow_expired_code() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = reqwest::Client::new();

    let code = device_code(&client, &s).await;
    let device_code = code["device_code"].as_str().unwrap();

    sqlx::query("UPDATE device_codes SET expires_at = $1")
        .bind(1_i64)
        .execute(s.core.db().pool())
        .await
        .unwrap();

    let (status, body) = poll(&client, &s, device_code).await;
    assert_eq!(status, 400);
    assert_eq!(body, serde_json::json!({"error": "expired_token"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_flow_slow_down_grows_interval() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = reqwest::Client::new();

    let code = device_code(&client, &s).await;
    let device_code = code["device_code"].as_str().unwrap();

    let (first_status, first_body) = poll(&client, &s, device_code).await;
    assert_eq!(first_status, 400);
    assert_eq!(
        first_body,
        serde_json::json!({"error": "authorization_pending"})
    );

    // An immediate second poll is inside the 5 s interval.
    let (status, body) = poll(&client, &s, device_code).await;
    assert_eq!(status, 400);
    assert_eq!(body, serde_json::json!({"error": "slow_down"}));

    let interval: i64 = sqlx::query_scalar("SELECT interval_secs FROM device_codes")
        .fetch_one(s.core.db().pool())
        .await
        .unwrap();
    assert_eq!(interval, 10, "slow_down must persist interval + 5");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_flow_rejects_bad_requests() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = reqwest::Client::new();

    // Unknown client.
    let bad_client = client
        .post(s.url("/api/v1/oauth/device/code"))
        .form(&[("client_id", "nope"), ("scope", "session:upload")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_client.status(), 400);

    // Unknown scope.
    let bad_scope = client
        .post(s.url("/api/v1/oauth/device/code"))
        .form(&[("client_id", "starforge-cli"), ("scope", "bogus")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_scope.status(), 400);

    // Unknown device code.
    let (status, body) = poll(&client, &s, &"0".repeat(64)).await;
    assert_eq!(status, 400);
    assert_eq!(body, serde_json::json!({"error": "invalid_grant"}));

    // Any other grant type is unsupported.
    let unknown = "0".repeat(64);
    let unsupported = client
        .post(s.url("/api/v1/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("device_code", unknown.as_str()),
            ("client_id", "starforge-cli"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), 400);
    assert_eq!(
        unsupported.json::<Value>().await.unwrap(),
        serde_json::json!({"error": "unsupported_grant_type"})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_only_token_cannot_upload() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let read_only = s.token(&alice, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();

    let denied = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_OAUTH}")))
        .bearer_auth(&read_only)
        .json(&meta_body(ULID_OAUTH))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_streaming_cap_is_413() {
    // Build a valid segment first so the at-cap PUT exercises the cap gate only.
    let jsonl = "{\"v\":1,\"seq\":0,\"ts\":\"2026-11-04T00:00:00Z\",\"kind\":\"user_message\",\"text\":\"hi\"}\n";
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    let cap = bytes.len() as u64;
    let s = TestServer::start_with(|config| {
        config.sessions.max_segment_bytes = cap;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();

    let created = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_OAUTH}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_OAUTH))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());

    // Exactly at the cap succeeds.
    let exact = client
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID_OAUTH}/segments/0"
        )))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(exact.status(), 200);

    // Far over the cap is rejected mid-stream with 413 (the cap gate runs
    // before header and content validation).
    let big = client
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID_OAUTH}/segments/1"
        )))
        .bearer_auth(&upload)
        .body(vec![9u8; 64 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(big.status(), 413);
}
