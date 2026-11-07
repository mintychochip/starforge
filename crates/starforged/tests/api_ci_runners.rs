//! CI runner registration and CRUD API tests (M6a A2): minting a
//! registration token, registering a runner, listing, revoking, and the
//! one-time/expiry/hash guarantees behind them.
mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

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

async fn mint(s: &TestServer, token: &str, owner: &str, repo: &str) -> (StatusCode, Value) {
    api(
        &s.browser(),
        "POST",
        &s.url(&format!(
            "/api/v1/repos/{owner}/{repo}/runners/registration-token"
        )),
        token,
        Some(json!({ "labels": ["linux"], "ephemeral": false })),
    )
    .await
}

async fn register(s: &TestServer, registration_token: &str) -> (StatusCode, Value) {
    api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/register"),
        "",
        Some(json!({
            "registration_token": registration_token,
            "name": "r1",
            "labels": ["linux"],
            "version": "1.0",
            "ephemeral": false,
        })),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_register_list_revoke_round_trip() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;

    // Mint: `sfrt_…`, returned once.
    let (status, body) = mint(&s, &token, "alice", "proj").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registration_token = body["token"].as_str().unwrap().to_owned();
    assert!(registration_token.starts_with("sfrt_"), "{body}");
    assert!(body.get("expires_at").is_some(), "{body}");
    // The token is stored hashed, never in plaintext.
    let stored_hash: String =
        sqlx::query_scalar("SELECT token_hash FROM runner_registration_tokens WHERE repo_id = $1")
            .bind(repo.id)
            .fetch_one(s.db().pool())
            .await
            .unwrap();
    assert_eq!(
        stored_hash,
        starforged_core::crypto::sha256_hex(&registration_token)
    );
    assert_ne!(stored_hash, registration_token);

    // Register: `sfr_…` auth token, shown once.
    let (status, body) = register(&s, &registration_token).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let runner_id = body["runner_id"].as_i64().unwrap();
    let auth_token = body["auth_token"].as_str().unwrap().to_owned();
    assert!(auth_token.starts_with("sfr_"), "{body}");
    // The runner's auth token is also stored hashed only.
    let stored_runner_hash: String =
        sqlx::query_scalar("SELECT token_hash FROM runners WHERE id = $1")
            .bind(runner_id)
            .fetch_one(s.db().pool())
            .await
            .unwrap();
    assert_eq!(
        stored_runner_hash,
        starforged_core::crypto::sha256_hex(&auth_token)
    );

    // The registration token is one-time: replay fails.
    let (status, body) = register(&s, &registration_token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // List hides hashes and the auth token.
    let (status, body) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/runners"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let runners = body["runners"].as_array().unwrap();
    assert_eq!(runners.len(), 1);
    assert_eq!(runners[0]["id"], runner_id);
    assert_eq!(runners[0]["name"], "r1");
    assert_eq!(runners[0]["labels"], json!(["linux"]));
    let text = body.to_string();
    assert!(!text.contains("hash"), "{body}");
    assert!(!text.contains(&auth_token), "{body}");
    assert!(!text.contains(&registration_token), "{body}");

    // The auth token resolves as a runner principal (RunnerAuth's core).
    let principal = s.core.authenticate_runner(&auth_token).await.unwrap();
    assert_eq!(principal.runner_id, runner_id);
    // …but a runner token is not a PAT: PAT routes refuse it.
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/runners"),
        &auth_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Revoke: the runner disappears and its token stops working.
    let (status, _) = api(
        &s.browser(),
        "DELETE",
        &s.url(&format!("/api/v1/runners/{runner_id}")),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/runners"),
        &token,
        None,
    )
    .await;
    assert!(body["runners"].as_array().unwrap().is_empty());
    assert!(s.core.authenticate_runner(&auth_token).await.is_err());
    // A second revoke is 404.
    let (status, _) = api(
        &s.browser(),
        "DELETE",
        &s.url(&format!("/api/v1/runners/{runner_id}")),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Register and revoke are audited.
    for action in ["ci.runner.register", "ci.runner.revoke"] {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1")
            .bind(action)
            .fetch_one(s.db().pool())
            .await
            .unwrap();
        assert_eq!(count, 1, "{action}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_and_unknown_registration_tokens_are_refused() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;

    // An expired token (inserted directly with a past expiry) cannot register.
    let secret = "sfrt_expiredtest";
    let now = starforged_db::now();
    starforged_db::ci::insert_registration_token(
        s.db(),
        &starforged_db::ci::NewRegistrationToken {
            repo_id: repo.id,
            token_hash: &starforged_core::crypto::sha256_hex(secret),
            labels: r#"["linux"]"#,
            created_by: Some(alice.id),
            expires_at: now - 1,
            now,
        },
    )
    .await
    .unwrap();
    let (status, _) = register(&s, secret).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Unknown tokens are indistinguishable from expired ones.
    let (status, _) = register(&s, "sfrt_doesnotexist").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A runner auth token is not a registration token.
    let (status, _) = register(&s, "sfr_whatever").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_permission_and_scope_are_refused() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;

    // Bob cannot even see the private repo: 404 on mint and list.
    let bob_token = s.token(&bob, &[Scope::RepoWrite]).await;
    let (status, _) = mint(&s, &bob_token, "alice", "proj").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/runners"),
        &bob_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A collaborator with `write` sees the repo but cannot mint (needs `admin`).
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let (status, _) = mint(&s, &bob_token, "alice", "proj").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // …nor list (needs `maintain`).
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/runners"),
        &bob_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A read-scoped token fails the `repo:write` scope check even for the owner.
    let read_token = s.token(&alice, &[Scope::RepoRead]).await;
    let (status, _) = mint(&s, &read_token, "alice", "proj").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A `maintain` collaborator can list but cannot mint or revoke.
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Maintain)
        .await
        .unwrap();
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/runners"),
        &bob_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = mint(&s, &bob_token, "alice", "proj").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Register a runner as the owner; Bob cannot revoke it.
    let owner_token = s.token(&alice, &[Scope::RepoWrite]).await;
    let (_, body) = mint(&s, &owner_token, "alice", "proj").await;
    let registration_token = body["token"].as_str().unwrap().to_owned();
    let (_, body) = register(&s, &registration_token).await;
    let runner_id = body["runner_id"].as_i64().unwrap();
    let (status, _) = api(
        &s.browser(),
        "DELETE",
        &s.url(&format!("/api/v1/runners/{runner_id}")),
        &bob_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Revoking a nonexistent runner is 404 for the owner.
    let (status, _) = api(
        &s.browser(),
        "DELETE",
        &s.url("/api/v1/runners/999999"),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runner_cannot_widen_token_labels() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let (_, body) = mint(&s, &token, "alice", "proj").await;
    let registration_token = body["token"].as_str().unwrap().to_owned();
    // Asking for a label the token does not carry is refused.
    let (status, _) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/register"),
        "",
        Some(json!({
            "registration_token": registration_token,
            "name": "r1",
            "labels": ["linux", "gpu"],
            "version": "1.0",
            "ephemeral": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
