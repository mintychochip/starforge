//! CLI `sessions publish`/`unpublish` end to end against the real server.
//!
//! The CLI library handlers ([`session_admin::publish`]/[`session_admin::unpublish`])
//! run against the in-process [`TestServer`] (not the stub server the CLI
//! crate tests use), and every assertion observes server state: the stored
//! `visibility` column (via `starforged-db`) and the session API's anonymous
//! readability (§6.4: a published session on a public repo is readable by
//! anyone, an unpublished one is not). A token without the `session:upload`
//! scope gets the CLI auth error; an unknown ULID gets the not-found error.

mod common;

use common::TestServer;
use serde_json::{Value, json};
use starforge_cli::api::ApiClient;
use starforge_cli::commands::session_admin;
use starforge_cli::upload::UploadClient;
use starforge_format::SessionMeta;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UNKNOWN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAX";

fn meta() -> SessionMeta {
    let body = json!({
        "format": "starforge.session/v1",
        "id": ULID,
        "agent": {"name": "pi", "version": "0.5.2"},
        "models": ["pi-model-x"],
        "title": "publish me",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/a.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "0.1.0", "adapter_version_verified": false},
    });
    SessionMeta::parse(&serde_json::to_string(&body).unwrap()).unwrap()
}

fn event_lines() -> Vec<String> {
    vec![
        r#"{"v":1,"seq":0,"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"hello"}"#
            .to_string(),
        r#"{"v":1,"seq":1,"ts":"2026-11-04T00:01:00Z","kind":"tool_call","tool":{"name":"Edit","input":{"file_path":"src/a.rs"}}}"#
            .to_string(),
        r#"{"v":1,"seq":2,"ts":"2026-11-04T00:02:00Z","kind":"assistant_message","text":"done","model":null,"usage":{"input":0,"output":0,"cache_read":0,"cache_write":0,"reasoning":0}}"#
            .to_string(),
    ]
}

/// Upload one session (meta, one segment, complete, one claim link) through
/// the CLI upload client, exactly as `sync` would.
async fn upload_session(upload: &UploadClient, owner_repo: &str) {
    upload.put_meta(owner_repo, &meta()).await.unwrap();
    let mut jsonl = event_lines().join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    upload
        .put_segment(owner_repo, ULID, 0, &bytes)
        .await
        .unwrap();
    upload.post_complete(owner_repo, ULID).await.unwrap();
    upload
        .post_links(
            owner_repo,
            ULID,
            &[json!({"sha": SHA, "confidence": "exact", "seq_start": 0, "seq_end": 1})],
        )
        .await
        .unwrap();
}

async fn repo_id(s: &TestServer, owner: &starforged_core::accounts::User, name: &str) -> i64 {
    s.core
        .repo_for(Some(owner), &owner.handle, name)
        .await
        .unwrap()
        .repo
        .id
}

async fn get_session(s: &TestServer, token: Option<&str>, repo: &str) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut req = client.get(s.url(&format!("/api/v1/repos/{repo}/sessions/{ULID}")));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let response = req.send().await.unwrap();
    let status = response.status().as_u16();
    let body = response.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn get_events_status(s: &TestServer, token: Option<&str>, repo: &str) -> u16 {
    let client = reqwest::Client::new();
    let mut req = client.get(s.url(&format!("/api/v1/repos/{repo}/sessions/{ULID}/events")));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    req.send().await.unwrap().status().as_u16()
}

async fn db_visibility(s: &TestServer, repo: i64) -> String {
    db_sessions::session_by_ulid(s.core.db(), repo, ULID)
        .await
        .unwrap()
        .expect("session row")
        .visibility
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_unpublish_toggles_public_visibility() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "src", Visibility::Public).await;
    let token = s
        .token(&alice, &[Scope::SessionUpload, Scope::RepoRead])
        .await;
    let src_id = repo_id(&s, &alice, "src").await;

    let upload = UploadClient::new(s.base.clone(), token.clone());
    upload_session(&upload, "alice/src").await;

    // Baseline: `inherit`, invisible to anonymous readers, visible to owner.
    assert_eq!(db_visibility(&s, src_id).await, "inherit");
    let (status, body) = get_session(&s, Some(&token), "alice/src").await;
    assert_eq!(status, 200);
    assert_eq!(body["visibility"], "inherit");
    assert_eq!(get_session(&s, None, "alice/src").await.0, 404);
    assert_eq!(get_events_status(&s, None, "alice/src").await, 404);

    // Publish through the CLI handler: stored state and anonymous
    // readability both flip (§6.4 public + published = readable by anyone).
    let api = ApiClient::new(&s.base, "alice/src", &token).unwrap();
    let (out, code) = session_admin::publish(&api, ULID).await;
    assert_eq!(code, 0, "publish out: {out}");
    assert_eq!(out, format!("published {ULID}"));
    assert_eq!(db_visibility(&s, src_id).await, "published");
    let (status, body) = get_session(&s, Some(&token), "alice/src").await;
    assert_eq!(status, 200);
    assert_eq!(body["visibility"], "published");
    assert_eq!(
        get_session(&s, None, "alice/src").await.0,
        200,
        "published session must be readable anonymously"
    );
    assert_eq!(
        get_events_status(&s, None, "alice/src").await,
        200,
        "published session events must be readable anonymously"
    );

    // Unpublish: back to `inherit` and invisible again.
    let (out, code) = session_admin::unpublish(&api, ULID).await;
    assert_eq!(code, 0, "unpublish out: {out}");
    assert_eq!(out, format!("unpublished {ULID}"));
    assert_eq!(db_visibility(&s, src_id).await, "inherit");
    let (status, body) = get_session(&s, Some(&token), "alice/src").await;
    assert_eq!(status, 200);
    assert_eq!(body["visibility"], "inherit");
    assert_eq!(
        get_session(&s, None, "alice/src").await.0,
        404,
        "unpublished session must be invisible to anonymous readers again"
    );
    assert_eq!(get_events_status(&s, None, "alice/src").await, 404);

    // Unpublishing a never-published session is an `Ok` no-op.
    let (out, code) = session_admin::unpublish(&api, ULID).await;
    assert_eq!(code, 0, "second unpublish out: {out}");
    assert_eq!(out, format!("unpublished {ULID}"));
    assert_eq!(db_visibility(&s, src_id).await, "inherit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_without_upload_scope_is_an_auth_error() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "src", Visibility::Public).await;
    let token = s
        .token(&alice, &[Scope::SessionUpload, Scope::RepoRead])
        .await;
    let src_id = repo_id(&s, &alice, "src").await;
    let upload = UploadClient::new(s.base.clone(), token.clone());
    upload_session(&upload, "alice/src").await;

    // Read-only token: the server answers 403 and the CLI renders its auth
    // error (exit 1) instead of panicking; the session stays unpublished.
    let readonly = s.token(&alice, &[Scope::RepoRead]).await;
    let api = ApiClient::new(&s.base, "alice/src", &readonly).unwrap();
    let (out, code) = session_admin::publish(&api, ULID).await;
    assert_eq!(code, 1, "out: {out}");
    assert!(
        out.contains("authentication failed")
            && out.contains("this token lacks the session:upload scope")
            && out.contains("starforge auth login"),
        "auth error expected, got: {out}"
    );
    assert_eq!(db_visibility(&s, src_id).await, "inherit");
    assert_eq!(get_session(&s, None, "alice/src").await.0, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_unknown_ulid_is_not_found() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "src", Visibility::Public).await;
    let token = s
        .token(&alice, &[Scope::SessionUpload, Scope::RepoRead])
        .await;
    let upload = UploadClient::new(s.base.clone(), token.clone());
    upload_session(&upload, "alice/src").await;

    let api = ApiClient::new(&s.base, "alice/src", &token).unwrap();
    let (out, code) = session_admin::publish(&api, UNKNOWN).await;
    assert_eq!(code, 1, "out: {out}");
    assert_eq!(out, "error: not found (not_found)");

    let (out, code) = session_admin::unpublish(&api, UNKNOWN).await;
    assert_eq!(code, 1, "out: {out}");
    assert_eq!(out, "error: not found (not_found)");
}
