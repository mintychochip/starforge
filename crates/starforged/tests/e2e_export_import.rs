//! V1: CLI session administration and export/import end to end.
//!
//! The full loop with real CLI code against the in-process [`TestServer`]:
//! upload a session through the CLI upload client, export it, delete it
//! with `sessions delete` (blob refcounts decremented), import the bundle
//! into another repository (session visible, links recreated, events and
//! segment bytes byte-faithful), then publish/unpublish toggles anonymous
//! visibility. A user who cannot read a session cannot export it.
mod common;

use common::TestServer;
use serde_json::{Value, json};
use starforge_cli::api::ApiClient;
use starforge_cli::commands::bundle::{BundleCtx, export, import};
use starforge_cli::commands::session_admin;
use starforge_cli::upload::UploadClient;
use starforge_format::SessionMeta;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn meta() -> SessionMeta {
    let body = json!({
        "format": "starforge.session/v1",
        "id": ULID,
        "agent": {"name": "pi", "version": "0.5.2"},
        "models": ["pi-model-x"],
        "title": "export me",
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
        // The normalized shape capture always emits: an assistant event
        // carries `model` and `usage` explicitly (defaulted when unknown),
        // so the server render adds nothing to it.
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

async fn get_events(s: &TestServer, token: &str, repo: &str) -> Value {
    let client = reqwest::Client::new();
    client
        .get(s.url(&format!("/api/v1/repos/{repo}/sessions/{ULID}/events")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn get_session_status(s: &TestServer, token: Option<&str>, repo: &str) -> u16 {
    let client = reqwest::Client::new();
    let mut req = client.get(s.url(&format!("/api/v1/repos/{repo}/sessions/{ULID}")));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    req.send().await.unwrap().status().as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_delete_import_round_trip() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "src", Visibility::Public).await;
    s.repo(&alice, "dst", Visibility::Public).await;
    let token = s
        .token(&alice, &[Scope::SessionUpload, Scope::RepoRead])
        .await;
    let src_id = repo_id(&s, &alice, "src").await;

    // Upload via the CLI flow.
    let upload = UploadClient::new(s.base.clone(), token.clone());
    upload_session(&upload, "alice/src").await;
    assert_eq!(get_session_status(&s, Some(&token), "alice/src").await, 200);
    let events_before = get_events(&s, &token, "alice/src").await;
    let session = db_sessions::session_by_ulid(s.core.db(), src_id, ULID)
        .await
        .unwrap()
        .expect("session row");
    let segments = db_sessions::segments_of(s.core.db(), session.id)
        .await
        .unwrap();
    let blob_hash = segments[0].blob_hash.clone();
    assert_eq!(
        db_sessions::blob_by_hash(s.core.db(), &blob_hash)
            .await
            .unwrap()
            .unwrap()
            .refcount,
        1
    );
    let segment_bytes = s
        .core
        .config()
        .blob_store
        .get_by_hash(&blob_hash)
        .await
        .unwrap();

    // Export the session.
    let api_src = ApiClient::new(&s.base, "alice/src", &token).unwrap();
    let ctx_src = BundleCtx::new(api_src, &s.base, "alice/src", &token);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    let (out, code) = export(&ctx_src, &[ULID.to_string()], &dir).await;
    assert_eq!(code, 0, "export out: {out}");
    let session_dir = dir.join("alice__src").join(ULID);
    let exported_meta: Value =
        serde_json::from_str(&std::fs::read_to_string(session_dir.join("session.json")).unwrap())
            .unwrap();
    assert_eq!(exported_meta["ulid"], ULID);
    let exported_events = std::fs::read_to_string(session_dir.join("events.jsonl")).unwrap();
    assert_eq!(exported_events.lines().count(), 3);
    assert_eq!(
        std::fs::read(session_dir.join("segments").join("0.raw.zst")).unwrap(),
        segment_bytes,
        "exported segment must be byte-faithful"
    );
    let exported_links: Value =
        serde_json::from_str(&std::fs::read_to_string(session_dir.join("links.json")).unwrap())
            .unwrap();
    assert_eq!(
        exported_links,
        json!([{"sha": SHA, "confidence": "exact", "seq_start": 0, "seq_end": 1}])
    );

    // Delete it: gone, blob refcount decremented.
    let (out, code) = session_admin::delete(&ctx_src.api, ULID, true).await;
    assert_eq!(code, 0, "delete out: {out}");
    assert_eq!(
        get_session_status(&s, Some(&token), "alice/src").await,
        404,
        "deleted session must be gone"
    );
    let blob = db_sessions::blob_by_hash(s.core.db(), &blob_hash)
        .await
        .unwrap();
    assert_eq!(
        blob.map(|row| row.refcount),
        Some(0),
        "delete must decrement the blob refcount"
    );

    // Import into another repository: visible, links recreated, round trip
    // byte-faithful.
    let api_dst = ApiClient::new(&s.base, "alice/dst", &token).unwrap();
    let ctx_dst = BundleCtx::new(api_dst, &s.base, "alice/dst", &token);
    let (out, code) = import(&ctx_dst, &dir).await;
    assert_eq!(code, 0, "import out: {out}");
    assert_eq!(
        out,
        format!("{ULID}: imported\nimported 1 session(s), 0 already present")
    );
    assert_eq!(get_session_status(&s, Some(&token), "alice/dst").await, 200);
    let events_after = get_events(&s, &token, "alice/dst").await;
    assert_eq!(
        events_before, events_after,
        "events must round-trip exactly"
    );
    let dst_id = repo_id(&s, &alice, "dst").await;
    let imported = db_sessions::session_by_ulid(s.core.db(), dst_id, ULID)
        .await
        .unwrap()
        .expect("imported session row");
    let imported_segments = db_sessions::segments_of(s.core.db(), imported.id)
        .await
        .unwrap();
    assert_eq!(imported_segments.len(), 1);
    let imported_bytes = s
        .core
        .config()
        .blob_store
        .get_by_hash(&imported_segments[0].blob_hash)
        .await
        .unwrap();
    // D2: import re-segments the normalized events, so every event line must
    // survive unchanged. Field ORDER inside a line legitimately differs (the
    // API round-trip serializes through a sorted-key JSON value), so compare
    // the parsed events, not the raw lines.
    let parsed = |bytes: &[u8]| -> Vec<Value> {
        let text = String::from_utf8(starforge_format::decompress(bytes).unwrap()).unwrap();
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    };
    assert_eq!(
        parsed(&imported_bytes),
        parsed(&segment_bytes),
        "re-segmented import must reproduce the original events"
    );
    // D2: import re-segments the exported lines verbatim, so the bundle
    // content must equal the dst segment content event-for-event.
    let bundle_events: Vec<Value> = exported_events
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        parsed(&imported_bytes),
        bundle_events,
        "import must re-segment the exported lines verbatim"
    );
    let links = s.core.session_links(imported.id).await.unwrap();
    assert_eq!(links.len(), 1, "links must be recreated");
    assert_eq!(links[0].sha, SHA);
    assert_eq!(links[0].confidence, "exact");

    // Re-importing reports exists and skips.
    let (out, code) = import(&ctx_dst, &dir).await;
    assert_eq!(code, 0, "re-import out: {out}");
    assert_eq!(
        out,
        format!("{ULID}: exists, skipped\nimported 0 session(s), 1 already present")
    );

    // Publish/unpublish toggle anonymous visibility on the public repo.
    assert_eq!(
        get_session_status(&s, None, "alice/dst").await,
        404,
        "unpublished session must be invisible to anonymous readers"
    );
    let (out, code) = session_admin::publish(&ctx_dst.api, ULID).await;
    assert_eq!(code, 0, "publish out: {out}");
    assert_eq!(
        get_session_status(&s, None, "alice/dst").await,
        200,
        "published session must be visible to anonymous readers"
    );
    let (out, code) = session_admin::unpublish(&ctx_dst.api, ULID).await;
    assert_eq!(code, 0, "unpublish out: {out}");
    assert_eq!(
        get_session_status(&s, None, "alice/dst").await,
        404,
        "unpublished session must be invisible again"
    );

    // Export-all lists the imported session through the readable listing.
    let dir2 = tmp.path().join("bundle2");
    let (out, code) = export(&ctx_dst, &[], &dir2).await;
    assert_eq!(code, 0, "export-all out: {out}");
    assert!(out.contains(&format!("exported {ULID}")), "out: {out}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_unreadable_session_is_a_clear_cli_error() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "priv", Visibility::Private).await;
    let alice_token = s
        .token(&alice, &[Scope::SessionUpload, Scope::RepoRead])
        .await;
    upload_session(
        &UploadClient::new(s.base.clone(), alice_token),
        "alice/priv",
    )
    .await;

    // Bob has no access to the private repo: the session is undiscoverable
    // and the export fails with the clear 404 error.
    let bob_token = s.token(&bob, &[Scope::RepoRead]).await;
    let api_bob = ApiClient::new(&s.base, "alice/priv", &bob_token).unwrap();
    let ctx_bob = BundleCtx::new(api_bob, &s.base, "alice/priv", &bob_token);
    let tmp = tempfile::tempdir().unwrap();
    let (out, code) = export(&ctx_bob, &[ULID.to_string()], &tmp.path().join("bundle")).await;
    assert_eq!(code, 1);
    assert_eq!(
        out,
        format!("error: cannot export session {ULID}: session not found or not readable")
    );
}
