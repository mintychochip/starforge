mod common;

use common::*;
use serde_json::{Value, json};
use starforge_format::SessionMeta;
use starforged_core::permission::Permission;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const ULID_C: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
const ULID_D: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
const ULID_Q: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";
const ULID_E: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA0";
const ULID_F: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA1";
const ULID_G: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA2";
const ULID_H: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA3";
const ULID_J: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA4";
const ULID_K: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA5";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "test session",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

fn meta_url(s: &TestServer, ulid: &str) -> String {
    s.url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}"))
}

/// One minimal valid `user_message` event line with sequence number `seq`.
fn user_event(seq: u64) -> String {
    format!(
        r#"{{"v":1,"seq":{seq},"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"hello {seq}"}}"#
    )
}

/// Compresses JSONL `lines` (newline-joined plus trailing newline) and returns
/// the bytes with their BLAKE3 hex, ready for a segment PUT.
fn segment_payload(lines: &[String]) -> (Vec<u8>, String) {
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    (bytes, hash)
}

async fn blob_refcount(db: &starforged_db::Db, hash: &str) -> i64 {
    db_sessions::blob_by_hash(db, hash)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("missing blob row for {hash}"))
        .refcount
}

struct Ctx {
    s: TestServer,
    upload: String,
    read_only: String,
    bob_upload: String,
    carol_upload: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let admin = s.token(&alice, &[Scope::RepoWrite]).await;
        let _ = admin;
        s.repo(
            &alice,
            "proj",
            starforged_core::permission::Visibility::Private,
        )
        .await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        let upload = s.token(&alice, &[Scope::SessionUpload]).await;
        let read_only = s.token(&alice, &[Scope::RepoRead]).await;
        let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
        let carol_upload = s.token(&carol, &[Scope::SessionUpload]).await;
        Ctx {
            s,
            upload,
            read_only,
            bob_upload,
            carol_upload,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_status_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // No token → 401 + WWW-Authenticate.
    let anon = client
        .put(meta_url(&c.s, ULID_A))
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 401);
    assert_eq!(anon.headers()["www-authenticate"], "Bearer");
    assert_eq!(
        anon.json::<Value>().await.unwrap()["error"]["code"],
        "unauthenticated"
    );

    // Bogus token → 401.
    let bogus = client
        .put(meta_url(&c.s, ULID_A))
        .bearer_auth("sfp_0000000000000000000000000000000000000000000000000000000000000000")
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(bogus.status(), 401);

    // Token without session:upload → 403.
    let wrong_scope = client
        .put(meta_url(&c.s, ULID_A))
        .bearer_auth(&c.read_only)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_scope.status(), 403);
    assert_eq!(
        wrong_scope.json::<Value>().await.unwrap()["error"]["code"],
        "forbidden"
    );

    // Member with only read → 403.
    let bob = client
        .put(meta_url(&c.s, ULID_A))
        .bearer_auth(&c.bob_upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(bob.status(), 403);

    // Non-member on a private repo → 404.
    let carol = client
        .put(meta_url(&c.s, ULID_A))
        .bearer_auth(&c.carol_upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(carol.status(), 404);

    // Unknown repo → 404.
    let unknown_repo = client
        .put(c.s.url(&format!("/api/v1/repos/alice/nope/sessions/{ULID_A}")))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown_repo.status(), 404);

    // Owner with session:upload → 201 first, 200 on re-PUT.
    let created = client
        .put(meta_url(&c.s, ULID_A))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let body: Value = created.json().await.unwrap();
    assert_eq!(body["ulid"], ULID_A);
    assert_eq!(body["lifecycle"], "receiving");
    assert!(body["id"].is_number());

    let again = client
        .put(meta_url(&c.s, ULID_A))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);
    let again_body: Value = again.json().await.unwrap();
    assert_eq!(again_body["ulid"], ULID_A);
    assert_eq!(again_body["lifecycle"], "receiving");

    // Malformed JSON → 422.
    let malformed = client
        .put(meta_url(&c.s, ULID_B))
        .bearer_auth(&c.upload)
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 422);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_complete_links_flow() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let seg_url = |ulid: &str, n: u64| {
        c.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ulid}/segments/{n}"
        ))
    };

    // Segment on an unknown session → 404.
    let missing = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", "00")
        .body("bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    // Segment auth matrix.
    let created = client
        .put(meta_url(&c.s, ULID_B))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_B))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());

    let anon = client
        .put(seg_url(ULID_B, 0))
        .body("bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 401);
    let wrong_scope = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.read_only)
        .body("bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_scope.status(), 403);
    let bob = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.bob_upload)
        .body("bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(bob.status(), 403);

    // Happy path → 200 with id/ulid/state.
    let (bytes, hash) = segment_payload(&[user_event(0), user_event(1)]);
    let put = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    let put_body: Value = put.json().await.unwrap();
    assert_eq!(put_body["ulid"], ULID_B);
    assert_eq!(put_body["lifecycle"], "receiving");

    // Same bytes again → 200 (idempotent).
    let retry = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), 200);

    // Different bytes at the same n → 409 with exactly {"hash": "<stored hex>"}.
    let (other, other_hash) = segment_payload(&[user_event(0), user_event(9)]);
    let conflict = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &other_hash)
        .body(other)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 409);
    let conflict_body: Value = conflict.json().await.unwrap();
    assert_eq!(
        conflict_body,
        json!({"hash": hash}),
        "409 must be exactly the stored hash, no envelope"
    );

    // complete with a non-empty body → 422; {} flips state.
    let complete_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{ULID_B}/complete"
    ));
    let bad_complete = client
        .post(&complete_url)
        .bearer_auth(&c.upload)
        .json(&json!({"oops": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_complete.status(), 422);
    let done = client
        .post(&complete_url)
        .bearer_auth(&c.upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    let done_body: Value = done.json().await.unwrap();
    assert_eq!(done_body["ulid"], ULID_B);
    assert_eq!(done_body["lifecycle"], "complete");

    // links: insert + idempotent re-post of the same SHA → one row.
    let links_url =
        c.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_B}/links"));
    let sha = "a".repeat(40);
    let links = client
        .post(&links_url)
        .bearer_auth(&c.upload)
        .json(&json!({"links": [{"sha": sha}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(links.status(), 200);
    assert_eq!(links.json::<Value>().await.unwrap()["accepted"], 1);
    let links_again = client
        .post(&links_url)
        .bearer_auth(&c.upload)
        .json(&json!({"links": [{"sha": sha}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(links_again.status(), 200);
    let session = db_sessions::session_by_ulid(c.s.core.db(), 1, ULID_B)
        .await
        .unwrap()
        .expect("session row");
    let rows = db_sessions::links_of_session(c.s.core.db(), session.id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);

    // Links on an unknown session → 404.
    let unknown = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_C}/links")))
        .bearer_auth(&c.upload)
        .json(&json!({"links": [{"sha": sha}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_body_cap_is_413() {
    let s = TestServer::start_with(|config| {
        config.sessions.max_segment_bytes = 8;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(
        &alice,
        "proj",
        starforged_core::permission::Visibility::Private,
    )
    .await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let created = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_D}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_D))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());
    let big = client
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID_D}/segments/0"
        )))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", "cc")
        .body(vec![7u8; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(big.status(), 413);
    assert_eq!(
        big.json::<Value>().await.unwrap()["error"]["code"],
        "payload_too_large"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_quota_rejects_segments() {
    let s = TestServer::start_with(|config| {
        config.sessions.max_repo_bytes = 10;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(
        &alice,
        "proj",
        starforged_core::permission::Visibility::Private,
    )
    .await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let created = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_Q}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_Q))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());
    let rejected = client
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID_Q}/segments/0"
        )))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", "dd")
        .body(vec![9u8; 64])
        .send()
        .await
        .unwrap();
    assert!(rejected.status().is_client_error());
    let body: Value = rejected.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("quota"),
        "quota rejection must say so: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_validation_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // URL ULID and body id must match.
    let mismatch = client
        .put(meta_url(&c.s, ULID_E))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_F))
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status(), 422);

    // Unknown format tag.
    let mut bad_format = meta_body(ULID_E);
    bad_format["format"] = json!("starforge-session/v9");
    let bad_format = client
        .put(meta_url(&c.s, ULID_E))
        .bearer_auth(&c.upload)
        .json(&bad_format)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_format.status(), 422);

    // Unknown agent name.
    let mut bad_agent = meta_body(ULID_E);
    bad_agent["agent"] = json!({"name": "clippy", "version": "1.0"});
    let bad_agent = client
        .put(meta_url(&c.s, ULID_E))
        .bearer_auth(&c.upload)
        .json(&bad_agent)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_agent.status(), 422);

    // Malformed ULID in the path.
    let bad_ulid = client
        .put(c.s.url("/api/v1/repos/alice/proj/sessions/not-a-ulid"))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_E))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_ulid.status(), 422);

    // A valid body still creates the session.
    let created = client
        .put(meta_url(&c.s, ULID_E))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_E))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_writer_reput_is_forbidden() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(
        &alice,
        "proj",
        starforged_core::permission::Visibility::Private,
    )
    .await;
    // Bob can upload but is not a repo admin.
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let alice_upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let url = s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_F}"));

    let created = client
        .put(&url)
        .bearer_auth(&alice_upload)
        .json(&meta_body(ULID_F))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    // Same user re-PUTs fine.
    let again = client
        .put(&url)
        .bearer_auth(&alice_upload)
        .json(&meta_body(ULID_F))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);

    // A different writer who is not an admin gets 403.
    let foreign = client
        .put(&url)
        .bearer_auth(&bob_upload)
        .json(&meta_body(ULID_F))
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), 403);
    assert_eq!(
        foreign.json::<Value>().await.unwrap()["error"]["code"],
        "forbidden"
    );

    // Promoting bob to admin lets the re-PUT through, keeping alice as uploader.
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Admin)
        .await
        .unwrap();
    let mut retitled = meta_body(ULID_F);
    retitled["title"] = json!("bob retitled");
    let admin_put = client
        .put(&url)
        .bearer_auth(&bob_upload)
        .json(&retitled)
        .send()
        .await
        .unwrap();
    assert_eq!(admin_put.status(), 200);
    let session = db_sessions::session_by_ulid(s.core.db(), 1, ULID_F)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.uploader_id, alice.id, "uploader stays pinned");
    assert_eq!(session.title, "bob retitled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_header_and_event_validation() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let seg_url = |n: u64| {
        c.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID_G}/segments/{n}"
        ))
    };
    let created = client
        .put(meta_url(&c.s, ULID_G))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_G))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());
    let (bytes, hash) = segment_payload(&[user_event(0)]);

    // Missing hash header → 400.
    let missing = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 400);

    // Wrong hash → 422.
    let wrong = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", "0".repeat(64))
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 422);

    // Tampered body under a once-valid hash → 422.
    let mut tampered = bytes.clone();
    tampered[0] ^= 0xff;
    let tampered_put = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &hash)
        .body(tampered)
        .send()
        .await
        .unwrap();
    assert_eq!(tampered_put.status(), 422);

    // Skipping ahead of the next expected number → 422.
    let gap = client
        .put(seg_url(1))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(gap.status(), 422);

    // Body that is not zstd → 422.
    let raw = b"plain jsonl, not compressed".to_vec();
    let not_zstd = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &starforge_format::blake3_hex(&raw))
        .body(raw)
        .send()
        .await
        .unwrap();
    assert_eq!(not_zstd.status(), 422);

    // One bad JSONL line → 422 naming the line number.
    let lines = vec![user_event(0), "{not json".to_string(), user_event(2)];
    let (bad, bad_hash) = segment_payload(&lines);
    let bad_line = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &bad_hash)
        .body(bad)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_line.status(), 422);
    let bad_body: Value = bad_line.json().await.unwrap();
    assert!(
        bad_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("line 2"),
        "must report the failing line number: {bad_body}"
    );

    // Non-v:1 event → 422.
    let v2 = vec![
        r#"{"v":2,"seq":0,"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"hi"}"#
            .to_string(),
    ];
    let (v2bytes, v2hash) = segment_payload(&v2);
    let non_v1 = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &v2hash)
        .body(v2bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(non_v1.status(), 422);

    // Unknown kinds with v:1 are accepted (evolution rule).
    let future = vec![
        r#"{"v":1,"seq":0,"ts":"2026-11-04T00:00:00Z","kind":"future_kind","text":"hi"}"#
            .to_string(),
    ];
    let (fbytes, fhash) = segment_payload(&future);
    let unknown_kind = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &fhash)
        .body(fbytes)
        .send()
        .await
        .unwrap();
    assert_eq!(unknown_kind.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_idempotency_refcount_and_overlap() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let seg_url = |n: u64| {
        c.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID_H}/segments/{n}"
        ))
    };
    let created = client
        .put(meta_url(&c.s, ULID_H))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_H))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());

    let (first, first_hash) = segment_payload(&[user_event(0), user_event(1)]);
    let put = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &first_hash)
        .body(first.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    assert_eq!(
        blob_refcount(c.s.core.db(), &first_hash).await,
        1,
        "one accepted segment holds one blob ref"
    );

    // Identical re-PUT → 200 with the refcount untouched.
    let retry = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &first_hash)
        .body(first.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), 200);
    assert_eq!(blob_refcount(c.s.core.db(), &first_hash).await, 1);

    // Different bytes at the same n → 409 with exactly the stored hash.
    let (clash, clash_hash) = segment_payload(&[user_event(0), user_event(7)]);
    let conflict = client
        .put(seg_url(0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &clash_hash)
        .body(clash.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 409);
    assert_eq!(
        conflict.json::<Value>().await.unwrap(),
        json!({"hash": first_hash})
    );
    assert!(
        db_sessions::blob_by_hash(c.s.core.db(), &clash_hash)
            .await
            .unwrap()
            .is_none(),
        "rejected bytes must not leave a blob ref behind"
    );
    assert_eq!(blob_refcount(c.s.core.db(), &first_hash).await, 1);

    // Overlapping sequence ranges regress → 422.
    let (overlap, overlap_hash) = segment_payload(&[user_event(1), user_event(2)]);
    let overlapped = client
        .put(seg_url(1))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &overlap_hash)
        .body(overlap)
        .send()
        .await
        .unwrap();
    assert_eq!(overlapped.status(), 422);

    // The next sequential, non-overlapping segment stores.
    let (second, second_hash) = segment_payload(&[user_event(2), user_event(3)]);
    let next = client
        .put(seg_url(1))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &second_hash)
        .body(second)
        .send()
        .await
        .unwrap();
    assert_eq!(next.status(), 200);
    let session = db_sessions::session_by_ulid(c.s.core.db(), 1, ULID_H)
        .await
        .unwrap()
        .expect("session row");
    let segments = db_sessions::segments_of(c.s.core.db(), session.id)
        .await
        .unwrap();
    assert_eq!(segments.len(), 2);
    assert_eq!((segments[0].seq_start, segments[0].seq_end), (0, 1));
    assert_eq!((segments[1].seq_start, segments[1].seq_end), (2, 3));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_is_idempotent() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let complete_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{ULID_J}/complete"
    ));
    let created = client
        .put(meta_url(&c.s, ULID_J))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_J))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());

    for _ in 0..2 {
        let done = client
            .post(&complete_url)
            .bearer_auth(&c.upload)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(done.status(), 200);
        let body: Value = done.json().await.unwrap();
        assert_eq!(body["lifecycle"], "complete");
    }

    // Unknown session → 404.
    let unknown_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{ULID_K}/complete"
    ));
    let unknown = client
        .post(&unknown_url)
        .bearer_auth(&c.upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn links_batch_is_atomic() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let links_url =
        c.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_K}/links"));
    let created = client
        .put(meta_url(&c.s, ULID_K))
        .bearer_auth(&c.upload)
        .json(&meta_body(ULID_K))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());
    let good = "b".repeat(40);

    // One bad entry poisons the batch: 422 and no partial insert.
    let poisoned = client
        .post(&links_url)
        .bearer_auth(&c.upload)
        .json(&json!({"links": [{"sha": good}, {"sha": "not-hex"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(poisoned.status(), 422);
    let session = db_sessions::session_by_ulid(c.s.core.db(), 1, ULID_K)
        .await
        .unwrap()
        .expect("session row");
    assert!(
        db_sessions::links_of_session(c.s.core.db(), session.id)
            .await
            .unwrap()
            .is_empty()
    );

    // Unknown confidence and inverted ranges are also rejected wholesale.
    for bad in [
        json!({"links": [{"sha": good, "confidence": "vibes"}]}),
        json!({"links": [{"sha": good, "seq_start": 5, "seq_end": 2}]}),
    ] {
        let rejected = client
            .post(&links_url)
            .bearer_auth(&c.upload)
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), 422);
    }
    assert!(
        db_sessions::links_of_session(c.s.core.db(), session.id)
            .await
            .unwrap()
            .is_empty()
    );

    // Duplicate SHAs in one payload dedupe to a single row.
    let deduped = client
        .post(&links_url)
        .bearer_auth(&c.upload)
        .json(&json!({"links": [
            {"sha": good, "confidence": "exact", "seq_start": 0, "seq_end": 3},
            {"sha": good, "confidence": "exact", "seq_start": 0, "seq_end": 3},
        ]}))
        .send()
        .await
        .unwrap();
    assert_eq!(deduped.status(), 200);
    assert_eq!(deduped.json::<Value>().await.unwrap()["accepted"], 1);
    assert_eq!(
        db_sessions::links_of_session(c.s.core.db(), session.id)
            .await
            .unwrap()
            .len(),
        1
    );

    // Idempotent re-POST keeps the same single row.
    let again = client
        .post(&links_url)
        .bearer_auth(&c.upload)
        .json(&json!({"links": [{"sha": good}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);
    assert_eq!(
        db_sessions::links_of_session(c.s.core.db(), session.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

const ULID_M: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA6";
const ULID_PARENT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA7";

/// The full CLI shape through the real `SessionMeta` struct: every column the
/// server stores must arrive, not just the stubs the old fixtures carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_round_trip_stores_cli_fields() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    // The exact struct the CLI sends, serialized — never a hand-written stub.
    let raw = json!({
        "format": "starforge.session/v1",
        "id": ULID_M,
        "agent": {"name": "codex", "version": "3.0.0"},
        "models": ["opus", "sonnet"],
        "title": "Round trip session",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": "2026-11-04T01:30:00Z",
        "repo": {"branch": "feature/round-trip", "head_at_start": "cccccccccccccccccccccccccccccccccccccccc"},
        "parent_id": ULID_PARENT,
        "usage": {"input": 100, "output": 200, "cache_read": 300, "cache_write": 400, "reasoning": 500},
        "files_touched": ["src/main.rs", "src/lib.rs"],
        "redaction": {"fingerprint": "fp-roundtrip", "counts": {"email": 2, "literal": 1}},
        "capture": {"mode": "hook", "cli_version": "1.2.3", "adapter_version_verified": true},
    });
    let parsed = SessionMeta::parse(&raw.to_string()).expect("fixture is valid CLI metadata");
    let created = client
        .put(meta_url(&c.s, ULID_M))
        .bearer_auth(&c.upload)
        .json(&serde_json::to_value(&parsed).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let body: Value = created.json().await.unwrap();
    assert_eq!(body["lifecycle"], "receiving");
    assert_eq!(body["quarantine"], "none");

    let row = db_sessions::session_by_ulid(c.s.core.db(), 1, ULID_M)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(row.agent_name, "codex");
    assert_eq!(row.agent_version, "3.0.0");
    assert_eq!(row.title, "Round trip session");
    assert_eq!(row.branch, "feature/round-trip");
    assert_eq!(row.head_sha, "cccccccccccccccccccccccccccccccccccccccc");
    assert_eq!(row.started_at, 1793750400);
    assert_eq!(row.ended_at, Some(1793755800));
    assert_eq!(row.parent_ulid.as_deref(), Some(ULID_PARENT));
    assert_eq!(row.usage_input, 100);
    assert_eq!(row.usage_output, 200);
    assert_eq!(row.usage_cache_read, 300);
    assert_eq!(row.usage_cache_write, 400);
    assert_eq!(row.usage_reasoning, 500);
    assert_eq!(row.models, r#"["opus","sonnet"]"#);
    assert_eq!(row.files_touched, r#"["src/main.rs","src/lib.rs"]"#);
    assert_eq!(row.redaction_fingerprint, "fp-roundtrip");
    let counts: Value = serde_json::from_str(&row.redaction_counts).unwrap();
    assert_eq!(counts, json!({"email": 2, "literal": 1}));
    assert_eq!(row.capture_mode, "hook");
    assert_eq!(row.cli_version, "1.2.3");
    assert_eq!(row.adapter_verified, 1);
    assert_eq!(row.lifecycle, "receiving");
    assert_eq!(row.quarantine, "none");
}
