mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Permission;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const ULID_C: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
const ULID_D: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
const ULID_Q: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge-session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "test session",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {},
        "parent_id": null,
        "usage": {},
        "files_touched": [],
        "redaction": {},
        "capture": {},
    })
}

fn meta_url(s: &TestServer, ulid: &str) -> String {
    s.url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}"))
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
    assert_eq!(body["state"], "receiving");
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
    assert_eq!(again_body["state"], "receiving");

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
    let bytes = b"segment-zero-bytes".to_vec();
    let put = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", "aa")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    let put_body: Value = put.json().await.unwrap();
    assert_eq!(put_body["ulid"], ULID_B);
    assert_eq!(put_body["state"], "receiving");

    // Same bytes again → 200 (idempotent).
    let retry = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", "aa")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), 200);

    // Different bytes at the same n → 409 with exactly {"hash": "<stored hex>"}.
    let conflict = client
        .put(seg_url(ULID_B, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", "bb")
        .body(b"different-bytes".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 409);
    let conflict_body: Value = conflict.json().await.unwrap();
    assert!(
        conflict_body.get("error").is_none(),
        "409 must not use the envelope"
    );
    assert!(conflict_body["hash"].is_string());

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
    assert_eq!(done_body["state"], "complete");

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
