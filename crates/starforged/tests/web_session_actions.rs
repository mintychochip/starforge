//! M1e E5: session publish/unpublish + delete + admin rescan, web + API.
//! Seeds sessions through the real ingest HTTP wire, then asserts the
//! permission matrix, CSRF enforcement, blob refcounts, audit rows, and
//! stranger visibility before/after unpublish.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_PUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";
const ULID_PRIV: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB2";
const ULID_DEL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB3";
const ULID_DEL_ADMIN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB4";
const ULID_CLEAN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB5";
const ULID_SECRET: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB6";
const ULID_WEB_PUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB7";
const ULID_WEB_DEL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB8";
const ULID_WEB_DEL_CSRF: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB9";
const ULID_WEB_RESCAN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC0";

const CLAIM_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRAILER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "e5 session",
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

fn text_event(seq: u64, text: &str) -> String {
    json!({"v": 1, "seq": seq, "ts": "2026-11-04T00:00:00Z", "kind": "user_message", "text": text})
        .to_string()
}

fn segment_payload(lines: &[String]) -> (Vec<u8>, String) {
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    (bytes, hash)
}

/// Uploads `meta` + `segments` as `token` bearer, exactly like the CLI.
/// Returns the blob hashes so tests can assert refcounts.
async fn upload(
    s: &TestServer,
    client: &reqwest::Client,
    token: &str,
    owner: &str,
    repo: &str,
    ulid: &str,
    segments: &[Vec<String>],
) -> Vec<String> {
    let meta_url = s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}"));
    let created = client
        .put(&meta_url)
        .bearer_auth(token)
        .json(&meta_body(ulid))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "{ulid} meta");
    let mut hashes = Vec::new();
    for (n, lines) in segments.iter().enumerate() {
        let (bytes, hash) = segment_payload(lines);
        let put = client
            .put(s.url(&format!(
                "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}"
            )))
            .bearer_auth(token)
            .header("X-Starforge-Blake3", &hash)
            .body(bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(put.status(), 200, "{ulid} segment {n}");
        hashes.push(hash);
    }
    hashes
}

async fn audit_actions(s: &TestServer) -> Vec<(String, String)> {
    starforged_db::audit::recent(s.core.db(), 200)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.action, row.target))
        .collect()
}
struct Ctx {
    s: TestServer,
    alice_upload: String,
    bob_upload: String,
    carol_upload: String,
    repo_id: i64,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;

        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        s.repo(&alice, "pubr", Visibility::Public).await;
        s.repo(&alice, "privr", Visibility::Private).await;
        s.core
            .set_collaborator(&alice, "alice", "pubr", "bob", Permission::Maintain)
            .await
            .unwrap();
        // Carol writes but holds neither maintain nor admin: she can upload
        // yet must still be denied publish and foreign delete.
        s.core
            .set_collaborator(&alice, "alice", "pubr", "carol", Permission::Write)
            .await
            .unwrap();
        let alice_upload = s.token(&alice, &[Scope::SessionUpload]).await;
        let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
        let carol_upload = s.token(&carol, &[Scope::SessionUpload]).await;
        let repo_id = s
            .core
            .repo_for(Some(&alice), "alice", "pubr")
            .await
            .unwrap()
            .repo
            .id;
        Ctx {
            s,
            alice_upload,
            bob_upload,
            carol_upload,
            repo_id,
        }
    }

    fn api(&self, ulid: &str, action: &str) -> String {
        self.s.url(&format!(
            "/api/v1/repos/alice/pubr/sessions/{ulid}/{action}"
        ))
    }

    fn meta(&self, ulid: &str) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/pubr/sessions/{ulid}"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_publish_unpublish_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let segs = vec![vec![text_event(0, "hello publish")]];
    upload(
        &c.s,
        &client,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_PUB,
        &segs,
    )
    .await;

    // Unpublished: a stranger (anonymous) cannot see it.
    let anon_meta = client.get(c.meta(ULID_PUB)).send().await.unwrap();
    assert_eq!(anon_meta.status(), 404);

    // Anonymous publish: 401. Non-maintain publish: 403.
    assert_eq!(
        client
            .post(c.api(ULID_PUB, "publish"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let denied = client
        .post(c.api(ULID_PUB, "publish"))
        .bearer_auth(&c.carol_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    // Maintain user publishes on the public repo: 200.
    let published = client
        .post(c.api(ULID_PUB, "publish"))
        .bearer_auth(&c.bob_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);
    let body: Value = published.json().await.unwrap();
    assert_eq!(body["visibility"], json!("published"));

    // A stranger can now read the published public session.
    let stranger = client.get(c.meta(ULID_PUB)).send().await.unwrap();
    assert_eq!(stranger.status(), 200);

    // Publishing on a private repo is 422: publishing has no effect there.
    upload(
        &c.s,
        &client,
        &c.alice_upload,
        "alice",
        "privr",
        ULID_PRIV,
        &segs,
    )
    .await;
    let priv_publish = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/privr/sessions/{ULID_PRIV}/publish"
        )))
        .bearer_auth(&c.alice_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(priv_publish.status(), 422);
    let err: Value = priv_publish.json().await.unwrap();
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no effect"),
        "{err}"
    );

    // Unpublish: stranger goes back to 404; repeat unpublish is a no-op 200.
    let unpublished = client
        .post(c.api(ULID_PUB, "unpublish"))
        .bearer_auth(&c.bob_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(unpublished.status(), 200);
    assert_eq!(
        client.get(c.meta(ULID_PUB)).send().await.unwrap().status(),
        404
    );
    assert_eq!(
        client
            .post(c.api(ULID_PUB, "unpublish"))
            .bearer_auth(&c.bob_upload)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let actions = audit_actions(&c.s).await;
    for (action, target) in [
        ("session.publish", ULID_PUB),
        ("session.unpublish", ULID_PUB),
    ] {
        assert!(
            actions
                .iter()
                .any(|(a, t)| a == action && t == &format!("session:{target}")),
            "{action} missing in {actions:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_delete_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let segs = vec![vec![text_event(0, "hello delete")]];
    let hashes = upload(
        &c.s,
        &client,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_DEL,
        &segs,
    )
    .await;

    // A claim link plus a trailer-first NULL row under the same ULID.
    let links = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/pubr/sessions/{ULID_DEL}/links"
        )))
        .bearer_auth(&c.bob_upload)
        .json(&json!({"links": [{"sha": CLAIM_SHA, "confidence": "exact"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(links.status(), 200);
    c.s.core
        .record_trailer_links(
            c.repo_id,
            &[(
                TRAILER_SHA.into(),
                format!("work\nStarforge-Session: {ULID_DEL}"),
            )],
        )
        .await
        .unwrap();

    let delete_url =
        c.s.url(&format!("/api/v1/repos/alice/pubr/sessions/{ULID_DEL}"));
    // A non-uploader without admin learns nothing: 404, not 403.
    assert_eq!(
        client
            .delete(&delete_url)
            .bearer_auth(&c.carol_upload)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // The uploader deletes: 204.
    assert_eq!(
        client
            .delete(&delete_url)
            .bearer_auth(&c.bob_upload)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    // Blob refcount decremented, links (claimed and trailer-first) gone, row gone.
    let blob = db_sessions::blob_by_hash(c.s.core.db(), &hashes[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blob.refcount, 0);
    assert!(
        db_sessions::links_for_sha(c.s.core.db(), c.repo_id, CLAIM_SHA)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db_sessions::links_for_sha(c.s.core.db(), c.repo_id, TRAILER_SHA)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db_sessions::session_by_ulid(c.s.core.db(), c.repo_id, ULID_DEL)
            .await
            .unwrap()
            .is_none()
    );
    // Second delete: 404.
    assert_eq!(
        client
            .delete(&delete_url)
            .bearer_auth(&c.bob_upload)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // A repo admin deletes someone else's session the same way.
    upload(
        &c.s,
        &client,
        &c.carol_upload,
        "alice",
        "pubr",
        ULID_DEL_ADMIN,
        &segs,
    )
    .await;
    let admin_delete = c.s.url(&format!(
        "/api/v1/repos/alice/pubr/sessions/{ULID_DEL_ADMIN}"
    ));
    assert_eq!(
        client
            .delete(&admin_delete)
            .bearer_auth(&c.alice_upload)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );

    let actions = audit_actions(&c.s).await;
    for target in [ULID_DEL, ULID_DEL_ADMIN] {
        assert!(
            actions
                .iter()
                .any(|(a, t)| a == "session.deleted" && t == &format!("session:{target}")),
            "session.deleted for {target} missing in {actions:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_rescan_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    upload(
        &c.s,
        &client,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_CLEAN,
        &[vec![text_event(0, "nothing suspicious here")]],
    )
    .await;

    // Maintain is not enough; strangers learn nothing about unknown ULIDs.
    assert_eq!(
        client
            .post(c.api(ULID_CLEAN, "rescan"))
            .bearer_auth(&c.bob_upload)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(c.s.url("/api/v1/repos/alice/pubr/sessions/01ARZ3NDEKTSV4RRFFQ69G5FZZ/rescan"))
            .bearer_auth(&c.alice_upload)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Clean session rescans to "none".
    let clean = client
        .post(c.api(ULID_CLEAN, "rescan"))
        .bearer_auth(&c.alice_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(clean.status(), 200);
    let verdict: Value = clean.json().await.unwrap();
    assert_eq!(verdict["quarantine"], json!("none"));

    // A planted key quarantines at upload; release, then rescan re-arms it.
    let pem = "key -----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEF\\n-----END PRIVATE KEY----- done";
    upload(
        &c.s,
        &client,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_SECRET,
        &[vec![text_event(0, "hello"), text_event(1, pem)]],
    )
    .await;
    let release = client
        .post(c.api(ULID_SECRET, "release"))
        .bearer_auth(&c.alice_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(release.status(), 200);
    let rescan = client
        .post(c.api(ULID_SECRET, "rescan"))
        .bearer_auth(&c.alice_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(rescan.status(), 200);
    let verdict: Value = rescan.json().await.unwrap();
    assert_eq!(verdict["quarantine"], json!("quarantined"));
    assert_eq!(verdict["reason"], json!("private-key"));
    // Idempotent: rescanning the quarantined session keeps the verdict.
    let again = client
        .post(c.api(ULID_SECRET, "rescan"))
        .bearer_auth(&c.alice_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);
    assert_eq!(
        again.json::<Value>().await.unwrap()["quarantine"],
        json!("quarantined")
    );

    let actions = audit_actions(&c.s).await;
    assert!(
        actions
            .iter()
            .any(|(a, t)| a == "session.rescan" && t == &format!("session:{ULID_SECRET}")),
        "session.rescan missing in {actions:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_publish_forms_require_csrf() {
    let c = Ctx::start().await;
    let api = reqwest::Client::new();
    upload(
        &c.s,
        &api,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_WEB_PUB,
        &[vec![text_event(0, "web publish me")]],
    )
    .await;
    let (browser, csrf) = c.s.login("bob").await;
    let page = c.s.url(&format!("/alice/pubr/sessions/{ULID_WEB_PUB}"));
    let publish = format!("{page}/publish");

    let html = get_text(&browser, &page).await;
    assert!(html.contains("/publish"), "publish form missing");

    // Bad token: 403, no state change. Missing field: 403, no state change.
    assert_eq!(
        browser
            .post(&publish)
            .form(&[("_csrf", "forged")])
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        browser
            .post(&publish)
            .form(&[("other", "x")])
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let row = db_sessions::session_by_ulid(c.s.core.db(), c.repo_id, ULID_WEB_PUB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.visibility, "inherit");

    // Good token: redirect to the viewer, now showing Published.
    let done = browser
        .post(&publish)
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 303);
    assert_eq!(
        done.headers()["location"],
        format!("/alice/pubr/sessions/{ULID_WEB_PUB}")
    );
    let html = get_text(&browser, &page).await;
    assert!(html.contains("published"), "viewer should show Published");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_delete_and_rescan_forms() {
    let c = Ctx::start().await;
    let api = reqwest::Client::new();
    let segs = vec![vec![text_event(0, "web delete me")]];
    upload(
        &c.s,
        &api,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_WEB_DEL,
        &segs,
    )
    .await;
    upload(
        &c.s,
        &api,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_WEB_DEL_CSRF,
        &segs,
    )
    .await;
    upload(
        &c.s,
        &api,
        &c.bob_upload,
        "alice",
        "pubr",
        ULID_WEB_RESCAN,
        &[vec![text_event(0, "nothing suspicious here")]],
    )
    .await;

    // A non-uploader without admin sees no delete form.
    let (carol, _) = c.s.login("carol").await;
    let html = get_text(
        &carol,
        &c.s.url(&format!("/alice/pubr/sessions/{ULID_WEB_DEL}")),
    )
    .await;
    assert!(
        !html.contains("/delete"),
        "read member must not see a delete form"
    );

    let (browser, csrf) = c.s.login("bob").await;
    // Bad token on delete: 403 and the session survives.
    let bad = browser
        .post(c.s.url(&format!("/alice/pubr/sessions/{ULID_WEB_DEL_CSRF}/delete")))
        .form(&[("_csrf", "forged")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403);
    assert!(
        db_sessions::session_by_ulid(c.s.core.db(), c.repo_id, ULID_WEB_DEL_CSRF)
            .await
            .unwrap()
            .is_some()
    );

    // The uploader deletes: redirect to the repo page, session gone.
    let done = browser
        .post(c.s.url(&format!("/alice/pubr/sessions/{ULID_WEB_DEL}/delete")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 303);
    assert_eq!(done.headers()["location"], "/alice/pubr");
    assert_eq!(
        browser
            .get(c.s.url(&format!("/alice/pubr/sessions/{ULID_WEB_DEL}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Admin rescan over the web: bad token 403, good token redirects.
    let (admin, admin_csrf) = c.s.login("alice").await;
    let rescan =
        c.s.url(&format!("/alice/pubr/sessions/{ULID_WEB_RESCAN}/rescan"));
    assert_eq!(
        admin
            .post(&rescan)
            .form(&[("_csrf", "forged")])
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let done = admin
        .post(&rescan)
        .form(&[("_csrf", admin_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 303);

    let actions = audit_actions(&c.s).await;
    for (action, target) in [
        ("session.deleted", ULID_WEB_DEL),
        ("session.rescan", ULID_WEB_RESCAN),
    ] {
        assert!(
            actions
                .iter()
                .any(|(a, t)| a == action && t == &format!("session:{target}")),
            "{action} for {target} missing in {actions:?}"
        );
    }
}
