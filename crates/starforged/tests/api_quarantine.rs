//! D5: server re-scan, quarantine, audit, and the admin quarantine queue.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Permission;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const PQ_KEY: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
const PQ_EMAIL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";
const PQ_LITERAL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB2";
const PQ_PRECEDENCE: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB3";
const PQ_RELEASE: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB4";
const PQ_PURGE: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB5";
const PQ_BLOCK: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB6";
const PQ_BOMB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB7";

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

/// One minimal valid `user_message` event line with sequence number `seq`.
fn user_event(seq: u64) -> String {
    format!(
        r#"{{"v":1,"seq":{seq},"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"hello {seq}"}}"#
    )
}

/// A `user_message` event line whose text is `text` (JSON-escaped).
fn event_with_text(seq: u64, text: &str) -> String {
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{"v":1,"seq":{seq},"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"{escaped}"}}"#
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

struct Ctx {
    s: TestServer,
    upload: String,
    bob_upload: String,
    carol_upload: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        Self::wrap(s).await
    }

    async fn wrap(s: TestServer) -> Ctx {
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
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
        let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
        let carol_upload = s.token(&carol, &[Scope::SessionUpload]).await;
        Ctx {
            s,
            upload,
            bob_upload,
            carol_upload,
        }
    }

    fn meta_url(&self, ulid: &str) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}"))
    }

    fn seg_url(&self, ulid: &str, n: i64) -> String {
        self.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ulid}/segments/{n}"
        ))
    }

    async fn put_meta(&self, ulid: &str) {
        let client = reqwest::Client::new();
        let created = client
            .put(self.meta_url(ulid))
            .bearer_auth(&self.upload)
            .json(&meta_body(ulid))
            .send()
            .await
            .unwrap();
        assert!(created.status().is_success());
    }

    async fn put_segment(&self, ulid: &str, n: i64, lines: &[String]) -> reqwest::Response {
        let (bytes, hash) = segment_payload(lines);
        reqwest::Client::new()
            .put(self.seg_url(ulid, n))
            .bearer_auth(&self.upload)
            .header("X-Starforge-Blake3", &hash)
            .body(bytes)
            .send()
            .await
            .unwrap()
    }

    async fn session_row(&self, ulid: &str) -> starforged_db::sessions::SessionRow {
        let repo_id = self.repo_id().await;
        db_sessions::session_by_ulid(self.s.core.db(), repo_id, ulid)
            .await
            .unwrap()
            .expect("session row")
    }

    async fn repo_id(&self) -> i64 {
        // Any session row carries the repo id; fall back to the owner lookup.
        let alice = self
            .s
            .core
            .user_by_handle("alice")
            .await
            .unwrap()
            .expect("alice");
        self.s
            .core
            .repo_for(Some(&alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id
    }

    async fn set_repo_rules(&self, toml: &str) {
        sqlx::query("UPDATE repos SET redact_rules = $1 WHERE id = $2")
            .bind(toml)
            .bind(self.repo_id().await)
            .execute(self.s.core.db().pool())
            .await
            .unwrap();
    }

    async fn audit_actions(&self) -> Vec<(String, String)> {
        starforged_db::audit::recent(self.s.core.db(), 100)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.action, row.target))
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_key_quarantines_and_segment_still_stored() {
    let c = Ctx::start().await;
    c.put_meta(PQ_KEY).await;
    let pem = "key -----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEF\\n-----END PRIVATE KEY----- done";
    let put = c
        .put_segment(PQ_KEY, 0, &[user_event(0), event_with_text(1, pem)])
        .await;
    assert_eq!(put.status(), 200);

    let row = c.session_row(PQ_KEY).await;
    assert_eq!(row.quarantine, "quarantined");
    assert_eq!(row.quarantine_reason, "private-key");
    assert_eq!(row.quarantine_detail, "segment 0 line 2");

    // The segment is stored: row present, blob refcounted.
    let segments = db_sessions::segments_of(c.s.core.db(), row.id)
        .await
        .unwrap();
    assert_eq!(segments.len(), 1);
    let blob = db_sessions::blob_by_hash(c.s.core.db(), &segments[0].blob_hash)
        .await
        .unwrap()
        .expect("blob row");
    assert_eq!(blob.refcount, 1);

    // The quarantine verdict is audited.
    let actions = c.audit_actions().await;
    assert!(
        actions
            .iter()
            .any(|(a, t)| a == "session.quarantine" && t == &format!("session:{PQ_KEY}")),
        "{actions:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_confidence_email_does_not_quarantine() {
    let c = Ctx::start().await;
    c.put_meta(PQ_EMAIL).await;
    // PII email detection is off by default, so this is not even counted.
    let put = c
        .put_segment(
            PQ_EMAIL,
            0,
            &[event_with_text(0, "contact alice@example.com for help")],
        )
        .await;
    assert_eq!(put.status(), 200);

    let row = c.session_row(PQ_EMAIL).await;
    assert_eq!(row.quarantine, "none");
    assert_eq!(row.quarantine_reason, "");
    assert!(row.redaction_counts.is_empty() || row.redaction_counts == "{}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_literal_rule_quarantines() {
    let c = Ctx::start().await;
    c.set_repo_rules("[entropy]\nliterals = [\"REPO-MARKER-42\"]\n")
        .await;
    c.put_meta(PQ_LITERAL).await;
    let put = c
        .put_segment(
            PQ_LITERAL,
            0,
            &[
                user_event(0),
                user_event(1),
                event_with_text(2, "deploying REPO-MARKER-42 now"),
            ],
        )
        .await;
    assert_eq!(put.status(), 200);

    let row = c.session_row(PQ_LITERAL).await;
    assert_eq!(row.quarantine, "quarantined");
    assert_eq!(row.quarantine_reason, "literal");
    assert_eq!(row.quarantine_detail, "segment 0 line 3");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn site_rules_override_repo_weakening() {
    // A 36-byte all-unique alphanumeric token: entropy ~5.2 bits/char,
    // detected at min_len 20 but invisible at min_len 64.
    let token = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ";
    assert_eq!(token.len(), 36);

    // Control: repo weakens entropy detection, no site rules → missed.
    let plain = Ctx::start().await;
    plain.set_repo_rules("[entropy]\nmin_len = 64\n").await;
    plain.put_meta(PQ_PRECEDENCE).await;
    let put = plain
        .put_segment(
            PQ_PRECEDENCE,
            0,
            &[event_with_text(0, &format!("token {token} here"))],
        )
        .await;
    assert_eq!(put.status(), 200);
    let row = plain.session_row(PQ_PRECEDENCE).await;
    assert_eq!(row.quarantine, "none", "low-confidence never quarantines");
    assert!(
        !row.redaction_counts.contains("high-entropy"),
        "weakened repo rules miss the token: {}",
        row.redaction_counts
    );

    // Site rules restore sensitivity and win over the repo.
    let s = TestServer::start_with(|config| {
        config.sessions.site_redact_rules = Some("[entropy]\nmin_len = 20\n".to_owned());
    })
    .await;
    let c = Ctx::wrap(s).await;
    c.set_repo_rules("[entropy]\nmin_len = 64\n").await;
    c.put_meta(PQ_PRECEDENCE).await;
    let put = c
        .put_segment(
            PQ_PRECEDENCE,
            0,
            &[event_with_text(0, &format!("token {token} here"))],
        )
        .await;
    assert_eq!(put.status(), 200);
    let row = c.session_row(PQ_PRECEDENCE).await;
    assert_eq!(row.quarantine, "none", "low-confidence never quarantines");
    assert!(
        row.redaction_counts.contains("\"high-entropy\":1"),
        "site rules restore detection: {}",
        row.redaction_counts
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_clears_quarantine_and_audits() {
    let c = Ctx::start().await;
    c.put_meta(PQ_RELEASE).await;
    let pem = "key -----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEF\\n-----END PRIVATE KEY----- done";
    assert_eq!(
        c.put_segment(PQ_RELEASE, 0, &[event_with_text(0, pem)])
            .await
            .status(),
        200
    );
    let client = reqwest::Client::new();
    let queue_url =
        c.s.url("/api/v1/repos/alice/proj/sessions?quarantined=true");

    // Repo admin lists the queue.
    let listed = client
        .get(&queue_url)
        .bearer_auth(&c.upload)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);
    let body: Value = listed.json().await.unwrap();
    let ulids: Vec<&str> = body["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["ulid"].as_str().unwrap())
        .collect();
    assert!(ulids.contains(&PQ_RELEASE), "{body}");
    let entry = body["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["ulid"] == PQ_RELEASE)
        .unwrap();
    assert_eq!(entry["quarantine"], "quarantined");
    assert_eq!(entry["reason"], "private-key");

    // Release clears the flag and audits.
    let release_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{PQ_RELEASE}/release"
    ));
    let released = client
        .post(&release_url)
        .bearer_auth(&c.upload)
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), 200);
    let view: Value = released.json().await.unwrap();
    assert_eq!(view["ulid"], PQ_RELEASE);
    assert_eq!(view["quarantine"], "released");

    let row = c.session_row(PQ_RELEASE).await;
    assert_eq!(row.quarantine, "released");

    // The queue no longer lists it.
    let listed = client
        .get(&queue_url)
        .bearer_auth(&c.upload)
        .send()
        .await
        .unwrap();
    let body: Value = listed.json().await.unwrap();
    assert!(
        !body["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["ulid"] == PQ_RELEASE),
        "{body}"
    );

    // Both audit rows exist; releasing again is 422.
    let actions = c.audit_actions().await;
    assert!(
        actions
            .iter()
            .any(|(a, t)| a == "session.quarantine" && t == &format!("session:{PQ_RELEASE}")),
        "{actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|(a, t)| a == "session.quarantine.released"
                && t == &format!("session:{PQ_RELEASE}")),
        "{actions:?}"
    );
    let again = client
        .post(&release_url)
        .bearer_auth(&c.upload)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 422);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purge_removes_rows_and_decrefs_blobs() {
    let c = Ctx::start().await;
    c.put_meta(PQ_PURGE).await;
    let pem = "key -----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEF\\n-----END PRIVATE KEY----- done";
    assert_eq!(
        c.put_segment(PQ_PURGE, 0, &[event_with_text(0, pem)])
            .await
            .status(),
        200
    );
    let row = c.session_row(PQ_PURGE).await;
    let segments = db_sessions::segments_of(c.s.core.db(), row.id)
        .await
        .unwrap();
    assert_eq!(segments.len(), 1);
    let hash = segments[0].blob_hash.clone();

    // A commit claim link must go with the session.
    let client = reqwest::Client::new();
    let links_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{PQ_PURGE}/links"
    ));
    let sha = "c".repeat(40);
    let links = client
        .post(&links_url)
        .bearer_auth(&c.upload)
        .json(&json!({"links": [{"sha": sha}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(links.status(), 200);

    let purge_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{PQ_PURGE}/purge"
    ));
    let purged = client
        .post(&purge_url)
        .bearer_auth(&c.upload)
        .send()
        .await
        .unwrap();
    assert_eq!(purged.status(), 204);

    // Session row gone, segment rows gone, blob refcount back to zero.
    let repo_id = c.repo_id().await;
    assert!(
        db_sessions::session_by_ulid(c.s.core.db(), repo_id, PQ_PURGE)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db_sessions::segments_of(c.s.core.db(), row.id)
            .await
            .unwrap()
            .is_empty()
    );
    let blob = db_sessions::blob_by_hash(c.s.core.db(), &hash)
        .await
        .unwrap()
        .expect("blob row survives for the GC sweep");
    assert_eq!(blob.refcount, 0);
    let links = db_sessions::links_of_session(c.s.core.db(), row.id)
        .await
        .unwrap();
    assert!(links.is_empty());

    let actions = c.audit_actions().await;
    assert!(
        actions
            .iter()
            .any(|(a, t)| a == "session.purged" && t == &format!("session:{PQ_PURGE}")),
        "{actions:?}"
    );

    // Purging again is 404.
    let again = client
        .post(&purge_url)
        .bearer_auth(&c.upload)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantine_endpoints_enforce_admin() {
    let c = Ctx::start().await;
    c.put_meta(PQ_BLOCK).await;
    let pem = "key -----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEF\\n-----END PRIVATE KEY----- done";
    assert_eq!(
        c.put_segment(PQ_BLOCK, 0, &[event_with_text(0, pem)])
            .await
            .status(),
        200
    );
    let client = reqwest::Client::new();
    let queue_url =
        c.s.url("/api/v1/repos/alice/proj/sessions?quarantined=true");
    let release_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{PQ_BLOCK}/release"
    ));
    let purge_url = c.s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{PQ_BLOCK}/purge"
    ));

    // Read collaborator (visible repo, insufficient permission) → 403.
    for (method, url) in [
        ("get", queue_url.clone()),
        ("post", release_url.clone()),
        ("post", purge_url.clone()),
    ] {
        let res = if method == "get" {
            client.get(&url)
        } else {
            client.post(&url)
        }
        .bearer_auth(&c.bob_upload)
        .send()
        .await
        .unwrap();
        assert_eq!(res.status(), 403, "{method} {url}");
    }

    // Stranger (invisible repo) → 404.
    let hidden = client
        .get(&queue_url)
        .bearer_auth(&c.carol_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), 404);

    // Anonymous → 401.
    let anon = client.get(&queue_url).send().await.unwrap();
    assert_eq!(anon.status(), 401);

    // A clean session purged by a non-admin is still 403, not 404.
    let denied = client
        .post(&purge_url)
        .bearer_auth(&c.bob_upload)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantine_does_not_block_later_uploads() {
    let c = Ctx::start().await;
    c.put_meta(PQ_BLOCK).await;
    let pem = "key -----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEF\\n-----END PRIVATE KEY----- done";
    assert_eq!(
        c.put_segment(PQ_BLOCK, 0, &[event_with_text(0, pem)])
            .await
            .status(),
        200
    );
    // A later clean segment is accepted; the state stays quarantined.
    let put = c.put_segment(PQ_BLOCK, 1, &[user_event(1)]).await;
    assert_eq!(put.status(), 200);
    let row = c.session_row(PQ_BLOCK).await;
    assert_eq!(row.quarantine, "quarantined");
    assert_eq!(row.quarantine_reason, "private-key");
    assert_eq!(row.quarantine_detail, "segment 0 line 1");
    // No second quarantine audit row for the clean upload.
    let count = c
        .audit_actions()
        .await
        .into_iter()
        .filter(|(a, t)| a == "session.quarantine" && t == &format!("session:{PQ_BLOCK}"))
        .count();
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decompression_bomb_is_rejected_before_storage() {
    let s = TestServer::start_with(|config| {
        config.sessions.max_decompressed_bytes = 1024;
    })
    .await;
    let c = Ctx::wrap(s).await;
    c.put_meta(PQ_BOMB).await;

    // ~200 padded events: tiny compressed, ~30 KiB decompressed.
    let mut lines = Vec::new();
    for seq in 0..200u64 {
        lines.push(event_with_text(
            seq,
            &format!("padding-{} {}", seq, "x".repeat(150)),
        ));
    }
    let (bytes, hash) = segment_payload(&lines);
    assert!(bytes.len() < 4096, "bomb must stay small on the wire");
    let bomb = reqwest::Client::new()
        .put(c.seg_url(PQ_BOMB, 0))
        .bearer_auth(&c.upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(bomb.status(), 422);

    // Nothing stored: no blob ref, no segment row.
    let row = c.session_row(PQ_BOMB).await;
    assert!(
        db_sessions::segments_of(c.s.core.db(), row.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db_sessions::blob_by_hash(c.s.core.db(), &hash)
            .await
            .unwrap()
            .is_none()
    );

    // A normal segment is still accepted.
    let put = c.put_segment(PQ_BOMB, 0, &[user_event(0)]).await;
    assert_eq!(put.status(), 200);
}
const PQ_GUARD: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB9";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_writes_require_uploader_or_admin() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    s.repo(
        &alice,
        "proj",
        starforged_core::permission::Visibility::Private,
    )
    .await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Write)
        .await
        .unwrap();
    let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
    let carol_upload = s.token(&carol, &[Scope::SessionUpload]).await;
    let alice_upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let meta_url = s.url(&format!("/api/v1/repos/alice/proj/sessions/{PQ_GUARD}"));
    let seg_url = |n: i64| {
        s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{PQ_GUARD}/segments/{n}"
        ))
    };
    let complete_url = s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{PQ_GUARD}/complete"
    ));
    let links_url = s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{PQ_GUARD}/links"
    ));
    let put_segment = |token: &str, n: i64, lines: &[String]| {
        let (bytes, hash) = segment_payload(lines);
        client
            .put(seg_url(n))
            .bearer_auth(token)
            .header("X-Starforge-Blake3", &hash)
            .body(bytes)
            .send()
    };
    let sha = "d".repeat(40);

    // Bob (writer) creates the session and stores segment 0.
    let created = client
        .put(&meta_url)
        .bearer_auth(&bob_upload)
        .json(&meta_body(PQ_GUARD))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let seg0 = [user_event(0), user_event(1)];
    assert_eq!(
        put_segment(&bob_upload, 0, &seg0).await.unwrap().status(),
        200
    );

    // Carol (writer, not uploader, not admin) is refused everywhere — even
    // the squat attempt on the stored segment number answers 403, not 409.
    let squat = [user_event(0), user_event(9)];
    assert_eq!(
        put_segment(&carol_upload, 0, &squat)
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        put_segment(&carol_upload, 1, &[user_event(2)])
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(&complete_url)
            .bearer_auth(&carol_upload)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(&links_url)
            .bearer_auth(&carol_upload)
            .json(&json!({"links": [{"sha": sha}]}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .put(&meta_url)
            .bearer_auth(&carol_upload)
            .json(&meta_body(PQ_GUARD))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    // Nothing Carol tried stuck.
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    let row = db_sessions::session_by_ulid(s.core.db(), repo_id, PQ_GUARD)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(row.lifecycle, "receiving");
    assert_eq!(row.uploader_id, bob.id);
    assert_eq!(
        db_sessions::segments_of(s.core.db(), row.id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        db_sessions::links_of_session(s.core.db(), row.id)
            .await
            .unwrap()
            .is_empty()
    );

    // Alice (repo admin, not the uploader) may still act; ownership stays pinned.
    let seg1 = [user_event(2)];
    assert_eq!(
        put_segment(&alice_upload, 1, &seg1).await.unwrap().status(),
        200
    );
    let row = db_sessions::session_by_ulid(s.core.db(), repo_id, PQ_GUARD)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(row.uploader_id, bob.id);

    // Bob's own flow is unchanged: idempotent re-upload, complete, links.
    assert_eq!(
        put_segment(&bob_upload, 1, &seg1).await.unwrap().status(),
        200
    );
    let done = client
        .post(&complete_url)
        .bearer_auth(&bob_upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    let links = client
        .post(&links_url)
        .bearer_auth(&bob_upload)
        .json(&json!({"links": [{"sha": sha}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(links.status(), 200);
    assert_eq!(links.json::<Value>().await.unwrap()["accepted"], 1);
}
