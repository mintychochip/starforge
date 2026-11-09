//! M1e E2: session viewer page. Seeds sessions through the real ingest
//! HTTP wire (exactly as the CLI drives it), then asserts read-rule
//! enforcement (§6.4), per-kind rendering, escaping, server-side redaction,
//! pagination/focus, and corrupt-segment notices.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_KINDS: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC1";
const ULID_UNPUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC2";
const ULID_QUAR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC3";
const ULID_BIG: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC4";
const ULID_CORRUPT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC5";

/// A realistic `ghp_` classic token (38 alphanumerics, over the 36 minimum
/// for `known-token`). It travels only inside segment bytes; the viewer must
/// render `[redacted:known-token]` and never the raw secret.
const PLANTED_TOKEN: &str = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ12";

fn meta_body(ulid: &str, verified: bool) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1", "m2"],
        "title": "viewer fixture",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": verified},
    })
}

fn event(seq: u64, kind: &str, payload: Value) -> String {
    let mut line = json!({"v": 1, "seq": seq, "ts": "2026-11-04T00:00:00Z", "kind": kind});
    for (k, v) in payload.as_object().unwrap() {
        line[k] = v.clone();
    }
    line.to_string()
}

fn segment_payload(lines: &[String]) -> (Vec<u8>, String) {
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    (bytes, hash)
}

/// Uploads `meta` + `segments` (each a list of JSONL lines) as `token`
/// bearer, exactly like the CLI spool upload. Returns the session id.
/// `viewer` is any user holding repo read (the uploader always qualifies).
#[allow(clippy::too_many_arguments)]
async fn upload(
    s: &TestServer,
    client: &reqwest::Client,
    token: &str,
    viewer: &starforged_core::accounts::User,
    owner: &str,
    repo: &str,
    ulid: &str,
    meta: Value,
    segments: &[Vec<String>],
) -> i64 {
    let meta_url = s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}"));
    let created = client
        .put(&meta_url)
        .bearer_auth(token)
        .json(&meta)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "{ulid} meta");
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
    }
    let access = s
        .core
        .repo_for(Some(viewer), owner, repo)
        .await
        .unwrap_or_else(|_| panic!("repo_for {owner}/{repo}"));
    db_sessions::session_by_ulid(s.core.db(), access.repo.id, ulid)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("session row {ulid}"))
        .id
}

fn viewer_url(s: &TestServer, owner: &str, repo: &str, ulid: &str) -> String {
    s.url(&format!("/{owner}/{repo}/sessions/{ulid}"))
}

fn kinds_fixture() -> Vec<Vec<String>> {
    vec![
        vec![
            event(0, "user_message", json!({"text": "hello viewer"})),
            event(
                1,
                "assistant_message",
                json!({"text": "answer with [redacted:known_token] inside", "model": "m1"}),
            ),
            event(2, "reasoning", json!({"text": "thinking it through"})),
            event(
                3,
                "tool_call",
                json!({"tool": {"name": "bash", "input": {"cmd": "ls <script>"}}}),
            ),
            event(
                4,
                "tool_result",
                json!({"result": {"output": "got <script>alert(1)</script> back", "is_error": true}}),
            ),
        ],
        vec![
            event(
                5,
                "file_change",
                json!({"path": "src/main.rs", "change": "modify",
                    "diff": "--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-old\n+new"}),
            ),
            event(6, "compaction", json!({"summary": "context compacted"})),
            event(
                7,
                "subagent_start",
                json!({"subagent_id": "agent-1", "task": "research widgets"}),
            ),
            event(
                8,
                "subagent_end",
                json!({"subagent_id": "agent-1", "task": "research widgets"}),
            ),
            event(9, "system", json!({"text": "session opened"})),
            event(
                10,
                "future_kind",
                json!({"extra": "<img src=x onerror=alert(1)>"}),
            ),
        ],
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_sees_kinds_and_strangers_get_404() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload_token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    upload(
        &s,
        &client,
        &upload_token,
        &alice,
        "alice",
        "proj",
        ULID_KINDS,
        meta_body(ULID_KINDS, false),
        &kinds_fixture(),
    )
    .await;
    let url = viewer_url(&s, "alice", "proj", ULID_KINDS);

    // Anonymous and stranger (no grant) on a private repo: 404, not 403.
    assert_eq!(client.get(&url).send().await.unwrap().status(), 404);
    let (bob, _) = s.login("bob").await;
    assert_eq!(bob.get(&url).send().await.unwrap().status(), 404);

    let (alice_client, _) = s.login("alice").await;
    let res = alice_client.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["x-robots-tag"], "noindex");
    let html = res.text().await.unwrap();

    // Header meta.
    for needle in [
        "pi",
        "2.1",
        "unverified",
        "m1",
        "m2",
        "feature/widget",
        "fp-1",
        "discovery",
        "2026-11-04 00:00 UTC",
    ] {
        assert!(html.contains(needle), "missing {needle:?} in:\n{html}");
    }
    // Every kind block present, with its event text.
    for needle in [
        "user_message",
        "assistant_message",
        "reasoning",
        "tool_call",
        "tool_result",
        "file_change",
        "compaction",
        "subagent_start",
        "subagent_end",
        "system",
        "future_kind",
        "hello viewer",
        "thinking",
        "through",
        "bash",
        "src/main.rs",
        "context",
        "compacted",
        "agent-1",
        "opened",
        "[redacted:known_token]",
    ] {
        assert!(html.contains(needle), "missing {needle:?} in:\n{html}");
    }
    // Active markup escaped, never raw (`onerror` survives only as inert
    // escaped text inside the unknown-kind `<pre>` block). The only
    // `<script>` allowed is the same-origin viewer ES module.
    let module_tag = r#"<script type="module" src="/static/session-viewer.js"></script>"#;
    assert_eq!(
        html.matches("<script").count(),
        html.matches(module_tag).count(),
        "raw script in:\n{html}"
    );
    assert!(!html.contains("<img"), "raw image in:\n{html}");
    // The untrusted frame stays visible and intact around prose.
    assert!(
        html.contains(r#"<div class="untrusted-frame">"#),
        "frame in:\n{html}"
    );
    assert!(
        html.contains("&lt;&lt;&lt;STARFORGE-UNTRUSTED-BEGINS&gt;&gt;&gt;"),
        "frame begins in:\n{html}"
    );
    assert!(
        html.contains("&lt;&lt;&lt;STARFORGE-UNTRUSTED-ENDS&gt;&gt;&gt;"),
        "frame ends in:\n{html}"
    );
    // Deep-link anchors.
    assert!(
        html.contains(r#"id="turn-0""#),
        "missing anchor in:\n{html}"
    );
    assert!(
        html.contains(r#"id="turn-10""#),
        "missing anchor in:\n{html}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_public_session_visible_to_stranger() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "open", Visibility::Public).await;
    let upload_token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let id = upload(
        &s,
        &client,
        &upload_token,
        &alice,
        "alice",
        "open",
        ULID_UNPUB,
        meta_body(ULID_UNPUB, true),
        &[vec![event(
            0,
            "user_message",
            json!({"text": "public draft"}),
        )]],
    )
    .await;
    let url = viewer_url(&s, "alice", "open", ULID_UNPUB);

    // Unpublished: stranger and anonymous 404 …
    assert_eq!(client.get(&url).send().await.unwrap().status(), 404);
    let (bob, _) = s.login("bob").await;
    assert_eq!(bob.get(&url).send().await.unwrap().status(), 404);
    // … but an explicit member reads it.
    s.core
        .set_collaborator(&alice, "alice", "open", "bob", Permission::Read)
        .await
        .unwrap();
    let member = bob.get(&url).send().await.unwrap();
    assert_eq!(member.status(), 200);
    assert!(member.text().await.unwrap().contains("public draft"));

    // Published: the stranger reads it.
    db_sessions::set_visibility(s.core.db(), id, "published")
        .await
        .unwrap();
    let stranger = client.get(&url).send().await.unwrap();
    assert_eq!(stranger.status(), 200);
    assert!(stranger.text().await.unwrap().contains("public draft"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantined_session_banner_redaction_and_admin_buttons() {
    assert!(
        PLANTED_TOKEN.len() - 4 >= 36,
        "planted token must trip known-token"
    );
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.user("dave").await;
    s.repo(&alice, "vault", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "vault", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "vault", "dave", Permission::Read)
        .await
        .unwrap();
    // Bob uploads: he is the uploader, a member, but not an admin.
    let bob_token = s.token(&bob, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    upload(
        &s,
        &client,
        &bob_token,
        &bob,
        "alice",
        "vault",
        ULID_QUAR,
        meta_body(ULID_QUAR, true),
        &[vec![
            event(0, "user_message", json!({"text": "check this output"})),
            event(
                1,
                "tool_result",
                json!({"result": {"output": format!("leaked {PLANTED_TOKEN} here")}}),
            ),
        ]],
    )
    .await;
    let url = viewer_url(&s, "alice", "vault", ULID_QUAR);

    // A member who is neither uploader nor admin 404s; so does anonymous.
    let (dave, _) = s.login("dave").await;
    assert_eq!(dave.get(&url).send().await.unwrap().status(), 404);
    assert_eq!(client.get(&url).send().await.unwrap().status(), 404);

    // The uploader sees the banner + content, but no admin buttons.
    let (bob_client, bob_csrf) = s.login("bob").await;
    let res = bob_client.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let html = res.text().await.unwrap();
    assert!(html.contains("quarantine"), "missing banner in:\n{html}");
    assert!(html.contains("known-token"), "missing reason in:\n{html}");
    assert!(
        html.contains("[redacted:known-token]"),
        "missing marker in:\n{html}"
    );
    assert!(
        !html.contains(PLANTED_TOKEN),
        "planted secret leaked in:\n{html}"
    );
    assert!(
        !html.contains("/sessions/01ARZ3NDEKTSV4RRFFQ69G5FC3/release"),
        "uploader must not see release in:\n{html}"
    );

    // The repo admin sees the banner + release/purge buttons.
    let (alice_client, alice_csrf) = s.login("alice").await;
    let admin_html = get_text(&alice_client, &url).await;
    assert!(admin_html.contains("quarantine"), "missing banner");
    assert!(
        admin_html.contains("/alice/vault/sessions/01ARZ3NDEKTSV4RRFFQ69G5FC3/release"),
        "missing release button in:\n{admin_html}"
    );
    assert!(
        admin_html.contains("/alice/vault/sessions/01ARZ3NDEKTSV4RRFFQ69G5FC3/purge"),
        "missing purge button in:\n{admin_html}"
    );
    assert!(
        !admin_html.contains(PLANTED_TOKEN),
        "planted secret leaked for admin"
    );

    // The download carries the same redacted transcript, never the secret.
    let download = bob_client
        .get(format!("{url}/download"))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(download.headers()["x-robots-tag"], "noindex");
    assert!(
        download.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert!(
        download.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("attachment")
    );
    let jsonl = download.text().await.unwrap();
    assert!(
        jsonl.contains("[redacted:known-token]"),
        "marker in:\n{jsonl}"
    );
    assert!(!jsonl.contains(PLANTED_TOKEN), "secret leaked in:\n{jsonl}");
    // A non-reader cannot download either.
    assert_eq!(
        dave.get(format!("{url}/download"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // A non-admin cannot release someone else's quarantine decision.
    let denied = bob_client
        .post(format!("{url}/release"))
        .form(&[("_csrf", bob_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);

    // The admin releases, then purges: content goes away with it.
    let released = alice_client
        .post(format!("{url}/release"))
        .form(&[("_csrf", alice_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), 303);
    let after = get_text(&alice_client, &url).await;
    assert!(!after.contains("quarantine"), "banner survived release");
    let purged = alice_client
        .post(format!("{url}/purge"))
        .form(&[("_csrf", alice_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(purged.status(), 303);
    assert_eq!(alice_client.get(&url).send().await.unwrap().status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pagination_focus_and_corrupt_segment() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "big", Visibility::Private).await;
    let upload_token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let mut lines = Vec::new();
    for i in 0..201u64 {
        lines.push(event(
            i,
            "user_message",
            json!({"text": format!("message number {i}")}),
        ));
    }
    upload(
        &s,
        &client,
        &upload_token,
        &alice,
        "alice",
        "big",
        ULID_BIG,
        meta_body(ULID_BIG, true),
        &[lines],
    )
    .await;
    let url = viewer_url(&s, "alice", "big", ULID_BIG);
    let (alice_client, _) = s.login("alice").await;

    // 201 events split into two pages with distinct content.
    let p1 = get_text(&alice_client, &format!("{url}?page=1")).await;
    assert!(p1.contains("Page 1 of 2"), "pager in:\n{p1}");
    assert!(p1.contains(r#"id="turn-0""#), "anchors in:\n{p1}");
    assert!(!p1.contains(r#"id="turn-200""#), "page split in:\n{p1}");
    let p2 = get_text(&alice_client, &format!("{url}?page=2")).await;
    assert!(p2.contains("Page 2 of 2"), "pager in:\n{p2}");
    assert!(p2.contains(r#"id="turn-200""#), "anchors in:\n{p2}");
    assert!(!p2.contains(r#"id="turn-0""#), "page split in:\n{p2}");
    assert_eq!(
        alice_client
            .get(format!("{url}?page=99"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Focus resolves to the containing page and marks the event.
    let focused = get_text(&alice_client, &format!("{url}?focus=200")).await;
    assert!(focused.contains(r#"id="turn-200""#), "focus in:\n{focused}");
    assert!(
        focused.contains("Page 2 of 2"),
        "focus pager in:\n{focused}"
    );
    let unknown_focus = get_text(&alice_client, &format!("{url}?focus=99999")).await;
    assert!(
        unknown_focus.contains("Page 1 of 2"),
        "unknown focus falls back in:\n{unknown_focus}"
    );

    // A corrupt segment renders an inline notice, never a 500.
    let garbage = b"definitely not a zstd stream".to_vec();
    let stored = s.core.config().blob_store.put(&garbage).await.unwrap();
    let corrupt_id = upload(
        &s,
        &client,
        &upload_token,
        &alice,
        "alice",
        "big",
        ULID_CORRUPT,
        meta_body(ULID_CORRUPT, true),
        &[vec![event(
            0,
            "user_message",
            json!({"text": "clean event"}),
        )]],
    )
    .await;
    db_sessions::insert_segment(
        s.core.db(),
        corrupt_id,
        1,
        1,
        1,
        &stored.hash,
        garbage.len() as i64,
    )
    .await
    .unwrap();
    let corrupt = alice_client
        .get(viewer_url(&s, "alice", "big", ULID_CORRUPT))
        .send()
        .await
        .unwrap();
    assert_eq!(corrupt.status(), 200);
    let corrupt_html = corrupt.text().await.unwrap();
    assert!(
        corrupt_html.contains("clean event"),
        "events in:\n{corrupt_html}"
    );
    assert!(
        corrupt_html.contains("unreadable segment"),
        "notice in:\n{corrupt_html}"
    );
}

const ULID_API: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC6";
const ULID_API_BIG: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC7";
const CLAIM_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_meta_events_and_download() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "apiproj", Visibility::Private).await;
    let upload_token = s.token(&alice, &[Scope::SessionUpload]).await;
    let alice_read = s.token(&alice, &[Scope::RepoRead]).await;
    let bob_read = s.token(&bob, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();
    let lines = vec![
        event(0, "user_message", json!({"text": "first"})),
        event(1, "user_message", json!({"text": "second"})),
        event(2, "user_message", json!({"text": "third"})),
    ];
    upload(
        &s,
        &client,
        &upload_token,
        &alice,
        "alice",
        "apiproj",
        ULID_API,
        meta_body(ULID_API, true),
        std::slice::from_ref(&lines),
    )
    .await;
    // One commit claim, so the meta `links` array is non-empty.
    let claimed = client
        .post(s.url(&format!("/api/v1/repos/alice/apiproj/sessions/{ULID_API}/links")))
        .bearer_auth(&upload_token)
        .json(&json!({"links": [{"sha": CLAIM_SHA, "confidence": "exact", "seq_start": 0, "seq_end": 2}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(claimed.status(), 200);
    let mut big_lines = Vec::new();
    for i in 0..201u64 {
        big_lines.push(event(
            i,
            "user_message",
            json!({"text": format!("big {i}")}),
        ));
    }
    upload(
        &s,
        &client,
        &upload_token,
        &alice,
        "alice",
        "apiproj",
        ULID_API_BIG,
        meta_body(ULID_API_BIG, true),
        &[big_lines],
    )
    .await;
    let meta_url = s.url(&format!("/api/v1/repos/alice/apiproj/sessions/{ULID_API}"));
    let events_url = s.url(&format!(
        "/api/v1/repos/alice/apiproj/sessions/{ULID_API_BIG}/events"
    ));

    // The uploader reads meta + links; a stranger 404s.
    let meta = client
        .get(&meta_url)
        .bearer_auth(&alice_read)
        .send()
        .await
        .unwrap();
    assert_eq!(meta.status(), 200);
    assert_eq!(meta.headers()["x-robots-tag"], "noindex");
    let meta_body: Value = meta.json().await.unwrap();
    assert_eq!(meta_body["ulid"], ULID_API);
    assert_eq!(meta_body["agent"]["name"], "pi");
    assert_eq!(meta_body["quarantine"]["state"], "none");
    assert_eq!(meta_body["links"][0]["sha"], CLAIM_SHA);
    assert_eq!(
        client
            .get(&meta_url)
            .bearer_auth(&bob_read)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Event pages mirror the viewer: page 2 holds only seq 200.
    let p2 = client
        .get(format!("{events_url}?page=2"))
        .bearer_auth(&alice_read)
        .send()
        .await
        .unwrap();
    assert_eq!(p2.status(), 200);
    assert_eq!(p2.headers()["x-robots-tag"], "noindex");
    let p2_body: Value = p2.json().await.unwrap();
    assert_eq!(p2_body["page"], 2);
    assert_eq!(p2_body["pages"], 2);
    assert_eq!(p2_body["total"], 201);
    assert_eq!(p2_body["events"].as_array().unwrap().len(), 1);
    assert_eq!(p2_body["events"][0]["seq"], 200);
    let p1_body: Value = client
        .get(format!("{events_url}?page=1"))
        .bearer_auth(&alice_read)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(p1_body["events"].as_array().unwrap().len(), 200);
    assert_eq!(
        client
            .get(format!("{events_url}?page=1"))
            .bearer_auth(&bob_read)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // The download is exactly the stored segment JSONL for clean sessions.
    let download_url = viewer_url(&s, "alice", "apiproj", ULID_API) + "/download";
    let (alice_client, _) = s.login("alice").await;
    let page = get_text(&alice_client, &viewer_url(&s, "alice", "apiproj", ULID_API)).await;
    assert!(page.contains("Commits (1)"), "{page}");
    let download = alice_client.get(&download_url).send().await.unwrap();
    assert_eq!(download.status(), 200);
    let mut expected = lines.join("\n");
    expected.push('\n');
    let body = download.text().await.unwrap();
    assert_eq!(body, expected);
    // A stranger cannot download.
    let (bob, _) = s.login("bob").await;
    assert_eq!(bob.get(&download_url).send().await.unwrap().status(), 404);
}
