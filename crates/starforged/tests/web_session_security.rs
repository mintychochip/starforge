//! M1e E6: viewer XSS corpus, web CSRF matrix, API auth, and
//! quarantine-hidden enforcement. Seeds hostile sessions through the real
//! ingest HTTP wire (exactly as the CLI drives it), then asserts every
//! rendering surface escapes or sanitizes the payloads.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_HOSTILE: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD1";
const ULID_CSRF_PUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD2";
const ULID_CSRF_DEL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD3";
const ULID_CSRF_QUAR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD4";
const ULID_HIDDEN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD5";

const P_SCRIPT: &str = "<script>alert(1)</script>";
const P_IMG: &str = "<img src=x onerror=alert(1)>";
const P_SVG: &str = "<svg onload=alert(1)>";
const P_DETAILS: &str = "<details ontoggle=alert(1)>";
const P_JS_LINK: &str = "[click](javascript:alert(1))";
const P_ATTR: &str = "\" onmouseover=alert(1) x=\"";
const P_MARKER: &str = "<<<STARFORGE-UNTRUSTED-ENDS>>>";

const P_EVIL_IMG: &str = "![x](https://evil.example/p.png)";
/// External tracking beacon in Markdown image syntax: must never become a
/// live fetch when the session is viewed.
const P_TRACK_MD: &str = "![x](https://attacker.example/track.png)";
/// Same beacon as raw HTML inside prose (comrak passes raw HTML through;
/// the session sanitizer must drop the element).
const P_TRACK_HTML: &str = "<img src=\"https://attacker.example/t.svg\">";
/// Relative image: also removed — session prose has no legitimate image
/// use, so even same-origin `src` gets no exception.
const P_REL_IMG: &str = "![x](/static/x.png)";
/// for `known-token`). Trips the server quarantine scan.
const PLANTED_TOKEN: &str = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ12";

fn meta_body(ulid: &str, title: &str, agent_version: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": agent_version},
        "models": ["m1"],
        "title": title,
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": [],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
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

/// Uploads `meta` + `segments` as `token` bearer, exactly like the CLI.
#[allow(clippy::too_many_arguments)]
async fn upload(
    s: &TestServer,
    client: &reqwest::Client,
    token: &str,
    owner: &str,
    repo: &str,
    ulid: &str,
    meta: Value,
    segments: &[Vec<String>],
) {
    let meta_url = s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}"));
    let created = client
        .put(&meta_url)
        .bearer_auth(token)
        .json(&meta)
        .send()
        .await
        .unwrap();
    assert_eq!(
        created.status(),
        201,
        "{ulid} meta: {}",
        created.text().await.unwrap()
    );
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
}

/// Every renderer gets at least one hostile payload: prose (user/assistant),
/// reasoning, tool name/input/output, file path/diff, compaction summary,
/// subagent task, system text, and the unknown-kind raw block.
fn hostile_segments() -> Vec<Vec<String>> {
    vec![
        vec![
            event(
                0,
                "user_message",
                json!({"text": format!("hello {P_SCRIPT} {P_TRACK_HTML}")}),
            ),
            event(
                1,
                "assistant_message",
                json!({"text": format!("see {P_JS_LINK} and {P_EVIL_IMG} {P_TRACK_MD} {P_REL_IMG} **bold**"), "model": "m1"}),
            ),
            event(
                2,
                "reasoning",
                json!({"text": format!("mulling {P_SVG} over")}),
            ),
            event(
                3,
                "tool_call",
                json!({"tool": {"name": "bash", "input": {"cmd": P_IMG, "flag": P_ATTR}}}),
            ),
            event(
                4,
                "tool_result",
                json!({"result": {"output": format!("back {P_SCRIPT} {P_ATTR}")}}),
            ),
        ],
        vec![
            event(
                5,
                "file_change",
                json!({"path": "src/widget.rs", "change": "modify",
                    "diff": format!("--- a\n+++ b\n@@\n-{P_DETAILS}\n+fine")}),
            ),
            event(
                6,
                "compaction",
                json!({"summary": format!("compacted {P_SVG}")}),
            ),
            event(
                7,
                "subagent_start",
                json!({"subagent_id": "agent-1", "task": format!("research{P_ATTR}done")}),
            ),
            event(
                8,
                "subagent_end",
                json!({"subagent_id": "agent-1", "task": format!("researched {P_DETAILS}")}),
            ),
            event(
                9,
                "system",
                json!({"text": format!("opened\n{P_MARKER}\nnote {P_SCRIPT}")}),
            ),
            event(10, "future_kind", json!({"extra": P_IMG})),
        ],
    ]
}

/// The raw source-form payloads must never survive onto an HTML surface.
/// Each is transformed by at least one escaping layer (`<`/`>`/`"`/`<<<`),
/// so byte-absence is the correct oracle; `javascript:` must be stripped by
/// the Markdown sanitizer.
fn assert_no_raw_payloads(html: &str, surface: &str) {
    for raw in [
        P_SCRIPT,
        P_IMG,
        P_SVG,
        P_DETAILS,
        P_JS_LINK,
        P_ATTR,
        "javascript:",
        P_MARKER,
        P_EVIL_IMG,
        P_TRACK_MD,
        P_TRACK_HTML,
        P_REL_IMG,
        "attacker.example",
        "evil.example",
    ] {
        assert!(
            !html.contains(raw),
            "{surface}: raw payload {raw:?} survived in:\n{html}"
        );
    }
    // Active tag opens: the page legitimately contains `<details>` (tool
    // `<details>` blocks), so only the hostile open-tag forms are forbidden.
    // (`<img>` has no legitimate form on session surfaces — the prose
    // sanitizer drops image elements entirely; the viewer asserts that
    // separately below.)
    for raw in ["<script", "<svg", "<img src=x onerror", "<details ontoggle"] {
        assert!(
            !html.contains(raw),
            "{surface}: raw tag {raw:?} survived in:\n{html}"
        );
    }
}

/// Asserts the strict attacker-content CSP on viewer/download/blame
/// responses: nothing loads off-origin, no inline scripts.
fn assert_strict_csp(headers: &reqwest::header::HeaderMap, surface: &str) {
    let csp = headers["content-security-policy"].to_str().unwrap();
    for directive in [
        "default-src 'none'",
        "img-src 'self'",
        "style-src 'self'",
        "script-src 'self'",
    ] {
        assert!(
            csp.contains(directive),
            "{surface}: CSP {csp:?} lacks {directive}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_corpus_escaped_on_all_surfaces() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "vault", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "vault", "bob", Permission::Write)
        .await
        .unwrap();
    let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    upload(
        &s,
        &client,
        &bob_upload,
        "alice",
        "vault",
        ULID_HOSTILE,
        meta_body(ULID_HOSTILE, &format!("title {P_SCRIPT}"), "2.1"),
        &hostile_segments(),
    )
    .await;
    let page = s.url(&format!("/alice/vault/sessions/{ULID_HOSTILE}"));

    // 1. Viewer page: no raw payload anywhere, escaped text still present.
    // Attacker-influenced pages also carry the strict CSP as defense in
    // depth (no nonce mechanism exists — no page has inline scripts).
    let (bob_client, _) = s.login("bob").await;
    let viewer = bob_client.get(&page).send().await.unwrap();
    assert_eq!(viewer.status(), 200);
    assert_strict_csp(viewer.headers(), "viewer");
    let html = viewer.text().await.unwrap();
    assert_no_raw_payloads(&html, "viewer");
    assert!(html.contains("&lt;script&gt;"), "escaped text missing");
    assert!(html.contains("alert(1)"), "inert payload text missing");
    assert!(
        html.contains("&lt;&lt;&lt;STARFORGE-UNTRUSTED-BEGINS&gt;&gt;&gt;"),
        "untrusted frame begins missing"
    );
    // Each payload survives only as inert escaped text: the escaped form is
    // present, the raw tag/attribute form is gone (asserted above). Handler
    // substrings (`onerror=` etc.) legitimately occur inside those escaped
    // `<pre>` blocks, so byte-absence of the substring would be the wrong
    // oracle here.
    for escaped in [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&lt;img src=x onerror=alert(1)&gt;",
        "&lt;svg onload=alert(1)&gt;",
        "&lt;details ontoggle=alert(1)&gt;",
        "&quot; onmouseover=alert(1) x=&quot;",
    ] {
        assert!(html.contains(escaped), "escaped {escaped:?} missing");
    }
    // Tracking beacons are gone entirely: the session prose sanitizer drops
    // `<img>` elements (external, raw-HTML, and relative alike — session
    // prose has no legitimate image use), so no `img` with an external `src`
    // can phone home on view. Ordinary Markdown still renders.
    assert!(!html.contains("<img"), "live image element in:\n{html}");
    assert!(
        !html.contains("/static/x.png"),
        "relative image kept in:\n{html}"
    );
    assert!(
        html.contains("<strong>bold</strong>"),
        "markdown broke in:\n{html}"
    );
    let bob_read = s.token(&bob, &[Scope::RepoRead]).await;
    let meta = client
        .get(s.url(&format!(
            "/api/v1/repos/alice/vault/sessions/{ULID_HOSTILE}"
        )))
        .bearer_auth(&bob_read)
        .send()
        .await
        .unwrap();
    assert_eq!(meta.status(), 200);
    assert!(
        meta.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("application/json"),
        "meta is not JSON"
    );
    let meta_json: Value = meta.json().await.unwrap();
    assert_eq!(meta_json["ulid"], ULID_HOSTILE);
    let events = client
        .get(s.url(&format!(
            "/api/v1/repos/alice/vault/sessions/{ULID_HOSTILE}/events"
        )))
        .bearer_auth(&bob_read)
        .send()
        .await
        .unwrap();
    assert_eq!(events.status(), 200);
    assert!(
        events.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("application/json"),
        "events are not JSON"
    );

    // 3. Commit panel + blame chips: link the session, then assert both
    // surfaces carry the chip link with no raw payload.
    let alice_user = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let access = s
        .core
        .repo_for(Some(&alice_user), "alice", "vault")
        .await
        .unwrap();
    let session_id = db_sessions::session_by_ulid(s.core.db(), access.repo.id, ULID_HOSTILE)
        .await
        .unwrap()
        .unwrap()
        .id;
    let git_url = s.git_url(
        "alice",
        "vault",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "linked work").await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(&work, &["push", "-q", &git_url, "main"]).await;
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_HOSTILE,
        &sha,
        "exact",
        Some(0),
        Some(4),
    )
    .await
    .unwrap();
    let (alice_client, _) = s.login("alice").await;
    let commit = get_text(&alice_client, &s.url(&format!("/alice/vault/commit/{sha}"))).await;
    assert!(
        commit.contains(ULID_HOSTILE),
        "chip missing on commit panel"
    );
    assert_no_raw_payloads(&commit, "commit panel");
    let blame_res = alice_client
        .get(s.url("/alice/vault/blame/a.txt?at=main"))
        .send()
        .await
        .unwrap();
    assert_eq!(blame_res.status(), 200);
    assert_strict_csp(blame_res.headers(), "blame");
    let blame = blame_res.text().await.unwrap();
    assert!(blame.contains(ULID_HOSTILE), "chip missing on blame");
    assert_no_raw_payloads(&blame, "blame");

    // 4. Download: text/plain attachment carrying JSONL bytes, never HTML.
    let download = bob_client
        .get(format!("{page}/download"))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_strict_csp(download.headers(), "download");
    assert!(
        download.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain"),
        "download is not text/plain"
    );
    assert!(
        download.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("attachment"),
        "download is not an attachment"
    );
    let body = download.text().await.unwrap();
    assert!(!body.contains("<!DOCTYPE"), "download looks like HTML");
    for line in body.lines() {
        let value: Value = serde_json::from_str(line).expect("download line is JSON");
        assert!(value.get("kind").is_some(), "download line has no kind");
    }

    // 5. DOM-level browser assertions (no Playwright harness in this repo):
    // tool calls render as inline `<details>` (progressive enhancement, no
    // htmx fragment fetch), and the page carries no executable script.
    assert!(
        html.contains(r#"<details class="event event-tool-call">"#),
        "tool-call details missing"
    );
    assert!(html.contains(r#"id="turn-0""#), "turn anchor missing");
    assert!(!html.contains("<script"), "inline script in:\n{html}");
    assert!(!html.contains("hx-get"), "unexpected htmx in:\n{html}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_matrix_rejects_forgeries_without_state_change() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.core
        .set_collaborator(&alice, "alice", "open", "bob", Permission::Maintain)
        .await
        .unwrap();
    let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let text_segs = vec![vec![
        json!({"v": 1, "seq": 0, "ts": "2026-11-04T00:00:00Z",
            "kind": "user_message", "text": "csrf probe"})
        .to_string(),
    ]];
    upload(
        &s,
        &client,
        &bob_upload,
        "alice",
        "open",
        ULID_CSRF_PUB,
        meta_body(ULID_CSRF_PUB, "csrf pub", "1.0"),
        &text_segs,
    )
    .await;
    upload(
        &s,
        &client,
        &bob_upload,
        "alice",
        "open",
        ULID_CSRF_DEL,
        meta_body(ULID_CSRF_DEL, "csrf del", "1.0"),
        &text_segs,
    )
    .await;
    upload(
        &s,
        &client,
        &bob_upload,
        "alice",
        "open",
        ULID_CSRF_QUAR,
        meta_body(ULID_CSRF_QUAR, "csrf quar", "1.0"),
        &[vec![
            json!({"v": 1, "seq": 0, "ts": "2026-11-04T00:00:00Z",
                "kind": "tool_result",
                "result": {"output": format!("leaked {PLANTED_TOKEN}")}})
            .to_string(),
        ]],
    )
    .await;
    let (alice_client, _) = s.login("alice").await;
    let (_bob_client, bob_csrf) = s.login("bob").await;
    // A token minted for another session must not authorize this one.
    let foreign = bob_csrf.clone();

    let page = |ulid: &str| s.url(&format!("/alice/open/sessions/{ulid}"));
    // (action, ulid): publish/unpublish need a public repo; release/purge/
    // rescan need the quarantined session; delete needs its own session so
    // the probes cannot consume each other's fixtures.
    let posts = [
        ("publish", ULID_CSRF_PUB),
        ("unpublish", ULID_CSRF_PUB),
        ("delete", ULID_CSRF_DEL),
        ("release", ULID_CSRF_QUAR),
        ("purge", ULID_CSRF_QUAR),
        ("rescan", ULID_CSRF_QUAR),
    ];
    for (action, ulid) in posts {
        let url = format!("{}/{action}", page(ulid));
        // Missing token: empty form (the `CsrfForm` default) → 403.
        let missing = alice_client
            .post(&url)
            .form(&[("other", "x")])
            .send()
            .await
            .unwrap();
        assert_eq!(
            missing.status(),
            403,
            "{action}: missing token not rejected"
        );
        // Foreign token: another session's `_csrf` → 403.
        let forged = alice_client
            .post(&url)
            .form(&[("_csrf", foreign.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(forged.status(), 403, "{action}: foreign token not rejected");
    }

    // No state changed anywhere: visibility, quarantine, and rows intact.
    let alice_user = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let access = s
        .core
        .repo_for(Some(&alice_user), "alice", "open")
        .await
        .unwrap();
    for (ulid, visibility, quarantine) in [
        (ULID_CSRF_PUB, "inherit", "none"),
        (ULID_CSRF_DEL, "inherit", "none"),
        (ULID_CSRF_QUAR, "inherit", "quarantined"),
    ] {
        let row = db_sessions::session_by_ulid(s.core.db(), access.repo.id, ulid)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("session {ulid} vanished under CSRF probes"));
        assert_eq!(row.visibility, visibility, "{ulid} visibility moved");
        assert_eq!(row.quarantine, quarantine, "{ulid} quarantine moved");
    }
    // Forged posts are still visible as no-ops on the viewer too.
    let html = get_text(&alice_client, &page(ULID_CSRF_QUAR)).await;
    assert!(
        html.contains("quarantine"),
        "banner lost after forged release/purge"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_mutations_reject_unauthenticated_requests() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "open", Visibility::Public).await;
    let alice_upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let text_segs = vec![vec![
        json!({"v": 1, "seq": 0, "ts": "2026-11-04T00:00:00Z",
            "kind": "user_message", "text": "api auth probe"})
        .to_string(),
    ]];
    upload(
        &s,
        &client,
        &alice_upload,
        "alice",
        "open",
        ULID_CSRF_PUB,
        meta_body(ULID_CSRF_PUB, "api auth", "1.0"),
        &text_segs,
    )
    .await;
    let base = s.url(&format!(
        "/api/v1/repos/alice/open/sessions/{ULID_CSRF_PUB}"
    ));
    // The API carries no CSRF tokens — Bearer auth only. Without it, every
    // mutation answers 401. (Reads take an optional bearer and follow the
    // §6.4 read rules instead: an anonymous GET of this unpublished session
    // is 404, exactly like the viewer — covered by the quarantine test.)
    for (method, url) in [
        ("POST", format!("{base}/publish")),
        ("POST", format!("{base}/unpublish")),
        ("POST", format!("{base}/release")),
        ("POST", format!("{base}/purge")),
        ("POST", format!("{base}/rescan")),
        ("DELETE", base.clone()),
    ] {
        let request = match method {
            "POST" => client.post(&url),
            _ => client.delete(&url),
        };
        let status = request.send().await.unwrap().status();
        assert_eq!(status, 401, "{method} {url} without bearer: {status}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantine_hidden_from_member_but_visible_to_uploader_and_admin() {
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
    let bob_upload = s.token(&bob, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    upload(
        &s,
        &client,
        &bob_upload,
        "alice",
        "vault",
        ULID_HIDDEN,
        meta_body(ULID_HIDDEN, "hidden quar", "1.0"),
        &[vec![
            event(0, "user_message", json!({"text": "check this"})),
            event(
                1,
                "tool_result",
                json!({"result": {"output": format!("leaked {PLANTED_TOKEN}")}}),
            ),
        ]],
    )
    .await;
    let page = s.url(&format!("/alice/vault/sessions/{ULID_HIDDEN}"));
    let meta = s.url(&format!("/api/v1/repos/alice/vault/sessions/{ULID_HIDDEN}"));
    let events = format!("{meta}/events");
    let download = format!("{page}/download");

    // A member who is neither uploader nor admin: 404 on page, JSON meta,
    // events JSON, and download — for both anonymous and member principals.
    let (dave, _) = s.login("dave").await;
    let dave_read = s
        .token(
            &s.core.user_by_handle("dave").await.unwrap().unwrap(),
            &[Scope::RepoRead],
        )
        .await;
    for url in [&page, &meta, &events, &download] {
        assert_eq!(
            client.get(url).send().await.unwrap().status(),
            404,
            "anon {url}"
        );
        assert_eq!(
            dave.get(url).send().await.unwrap().status(),
            404,
            "member page {url}"
        );
        assert_eq!(
            client
                .get(url)
                .bearer_auth(&dave_read)
                .send()
                .await
                .unwrap()
                .status(),
            404,
            "member api {url}"
        );
    }

    // The uploader and the repo admin read everything.
    let (bob_client, _) = s.login("bob").await;
    let (alice_client, _) = s.login("alice").await;
    for (who, browser) in [("uploader", &bob_client), ("admin", &alice_client)] {
        for url in [&page, &download] {
            assert_eq!(
                browser.get(url).send().await.unwrap().status(),
                200,
                "{who} {url}"
            );
        }
    }
    let bob_read = s.token(&bob, &[Scope::RepoRead]).await;
    let alice_user = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let alice_read = s.token(&alice_user, &[Scope::RepoRead]).await;
    for (who, token) in [("uploader", &bob_read), ("admin", &alice_read)] {
        for url in [&meta, &events] {
            assert_eq!(
                client
                    .get(url)
                    .bearer_auth(token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                200,
                "{who} {url}"
            );
        }
    }
}
