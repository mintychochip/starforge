//! M5c V2: session viewer completeness (D3). Commit markers, per-turn
//! usage, in-session search, and split view — server-rendered (the page is
//! complete without JS), §6.4-authorized, XSS-safe, and redaction-safe.
//!
//! Seeds sessions through the real ingest HTTP wire (exactly as the CLI
//! drives it), then asserts behaviour on the HTML surface.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_VIEWER: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD1";
const ULID_SEARCH: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD2";
const ULID_LIMIT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD3";
const ULID_SPLIT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD4";
const ULID_VIS: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD5";
const ULID_XSS: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD6";

/// A realistic `ghp_` classic token (38 alphanumerics, over the 36 minimum
/// for `known-token`). It travels only inside segment bytes; search
/// previews and every new rendering path must never carry it raw.
const PLANTED_TOKEN: &str = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ12";

fn meta_body(ulid: &str, verified: bool) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1", "m2"],
        "title": "viewer completeness fixture",
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
    let access = s.core.repo_for(Some(viewer), owner, repo).await.unwrap();
    db_sessions::session_by_ulid(s.core.db(), access.repo.id, ulid)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("session row {ulid}"))
        .id
}

fn viewer_url(s: &TestServer, owner: &str, repo: &str, ulid: &str) -> String {
    s.url(&format!("/{owner}/{repo}/sessions/{ulid}"))
}

/// Pushes one commit with `message` to a fresh public repo owned by alice;
/// returns its sha.
async fn push_repo_with_message(s: &TestServer, message: &str) -> String {
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], message).await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    drop(tmp);
    sha
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_markers_and_per_turn_usage_render() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let session_id = upload(
        &s,
        &client,
        &token,
        &alice,
        "alice",
        "proj",
        ULID_VIEWER,
        meta_body(ULID_VIEWER, true),
        &[vec![
            event(0, "user_message", json!({"text": "first turn"})),
            event(
                1,
                "assistant_message",
                json!({"text": "answer one", "model": "m1",
                    "usage": {"input": 111, "output": 222, "cache_read": 33,
                        "cache_write": 44, "reasoning": 55}}),
            ),
            event(2, "user_message", json!({"text": "second turn"})),
            event(
                3,
                "assistant_message",
                json!({"text": "answer two", "model": "m1",
                    "usage": {"input": 0, "output": 0, "cache_read": 0,
                        "cache_write": 0, "reasoning": 0}}),
            ),
            event(4, "user_message", json!({"text": "third turn"})),
        ]],
    )
    .await;
    let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_VIEWER,
        sha,
        "exact",
        Some(0),
        Some(2),
    )
    .await
    .unwrap();

    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &viewer_url(&s, "alice", "proj", ULID_VIEWER)).await;

    // The marker renders after the `seq_end` event (turn-2) and before the
    // next event (turn-3), showing the short sha with commit/split links.
    let turn2 = html.find(r#"id="turn-2""#).expect("turn-2 anchor");
    let marker = html.find("commit-marker").expect("commit marker");
    let turn3 = html.find(r#"id="turn-3""#).expect("turn-3 anchor");
    assert!(turn2 < marker, "marker must follow turn-2:\n{html}");
    assert!(marker < turn3, "marker must precede turn-3:\n{html}");
    assert!(html.contains("aaaaaaa"), "short sha in:\n{html}");
    assert!(
        html.contains(&format!("/alice/proj/commit/{sha}")),
        "commit page link in:\n{html}"
    );
    assert!(
        html.contains(&format!("?split={sha}")),
        "split view link in:\n{html}"
    );

    // Per-turn usage: the assistant turn with nonzero usage shows all five
    // counters inside its own article; the zero-usage turn shows none.
    let turn1 = html.find(r#"id="turn-1""#).expect("turn-1 anchor");
    let turn2_pos = html[turn1..].find(r#"id="turn-2""#).unwrap() + turn1;
    let turn1_html = &html[turn1..turn2_pos];
    for needle in [
        "input 111",
        "output 222",
        "cache read 33",
        "cache write 44",
        "reasoning 55",
    ] {
        assert!(
            turn1_html.contains(needle),
            "missing usage {needle:?} in:\n{turn1_html}"
        );
    }
    let turn3_pos = html[turn3..]
        .find(r#"id="turn-4""#)
        .unwrap_or(html.len() - turn3)
        + turn3;
    let turn3_html = &html[turn3..turn3_pos];
    assert!(
        !turn3_html.contains("event-usage"),
        "zero usage must render no usage line in:\n{turn3_html}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_finds_page_two_and_respects_scope_and_redaction() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    // 203 events: page 1 holds seq 0..=199, page 2 holds seq 200..=202.
    let mut lines: Vec<String> = (0..200)
        .map(|seq| {
            event(
                seq,
                "user_message",
                json!({"text": format!("filler {seq}")}),
            )
        })
        .collect();
    lines.push(event(
        200,
        "user_message",
        json!({"text": format!("needle-XYZ and {PLANTED_TOKEN}")}),
    ));
    lines.push(event(
        201,
        "tool_call",
        json!({"tool": {"name": "needle-tool", "input": {"x": "needle-only-input"}}}),
    ));
    lines.push(event(
        202,
        "file_change",
        json!({"path": "src/needle-file.rs", "change": "modify"}),
    ));
    upload(
        &s,
        &client,
        &token,
        &alice,
        "alice",
        "proj",
        ULID_SEARCH,
        meta_body(ULID_SEARCH, true),
        &[lines],
    )
    .await;

    let (alice_client, _) = s.login("alice").await;
    let url = viewer_url(&s, "alice", "proj", ULID_SEARCH);

    // The page-2 hit links to page 2 and to its `#turn-<seq>` anchor.
    let html = get_text(&alice_client, &format!("{url}?q=needle-xyz")).await;
    assert!(html.contains("search-results"), "results in:\n{html}");
    assert!(html.contains("page=2"), "page-2 link in:\n{html}");
    assert!(html.contains("focus=200"), "focus link in:\n{html}");
    assert!(html.contains("#turn-200"), "anchor link in:\n{html}");
    // The planted token in the matching message is redacted before search:
    // the preview shows the marker, never the raw secret.
    assert!(
        html.contains("[redacted:known-token]"),
        "redaction marker in preview:\n{html}"
    );
    assert!(
        !html.contains(PLANTED_TOKEN),
        "planted secret leaked via search:\n{html}"
    );

    // Tool names and file paths are searched.
    let html = get_text(&alice_client, &format!("{url}?q=needle-tool")).await;
    assert!(html.contains("#turn-201"), "tool name hit in:\n{html}");
    let html = get_text(&alice_client, &format!("{url}?q=needle-file")).await;
    assert!(html.contains("#turn-202"), "file path hit in:\n{html}");

    // Tool inputs are not searched (spec §10.5 scope): the needle exists
    // only inside a tool input, so there are no hits.
    let html = get_text(&alice_client, &format!("{url}?q=needle-only-input")).await;
    assert!(html.contains("0 hits"), "no tool-input hits in:\n{html}");
    assert!(
        !html.contains("#turn-201"),
        "tool input must not hit:\n{html}"
    );

    // Case-insensitive: an upper-case query finds the lower-case text.
    let html = get_text(&alice_client, &format!("{url}?q=NEEDLE-XYZ")).await;
    assert!(
        html.contains("#turn-200"),
        "case-insensitive hit in:\n{html}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_is_limited_to_200_hits_and_escapes_the_query() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    // 210 matching events: the search must cap at exactly 200 hits.
    let lines: Vec<String> = (0..210)
        .map(|seq| event(seq, "user_message", json!({"text": "hitme filler"})))
        .collect();
    upload(
        &s,
        &client,
        &token,
        &alice,
        "alice",
        "proj",
        ULID_LIMIT,
        meta_body(ULID_LIMIT, true),
        &[lines],
    )
    .await;

    let (alice_client, _) = s.login("alice").await;
    let url = viewer_url(&s, "alice", "proj", ULID_LIMIT);
    let html = get_text(&alice_client, &format!("{url}?q=hitme")).await;
    assert_eq!(
        html.matches(r#"class="search-hit""#).count(),
        200,
        "exactly 200 hits:\n{html}"
    );
    assert!(html.contains("200 hits"), "hit count in:\n{html}");
    // The 201st matching event (seq 200) is beyond the cap.
    assert!(!html.contains("#turn-200"), "cap overflow in:\n{html}");

    // A hostile query is echoed escaped, never raw (numeric entities).
    let html = get_text(
        &alice_client,
        &format!("{url}?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    )
    .await;
    assert!(!html.contains("<script>alert"), "raw query echoed:\n{html}");
    assert!(
        html.contains("&#60;script&#62;") || html.contains("&lt;script&gt;"),
        "escaped query in:\n{html}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_view_renders_diff_and_refuses_unlinked_and_unreadable() {
    let s = TestServer::start().await;
    let sha = push_repo_with_message(&s, "split target").await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let session_id = upload(
        &s,
        &client,
        &token,
        &alice,
        "alice",
        "proj",
        ULID_SPLIT,
        meta_body(ULID_SPLIT, false),
        &[vec![event(
            0,
            "user_message",
            json!({"text": "split fixture"}),
        )]],
    )
    .await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_SPLIT,
        &sha,
        "exact",
        Some(0),
        Some(0),
    )
    .await
    .unwrap();
    let (alice_client, _) = s.login("alice").await;
    let url = viewer_url(&s, "alice", "proj", ULID_SPLIT);

    // The split view renders the commit's diff beside the transcript.
    let html = get_text(&alice_client, &format!("{url}?split={sha}")).await;
    assert!(html.contains("split-col"), "split column in:\n{html}");
    assert!(html.contains("split fixture"), "transcript in:\n{html}");
    assert!(html.contains("two"), "diff body in:\n{html}");
    assert!(html.contains("a.txt"), "diff path in:\n{html}");

    // A sha that is not linked to this session is refused with 404.
    let res = alice_client
        .get(format!(
            "{url}?split=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // A user without repository read cannot use the split view either.
    // (Private repo below: the stranger has no grant at all.)
    let s2 = TestServer::start().await;
    let carol = s2.user("carol").await;
    s2.repo(&carol, "vault", Visibility::Private).await;
    let carol_token = s2.token(&carol, &[Scope::SessionUpload]).await;
    let s2_session = upload(
        &s2,
        &client,
        &carol_token,
        &carol,
        "carol",
        "vault",
        ULID_VIS,
        meta_body(ULID_VIS, true),
        &[vec![event(
            0,
            "user_message",
            json!({"text": "private fixture"}),
        )]],
    )
    .await;
    let carol_access = s2
        .core
        .repo_for(Some(&carol), "carol", "vault")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s2.core.db(),
        carol_access.repo.id,
        s2_session,
        ULID_VIS,
        &sha,
        "exact",
        Some(0),
        Some(0),
    )
    .await
    .unwrap();
    s2.user("mallory").await;
    let (mallory, _) = s2.login("mallory").await;
    let res = mallory
        .get(s2.url(&format!("/carol/vault/sessions/{ULID_VIS}?split={sha}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404, "stranger must not reach split view");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_is_complete_without_js() {
    // A plain HTTP fetch (no script execution, ever): the search results
    // and the split columns must already exist server-side.
    let s = TestServer::start().await;
    let sha = push_repo_with_message(&s, "no js").await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let session_id = upload(
        &s,
        &client,
        &token,
        &alice,
        "alice",
        "proj",
        ULID_XSS,
        meta_body(ULID_XSS, true),
        &[vec![
            event(0, "user_message", json!({"text": "needle-nojs"})),
            event(
                1,
                "file_change",
                json!({"path": "<script>alert(1)</script>.txt", "change": "modify"}),
            ),
        ]],
    )
    .await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_XSS,
        &sha,
        "exact",
        Some(0),
        Some(1),
    )
    .await
    .unwrap();

    let url = viewer_url(&s, "alice", "proj", ULID_XSS);
    // The owner (uploader) fetches with both parameters over plain HTTP.
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &format!("{url}?q=needle-nojs&split={sha}")).await;
    assert!(
        html.contains("search-results"),
        "server results in:\n{html}"
    );
    assert!(html.contains("#turn-0"), "server search link in:\n{html}");
    assert!(
        html.contains("split-col"),
        "server split column in:\n{html}"
    );
    assert!(
        html.contains("transcript-col"),
        "transcript column in:\n{html}"
    );
    assert!(html.contains("commit-marker"), "server marker in:\n{html}");
    assert!(html.contains("commit/"), "marker commit link in:\n{html}");
    assert!(html.contains("two"), "server diff in:\n{html}");

    // The hostile file path renders escaped in the transcript and in the
    // search preview — never as live markup.
    assert!(!html.contains("<script>alert"), "raw payload:\n{html}");
    let html = get_text(&alice_client, &format!("{url}?q=script")).await;
    assert!(html.contains("#turn-1"), "hostile path hit in:\n{html}");
    assert!(
        !html.contains("<script>alert"),
        "raw payload in search:\n{html}"
    );
    assert!(
        html.contains("&#60;script&#62;") || html.contains("&lt;script&gt;"),
        "escaped preview in:\n{html}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visibility_rules_apply_to_search_split_and_markers() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let session_id = upload(
        &s,
        &client,
        &token,
        &alice,
        "alice",
        "proj",
        ULID_VIS,
        meta_body(ULID_VIS, true),
        &[vec![event(
            0,
            "user_message",
            json!({"text": "vis needle"}),
        )]],
    )
    .await;
    let sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_VIS,
        sha,
        "exact",
        Some(0),
        Some(0),
    )
    .await
    .unwrap();
    let url = viewer_url(&s, "alice", "proj", ULID_VIS);

    // Unpublished on a public repo: a stranger (no membership) gets 404 for
    // the viewer with search and split parameters alike (§6.4 rule 2).
    let (bob, _) = s.login("bob").await;
    let split_q = format!("?split={sha}");
    for query in ["", "?q=needle", split_q.as_str()] {
        let res = bob.get(format!("{url}{query}")).send().await.unwrap();
        assert_eq!(res.status(), 404, "stranger with {query:?}");
    }

    // Published: the stranger may read the session, search, and markers —
    // but the split sha here is linked yet has no commit, so it 404s at
    // the git lookup (still a denial, never a leak).
    db_sessions::set_visibility(s.core.db(), session_id, "published")
        .await
        .unwrap();
    let html = get_text(&bob, &format!("{url}?q=needle")).await;
    assert!(html.contains("#turn-0"), "published search in:\n{html}");
    assert!(
        html.contains("commit-marker"),
        "published marker in:\n{html}"
    );
    let res = bob.get(format!("{url}?split={sha}")).send().await.unwrap();
    assert_eq!(res.status(), 404, "phantom commit must 404");

    // Quarantined: the uploader keeps reading (banner visible); a stranger
    // is denied on every viewer surface.
    db_sessions::set_quarantine(
        s.core.db(),
        session_id,
        "quarantined",
        "known-token",
        "test",
    )
    .await
    .unwrap();
    let res = bob.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 404, "quarantined stranger");
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &format!("{url}?q=needle")).await;
    assert!(html.contains("quarantine"), "uploader banner in:\n{html}");
    assert!(html.contains("#turn-0"), "uploader search in:\n{html}");
}
