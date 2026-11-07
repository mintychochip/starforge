//! E4: blame with sessions. `GET /{owner}/{repo}/blame/{path}?at=<ref>&page=N`
//! renders line-numbered code with per-block attribution (author, time,
//! short sha, summary) and session chips for linked sessions the viewer may
//! read. Unreadable links are omitted entirely — never a locked chip, so
//! private-session ULIDs do not leak onto blame pages.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_BLAME: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC9";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": "blame fixture",
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

/// Uploads `meta` + one segment as `token` bearer, exactly like the CLI.
/// Returns the session id.
async fn upload_session(s: &TestServer, token: &str, owner: &str, repo: &str, ulid: &str) -> i64 {
    let client = reqwest::Client::new();
    let meta_url = s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}"));
    let created = client
        .put(&meta_url)
        .bearer_auth(token)
        .json(&meta_body(ulid))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "{ulid} meta");
    let line = json!({"v": 1, "seq": 5, "ts": "2026-11-04T00:00:00Z",
        "kind": "user_message", "text": "hello blame"})
    .to_string()
        + "\n";
    let bytes = starforge_format::compress(line.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    let put = client
        .put(s.url(&format!(
            "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/0"
        )))
        .bearer_auth(token)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "{ulid} segment 0");
    let viewer = s.core.user_by_handle(owner).await.unwrap().unwrap();
    let access = s.core.repo_for(Some(&viewer), owner, repo).await.unwrap();
    db_sessions::session_by_ulid(s.core.db(), access.repo.id, ulid)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("session row {ulid}"))
        .id
}

async fn get_status(client: &reqwest::Client, url: &str) -> (reqwest::StatusCode, String) {
    let response = client.get(url).send().await.unwrap();
    let status = response.status();
    (status, response.text().await.unwrap())
}

/// Raw HTTP GET that bypasses client-side dot-segment normalization, so a
/// `..` traversal reaches the server exactly as written.
async fn raw_get_status(base: &str, target: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let host = base.trim_start_matches("http://").to_owned();
    let mut stream = tokio::net::TcpStream::connect(&host).await.unwrap();
    let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf);
    head.split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("no status in reply: {head}"))
        .parse()
        .unwrap()
}

/// Pushes a public repo whose `file.txt` has three commits: `sha1` owns line 2,
/// `sha2` owns lines 3-4, `sha3` owns line 1. `sha3`'s summary carries markup
/// to prove summaries render escaped.
async fn push_three_commit_repo(s: &TestServer) -> (String, String, String) {
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("file.txt", "l1\nl2\n")]).await;
    let sha1 = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    commit_files(&work, &[("file.txt", b"l1\nl2\nl3\nl4\n")], "second").await;
    let sha2 = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    commit_files(
        &work,
        &[("file.txt", b"L1\nl2\nl3\nl4\n")],
        "third <script>alert(1)</script>",
    )
    .await;
    let sha3 = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    (sha1, sha2, sha3)
}

async fn link_session(s: &TestServer, sha: &str) {
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let session_id = upload_session(s, &token, "alice", "proj", ULID_BLAME).await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_BLAME,
        sha,
        "exact",
        Some(5),
        Some(9),
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blame_shows_blocks_in_order_with_session_chip() {
    let s = TestServer::start().await;
    let (sha1, sha2, sha3) = push_three_commit_repo(&s).await;
    link_session(&s, &sha1).await;
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url("/alice/proj/blame/file.txt?at=main")).await;
    for sha in [&sha1, &sha2, &sha3] {
        assert!(html.contains(&sha[..8]), "short sha missing in:\n{html}");
    }
    // Contiguous runs render oldest-last here: line 1 is sha3, line 2 is
    // sha1, lines 3-4 are sha2.
    let i3 = html.find(&sha3[..8]).unwrap();
    let i1 = html.find(&sha1[..8]).unwrap();
    let i2 = html.find(&sha2[..8]).unwrap();
    assert!(i3 < i1 && i1 < i2, "blocks out of order in:\n{html}");
    for n in 1..=4 {
        assert!(html.contains(&format!("id=\"L{n}\"")), "line {n} missing");
    }
    // The linked session renders as a chip with a viewer deep link.
    assert!(html.contains(ULID_BLAME), "chip missing in:\n{html}");
    assert!(
        html.contains(&format!("/alice/proj/sessions/{ULID_BLAME}#turn-5")),
        "deep link missing in:\n{html}"
    );
    // Omitting `at` falls back to the default branch.
    let fallback = get_text(&alice_client, &s.url("/alice/proj/blame/file.txt")).await;
    assert!(
        fallback.contains(&sha3[..8]),
        "default-branch fallback failed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stranger_sees_no_chips_but_page_renders() {
    let s = TestServer::start().await;
    let (sha1, _sha2, sha3) = push_three_commit_repo(&s).await;
    // Unpublished session on a public repo: bob is not a member, so the
    // chip (and its ULID) must stay hidden while the page still renders.
    link_session(&s, &sha1).await;
    s.user("bob").await;
    let (bob, _) = s.login("bob").await;
    let html = get_text(&bob, &s.url("/alice/proj/blame/file.txt?at=main")).await;
    assert!(html.contains(&sha3[..8]), "page did not render in:\n{html}");
    assert!(!html.contains(ULID_BLAME), "ULID leaked in:\n{html}");
    assert!(!html.contains("session-chips"), "chip leaked in:\n{html}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_path_and_rev_are_404() {
    let s = TestServer::start().await;
    push_three_commit_repo(&s).await;
    let (alice_client, _) = s.login("alice").await;
    let (status, _) = get_status(&alice_client, &s.url("/alice/proj/blame/nope.txt?at=main")).await;
    assert_eq!(status, 404, "unknown path was not 404");
    let (status, _) = get_status(
        &alice_client,
        &s.url("/alice/proj/blame/file.txt?at=no-such-rev"),
    )
    .await;
    assert_eq!(status, 404, "unknown rev was not 404");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traversal_path_is_404() {
    let s = TestServer::start().await;
    push_three_commit_repo(&s).await;
    let status = raw_get_status(&s.base, "/alice/proj/blame/../../etc/passwd?at=main").await;
    assert_eq!(status, 404, "traversal was not 404");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_file_paginates_with_continuation_headers() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let mut body = String::new();
    for i in 1..=501 {
        body.push_str(&format!("line-{i:03}\n"));
    }
    let work = work_repo(tmp.path(), "work", &[("big.txt", &body)]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let (alice_client, _) = s.login("alice").await;
    let page1 = get_text(&alice_client, &s.url("/alice/proj/blame/big.txt?at=main")).await;
    assert!(page1.contains("line-500"), "page 1 truncated early");
    assert!(!page1.contains("line-501"), "page 1 leaked past 500 lines");
    let page2 = get_text(
        &alice_client,
        &s.url("/alice/proj/blame/big.txt?at=main&page=2"),
    )
    .await;
    assert!(page2.contains("line-501"), "page 2 missing line 501");
    assert!(
        page2.contains("continued"),
        "page 2 header not marked continuation in:\n{page2}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_summary_renders_escaped() {
    let s = TestServer::start().await;
    push_three_commit_repo(&s).await;
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url("/alice/proj/blame/file.txt?at=main")).await;
    assert!(
        html.contains("&#60;script&#62;"),
        "summary not escaped in:\n{html}"
    );
    assert!(
        !html.contains("<script>alert"),
        "raw script tag in:\n{html}"
    );
}
