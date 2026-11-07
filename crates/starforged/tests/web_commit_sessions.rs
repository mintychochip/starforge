//! E3: commit Sessions panel. A commit page lists each linked session the
//! viewer may read (agent, started_at, confidence, source, viewer link);
//! links the viewer may not read are omitted entirely — never a locked
//! chip, so private-session ULIDs do not leak onto public commit pages.
mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID_LINKED: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC1";
const ULID_TRAILER_ONLY: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC2";
const ULID_QUAR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC3";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": "panel fixture",
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
        "kind": "user_message", "text": "hello panel"})
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

/// Pushes one commit with `message` to a fresh public repo; returns its sha.
async fn push_repo_with_message(s: &TestServer, message: &str) -> (String, String) {
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
    (sha, tmp.path().to_string_lossy().into_owned())
}

/// Polls until a link row exists for `sha` (the post-push scan runs async).
async fn wait_for_trailer_link(s: &TestServer, repo_id: i64, sha: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let links = db_sessions::links_for_sha(s.core.db(), repo_id, sha)
            .await
            .unwrap();
        if !links.is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no trailer link filed for {sha}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_panel_shows_readable_link_with_confidence_and_deep_link() {
    let s = TestServer::start().await;
    let (sha, _tmp) = push_repo_with_message(&s, "linked work").await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let session_id = upload_session(&s, &token, "alice", "proj", ULID_LINKED).await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_LINKED,
        &sha,
        "exact",
        Some(5),
        Some(9),
    )
    .await
    .unwrap();
    // The session is unpublished (`inherit`); the owner still reads it.
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(
        html.contains("id=\"sessions\""),
        "panel missing in:\n{html}"
    );
    assert!(html.contains("pi"), "agent missing in:\n{html}");
    assert!(html.contains("exact"), "confidence missing in:\n{html}");
    assert!(html.contains("cli_claim"), "source missing in:\n{html}");
    assert!(
        html.contains(&format!("/alice/proj/sessions/{ULID_LINKED}#turn-5")),
        "deep link missing in:\n{html}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stranger_sees_no_chip_and_no_ulid_leak() {
    let s = TestServer::start().await;
    let (sha, _tmp) = push_repo_with_message(&s, "linked work").await;
    s.user("bob").await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let session_id = upload_session(&s, &token, "alice", "proj", ULID_LINKED).await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    // Unpublished session on a public repo: bob holds repo read but is not a
    // member, so he cannot read the session.
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_LINKED,
        &sha,
        "heuristic",
        None,
        None,
    )
    .await
    .unwrap();
    let (bob, _) = s.login("bob").await;
    let html = get_text(&bob, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(
        !html.contains("id=\"sessions\""),
        "panel leaked in:\n{html}"
    );
    assert!(!html.contains(ULID_LINKED), "ULID leaked in:\n{html}");

    // The commits list shows no count badge and no ULID either.
    let list = get_text(&bob, &s.url("/alice/proj/commits/main")).await;
    assert!(!list.contains(ULID_LINKED), "ULID leaked in list:\n{list}");
    assert!(!list.contains("#sessions"), "count leaked in list:\n{list}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_page_shows_readable_counts_for_five_commit_history() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(
            &s.token(&alice, &[Scope::SessionUpload, Scope::RepoWrite])
                .await,
        ),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let mut shas = Vec::new();
    for i in 0..4 {
        commit_files(
            &work,
            &[("a.txt", format!("one\n{i}\n").as_bytes())],
            &format!("change {i}"),
        )
        .await;
        shas.push(
            git_ok(&work, &["rev-parse", "HEAD"])
                .await
                .trim()
                .to_owned(),
        );
    }
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let session_id = upload_session(&s, &token, "alice", "proj", ULID_LINKED).await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    // Link two of the five commits (initial + 4 changes).
    for sha in shas.iter().take(2) {
        db_sessions::upsert_claim_link(
            s.core.db(),
            access.repo.id,
            session_id,
            ULID_LINKED,
            sha,
            "exact",
            Some(5),
            Some(5),
        )
        .await
        .unwrap();
    }
    // One batched page render covers all five commits (no per-commit query).
    let (alice_client, _) = s.login("alice").await;
    let list = get_text(&alice_client, &s.url("/alice/proj/commits/main")).await;
    assert_eq!(list.matches("1 session").count(), 2, "counts in:\n{list}");
    assert!(
        list.contains(&format!("/alice/proj/commit/{}#sessions", shas[0])),
        "anchor link in:\n{list}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_without_links_shows_no_card() {
    let s = TestServer::start().await;
    let (sha, _tmp) = push_repo_with_message(&s, "plain work").await;
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(!html.contains("id=\"sessions\""), "empty panel in:\n{html}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trailer_only_link_shows_no_card() {
    let s = TestServer::start().await;
    let trailed = format!("trailed work\n\nStarforge-Session: {ULID_TRAILER_ONLY}");
    let (sha, _tmp) = push_repo_with_message(&s, &trailed).await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    // The scan files the trailer row (no session row exists yet); the panel
    // skips upload-pending trailers, showing nothing rather than a placeholder.
    // (The ULID itself remains visible in the public commit message body —
    // that is the pusher's own data, not a panel leak.)
    wait_for_trailer_link(&s, access.repo.id, &sha).await;
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(
        !html.contains("id=\"sessions\""),
        "trailer placeholder in:\n{html}"
    );
    assert!(
        !html.contains("/sessions/"),
        "viewer link leaked in:\n{html}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantined_link_omitted_for_member_shown_for_admin() {
    let s = TestServer::start().await;
    let (sha, _tmp) = push_repo_with_message(&s, "linked work").await;
    let bob = s.user("bob").await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let session_id = upload_session(&s, &token, "alice", "proj", ULID_QUAR).await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_QUAR,
        &sha,
        "exact",
        Some(5),
        Some(9),
    )
    .await
    .unwrap();
    db_sessions::set_quarantine(s.core.db(), session_id, "quarantined", "test", "detail")
        .await
        .unwrap();
    let _ = bob;

    // Bob is a non-admin member: the quarantined session is omitted entirely.
    let (bob_client, _) = s.login("bob").await;
    let html = get_text(&bob_client, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(
        !html.contains("id=\"sessions\""),
        "quarantined panel leaked in:\n{html}"
    );
    assert!(
        !html.contains(ULID_QUAR),
        "quarantined ULID leaked in:\n{html}"
    );

    // Alice (owner/admin) still reads it under review.
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(
        html.contains("id=\"sessions\""),
        "admin panel missing in:\n{html}"
    );
    assert!(html.contains(ULID_QUAR), "admin link missing in:\n{html}");
}

/// M2f F3: the commit Sessions panel shows agent, models, token totals, the
/// title preview, and link confidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panel_shows_models_totals_preview_and_confidence() {
    let s = TestServer::start().await;
    let (sha, _tmp) = push_repo_with_message(&s, "linked work").await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let session_id = upload_session(&s, &token, "alice", "proj", ULID_LINKED).await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        ULID_LINKED,
        &sha,
        "exact",
        Some(5),
        Some(9),
    )
    .await
    .unwrap();
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(html.contains("m1"), "models missing in:\n{html}");
    assert!(
        html.contains("panel fixture"),
        "title preview missing in:\n{html}"
    );
    assert!(html.contains("exact"), "confidence missing in:\n{html}");
    assert!(
        html.contains("total 30"),
        "token totals missing in:\n{html}"
    );
}

/// M2f F3 XSS: a hostile session title renders escaped in the commit panel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_session_title_escapes_in_panel() {
    const HOSTILE: &str = "01ARZ3NDEKTSV4RRFFQ69G5FCC";
    let s = TestServer::start().await;
    let (sha, _tmp) = push_repo_with_message(&s, "linked work").await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let mut meta = meta_body(HOSTILE);
    meta["title"] = Value::String("<script>alert(9)</script>".to_owned());
    let res = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{HOSTILE}")))
        .bearer_auth(&token)
        .json(&meta)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "hostile upload");
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    let session_id = db_sessions::session_by_ulid(s.core.db(), access.repo.id, HOSTILE)
        .await
        .unwrap()
        .unwrap()
        .id;
    db_sessions::upsert_claim_link(
        s.core.db(),
        access.repo.id,
        session_id,
        HOSTILE,
        &sha,
        "exact",
        None,
        None,
    )
    .await
    .unwrap();
    let (alice_client, _) = s.login("alice").await;
    let html = get_text(&alice_client, &s.url(&format!("/alice/proj/commit/{sha}"))).await;
    assert!(
        !html.contains("<script>alert(9)"),
        "live script in:\n{html}"
    );
    assert!(
        html.contains("&#60;script&#62;alert(9)"),
        "escaped title in:\n{html}"
    );
}
