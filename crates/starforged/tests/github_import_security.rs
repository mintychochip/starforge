//! M4c G3 security tests: the GitHub import API and settings page —
//! admin-only start, the 404/403 access matrix, archived refusal,
//! CSRF gating, and token secrecy (the token never appears in any
//! response, page, or stored error), plus XSS escaping of imported
//! content on the Trail pages it lands on.

mod common;

use std::time::{Duration, Instant};

use common::fake_github::FakeGithub;
use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::CreateUser;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const TOKEN: &str = "ghp_SECRETGITHUBTOKEN12345";

async fn api(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (u16, String, Value) {
    let req = match method {
        "PUT" => client.put(url),
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };
    let req = match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    };
    let req = match body {
        Some(b) => req.json(b),
        None => req,
    };
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    let text = res.text().await.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, text, v)
}

async fn pull_remote() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let work = work_repo(
        dir.path(),
        "remote",
        &[("src/main.rs", "line1\nline2\nline3\nline4\nline5\n")],
    )
    .await;
    git_ok(&work, &["checkout", "-q", "-b", "pr4"]).await;
    commit_files(
        &work,
        &[(
            "src/main.rs",
            b"line1\nline2\nline3\nline4 changed\nline5\n",
        )],
        "pr4 change",
    )
    .await;
    let head4 = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(&work, &["update-ref", "refs/pull/4/head", &head4]).await;
    git_ok(&work, &["update-ref", "refs/pull/2/head", &head4]).await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    (dir, format!("file://{}", work.display()))
}

async fn import_server(fake_base: String) -> TestServer {
    TestServer::start_with(move |config| {
        config.github.api_url = fake_base.clone();
        config.remotes.allow_file_urls = true;
    })
    .await
}

async fn alice_and_repo(
    s: &TestServer,
) -> (
    starforged_core::accounts::User,
    starforged_core::repos::Repo,
) {
    let alice = s
        .core
        .create_user(CreateUser {
            handle: "alice".into(),
            email: Some("octo@example.test".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    (alice, repo)
}

/// Polls the status endpoint until `state == want` (bounded 15 s).
async fn poll_state(s: &TestServer, token: &str, want: &str) -> (u16, String, Value) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let out = api(
            &client,
            "GET",
            &s.url("/api/v1/repos/alice/proj/import/github"),
            Some(token),
            None,
        )
        .await;
        if out.2["state"].as_str() == Some(want) || Instant::now() > deadline {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn api_start_and_status_report_progress_without_token() {
    let (_dir, file_url) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, _repo) = alice_and_repo(&s).await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let client = reqwest::Client::new();

    // No import yet: status is 404.
    let (status, _, _) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&rw),
        None,
    )
    .await;
    assert_eq!(status, 404);

    let (status, text, v) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&rw),
        Some(&json!({"repository": "octo/proj", "token": TOKEN})),
    )
    .await;
    assert_eq!(status, 202, "{text}");
    assert_eq!(v["state"], "pending");
    assert_eq!(v["source"], "octo/proj");
    assert!(!text.contains(TOKEN), "the token is never echoed: {text}");
    assert!(v.get("token").is_none() && v.get("token_sealed").is_none());

    let (_status, text, v) = poll_state(&s, &rw, "completed").await;
    assert_eq!(v["state"], "completed", "{text}");
    assert_eq!(v["issues_count"], json!(2));
    assert_eq!(v["pulls_count"], json!(2));
    assert_eq!(v["comments_count"], json!(2));
    assert_eq!(v["dropped_assignees"], json!(["hubot"]));
    assert_eq!(v["has_token"], false, "token deleted on finish");
    assert!(
        !text.contains(TOKEN),
        "status never carries the token: {text}"
    );

    // The audit rows were written.
    for action in ["repo.github_import_started", "repo.github_import_finished"] {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1")
            .bind(action)
            .fetch_one(s.db().pool())
            .await
            .unwrap();
        assert_eq!(n, 1, "audit {action}");
    }
}

#[tokio::test]
async fn api_access_matrix_404_403_and_archived() {
    let (_dir, file_url) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, _repo) = alice_and_repo(&s).await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();
    let alice_rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let bob_rw = s.token(&bob, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let carol_ro = s.token(&carol, &[Scope::RepoRead]).await;
    let mallory = s.user("mallory").await;
    let mallory_rw = s
        .token(&mallory, &[Scope::RepoRead, Scope::RepoWrite])
        .await;
    let body = json!({"repository": "octo/proj", "token": TOKEN});
    let client = reqwest::Client::new();

    // A non-reader gets 404 on both endpoints (indistinguishable from
    // a missing repository).
    for method in ["POST", "GET"] {
        let (status, text, _) = api(
            &client,
            method,
            &s.url("/api/v1/repos/alice/proj/import/github"),
            Some(&mallory_rw),
            if method == "POST" { Some(&body) } else { None },
        )
        .await;
        assert_eq!(status, 404, "non-reader {method}: {text}");
    }
    // Unauthenticated POST gets 401.
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        None,
        Some(&body),
    )
    .await;
    assert_eq!(status, 401);
    // Below admin (write collaborator) gets 403 on start; the read
    // collaborator cannot even hold repo:write, also 403.
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&bob_rw),
        Some(&body),
    )
    .await;
    assert_eq!(status, 403, "write collaborator cannot start");
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&carol_ro),
        Some(&body),
    )
    .await;
    assert_eq!(status, 403, "reader lacks repo:write");

    // Archived repositories refuse the import (422).
    s.core.archive_repo(&alice, "alice", "proj").await.unwrap();
    let (status, text, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&alice_rw),
        Some(&body),
    )
    .await;
    assert_eq!(status, 422, "archived: {text}");
    assert!(!text.contains(TOKEN));

    // A bad slug and an empty token are 422, never 500.
    s.core
        .unarchive_repo(&alice, "alice", "proj")
        .await
        .unwrap();
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&alice_rw),
        Some(&json!({"repository": "not-a-slug", "token": TOKEN})),
    )
    .await;
    assert_eq!(status, 422);
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&alice_rw),
        Some(&json!({"repository": "octo/proj", "token": " "})),
    )
    .await;
    assert_eq!(status, 422);
}

#[tokio::test]
async fn web_page_start_progress_and_csrf() {
    let (_dir, file_url) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, repo) = alice_and_repo(&s).await;
    let _bob = s.user("bob").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let _mallory = s.user("mallory").await;

    let (browser, csrf) = s.login("alice").await;
    let page = get_text(&browser, &s.url("/alice/proj/settings/github-import")).await;
    assert!(page.contains("Import from GitHub"), "{page}");
    assert!(page.contains(&csrf), "page carries the CSRF token");

    // A wrong CSRF token is refused with 403; a missing field fails
    // form deserialization with 422 (the codebase convention).
    let denied = browser
        .post(s.url("/alice/proj/settings/github-import"))
        .form(&[
            ("_csrf", "wrong-csrf"),
            ("repository", "octo/proj"),
            ("token", TOKEN),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403, "wrong CSRF must fail");
    let missing = browser
        .post(s.url("/alice/proj/settings/github-import"))
        .form(&[("repository", "octo/proj"), ("token", TOKEN)])
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 422, "missing CSRF field must fail");

    // Start with CSRF: 303 back to the page, progress visible, no token.
    let started = browser
        .post(s.url("/alice/proj/settings/github-import"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("repository", "octo/proj"),
            ("token", TOKEN),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(started.status(), 303, "start redirects to progress");

    // Bounded poll on the import row, then the page shows counts and
    // the dropped-assignee summary.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let row = starforged_db::github_imports::import_of_repo(s.db(), repo.id)
            .await
            .unwrap()
            .unwrap();
        if row.state == "completed" || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let page = get_text(&browser, &s.url("/alice/proj/settings/github-import")).await;
    assert!(page.contains("completed"), "{page}");
    assert!(page.contains("hubot"), "dropped assignees listed: {page}");
    assert!(!page.contains(TOKEN), "page never renders the token");

    // Access: a write collaborator gets 403 on the page; a non-reader
    // gets 404.
    let (bob_browser, _) = s.login("bob").await;
    let r = bob_browser
        .get(s.url("/alice/proj/settings/github-import"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "below admin gets 403");
    let (mallory_browser, _) = s.login("mallory").await;
    let r = mallory_browser
        .get(s.url("/alice/proj/settings/github-import"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "non-reader gets 404");
}

#[tokio::test]
async fn imported_content_is_escaped_on_trail_pages() {
    let (_dir, file_url) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, _repo) = alice_and_repo(&s).await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let client = reqwest::Client::new();
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/import/github"),
        Some(&rw),
        Some(&json!({"repository": "octo/proj", "token": TOKEN})),
    )
    .await;
    assert_eq!(status, 202);
    poll_state(&s, &rw, "completed").await;

    let (browser, _) = s.login("alice").await;
    // The fixture comment `Second comment <b>not bold</b>.` renders
    // through the sanitizing Markdown pipeline: the tag must not
    // survive as HTML.
    let trail = get_text(&browser, &s.url("/alice/proj/trails/1")).await;
    assert!(
        !trail.contains("<b>not bold</b>"),
        "raw HTML in imported comment:\n{trail}"
    );
    assert!(
        trail.contains("Second comment"),
        "comment text present:\n{trail}"
    );
    // Placeholder authors render escaped (covered deeply in
    // github_import.rs; here the imported handle marker is pinned).
    assert!(
        trail.contains("hubot (imported)"),
        "placeholder marker:\n{trail}"
    );
    assert!(!trail.contains(TOKEN), "trail page never carries the token");
}
