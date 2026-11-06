//! S4: `git grep` code search over the default branch — default-branch
//! only, case sensitivity, literal fixed strings, argument injection,
//! binary skipping, caps, links, empty repositories, 404s for non-readers,
//! and XSS escaping.
mod common;

use std::path::PathBuf;
use std::process::Command;

use common::*;
use serde_json::Value;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

/// Bounded poll (10 s) until `branch` resolves in the pushed repository.
async fn wait_for_tip(s: &TestServer, owner: &str, repo: &str, branch: &str) -> String {
    for _ in 0..100 {
        if let Some(tip) = repo_tip(s, owner, repo, branch).await {
            return tip;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for tip of {branch}");
}

async fn repo_tip(server: &TestServer, owner: &str, repo: &str, branch: &str) -> Option<String> {
    let row = starforged_db::repos::by_owner_and_name(server.core.db(), owner, repo)
        .await
        .ok()??;
    let path = server.core.repo_path(row.id);
    let branch_ref = format!("refs/heads/{branch}");
    let out = tokio::task::spawn_blocking(move || {
        Command::new("git")
            .args([
                "-C",
                path.to_str().unwrap(),
                "rev-parse",
                "--verify",
                "-q",
                &branch_ref,
            ])
            .output()
    })
    .await
    .ok()?;
    let out = out.ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        None
    }
}

struct Fixture {
    /// The working copy of the pushed repo.
    work: PathBuf,
    _tmp: tempfile::TempDir,
}

/// Creates a public or private repo owned by `alice`, pushes `files` as one
/// commit on `main`, and waits for the tip to land.
async fn pushed(s: &TestServer, visibility: Visibility, files: &[(&str, &str)]) -> Fixture {
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", visibility).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", files).await;
    git_ok(&work, &["remote", "add", "origin", &url]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    wait_for_tip(s, "alice", "proj", "main").await;
    Fixture { work, _tmp: tmp }
}

/// The JSON code-search API, anonymously or with a token.
async fn api_search(
    client: &reqwest::Client,
    s: &TestServer,
    qs: &str,
    token: Option<&str>,
) -> (u16, Value) {
    let mut req = client.get(format!(
        "{}/api/v1/repos/alice/proj/search/code?{qs}",
        s.base
    ));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    (status, body)
}

/// The web code-search page.
async fn web_search(client: &reqwest::Client, s: &TestServer, qs: &str) -> (u16, String) {
    let resp = client
        .get(s.url(&format!("/alice/proj/search?{qs}")))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_branch_only_case_and_links() {
    let s = TestServer::start().await;
    let f = pushed(
        &s,
        Visibility::Public,
        &[("hello.txt", "the quick needle\nsecond line\n")],
    )
    .await;

    // Push a second branch carrying content main does not have.
    git_ok(&f.work, &["checkout", "-q", "-b", "feature"]).await;
    commit_files(&f.work, &[("branch.txt", b"branchonly marker\n")], "branch").await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(
            &s.token(
                &s.core.user_by_handle("alice").await.unwrap().unwrap(),
                &[Scope::RepoWrite],
            )
            .await,
        ),
    );
    git_ok(&f.work, &["push", "-q", &url, "feature"]).await;
    wait_for_tip(&s, "alice", "proj", "feature").await;

    let client = reqwest::Client::new();
    let (status, body) = api_search(&client, &s, "q=needle", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["ref"], "main");
    assert!(!body["commit"].as_str().unwrap().is_empty());
    let matches = body["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["path"], "hello.txt");
    assert_eq!(matches[0]["line"], 1);
    assert_eq!(matches[0]["text"], "the quick needle");
    assert_eq!(body["truncated"], false);

    // The branch-only marker is absent: only the default branch is searched.
    let (status, body) = api_search(&client, &s, "q=branchonly", None).await;
    assert_eq!(status, 200);
    assert!(body["matches"].as_array().unwrap().is_empty());

    // Case sensitivity works; the insensitive switch finds lowercase "needle"
    // only when the query case differs... here the file has lowercase, so
    // an uppercase query matches only case-insensitively.
    let (status, body) = api_search(&client, &s, "q=NEEDLE", None).await;
    assert_eq!(status, 200);
    assert!(body["matches"].as_array().unwrap().is_empty());
    let (status, body) = api_search(&client, &s, "q=NEEDLE&case=insensitive", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["matches"].as_array().unwrap().len(), 1);

    // Each result links to the file and line on the web page.
    let client = s.browser();
    let (status, html) = web_search(&client, &s, "q=needle").await;
    assert_eq!(status, 200);
    assert!(
        html.contains("/alice/proj/blob/main/hello.txt"),
        "file link: {html}"
    );
    assert!(html.contains("#L1"), "line link: {html}");
    assert!(html.contains("the quick needle"), "match text renders");
    // The repo nav on code pages carries the search field.
    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(
        home.contains("action=\"/alice/proj/search\""),
        "the repo nav search field posts to the code search"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn literal_fixed_strings_and_injection() {
    let s = TestServer::start().await;
    pushed(
        &s,
        Visibility::Public,
        &[
            ("a.txt", "a.c\nabc\n"),
            ("b.txt", "run --open-files-in-pager now\n"),
            ("c.txt", "version -e --fixed-strings\n"),
        ],
    )
    .await;
    let client = reqwest::Client::new();

    // Regex metacharacters are literal.
    let (status, body) = api_search(&client, &s, "q=a.c", None).await;
    assert_eq!(status, 200);
    let matches = body["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "only the literal `a.c` line");
    assert_eq!(matches[0]["path"], "a.txt");

    // Argument injection: a query starting with `-` is searched literally,
    // not treated as an option.
    let (status, body) = api_search(&client, &s, "q=--open-files-in-pager", None).await;
    assert_eq!(status, 200);
    let matches = body["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["path"], "b.txt");

    // Other option-looking queries are literal too.
    let (status, body) = api_search(&client, &s, "q=-e", None).await;
    assert_eq!(status, 200);
    let matches = body["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "only the `-e` line");
    assert_eq!(matches[0]["path"], "c.txt");

    // An invalid `case` is 422.
    let (status, _) = api_search(&client, &s, "q=a&case=bogus", None).await;
    assert_eq!(status, 422);
    // Empty and over-long queries are 422.
    let long = "x".repeat(257);
    let (status, _) = api_search(&client, &s, &format!("q={long}"), None).await;
    assert_eq!(status, 422);
    let (status, _) = api_search(&client, &s, "q=", None).await;
    assert_eq!(status, 422);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_files_are_skipped_and_caps_truncate() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("seed.txt", "seed\n")]).await;
    git_ok(&work, &["remote", "add", "origin", &url]).await;
    // A binary file (NUL bytes) carrying the needle, plus a text file with
    // 260 needle lines: the binary match never appears, and the text
    // matches truncate at 200 with `truncated: true`.
    std::fs::write(
        work.join("bin.dat"),
        [0u8, b'n', b'e', b'e', b'd', b'l', b'e', 0],
    )
    .unwrap();
    let many = "needle\n".repeat(260);
    std::fs::write(work.join("many.txt"), many).unwrap();
    git_ok(&work, &["add", "-A"]).await;
    git_ok(&work, &["commit", "-q", "-m", "more"]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    wait_for_tip(&s, "alice", "proj", "main").await;

    let client = reqwest::Client::new();
    let (status, body) = api_search(&client, &s, "q=needle", None).await;
    assert_eq!(status, 200);
    let matches = body["matches"].as_array().unwrap();
    assert!(
        matches.iter().all(|m| m["path"] != "bin.dat"),
        "binary matches are skipped"
    );
    assert_eq!(matches.len(), 200, "the match cap applies");
    assert_eq!(body["truncated"], true, "dropped matches mark truncation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_repo_private_404_and_xss() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;

    // An empty repository gives an empty result, not an error.
    let client = reqwest::Client::new();
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let (status, body) = api_search(&client, &s, "q=needle", Some(&token)).await;
    assert_eq!(status, 200);
    assert!(body["matches"].as_array().unwrap().is_empty());

    // Non-readers get 404, never 403 or data.
    let (status, _) = api_search(&client, &s, "q=needle", None).await;
    assert_eq!(status, 404);
    let anon = s.browser();
    let resp = anon
        .get(s.url("/alice/proj/search?q=needle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    // Push hostile content and check it renders escaped.
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[("evil.txt", "needle <script>alert(1)</script>\n")],
    )
    .await;
    git_ok(&work, &["remote", "add", "origin", &url]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    wait_for_tip(&s, "alice", "proj", "main").await;

    let (alice_client, _) = s.login("alice").await;
    let (status, html) = web_search(&alice_client, &s, "q=needle").await;
    assert_eq!(status, 200);
    assert!(
        !html.contains("<script>alert(1)</script>"),
        "hostile content never renders raw"
    );
    assert!(
        html.contains("&#60;script&#62;"),
        "hostile content renders escaped: {html}"
    );
}
