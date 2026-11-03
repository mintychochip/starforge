mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browsing_trees_files_raw_and_readme() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[
            ("README.md", "# Hello\n\n<script>alert(1)</script>\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("docs/a b.txt", "spaced\n"),
        ],
    )
    .await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(
        &work,
        &[("feature.txt", b"on the branch\n")],
        "feature work",
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
    let client = s.browser();

    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(home.contains("<h1>Hello</h1>"), "{home}");
    assert!(!home.contains("<script>alert"), "README HTML is sanitized");
    assert!(
        home.contains(r#"<a href="/alice/proj/tree/main/src">src</a>"#),
        "{home}"
    );
    assert!(
        home.contains(r#"<a href="/alice/proj/blob/main/README.md">README.md</a>"#),
        "{home}"
    );
    assert!(
        !home.contains("feature.txt"),
        "the home page shows the default branch"
    );

    let docs = get_text(&client, &s.url("/alice/proj/tree/feature/x/docs")).await;
    assert!(
        docs.contains(r#"href="/alice/proj/blob/feature/x/docs/a%20b.txt""#),
        "{docs}"
    );
    assert!(
        get_text(&client, &s.url("/alice/proj/tree/feature/x"))
            .await
            .contains("feature.txt")
    );

    let file = get_text(&client, &s.url("/alice/proj/blob/main/src/main.rs")).await;
    assert!(file.contains("<pre>fn main() {}</pre>"), "{file}");
    assert!(
        file.contains(r#"href="/alice/proj/raw/main/src/main.rs""#),
        "{file}"
    );

    let raw = client
        .get(s.url("/alice/proj/raw/main/src/main.rs"))
        .send()
        .await
        .unwrap();
    assert_eq!(raw.headers()["content-type"], "text/plain; charset=utf-8");
    assert_eq!(raw.headers()["content-security-policy"], "sandbox");
    assert_eq!(raw.text().await.unwrap(), "fn main() {}\n");

    for missing in [
        "/alice/proj/blob/main/missing.rs",
        "/alice/proj/tree/nope",
        "/alice/proj/tree/main/README.md",
    ] {
        assert_eq!(
            client.get(s.url(missing)).send().await.unwrap().status(),
            404,
            "{missing}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_and_empty_repositories() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "hidden", Visibility::Private).await;
    s.repo(&alice, "empty", Visibility::Public).await;
    let client = s.browser();
    assert_eq!(
        client
            .get(s.url("/alice/hidden"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let empty = get_text(&client, &s.url("/alice/empty")).await;
    assert!(empty.contains("This repository is empty"));
    assert!(empty.contains(&format!("git remote add origin {}/alice/empty.git", s.base)));
    assert!(
        !empty.contains("Collaborators"),
        "only admins see the settings tab"
    );
    let (owner, _) = s.login("alice").await;
    assert!(
        get_text(&owner, &s.url("/alice/hidden"))
            .await
            .contains("Collaborators")
    );
}
