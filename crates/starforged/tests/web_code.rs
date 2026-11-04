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
        !empty.contains(r#"href="/alice/empty/settings""#),
        "only maintainers and admins see the Settings tab"
    );
    let (owner, _) = s.login("alice").await;
    assert!(
        get_text(&owner, &s.url("/alice/hidden"))
            .await
            .contains(r#"href="/alice/hidden/settings""#)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_files_are_streamed_not_buffered() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let marker = "large-file-marker-";
    let mut big = String::new();
    while big.len() < 1_572_864 {
        big.push_str(marker);
        big.push_str(&format!("{:06}\n", big.len()));
    }
    let big_bytes = big.into_bytes();
    let small = b"fn main() {}\n".to_vec();
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("small.txt", "placeholder\n")]).await;
    std::fs::write(work.join("README.md"), vec![b'R'; 1_572_864]).unwrap();
    commit_files(
        &work,
        &[("big.bin", &big_bytes), ("small.txt", &small)],
        "large and small files",
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "HEAD:main"]).await;
    let client = s.browser();

    let page = get_text(&client, &s.url("/alice/proj/blob/main/big.bin")).await;
    assert!(
        page.contains("This file is too large to display."),
        "{page}"
    );
    assert!(
        !page.contains(marker),
        "the blob page must not embed file content"
    );

    let raw = client
        .get(s.url("/alice/proj/raw/main/big.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 200);
    assert_eq!(raw.headers()["content-type"], "application/octet-stream");
    assert_eq!(raw.headers()["content-disposition"], "attachment");
    assert_eq!(raw.headers()["content-length"], big_bytes.len().to_string());
    assert_eq!(raw.bytes().await.unwrap(), big_bytes);

    let small_raw = client
        .get(s.url("/alice/proj/raw/main/small.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        small_raw.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    assert_eq!(small_raw.bytes().await.unwrap(), small);

    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(
        !home.contains("<article"),
        "an over-limit README is skipped, got: {home}"
    );
}
