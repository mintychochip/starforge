mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_pages_and_commit_diffs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    commit_files(
        &work,
        &[("a.txt", b"one\ntwo\n"), ("b.txt", b"new file\n")],
        "second change",
    )
    .await;
    let change = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    for i in 0..55 {
        git_ok(
            &work,
            &["commit", "-q", "--allow-empty", "-m", &format!("empty {i}")],
        )
        .await;
    }
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let client = s.browser();

    let first_page = get_text(&client, &s.url("/alice/proj/commits/main")).await;
    assert!(first_page.contains("empty 54"));
    assert!(first_page.contains(r#"href="?page=2""#));
    assert!(!first_page.contains("initial commit"));
    let second_page = get_text(&client, &s.url("/alice/proj/commits/main?page=2")).await;
    let newer = second_page
        .find("second change")
        .expect("second change listed");
    let older = second_page
        .find("initial commit")
        .expect("initial commit listed");
    assert!(newer < older, "newest first");
    assert!(second_page.contains(&format!(r#"href="/alice/proj/commit/{change}""#)));

    let diff = get_text(&client, &s.url(&format!("/alice/proj/commit/{change}"))).await;
    assert!(diff.contains("second change"));
    assert!(
        diff.contains(r#"<tr class="add"><td class="ln"></td><td class="ln">2</td><td><pre>two</pre></td></tr>"#),
        "{diff}"
    );
    assert!(
        diff.contains(r#"<span class="badge">added</span> b.txt"#),
        "{diff}"
    );

    let zeros = "0".repeat(40);
    assert_eq!(
        client
            .get(s.url(&format!("/alice/proj/commit/{zeros}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(s.url("/alice/proj/commit/HEAD"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // A path history lists the commits that touched it.
    let path_page = get_text(&client, &s.url("/alice/proj/commits/main/a.txt")).await;
    assert!(path_page.contains("second change"), "{path_page}");
    assert!(path_page.contains("initial commit"), "{path_page}");
    assert!(!path_page.contains("empty 54"), "{path_page}");
    assert!(path_page.contains(r#"href="/alice/proj/commits/main""#));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_history_filters_by_file_and_directory() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "touch a").await;
    commit_files(&work, &[("src/b.txt", b"bee\n")], "add b").await;
    commit_files(&work, &[("src/b.txt", b"bee\ntwo\n")], "touch b").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let client = s.browser();

    let file_page = get_text(&client, &s.url("/alice/proj/commits/main/a.txt")).await;
    assert!(file_page.contains("touch a"), "{file_page}");
    assert!(file_page.contains("initial commit"), "{file_page}");
    assert!(!file_page.contains("add b"), "{file_page}");
    assert!(!file_page.contains("touch b"), "{file_page}");
    assert!(file_page.contains("History of"), "{file_page}");
    assert!(
        file_page.contains(r#"href="/alice/proj/commits/main">Full history"#),
        "{file_page}"
    );

    let dir_page = get_text(&client, &s.url("/alice/proj/commits/main/src")).await;
    assert!(dir_page.contains("touch b"), "{dir_page}");
    assert!(dir_page.contains("add b"), "{dir_page}");
    assert!(!dir_page.contains("touch a"), "{dir_page}");
    assert!(!dir_page.contains("initial commit"), "{dir_page}");

    assert_eq!(
        client
            .get(s.url("/alice/proj/commits/main/nope.txt"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Blob pages link to the file's history; directory trees link to theirs.
    let blob = get_text(&client, &s.url("/alice/proj/blob/main/a.txt")).await;
    assert!(
        blob.contains(r#"href="/alice/proj/commits/main/a.txt">History"#),
        "{blob}"
    );
    let tree = get_text(&client, &s.url("/alice/proj/tree/main/src")).await;
    assert!(
        tree.contains(r#"href="/alice/proj/commits/main/src">History"#),
        "{tree}"
    );
    let root = get_text(&client, &s.url("/alice/proj/tree/main")).await;
    assert!(!root.contains(">History</a>"), "{root}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_history_stays_private() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "secret", Visibility::Private).await;
    let url = s.git_url(
        "alice",
        "secret",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let client = s.browser();
    for path in [
        "/alice/secret/commits/main",
        "/alice/secret/commits/main/a.txt",
    ] {
        assert_eq!(
            client.get(s.url(path)).send().await.unwrap().status(),
            404,
            "{path}"
        );
    }
}
