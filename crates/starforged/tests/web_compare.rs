mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comparing_refs_lists_new_commits_and_the_diff_from_the_merge_base() {
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
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    commit_files(&work, &[("b.txt", b"bee\n")], "add bee").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit_files(&work, &[("c.txt", b"main only\n")], "main moves on").await;
    git_ok(&work, &["checkout", "-q", "--orphan", "unrelated"]).await;
    git_ok(&work, &["rm", "-rfq", "."]).await;
    commit_files(&work, &[("z.txt", b"z\n")], "unrelated root").await;
    git_ok(
        &work,
        &["push", "-q", &url, "main", "feature/x", "unrelated"],
    )
    .await;
    let client = s.browser();

    let page = get_text(&client, &s.url("/alice/proj/compare/main...feature/x")).await;
    let newer = page.find("add bee").expect("the newest commit is listed");
    let older = page.find("add two").expect("the older commit is listed");
    assert!(newer < older, "newest first");
    assert!(page.contains("2 commits"), "{page}");
    assert!(
        !page.contains("main moves on"),
        "commits only on the base are not listed"
    );
    assert!(
        page.contains(r#"<span class="badge">added</span> b.txt"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<tr class="add"><td class="ln"></td><td class="ln">2</td><td><pre>two</pre></td></tr>"#),
        "{page}"
    );
    assert!(!page.contains("c.txt"), "the diff starts at the merge base");

    let same = get_text(&client, &s.url("/alice/proj/compare/main...main")).await;
    assert!(
        same.contains("main has no commits that main lacks."),
        "{same}"
    );
    let unrelated = get_text(&client, &s.url("/alice/proj/compare/main...unrelated")).await;
    assert!(unrelated.contains("share no history"), "{unrelated}");

    let picked = client
        .get(s.url("/alice/proj/compare?base=main&head=feature/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(picked.status(), 303);
    assert_eq!(
        picked.headers()["location"],
        "/alice/proj/compare/main...feature/x"
    );
    let picker = get_text(&client, &s.url("/alice/proj/compare")).await;
    assert!(
        picker.contains(r#"<option value="feature/x" selected>feature/x</option>"#),
        "the head defaults to another branch: {picker}"
    );
    assert!(
        picker.contains(r#"<option value="main" selected>main</option>"#),
        "{picker}"
    );

    for missing in [
        "/alice/proj/compare/main...nope",
        "/alice/proj/compare/main",
        "/alice/proj/compare/main...feature/x/a.txt",
    ] {
        assert_eq!(
            client.get(s.url(missing)).send().await.unwrap().status(),
            404,
            "{missing}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_comparisons_list_250_commits_and_count_the_rest() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "long"]).await;
    for i in 0..253 {
        git_ok(
            &work,
            &["commit", "-q", "--allow-empty", "-m", &format!("step {i}")],
        )
        .await;
    }
    git_ok(&work, &["push", "-q", &url, "main", "long"]).await;
    let page = get_text(&s.browser(), &s.url("/alice/proj/compare/main...long")).await;
    assert!(page.contains("253 commits"), "{page}");
    assert!(page.contains("and 3 more commits"), "{page}");
    assert_eq!(page.matches("<li>").count(), 250);
}
