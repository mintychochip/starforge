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
    assert_eq!(
        client
            .get(s.url("/alice/proj/commits/main/a.txt"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
