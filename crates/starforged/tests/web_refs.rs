mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branches_and_tags_pages() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    git_ok(tmp.path(), &["init", "-q", "work"]).await;
    let work = tmp.path().join("work");
    let day = 86_400;
    let t0 = 1_700_000_000;
    let commit = |file: &'static str, message: &'static str, when: i64| {
        let work = work.clone();
        async move {
            std::fs::write(work.join(file), message).unwrap();
            git_ok(&work, &["add", "-A"]).await;
            git_dated(&work, &["commit", "-q", "-m", message], when).await;
        }
    };
    commit("a.txt", "root", t0).await;
    git_ok(&work, &["branch", "old"]).await;
    git_ok(&work, &["tag", "v0.1"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit("f.txt", "feature work", t0 + 2 * day).await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit("m.txt", "main work", t0 + day).await;
    git_dated(
        &work,
        &["tag", "-a", "v1.0", "-m", "First release\n\nNotes here"],
        t0 + 3 * day,
    )
    .await;
    git_ok(
        &work,
        &["push", "-q", &url, "main", "feature", "old", "v0.1", "v1.0"],
    )
    .await;

    let client = s.browser();
    let branches = get_text(&client, &s.url("/alice/proj/branches")).await;
    let main_at = branches
        .find(r#">main</a> <span class="badge">default</span>"#)
        .unwrap_or_else(|| panic!("{branches}"));
    let feature_at = branches.find(">feature</a>").unwrap();
    let old_at = branches.find(">old</a>").unwrap();
    assert!(
        main_at < feature_at && feature_at < old_at,
        "the default branch first, then the newest: {branches}"
    );
    assert!(branches.contains(r#"href="/alice/proj/compare/main...feature""#));
    assert!(!branches.contains("/alice/proj/compare/main...main"));
    assert!(branches.contains("feature work"));
    assert!(branches.contains(" ago"), "{branches}");

    let tags = get_text(&client, &s.url("/alice/proj/tags")).await;
    let v1 = tags.find(">v1.0</a>").unwrap_or_else(|| panic!("{tags}"));
    let v0 = tags.find(">v0.1</a>").unwrap();
    assert!(v1 < v0, "newest first: {tags}");
    assert!(tags.contains("First release"));
    assert!(!tags.contains("Notes here"), "only the first line");
    assert!(tags.contains(r#"href="/alice/proj/tree/v1.0""#));

    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(home.contains(r#"href="/alice/proj/branches""#), "{home}");
    assert!(home.contains(r#"href="/alice/proj/tags""#), "{home}");
    let empty = s.repo(&alice, "empty", Visibility::Public).await;
    let none = get_text(&client, &s.url(&format!("/alice/{}/branches", empty.name))).await;
    assert!(none.contains("No branches yet."), "{none}");
}
