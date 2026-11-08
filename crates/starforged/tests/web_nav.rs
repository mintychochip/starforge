//! Repo navigation wiring: the CI and Compare tabs, the branch-row links,
//! and creating a trail from a branch with its `head` tracked as a change.
//! The Trail number and Change `k` are read back from Core so the tests
//! assert behavior, not page text.
mod common;

use common::*;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    _tmp: tempfile::TempDir,
}

async fn start() -> Ctx {
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
    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "feature work").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit_files(&work, &[("c.txt", b"main only\n")], "main moves on").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature"]).await;
    Ctx {
        s,
        alice,
        _tmp: tmp,
    }
}

async fn trail_count(c: &Ctx) -> usize {
    c.s.core
        .list_trails(
            Some(&c.alice),
            "alice",
            "proj",
            &starforged_core::trails::TrailFilterInput::default(),
        )
        .await
        .unwrap()
        .trails
        .len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_tabs_and_ci_active_tab() {
    let c = start().await;
    let anon = c.s.browser();

    let home = get_text(&anon, &c.s.url("/alice/proj")).await;
    assert!(home.contains(r#"href="/alice/proj/ci">CI</a>"#), "{home}");
    assert!(
        home.contains(r#"href="/alice/proj/compare">Compare</a>"#),
        "{home}"
    );
    assert!(
        !home.contains(r#"aria-current="page">CI</a>"#),
        "the code page must not mark CI active: {home}"
    );

    let ci = get_text(&anon, &c.s.url("/alice/proj/ci")).await;
    assert!(ci.contains(r#"aria-current="page">CI</a>"#), "{ci}");

    let compare = get_text(&anon, &c.s.url("/alice/proj/compare")).await;
    assert!(
        compare.contains(r#"aria-current="page">Compare</a>"#),
        "{compare}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branches_page_rows_link_commits_and_new_trail() {
    let c = start().await;

    let anon = c.s.browser();
    let anon_page = get_text(&anon, &c.s.url("/alice/proj/branches")).await;
    assert!(
        anon_page.contains(r#"href="/alice/proj/commits/main""#),
        "{anon_page}"
    );
    assert!(
        anon_page.contains(r#"href="/alice/proj/commits/feature""#),
        "{anon_page}"
    );
    assert!(
        !anon_page.contains("/alice/proj/trails/new"),
        "anonymous readers must not see New Trail: {anon_page}"
    );

    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.s.url("/alice/proj/branches")).await;
    assert!(
        page.contains(r#"href="/alice/proj/trails/new?head=feature""#),
        "{page}"
    );
    assert!(
        !page.contains("/alice/proj/trails/new?head=main"),
        "the default branch must not offer New Trail: {page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_trail_form_prefills_and_tracks_head_as_a_change() {
    let c = start().await;
    let (alice, _) = c.s.login("alice").await;

    let form = get_text(&alice, &c.s.url("/alice/proj/trails/new?head=feature")).await;
    assert_eq!(extract_input(&form, "head"), "feature", "{form}");
    assert_eq!(extract_input(&form, "base"), "main", "{form}");
    let csrf = extract_input(&form, "_csrf");

    let res = alice
        .post(c.s.url("/alice/proj/trails/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("title", "feature trail"),
            ("intent", "build the thing"),
            ("head", "feature"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(location, "/alice/proj/trails/1");

    let changes =
        c.s.core
            .list_changes(Some(&c.alice), "alice", "proj", 1, None)
            .await
            .unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].head_branch.as_deref(), Some("feature"));
    assert_eq!(changes[0].base_branch, "main");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_trail_with_unknown_head_writes_no_trail() {
    let c = start().await;
    let (alice, _) = c.s.login("alice").await;
    let form = get_text(&alice, &c.s.url("/alice/proj/trails/new")).await;
    let csrf = extract_input(&form, "_csrf");

    let res = alice
        .post(c.s.url("/alice/proj/trails/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("title", "ghost trail"),
            ("intent", "build the thing"),
            ("head", "ghost"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body = res.text().await.unwrap();
    assert!(body.contains("unknown head branch"), "{body}");
    assert_eq!(trail_count(&c).await, 0, "an unknown head writes no trail");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_only_collaborator_cannot_start_a_branch_trail() {
    let c = start().await;
    let _bob = c.s.user("bob").await;
    c.s.core
        .set_collaborator(&c.alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let (bob, _) = c.s.login("bob").await;

    let page = get_text(&bob, &c.s.url("/alice/proj/branches")).await;
    assert!(
        !page.contains("/alice/proj/trails/new?head=feature"),
        "a read-only collaborator must not see New Trail: {page}"
    );

    let form = get_text(&bob, &c.s.url("/alice/proj/trails/new")).await;
    let csrf = extract_input(&form, "_csrf");
    let res = bob
        .post(c.s.url("/alice/proj/trails/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("title", "reader trail"),
            ("intent", "build the thing"),
            ("head", "feature"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "tracking a branch needs triage");
    assert_eq!(trail_count(&c).await, 0, "a refused start writes no trail");
}
