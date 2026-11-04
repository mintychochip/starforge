mod common;

use common::*;
use serde_json::Value;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_names_redirect_pages_git_and_the_api() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    s.repo(&alice, "taken", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("src/main.rs", "fn main() {}\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;

    let (owner, csrf) = s.login("alice").await;
    let conflict = owner
        .post(s.url("/alice/proj/settings/rename"))
        .form(&[("_csrf", csrf.as_str()), ("new_name", "taken")])
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 422);
    assert!(conflict.text().await.unwrap().contains("already exists"));
    let renamed = owner
        .post(s.url("/alice/proj/settings/rename"))
        .form(&[("_csrf", csrf.as_str()), ("new_name", "renamed")])
        .send()
        .await
        .unwrap();
    assert_eq!(renamed.status(), 303);
    assert_eq!(renamed.headers()["location"], "/alice/renamed/settings");

    let client = s.browser();
    for (old, new) in [
        ("/alice/proj", "/alice/renamed"),
        (
            "/alice/proj/tree/main/src?x=1",
            "/alice/renamed/tree/main/src?x=1",
        ),
        (
            "/alice/PROJ/blob/main/src/main.rs",
            "/alice/renamed/blob/main/src/main.rs",
        ),
    ] {
        let response = client.get(s.url(old)).send().await.unwrap();
        assert_eq!(response.status(), 301, "{old}");
        assert_eq!(response.headers()["location"], new, "{old}");
    }
    assert_eq!(
        client
            .get(s.url("/alice/renamed/tree/main/src"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let api = client
        .get(s.url("/api/v1/repos/alice/proj"))
        .send()
        .await
        .unwrap();
    assert_eq!(api.status(), 301);
    assert_eq!(api.headers()["location"], "/api/v1/repos/alice/renamed");
    let followed: Value = reqwest::get(s.url("/api/v1/repos/alice/proj"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(followed["full_name"], "alice/renamed");

    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "proj", None),
            "anonymous",
        ],
    )
    .await;
    assert!(tmp.path().join("anonymous/src/main.rs").is_file());
    commit_files(
        &work,
        &[("more.txt", b"more\n")],
        "pushed through the old name",
    )
    .await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
    assert!(
        get_text(&client, &s.url("/alice/renamed/commits/main"))
            .await
            .contains("pushed through the old name")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_need_read_access_and_yield_to_new_repositories() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "secret", Visibility::Private).await;
    s.core
        .rename_repo(&alice, "alice", "secret", "hidden")
        .await
        .unwrap();

    let anonymous = s.browser();
    assert_eq!(
        anonymous
            .get(s.url("/alice/secret"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        anonymous
            .get(s.url("/alice/secret.git/info/refs?service=git-upload-pack"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "anonymous git clients are asked to sign in, as for any hidden repository"
    );
    let (bob, _) = s.login("bob").await;
    assert_eq!(
        bob.get(s.url("/alice/secret"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let (owner, _) = s.login("alice").await;
    let moved = owner.get(s.url("/alice/secret")).send().await.unwrap();
    assert_eq!(moved.status(), 301);
    assert_eq!(moved.headers()["location"], "/alice/hidden");

    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let tmp = tempfile::tempdir().unwrap();
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "secret", Some(&token)),
            "copy",
        ],
    )
    .await;

    s.core
        .rename_repo(&alice, "alice", "hidden", "final")
        .await
        .unwrap();
    let hop = owner.get(s.url("/alice/secret")).send().await.unwrap();
    assert_eq!(
        hop.headers()["location"],
        "/alice/final",
        "a chain of renames resolves in one hop"
    );

    s.repo(&alice, "secret", Visibility::Public).await;
    assert_eq!(
        anonymous
            .get(s.url("/alice/secret"))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the new repository answers, not a redirect"
    );
}
