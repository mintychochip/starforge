mod common;

use common::*;
use starforged_core::accounts::CreateUser;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_hides_the_repository_everywhere_until_its_owner_restores_it() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
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
    let wrong = owner
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 422);
    assert!(
        wrong
            .text()
            .await
            .unwrap()
            .contains("Type alice/proj to confirm.")
    );
    let deleted = owner
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "alice/proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 303);
    assert_eq!(deleted.headers()["location"], "/settings/repositories");

    for path in [
        "/alice/proj",
        "/alice/proj/tree/main",
        "/alice/proj/settings",
    ] {
        assert_eq!(
            owner.get(s.url(path)).send().await.unwrap().status(),
            404,
            "{path}"
        );
    }
    assert!(
        !get_text(&owner, &s.url("/"))
            .await
            .contains(r#"href="/alice/proj""#),
        "gone from the dashboard"
    );
    assert_eq!(
        s.browser()
            .get(s.url("/api/v1/repos/alice/proj"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let clone = git(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "gone",
        ],
    )
    .await;
    assert!(
        !clone.status.success(),
        "git answers like a missing repository"
    );
    let reused = owner
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "proj"),
            ("visibility", "public"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(reused.status(), 422);
    assert!(reused.text().await.unwrap().contains("deleted repository"));

    let listing = get_text(&owner, &s.url("/settings/repositories")).await;
    assert!(listing.contains("alice/proj"), "{listing}");
    let restored = owner
        .post(s.url(&format!("/settings/repositories/{}/restore", repo.id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(restored.status(), 303);
    assert_eq!(restored.headers()["location"], "/alice/proj");
    assert!(
        get_text(&owner, &s.url("/alice/proj"))
            .await
            .contains("a.txt")
    );
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "back",
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_admins_delete_and_only_owners_and_site_admins_restore() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    s.repo(&alice, "other", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
        .await
        .unwrap();

    let (mia, mia_csrf) = s.login("mia").await;
    let refused = mia
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", mia_csrf.as_str()), ("confirm", "alice/proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    s.core
        .delete_repo(&alice, "alice", "proj", "alice/proj")
        .await
        .unwrap();
    let restore = mia
        .post(s.url(&format!("/settings/repositories/{}/restore", repo.id)))
        .form(&[("_csrf", mia_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(restore.status(), 404);

    let (root, root_csrf) = s.login("root").await;
    let by_admin = root
        .post(s.url("/alice/other/settings/delete"))
        .form(&[("_csrf", root_csrf.as_str()), ("confirm", "alice/other")])
        .send()
        .await
        .unwrap();
    assert_eq!(by_admin.status(), 303);
    assert_eq!(
        by_admin.headers()["location"],
        "/alice",
        "a site admin lands on the owner's page"
    );
}
