mod common;

use common::{TestServer, get_text, git};
use starforged_core::accounts::{CreateUser, User};
use starforged_core::permission::Visibility;

async fn root_client(s: &TestServer) -> (reqwest::Client, String, User) {
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(common::PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let (client, csrf) = s.login("root").await;
    (client, csrf, root)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleted_repos_restore_and_purge_now() {
    let s = TestServer::start().await;
    let (admin, csrf, root) = root_client(&s).await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;

    // Private repos are visible to admins.
    let page = get_text(&admin, &s.url("/admin/repositories")).await;
    assert!(page.contains("alice/proj"), "{page}");

    // The owner deletes through the existing settings endpoint.
    let (owner, owner_csrf) = s.login("alice").await;
    let deleted = owner
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", owner_csrf.as_str()), ("confirm", "alice/proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 303);

    // The repo is gone publicly but listed as deleted for the admin.
    assert_eq!(
        admin
            .get(s.url("/alice/proj"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert!(
        s.core
            .admin_deleted_repos(&root)
            .await
            .unwrap()
            .iter()
            .any(|r| r.name == "proj" && r.owner == "alice"),
        "deleted repos list the repo"
    );
    let page = get_text(&admin, &s.url("/admin/repositories")).await;
    assert!(page.contains("alice/proj"), "{page}");
    assert!(
        page.contains(&format!("/admin/repositories/{}/restore", repo.id)),
        "restore form:\n{page}"
    );
    assert!(
        page.contains(&format!("/admin/repositories/{}/purge", repo.id)),
        "purge form:\n{page}"
    );

    // Restore brings it back.
    let restored = admin
        .post(s.url(&format!("/admin/repositories/{}/restore", repo.id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(restored.status(), 303);
    assert_eq!(restored.headers()["location"], "/admin/repositories");
    let body = get_text(&admin, &s.url("/alice/proj")).await;
    assert!(body.contains("alice/proj"), "{body}");

    // Delete again, then purge removes it for good.
    let deleted = owner
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", owner_csrf.as_str()), ("confirm", "alice/proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 303);
    let purged = admin
        .post(s.url(&format!("/admin/repositories/{}/purge", repo.id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(purged.status(), 303);
    assert_eq!(purged.headers()["location"], "/admin/repositories");
    assert!(
        !s.core
            .admin_deleted_repos(&root)
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == repo.id),
        "purged repo leaves the deleted list"
    );
    let page = get_text(&admin, &s.url("/admin/repositories")).await;
    assert!(!page.contains("alice/proj"), "{page}");
    assert_eq!(
        admin
            .get(s.url("/alice/proj"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let tmp = tempfile::tempdir().unwrap();
    let clone = git(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "proj", None), "gone"],
    )
    .await;
    assert!(!clone.status.success(), "clone answers missing");

    // Purging a live repository answers 404.
    let live = s.repo(&alice, "live", Visibility::Public).await;
    let purge_live = admin
        .post(s.url(&format!("/admin/repositories/{}/purge", live.id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(purge_live.status(), 404);

    // Non-admins get 404.
    let anon = s.browser();
    assert_eq!(
        anon.get(s.url("/admin/repositories"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        owner
            .get(s.url("/admin/repositories"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
