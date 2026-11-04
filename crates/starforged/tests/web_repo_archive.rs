mod common;

use common::*;
use serde_json::Value;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archived_repositories_refuse_pushes_until_unarchived() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
        .await
        .unwrap();
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let url = s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;

    let (mia, mia_csrf) = s.login("mia").await;
    let refused = mia
        .post(s.url("/alice/proj/settings/archive"))
        .form(&[("_csrf", mia_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403, "archiving needs admin");

    let (owner, csrf) = s.login("alice").await;
    let archived = owner
        .post(s.url("/alice/proj/settings/archive"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(archived.status(), 303);
    let home = get_text(&s.browser(), &s.url("/alice/proj")).await;
    assert!(home.contains("This repository is archived"), "{home}");
    assert!(
        home.contains(r#"<span class="badge">archived</span>"#),
        "{home}"
    );

    commit_files(&work, &[("b.txt", b"b\n")], "after archiving").await;
    let push = git(&work, &["push", &url, "main"]).await;
    assert!(!push.status.success());
    let stderr = String::from_utf8_lossy(&push.stderr);
    assert!(
        stderr.contains("remote: This repository is archived; pushes are disabled."),
        "{stderr}"
    );
    let refs = s
        .browser()
        .get(s.url("/alice/proj.git/info/refs?service=git-receive-pack"))
        .basic_auth("git", Some(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(refs.status(), 403);
    assert_eq!(
        refs.text().await.unwrap(),
        "This repository is archived; pushes are disabled.\n"
    );
    git_ok(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "proj", None), "copy"],
    )
    .await;
    let json: Value = s
        .browser()
        .get(s.url("/api/v1/repos/alice/proj"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(json["archived"], true);
    let settings = get_text(&owner, &s.url("/alice/proj/settings")).await;
    assert!(
        settings.contains("/alice/proj/settings/unarchive"),
        "settings stay editable"
    );

    let unarchived = owner
        .post(s.url("/alice/proj/settings/unarchive"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(unarchived.status(), 303);
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    assert!(
        !get_text(&s.browser(), &s.url("/alice/proj"))
            .await
            .contains("This repository is archived")
    );
}
