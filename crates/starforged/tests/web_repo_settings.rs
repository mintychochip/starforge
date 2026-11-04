mod common;

use common::*;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintainers_edit_general_settings_and_admins_change_visibility() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.user("walt").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "walt", Permission::Write)
        .await
        .unwrap();
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# Proj\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "dev"]).await;
    commit_files(&work, &[("dev.txt", b"dev\n")], "dev work").await;
    git_ok(&work, &["push", "-q", &url, "main", "dev"]).await;

    let anonymous = s
        .browser()
        .get(s.url("/alice/proj/settings"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 303);
    assert!(
        anonymous.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/login?next=")
    );

    let (walt, _) = s.login("walt").await;
    assert!(
        !get_text(&walt, &s.url("/alice/proj"))
            .await
            .contains(r#"href="/alice/proj/settings""#),
        "writers do not see the Settings tab"
    );
    assert_eq!(
        walt.get(s.url("/alice/proj/settings"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let (mia, mia_csrf) = s.login("mia").await;
    assert!(
        get_text(&mia, &s.url("/alice/proj"))
            .await
            .contains(r#"href="/alice/proj/settings""#)
    );
    let settings = get_text(&mia, &s.url("/alice/proj/settings")).await;
    assert!(settings.contains(r#"name="description""#), "{settings}");
    assert!(
        settings.contains(r#"<option value="dev">dev</option>"#),
        "{settings}"
    );
    assert!(
        !settings.contains("/settings/visibility"),
        "maintainers do not see admin settings"
    );
    assert!(
        !settings.contains("/settings/collaborators"),
        "nor the collaborators page"
    );

    let saved = mia
        .post(s.url("/alice/proj/settings"))
        .form(&[
            ("_csrf", mia_csrf.as_str()),
            ("description", "A demo"),
            ("default_branch", "dev"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    assert_eq!(saved.headers()["location"], "/alice/proj/settings");
    let home = get_text(&mia, &s.url("/alice/proj")).await;
    assert!(home.contains("A demo"), "{home}");
    assert!(
        home.contains("dev.txt"),
        "the home page shows the new default branch"
    );
    assert!(
        get_text(&mia, &s.url("/alice/proj/commits"))
            .await
            .contains("dev work"),
        "the Commits tab follows the default branch"
    );
    assert_eq!(
        std::fs::read_to_string(s.core.repo_path(repo.id).join("HEAD")).unwrap(),
        "ref: refs/heads/dev\n"
    );
    git_ok(tmp.path(), &["clone", "-q", &url, "clone"]).await;
    assert_eq!(
        git_ok(
            &tmp.path().join("clone"),
            &["rev-parse", "--abbrev-ref", "HEAD"]
        )
        .await
        .trim(),
        "dev",
        "new clones check out the default branch"
    );

    let unknown = mia
        .post(s.url("/alice/proj/settings"))
        .form(&[
            ("_csrf", mia_csrf.as_str()),
            ("description", "Changed"),
            ("default_branch", "nope"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 422);
    assert!(unknown.text().await.unwrap().contains("no branch named"));
    assert!(
        !get_text(&mia, &s.url("/alice/proj"))
            .await
            .contains("Changed"),
        "a refused branch leaves the description unchanged"
    );
    let forbidden = mia
        .post(s.url("/alice/proj/settings/visibility"))
        .form(&[("_csrf", mia_csrf.as_str()), ("visibility", "public")])
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 403);

    let (owner, csrf) = s.login("alice").await;
    let admin_view = get_text(&owner, &s.url("/alice/proj/settings")).await;
    assert!(admin_view.contains("/alice/proj/settings/visibility"));
    assert!(admin_view.contains(r#"href="/alice/proj/settings/collaborators""#));
    let public = owner
        .post(s.url("/alice/proj/settings/visibility"))
        .form(&[("_csrf", csrf.as_str()), ("visibility", "public")])
        .send()
        .await
        .unwrap();
    assert_eq!(public.status(), 303);
    assert_eq!(
        s.browser()
            .get(s.url("/alice/proj"))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "anyone can read a public repository"
    );
    let actions: Vec<String> = starforged_db::audit::recent(s.core.db(), 20)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(
        actions.contains(&"repo.visibility".to_owned()),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"repo.default_branch".to_owned()),
        "{actions:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_commits_tab_works_before_the_first_push() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "empty", Visibility::Public).await;
    let client = s.browser();
    let home = get_text(&client, &s.url("/alice/empty")).await;
    assert!(home.contains(r#"href="/alice/empty/commits""#), "{home}");
    let commits = get_text(&client, &s.url("/alice/empty/commits")).await;
    assert!(commits.contains("No commits yet."), "{commits}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintainers_control_refs_for_access_from_settings() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.user("ted").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "ted", Permission::Triage)
        .await
        .unwrap();

    // Triage is below the maintain gate: the page stays hidden and the POST
    // is refused.
    let (ted, ted_csrf) = s.login("ted").await;
    assert_eq!(
        ted.get(s.url("/alice/proj/settings"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let refused = ted
        .post(s.url("/alice/proj/settings/refs-for-access"))
        .form(&[("_csrf", ted_csrf.as_str()), ("refs_for_access", "members")])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    assert_eq!(
        s.core.refs_for_access(repo.id).await.unwrap(),
        "anyone_with_read",
        "a refused change writes nothing"
    );

    // A maintainer sees the control defaulting to anyone-with-read.
    let (mia, mia_csrf) = s.login("mia").await;
    let settings = get_text(&mia, &s.url("/alice/proj/settings")).await;
    assert!(settings.contains(r#"name="refs_for_access""#), "{settings}");
    assert!(
        settings.contains(r#"<option value="anyone_with_read" selected>"#),
        "{settings}"
    );

    // The value round-trips through the page.
    let saved = mia
        .post(s.url("/alice/proj/settings/refs-for-access"))
        .form(&[("_csrf", mia_csrf.as_str()), ("refs_for_access", "members")])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    assert_eq!(saved.headers()["location"], "/alice/proj/settings");
    assert_eq!(s.core.refs_for_access(repo.id).await.unwrap(), "members");
    let settings = get_text(&mia, &s.url("/alice/proj/settings")).await;
    assert!(
        settings.contains(r#"<option value="members" selected>"#),
        "{settings}"
    );

    // Unknown values are refused with the page again, not a silent no-op.
    let bad = mia
        .post(s.url("/alice/proj/settings/refs-for-access"))
        .form(&[
            ("_csrf", mia_csrf.as_str()),
            ("refs_for_access", "everyone"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
    assert!(bad.text().await.unwrap().contains("refs_for_access"));
    assert_eq!(
        s.core.refs_for_access(repo.id).await.unwrap(),
        "members",
        "a refused value keeps the old mode"
    );
}
