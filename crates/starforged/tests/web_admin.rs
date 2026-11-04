mod common;

use common::{TestServer, get_text};
use starforged_core::accounts::CreateUser;
use starforged_core::permission::Visibility;

async fn admin_client(s: &TestServer) -> (reqwest::Client, String) {
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(common::PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    s.login("root").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overview_shows_counts_and_config() {
    let s = TestServer::start().await;
    let (client, _csrf) = admin_client(&s).await;
    let alice = s.user("alice").await;
    s.repo(&alice, "hello", Visibility::Public).await;

    let body = get_text(&client, &s.url("/admin")).await;
    assert!(
        body.contains("<dt>Users</dt><dd>2</dd>"),
        "two users:\n{body}"
    );
    assert!(
        body.contains("<dt>Repositories</dt><dd>1</dd>"),
        "one repo:\n{body}"
    );
    assert!(body.contains("Registration mode"), "mode label:\n{body}");
    assert!(body.contains("invite"), "invite mode:\n{body}");
    assert!(body.contains("not configured"), "mail status:\n{body}");
    assert!(!body.contains("file://"), "never the mail URL:\n{body}");

    let marker = "<dt>Git version</dt><dd>";
    let start = body.find(marker).expect("git version label:\n{body}") + marker.len();
    let version: String = body[start..].chars().take_while(|&c| c != '<').collect();
    let (major, minor) = version.split_once('.').expect("major.minor git version");
    assert!(major.parse::<u32>().is_ok(), "numeric major: {version}");
    assert!(minor.parse::<u32>().is_ok(), "numeric minor: {version}");

    for tab in [
        "/admin/users",
        "/admin/invites",
        "/admin/repositories",
        "/admin/jobs",
    ] {
        assert!(
            body.contains(&format!(r#"href="{tab}""#)),
            "tab {tab}:\n{body}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_pages_404_to_non_admins() {
    let s = TestServer::start().await;
    let (_admin, _) = admin_client(&s).await;
    s.user("alice").await;
    let (user_client, _) = s.login("alice").await;
    let anon = s.browser();

    for path in [
        "/admin",
        "/admin/users",
        "/admin/invites",
        "/admin/repositories",
        "/admin/jobs",
    ] {
        let anonymous = anon.get(s.url(path)).send().await.unwrap();
        assert_eq!(anonymous.status(), 404, "anon GET {path}");
        let signed_in = user_client.get(s.url(path)).send().await.unwrap();
        assert_eq!(signed_in.status(), 404, "non-admin GET {path}");
    }

    let post = anon
        .post(s.url("/admin/users/alice/suspend"))
        .form(&[("_csrf", "bogus")])
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 404, "no-session POST suspend");
}
