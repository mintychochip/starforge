mod common;

use common::{TestServer, get_text};
use starforged_core::accounts::CreateUser;

async fn root_client(s: &TestServer) -> (reqwest::Client, String) {
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
async fn users_list_searches_and_detail_shows_state() {
    let s = TestServer::start().await;
    let (client, _) = root_client(&s).await;
    s.user("alice").await;
    let list = get_text(&client, &s.url("/admin/users")).await;
    assert!(list.contains("/admin/users/alice"), "{list}");
    assert!(list.contains("/admin/users/root"), "{list}");
    let searched = get_text(&client, &s.url("/admin/users?q=ali")).await;
    assert!(searched.contains("/admin/users/alice"), "{searched}");
    assert!(!searched.contains("/admin/users/root"), "{searched}");
    let detail = get_text(&client, &s.url("/admin/users/alice")).await;
    assert!(detail.contains("alice"), "{detail}");
    assert!(
        detail.contains("action=\"/admin/users/alice/suspend\""),
        "{detail}"
    );
    let missing = client
        .get(s.url("/admin/users/nobody"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}
