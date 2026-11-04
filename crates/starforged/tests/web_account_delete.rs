mod common;

use common::*;
use starforged_core::permission::Visibility;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_delete_their_account_after_typing_their_handle() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let (client, csrf) = s.login("alice").await;
    let page = get_text(&client, &s.url("/settings/delete")).await;
    assert!(page.contains(r#"action="/settings/delete""#), "{page}");

    let blocked = client
        .post(s.url("/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 422);
    assert!(
        blocked
            .text()
            .await
            .unwrap()
            .contains("Delete your repositories first: proj.")
    );
    s.core
        .delete_repo(&alice, "alice", "proj", "alice/proj")
        .await
        .unwrap();
    let wrong = client
        .post(s.url("/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "nope")])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 422);

    let deleted = client
        .post(s.url("/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 200);
    assert!(
        deleted
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("sf_session=")),
        "the session cookie is cleared"
    );
    assert!(deleted.text().await.unwrap().contains("Account deleted"));
    assert_eq!(
        client
            .get(s.url("/settings/profile"))
            .send()
            .await
            .unwrap()
            .status(),
        303,
        "signed out"
    );
    let (_, again) = s.try_login("alice", PASSWORD).await;
    assert_ne!(again.status(), 303, "the account cannot sign in");
    assert_eq!(
        s.browser()
            .get(s.url("/alice"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
