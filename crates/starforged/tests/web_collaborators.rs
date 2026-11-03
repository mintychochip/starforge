mod common;

use common::*;
use starforged_core::permission::Visibility;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_pages_and_collaborator_management() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "secret", Visibility::Private).await;
    s.repo(&alice, "open", Visibility::Public).await;

    let anonymous = s.browser();
    let owner_page = get_text(&anonymous, &s.url("/alice")).await;
    assert!(owner_page.contains(r#"href="/alice/open""#));
    assert!(
        !owner_page.contains("secret"),
        "private repositories stay hidden"
    );
    assert_eq!(
        anonymous
            .get(s.url("/nobody"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let (bob, bob_csrf) = s.login("bob").await;
    assert_eq!(
        bob.get(s.url("/alice/secret/settings/collaborators"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let (alice_client, csrf) = s.login("alice").await;
    let settings = s.url("/alice/secret/settings/collaborators");
    let unknown = alice_client
        .post(&settings)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "nobody"),
            ("permission", "read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 422);
    assert!(unknown.text().await.unwrap().contains("no user named"));
    let added = alice_client
        .post(&settings)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "bob"),
            ("permission", "read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    assert_eq!(
        added.headers()["location"],
        "/alice/secret/settings/collaborators"
    );
    assert!(
        get_text(&alice_client, &settings)
            .await
            .contains(r#"<td><a href="/bob">bob</a></td><td>read</td>"#)
    );

    // bob can now see the repository but cannot manage it
    assert!(
        get_text(&bob, &s.url("/alice"))
            .await
            .contains(r#"href="/alice/secret""#)
    );
    assert_eq!(bob.get(&settings).send().await.unwrap().status(), 403);
    let escalate = bob
        .post(&settings)
        .form(&[
            ("_csrf", bob_csrf.as_str()),
            ("handle", "bob"),
            ("permission", "admin"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(escalate.status(), 403);

    let removed = alice_client
        .post(s.url("/alice/secret/settings/collaborators/bob/remove"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 303);
    assert!(!get_text(&bob, &s.url("/alice")).await.contains("secret"));
}
