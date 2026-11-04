mod common;

use common::*;
use starforged_core::accounts::CreateUser;

async fn unverified(s: &TestServer, handle: &str, email: &str) {
    s.core
        .create_user(CreateUser {
            handle: handle.into(),
            email: Some(email.into()),
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_accounts_confirm_their_address_before_signing_in() {
    let s = TestServer::start_with_mail(|_| {}).await;
    unverified(&s, "alice", "alice@example.com").await;

    let (_, wrong) = s.try_login("alice", "not the password").await;
    assert_eq!(wrong.status(), 401);
    assert!(
        !wrong.text().await.unwrap().contains("Verify your email"),
        "the reminder needs the right password"
    );
    let (client, blocked) = s.try_login("alice", PASSWORD).await;
    assert_eq!(blocked.status(), 403);
    let page = blocked.text().await.unwrap();
    assert!(
        page.contains("Verify your email address before signing in"),
        "{page}"
    );
    let csrf = extract_input(&page, "_csrf");

    let forged = client
        .post(s.url("/verify/resend"))
        .form(&[("_csrf", "forged"), ("email", "alice@example.com")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    for email in [
        "alice@example.com",
        "alice@example.com",
        "nobody@example.com",
    ] {
        let response = client
            .post(s.url("/verify/resend"))
            .form(&[("_csrf", csrf.as_str()), ("email", email)])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("If an unverified account uses that address")
        );
    }
    let inbox = s.inbox().await;
    assert_eq!(
        inbox.len(),
        1,
        "the second request was throttled and the unknown address got nothing"
    );
    let link = s.link_in(&inbox[0], "/verify/");

    let confirm = get_text(&client, &link).await;
    assert!(confirm.contains("Confirm your email address"));
    let confirm_csrf = extract_input(&confirm, "_csrf");
    let done = client
        .post(&link)
        .form(&[("_csrf", confirm_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    assert!(
        done.text()
            .await
            .unwrap()
            .contains("Your email address is verified")
    );
    assert_eq!(
        client.get(&link).send().await.unwrap().status(),
        404,
        "links work once"
    );

    s.login("alice").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_mail_unverified_accounts_sign_in() {
    let s = TestServer::start().await;
    unverified(&s, "bob", "bob@example.com").await;
    s.login("bob").await;
    let unknown = s
        .browser()
        .get(s.url(&format!("/verify/{}", "a".repeat(64))))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);
}
