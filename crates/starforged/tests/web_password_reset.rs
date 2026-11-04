mod common;

use common::*;
use starforged_core::accounts::CreateUser;
use starforged_core::passwords::AdminReset;

const NEW_PASSWORD: &str = "a brand new password";

/// Loads the reset form behind `link` and submits `password` twice (or `password` and `confirm`).
async fn submit_reset(
    client: &reqwest::Client,
    link: &str,
    password: &str,
    confirm: &str,
) -> reqwest::Response {
    let form = get_text(client, link).await;
    let csrf = extract_input(&form, "_csrf");
    client
        .post(link)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("password", password),
            ("confirm", confirm),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forgotten_passwords_reset_by_email() {
    let s = TestServer::start_with_mail(|_| {}).await;
    s.core
        .create_user(CreateUser {
            handle: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (old_session, _) = s.login("alice").await;

    let client = s.browser();
    assert!(
        get_text(&client, &s.url("/login"))
            .await
            .contains(r#"href="/forgot""#)
    );
    let form = get_text(&client, &s.url("/forgot")).await;
    let csrf = extract_input(&form, "_csrf");
    for email in [
        "nobody@example.com",
        "alice@example.com",
        "alice@example.com",
    ] {
        let response = client
            .post(s.url("/forgot"))
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
                .contains("If an account uses that address")
        );
    }
    let inbox = s.inbox().await;
    assert_eq!(
        inbox.len(),
        1,
        "unknown addresses get nothing and the repeat was throttled"
    );
    let link = s.link_in(&inbox[0], "/reset/");

    let mismatch = submit_reset(&client, &link, NEW_PASSWORD, "something else").await;
    assert_eq!(mismatch.status(), 422);
    let short = submit_reset(&client, &link, "short", "short").await;
    assert_eq!(
        short.status(),
        422,
        "a rejected password does not use up the link"
    );
    let done = submit_reset(&client, &link, NEW_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(done.status(), 200);
    assert!(done.text().await.unwrap().contains("Password changed"));

    let signed_out = old_session
        .get(s.url("/settings/tokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        signed_out.status(),
        303,
        "the reset ended existing sessions"
    );
    assert_eq!(s.try_login("alice", PASSWORD).await.1.status(), 401);
    assert_eq!(s.try_login("alice", NEW_PASSWORD).await.1.status(), 303);
    assert_eq!(
        client.get(&link).send().await.unwrap().status(),
        404,
        "links work once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_mail_there_is_no_forgot_page() {
    let s = TestServer::start().await;
    let client = s.browser();
    assert_eq!(
        client.get(s.url("/forgot")).send().await.unwrap().status(),
        404
    );
    assert!(
        !get_text(&client, &s.url("/login"))
            .await
            .contains(r#"href="/forgot""#)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn links_issued_by_admins_reset_passwords() {
    let s = TestServer::start().await;
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let bob = s.user("bob").await;
    let AdminReset::Link(link) = s.core.admin_password_reset(&root, &bob).await.unwrap() else {
        panic!("without mail the admin gets a link");
    };
    let done = submit_reset(&s.browser(), &link, NEW_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(done.status(), 200);
    assert_eq!(s.try_login("bob", NEW_PASSWORD).await.1.status(), 303);
}
