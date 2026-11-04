mod common;

use common::*;
use starforged_core::accounts::CreateUser;

const NEW_PASSWORD: &str = "a brand new password";

async fn post_form(
    client: &reqwest::Client,
    url: &str,
    fields: &[(&str, &str)],
) -> reqwest::Response {
    client.post(url).form(fields).send().await.unwrap()
}

/// `(session id, is the current session)` for each row of the sessions page.
fn sessions_on(page: &str) -> Vec<(i64, bool)> {
    page.split("<tr>")
        .filter_map(|row| {
            let start = row.find("/settings/sessions/")? + "/settings/sessions/".len();
            let id = row[start..].split('/').next()?.parse().ok()?;
            Some((id, row.contains("this session")))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_and_password_settings() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let (other, _) = s.login("alice").await;
    let csrf = csrf.as_str();

    let index = client.get(s.url("/settings")).send().await.unwrap();
    assert_eq!(index.status(), 303);
    assert_eq!(index.headers()["location"], "/settings/profile");
    let home = get_text(&client, &s.url("/")).await;
    assert!(home.contains(r#"<a href="/settings/profile">Settings</a>"#));

    let profile = s.url("/settings/profile");
    let saved = post_form(
        &client,
        &profile,
        &[("_csrf", csrf), ("display_name", "Alice Liddell")],
    )
    .await;
    assert_eq!(saved.status(), 200);
    assert!(
        saved
            .text()
            .await
            .unwrap()
            .contains(r#"value="Alice Liddell""#)
    );
    let too_long = "x".repeat(101);
    let rejected = post_form(
        &client,
        &profile,
        &[("_csrf", csrf), ("display_name", too_long.as_str())],
    )
    .await;
    assert_eq!(rejected.status(), 422);
    let forged = post_form(
        &client,
        &profile,
        &[("_csrf", "forged"), ("display_name", "x")],
    )
    .await;
    assert_eq!(forged.status(), 403);

    let password = s.url("/settings/password");
    let wrong = post_form(
        &client,
        &password,
        &[
            ("_csrf", csrf),
            ("current", "not my password"),
            ("password", NEW_PASSWORD),
            ("confirm", NEW_PASSWORD),
        ],
    )
    .await;
    assert_eq!(wrong.status(), 422);
    assert!(
        wrong
            .text()
            .await
            .unwrap()
            .contains("current password is incorrect")
    );
    let mismatch = post_form(
        &client,
        &password,
        &[
            ("_csrf", csrf),
            ("current", PASSWORD),
            ("password", NEW_PASSWORD),
            ("confirm", "something else"),
        ],
    )
    .await;
    assert_eq!(mismatch.status(), 422);
    let changed = post_form(
        &client,
        &password,
        &[
            ("_csrf", csrf),
            ("current", PASSWORD),
            ("password", NEW_PASSWORD),
            ("confirm", NEW_PASSWORD),
        ],
    )
    .await;
    assert_eq!(changed.status(), 200);
    assert_eq!(
        other.get(&profile).send().await.unwrap().status(),
        303,
        "the other session was signed out"
    );
    assert_eq!(
        client.get(&profile).send().await.unwrap().status(),
        200,
        "this session stays"
    );
    assert_eq!(s.try_login("alice", NEW_PASSWORD).await.1.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_can_be_listed_and_revoked() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let (second, _) = s.login("alice").await;
    let sessions_page = s.url("/settings/sessions");

    let listed = sessions_on(&get_text(&client, &sessions_page).await);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed.iter().filter(|(_, current)| *current).count(), 1);
    let other_id = listed.iter().find(|(_, current)| !current).unwrap().0;
    let revoked = post_form(
        &client,
        &s.url(&format!("/settings/sessions/{other_id}/revoke")),
        &[("_csrf", csrf.as_str())],
    )
    .await;
    assert_eq!(revoked.status(), 303);
    assert_eq!(
        second
            .get(s.url("/settings/profile"))
            .send()
            .await
            .unwrap()
            .status(),
        303,
        "the revoked session is signed out"
    );

    let (third, _) = s.login("alice").await;
    let others = post_form(
        &client,
        &s.url("/settings/sessions/revoke-others"),
        &[("_csrf", csrf.as_str())],
    )
    .await;
    assert_eq!(others.status(), 303);
    assert_eq!(
        third
            .get(s.url("/settings/profile"))
            .send()
            .await
            .unwrap()
            .status(),
        303
    );
    let remaining = sessions_on(&get_text(&client, &sessions_page).await);
    assert_eq!(remaining.len(), 1);

    s.user("bob").await;
    let (bob, bob_csrf) = s.login("bob").await;
    let not_his = post_form(
        &bob,
        &s.url(&format!("/settings/sessions/{}/revoke", remaining[0].0)),
        &[("_csrf", bob_csrf.as_str())],
    )
    .await;
    assert_eq!(not_his.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_apply_at_once_without_mail() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.core
        .create_user(CreateUser {
            handle: "bob".into(),
            email: Some("bob@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (client, csrf) = s.login("alice").await;
    let email = s.url("/settings/email");
    let taken = post_form(
        &client,
        &email,
        &[("_csrf", csrf.as_str()), ("email", "bob@example.com")],
    )
    .await;
    assert_eq!(taken.status(), 422);
    let changed = post_form(
        &client,
        &email,
        &[("_csrf", csrf.as_str()), ("email", "Alice@Example.com")],
    )
    .await;
    assert_eq!(changed.status(), 200);
    let page = changed.text().await.unwrap();
    assert!(
        page.contains("alice@example.com") && page.contains("unverified"),
        "{page}"
    );
    let user = s.core.user_by_id(alice.id).await.unwrap().unwrap();
    assert_eq!(
        (user.email.as_deref(), user.email_verified),
        (Some("alice@example.com"), false)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_wait_for_confirmation_with_mail() {
    let s = TestServer::start_with_mail(|_| {}).await;
    let alice = s
        .core
        .create_user(CreateUser {
            handle: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (client, csrf) = s.login("alice").await;
    let requested = post_form(
        &client,
        &s.url("/settings/email"),
        &[("_csrf", csrf.as_str()), ("email", "alice@new.example")],
    )
    .await;
    assert_eq!(requested.status(), 200);
    assert!(
        requested
            .text()
            .await
            .unwrap()
            .contains("We sent a confirmation link to alice@new.example")
    );
    assert_eq!(
        s.core
            .user_by_id(alice.id)
            .await
            .unwrap()
            .unwrap()
            .email
            .as_deref(),
        Some("alice@example.com"),
        "the old address stays until the link is used"
    );

    let link = s.link_in(&s.last_email_to("alice@new.example").await, "/verify/");
    let confirm = get_text(&client, &link).await;
    let confirm_csrf = extract_input(&confirm, "_csrf");
    let done = client
        .post(&link)
        .form(&[("_csrf", confirm_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    let user = s.core.user_by_id(alice.id).await.unwrap().unwrap();
    assert_eq!(
        (user.email.as_deref(), user.email_verified),
        (Some("alice@new.example"), true)
    );
}
