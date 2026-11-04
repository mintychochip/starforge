mod common;

use common::*;
use starforged_core::accounts::{CreateUser, User};

const NEW_PASSWORD: &str = "a long enough password";

async fn admin(s: &TestServer) -> User {
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Loads the sign-up form at `path` (`/join` or an invite link's path), fills in `fields`, and posts it.
async fn join(
    s: &TestServer,
    client: &reqwest::Client,
    path: &str,
    fields: &[(&str, &str)],
) -> reqwest::Response {
    let page = get_text(client, &s.url(path)).await;
    let csrf = extract_input(&page, "_csrf");
    let invite = extract_input(&page, "invite");
    let mut form = vec![
        ("_csrf", csrf.as_str()),
        ("invite", invite.as_str()),
        ("password", NEW_PASSWORD),
    ];
    form.extend_from_slice(fields);
    client
        .post(s.url("/join"))
        .form(&form)
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invite_mode_signs_up_only_with_an_invite() {
    let s = TestServer::start().await;
    let client = s.browser();
    let closed = client.get(s.url("/join")).send().await.unwrap();
    assert_eq!(closed.status(), 403);
    assert!(
        closed
            .text()
            .await
            .unwrap()
            .contains("Sign-up is by invitation")
    );
    assert!(
        !get_text(&client, &s.url("/login"))
            .await
            .contains(r#"href="/join""#)
    );

    let root = admin(&s).await;
    let invite = s.core.create_invite(&root, None).await.unwrap();
    let path = invite.link.strip_prefix(&s.base).unwrap().to_owned();
    let taken = join(
        &s,
        &client,
        &path,
        &[("handle", "root"), ("email", "alice@example.com")],
    )
    .await;
    assert_eq!(taken.status(), 422);
    assert!(taken.text().await.unwrap().contains("already taken"));
    let joined = join(
        &s,
        &client,
        &path,
        &[("handle", "alice"), ("email", "alice@example.com")],
    )
    .await;
    assert_eq!(
        joined.status(),
        303,
        "a sign-up that needs no verification signs in"
    );
    assert!(
        get_text(&client, &s.url("/"))
            .await
            .contains("Your repositories")
    );

    let reused = s.browser().get(s.url(&path)).send().await.unwrap();
    assert_eq!(reused.status(), 404);
    assert!(reused.text().await.unwrap().contains("Invite not valid"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_bound_invites_skip_verification() {
    let s = TestServer::start_with_mail(|_| {}).await;
    let root = admin(&s).await;
    s.core
        .create_invite(&root, Some("carol@example.com"))
        .await
        .unwrap();
    let link = s.link_in(&s.last_email_to("carol@example.com").await, "/join");
    let path = link.strip_prefix(&s.base).unwrap().to_owned();
    let client = s.browser();
    let form = get_text(&client, &s.url(&path)).await;
    assert!(
        form.contains(r#"value="carol@example.com" readonly"#),
        "{form}"
    );
    let wrong = join(
        &s,
        &client,
        &path,
        &[("handle", "carol"), ("email", "mallory@example.com")],
    )
    .await;
    assert_eq!(wrong.status(), 422);
    assert!(
        wrong
            .text()
            .await
            .unwrap()
            .contains(r#"value="carol@example.com" readonly"#),
        "the form keeps the invited address"
    );
    let joined = join(
        &s,
        &client,
        &path,
        &[("handle", "carol"), ("email", "carol@example.com")],
    )
    .await;
    assert_eq!(joined.status(), 303);
    assert_eq!(
        s.inbox().await.len(),
        1,
        "only the invite: an invited address needs no verification"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_mode_verifies_new_addresses_by_email() {
    let s = TestServer::start_with_mail(|config| config.registration.mode = "open".into()).await;
    let client = s.browser();
    assert!(
        get_text(&client, &s.url("/login"))
            .await
            .contains(r#"href="/join""#)
    );
    assert!(
        get_text(&client, &s.url("/"))
            .await
            .contains(r#"href="/join""#)
    );
    let forged = client
        .post(s.url("/join"))
        .form(&[
            ("_csrf", "forged"),
            ("invite", ""),
            ("handle", "dana"),
            ("email", "dana@example.com"),
            ("password", NEW_PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    let reserved = join(
        &s,
        &client,
        "/join",
        &[("handle", "verify"), ("email", "v@example.com")],
    )
    .await;
    assert_eq!(reserved.status(), 422);
    let joined = join(
        &s,
        &client,
        "/join",
        &[("handle", "dana"), ("email", "dana@example.com")],
    )
    .await;
    assert_eq!(joined.status(), 200);
    assert!(
        joined
            .text()
            .await
            .unwrap()
            .contains("We sent a link to dana@example.com")
    );
    let (_, blocked) = s.try_login("dana", NEW_PASSWORD).await;
    assert_eq!(blocked.status(), 403);

    let link = s.link_in(&s.last_email_to("dana@example.com").await, "/verify/");
    let confirm = get_text(&client, &link).await;
    let csrf = extract_input(&confirm, "_csrf");
    let confirmed = client
        .post(&link)
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.status(), 200);
    let (_, signed_in) = s.try_login("dana", NEW_PASSWORD).await;
    assert_eq!(signed_in.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domains_mode_limits_sign_up_to_listed_domains() {
    let s = TestServer::start_with_mail(|config| {
        config.registration.mode = "domains".into();
        config.registration.allowed_domains = vec!["example.com".into()];
    })
    .await;
    let client = s.browser();
    let outside = join(
        &s,
        &client,
        "/join",
        &[("handle", "eve"), ("email", "eve@elsewhere.org")],
    )
    .await;
    assert_eq!(outside.status(), 422);
    assert!(
        outside
            .text()
            .await
            .unwrap()
            .contains("limited to addresses at example.com")
    );
    let inside = join(
        &s,
        &client,
        "/join",
        &[("handle", "erin"), ("email", "erin@example.com")],
    )
    .await;
    assert_eq!(inside.status(), 200);
}
