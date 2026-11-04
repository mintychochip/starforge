mod common;

use common::{PASSWORD, TestServer, extract_input, get_text};
use starforged_core::accounts::CreateUser;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

/// POSTs an admin user-action form, folding the CSRF token into the body.
async fn post_user_action(
    client: &reqwest::Client,
    url: &str,
    csrf: &str,
    extra: &[(&str, &str)],
) -> reqwest::Response {
    let mut fields = vec![("_csrf", csrf)];
    fields.extend_from_slice(extra);
    client.post(url).form(&fields).send().await.unwrap()
}

/// The `/reset/<secret>` path shown on a re-rendered detail page.
fn reset_path(body: &str) -> String {
    let start = body.find("/reset/").expect("reset link in body");
    let rest = &body[start..];
    let end = rest
        .find(|c: char| c == '"' || c == '<' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest[..end].to_owned()
}

const NEW_PASSWORD: &str = "a brand new password";

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspend_unsuspend_ends_sessions_and_blocks_sign_in() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let bob = s.user("bob").await;
    let (bob_client, _) = s.login("bob").await;
    assert_eq!(
        bob_client.get(s.url("/")).send().await.unwrap().status(),
        200
    );
    let token = s.token(&bob, &[Scope::RepoRead]).await;
    let api = reqwest::Client::new();
    assert_eq!(
        api.get(s.url("/api/v1/user"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let before = post_user_action(&admin, &s.url("/admin/users/bob/suspend"), &csrf, &[]).await;
    assert_eq!(before.status(), 303);
    assert_eq!(before.headers()["location"], "/admin/users/bob");
    assert_eq!(s.try_login("bob", PASSWORD).await.1.status(), 401);
    let gone = bob_client
        .get(s.url("/settings/profile"))
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 303);
    assert!(
        gone.headers()["location"]
            .to_str()
            .unwrap()
            .contains("/login"),
        "{:?}",
        gone.headers()
    );
    assert_eq!(
        api.get(s.url("/api/v1/user"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let (admin2, csrf2) = s.login("root").await;
    let back = post_user_action(&admin2, &s.url("/admin/users/bob/unsuspend"), &csrf2, &[]).await;
    assert_eq!(back.status(), 303);
    assert_eq!(s.try_login("bob", PASSWORD).await.1.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_and_revoke_admin() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    s.user("bob").await;
    let (bob, _) = s.login("bob").await;
    assert_eq!(bob.get(s.url("/admin")).send().await.unwrap().status(), 404);
    let granted = post_user_action(&admin, &s.url("/admin/users/bob/grant"), &csrf, &[]).await;
    assert_eq!(granted.status(), 303);
    assert_eq!(granted.headers()["location"], "/admin/users/bob");
    assert_eq!(bob.get(s.url("/admin")).send().await.unwrap().status(), 200);
    let revoked = post_user_action(&admin, &s.url("/admin/users/bob/revoke"), &csrf, &[]).await;
    assert_eq!(revoked.status(), 303);
    assert_eq!(bob.get(s.url("/admin")).send().await.unwrap().status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_admin_guards() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let revoked = post_user_action(&admin, &s.url("/admin/users/root/revoke"), &csrf, &[]).await;
    assert_eq!(revoked.status(), 422);
    assert!(
        revoked
            .text()
            .await
            .unwrap()
            .contains("only site administrator"),
    );
    let suspended = post_user_action(&admin, &s.url("/admin/users/root/suspend"), &csrf, &[]).await;
    assert_eq!(suspended.status(), 422);
    assert!(
        suspended
            .text()
            .await
            .unwrap()
            .contains("You cannot suspend yourself."),
    );
    let deleted = post_user_action(
        &admin,
        &s.url("/admin/users/root/delete"),
        &csrf,
        &[("confirm", "root")],
    )
    .await;
    assert_eq!(deleted.status(), 422);
    assert!(
        deleted
            .text()
            .await
            .unwrap()
            .contains("You cannot delete yourself."),
    );
    s.user("bob").await;
    let granted = post_user_action(&admin, &s.url("/admin/users/bob/grant"), &csrf, &[]).await;
    assert_eq!(granted.status(), 303);
    let demoted = post_user_action(&admin, &s.url("/admin/users/root/revoke"), &csrf, &[]).await;
    assert_eq!(demoted.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_user_rules() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let bob = s.user("bob").await;
    s.repo(&bob, "proj", Visibility::Private).await;
    let blocked = post_user_action(
        &admin,
        &s.url("/admin/users/bob/delete"),
        &csrf,
        &[("confirm", "bob")],
    )
    .await;
    assert_eq!(blocked.status(), 422);
    assert!(
        blocked
            .text()
            .await
            .unwrap()
            .contains("still owns repositories"),
    );
    s.core
        .delete_repo(&bob, "bob", "proj", "bob/proj")
        .await
        .unwrap();
    let deleted = post_user_action(
        &admin,
        &s.url("/admin/users/bob/delete"),
        &csrf,
        &[("confirm", "bob")],
    )
    .await;
    assert_eq!(deleted.status(), 303);
    assert_eq!(deleted.headers()["location"], "/admin/users");
    assert!(s.core.user_by_handle("bob").await.unwrap().is_none());
    let root = s.core.user_by_handle("root").await.unwrap().unwrap();
    assert!(s.core.admin_deleted_repos(&root).await.unwrap().is_empty());
    assert_eq!(s.try_login("bob", PASSWORD).await.1.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_password_shows_link_without_mail() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    s.user("bob").await;
    let resp = post_user_action(
        &admin,
        &s.url("/admin/users/bob/reset-password"),
        &csrf,
        &[],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("/reset/"), "{body}");
    let link = s.url(&reset_path(&body));
    let client = s.browser();
    let form = get_text(&client, &link).await;
    assert!(form.contains("action="), "{form}");
    let reset_csrf = extract_input(&form, "_csrf");
    let done = client
        .post(&link)
        .form(&[
            ("_csrf", reset_csrf.as_str()),
            ("password", NEW_PASSWORD),
            ("confirm", NEW_PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    assert!(done.text().await.unwrap().contains("Password changed"));
    assert_eq!(s.try_login("bob", NEW_PASSWORD).await.1.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admins_create_users_directly_with_verified_addresses() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let created = admin
        .post(s.url("/admin/users"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "carol"),
            ("display_name", "Carol"),
            ("email", "carol@example.com"),
            ("password", "correct horse battery staple extra"),
            ("admin", "on"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    assert_eq!(
        created.headers().get("location").unwrap(),
        "/admin/users/carol"
    );
    let carol = s.core.user_by_handle("carol").await.unwrap().unwrap();
    assert!(carol.email_verified && carol.is_admin);
    let dup = admin
        .post(s.url("/admin/users"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "carol"),
            ("display_name", "Carol Again"),
            ("email", "carol2@example.com"),
            ("password", "correct horse battery staple extra"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 422);
}
