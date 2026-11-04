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

/// The invite code in the `/join?invite=…` link shown in a page body.
fn invite_code(body: &str) -> String {
    let marker = "/join?invite=";
    let start = body.find(marker).expect("invite link in body") + marker.len();
    let code: String = body[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    assert!(!code.is_empty(), "invite code in:\n{body}");
    code
}

/// The invite id in the first `action="/admin/invites/{id}/revoke"` in a page body.
fn invite_id(body: &str) -> i64 {
    let marker = "/admin/invites/";
    let start = body.find(marker).expect("revoke action in body") + marker.len();
    let id: String = body[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    id.parse().expect("invite id")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_without_email_shows_link_once() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let resp = admin
        .post(s.url("/admin/invites"))
        .form(&[("_csrf", csrf.as_str()), ("email", "")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let code = invite_code(&body);
    assert!(body.contains(&format!("/join?invite={code}")), "{body}");
    let list = get_text(&admin, &s.url("/admin/invites")).await;
    assert!(
        !list.contains(&code),
        "one-time link must not repeat in the list:\n{list}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_with_email_shows_pending_row() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let resp = admin
        .post(s.url("/admin/invites"))
        .form(&[("_csrf", csrf.as_str()), ("email", "guest@example.com")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("guest@example.com"), "{body}");
    assert!(body.contains("pending"), "{body}");
    let list = get_text(&admin, &s.url("/admin/invites")).await;
    assert!(list.contains("guest@example.com"), "{list}");
    assert!(list.contains("pending"), "{list}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_marks_revoked_and_second_revoke_404s() {
    let s = TestServer::start().await;
    let (admin, csrf) = root_client(&s).await;
    let created = admin
        .post(s.url("/admin/invites"))
        .form(&[("_csrf", csrf.as_str()), ("email", "")])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);
    let id = invite_id(&created.text().await.unwrap());
    let revoked = admin
        .post(s.url(&format!("/admin/invites/{id}/revoke")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 303);
    assert_eq!(revoked.headers().get("location").unwrap(), "/admin/invites");
    let list = get_text(&admin, &s.url("/admin/invites")).await;
    assert!(list.contains("revoked"), "{list}");
    let again = admin
        .post(s.url(&format!("/admin/invites/{id}/revoke")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_admin_invites_404() {
    let s = TestServer::start().await;
    let (_admin, _) = root_client(&s).await;
    s.user("alice").await;
    let (user_client, _) = s.login("alice").await;
    let resp = user_client
        .get(s.url("/admin/invites"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
