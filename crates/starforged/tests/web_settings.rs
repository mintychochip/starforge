mod common;

use common::*;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokens_are_created_shown_once_and_revoked() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let anonymous = s
        .browser()
        .get(s.url("/settings/tokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 303);
    assert_eq!(
        anonymous.headers()["location"],
        "/login?next=%2Fsettings%2Ftokens"
    );

    let (client, csrf) = s.login("alice").await;
    let created = client
        .post(s.url("/settings/tokens"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "laptop"),
            ("scopes", "repo:read"),
            ("scopes", "repo:write"),
            ("expires_days", "7"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);
    let secret = between(
        &created.text().await.unwrap(),
        r#"<pre class="token">"#,
        "</pre>",
    );
    let auth = s.core.authenticate_token(&secret).await.unwrap();
    assert_eq!(auth.scopes, vec![Scope::RepoRead, Scope::RepoWrite]);

    let listing = get_text(&client, &s.url("/settings/tokens")).await;
    assert!(
        !listing.contains(&secret),
        "the secret is never shown again"
    );
    assert!(listing.contains(&format!("sfp_…{}", &secret[secret.len() - 4..])));
    assert!(
        !listing.contains(r#"value="admin""#),
        "non-admins cannot pick the admin scope"
    );

    let no_scopes = client
        .post(s.url("/settings/tokens"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "x"),
            ("expires_days", "7"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(no_scopes.status(), 422);
    assert!(
        no_scopes
            .text()
            .await
            .unwrap()
            .contains("at least one scope is required")
    );

    let forged = client
        .post(s.url("/settings/tokens"))
        .form(&[
            ("_csrf", "x"),
            ("name", "x"),
            ("scopes", "repo:read"),
            ("expires_days", "7"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);

    let id = s.core.list_tokens(&auth.user).await.unwrap()[0].id;
    let revoked = client
        .post(s.url(&format!("/settings/tokens/{id}/revoke")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 303);
    assert!(s.core.authenticate_token(&secret).await.is_err());
    assert!(
        get_text(&client, &s.url("/settings/tokens"))
            .await
            .contains("revoked")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repositories_are_created_from_the_form() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    assert!(
        get_text(&client, &s.url("/new"))
            .await
            .contains(r#"name="name""#)
    );
    let created = client
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "Proj"),
            ("description", "demo"),
            ("visibility", "public"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    assert_eq!(created.headers()["location"], "/alice/Proj");
    let duplicate = client
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "proj"),
            ("description", ""),
            ("visibility", "private"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 422);
    assert!(duplicate.text().await.unwrap().contains("already exists"));
    let dashboard = get_text(&client, &s.url("/")).await;
    assert!(dashboard.contains(r#"<a href="/alice/Proj">alice/Proj</a>"#));
}
