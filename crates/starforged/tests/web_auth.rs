mod common;

use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_logout_csrf_and_security_headers() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = s.browser();

    let page = client.get(s.url("/login")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let headers = page.headers().clone();
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("default-src 'self'")
    );
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    let csrf = extract_input(&page.text().await.unwrap(), "_csrf");

    let wrong = client
        .post(s.url("/login"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/"),
            ("login", "alice"),
            ("password", "wrong password!"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    assert!(
        wrong
            .text()
            .await
            .unwrap()
            .contains("Incorrect handle, email, or password.")
    );

    let forged = client
        .post(s.url("/login"))
        .form(&[
            ("_csrf", "forged"),
            ("next", "/"),
            ("login", "alice"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);

    let ok = client
        .post(s.url("/login"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/settings/tokens"),
            ("login", "alice"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 303);
    assert_eq!(ok.headers()["location"], "/settings/tokens");
    let cookies: Vec<String> = ok
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("sf_session=")
            && c.contains("HttpOnly")
            && c.contains("SameSite=Lax")),
        "{cookies:?}"
    );

    let dashboard = get_text(&client, &s.url("/")).await;
    assert!(dashboard.contains(r#"<a href="/alice">alice</a>"#));
    assert_eq!(
        client.get(s.url("/login")).send().await.unwrap().status(),
        303,
        "signed-in users skip the form"
    );

    let session_csrf = extract_input(&dashboard, "_csrf");
    let bad_logout = client
        .post(s.url("/logout"))
        .form(&[("_csrf", "nope")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_logout.status(), 403);
    let logout = client
        .post(s.url("/logout"))
        .form(&[("_csrf", session_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 303);
    assert!(
        get_text(&client, &s.url("/"))
            .await
            .contains(r#"<a href="/login">Sign in</a>"#)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_never_redirects_off_site() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let client = s.browser();
    let page = get_text(&client, &s.url("/login?next=//evil.example/x")).await;
    assert!(
        page.contains(r#"name="next" value="/""#),
        "the form carries a sanitized next"
    );
    let csrf = extract_input(&page, "_csrf");
    let response = client
        .post(s.url("/login"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "https://evil.example"),
            ("login", "alice"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], "/");
}
