//! TOTP two-factor authentication (M3d D1): enrollment, second-factor
//! login, replay refusal, recovery codes, challenge limits, disable,
//! regeneration, and the admin reset (audited as `user.2fa_reset`).

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use common::*;
use starforged_core::accounts::CreateUser;
use starforged_core::totp::{base32, code_at};

fn now_step() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30
}

fn code_at_step(secret_base32: &str, step: u64) -> String {
    let secret = base32::decode(secret_base32).expect("enrollment secret is base32");
    format!("{:06}", code_at(&secret, step))
}

/// Enrolls alice and returns (session client, csrf, secret, recovery codes, last consumed step).
async fn enrolled(s: &TestServer) -> (reqwest::Client, String, String, Vec<String>, u64) {
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let page = get_text(&client, &s.url("/settings/two-factor")).await;
    assert!(page.contains("disabled"), "{page}");
    let enroll = client
        .post(s.url("/settings/two-factor"))
        .form(&[("_csrf", csrf.as_str()), ("action", "enroll")])
        .send()
        .await
        .unwrap();
    assert_eq!(enroll.status(), 200);
    let body = enroll.text().await.unwrap();
    let secret = between(&body, r#"<code class="totp-secret">"#, "</code>");
    assert!(body.contains("otpauth://totp/"), "{body}");
    let step = now_step();
    let confirmed = client
        .post(s.url("/settings/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "confirm"),
            ("code", code_at_step(&secret, step).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.status(), 200);
    let body = confirmed.text().await.unwrap();
    let shown = between(&body, r#"<pre class="recovery-codes">"#, "</pre>");
    let codes: Vec<String> = shown.split_whitespace().map(str::to_owned).collect();
    assert_eq!(codes.len(), 10, "{body}");
    (client, csrf, secret, codes, step)
}

/// Password login for a 2FA user: redirected to the second step, with a
/// challenge cookie and no session cookie. Returns (client, csrf).
async fn start_two_factor(s: &TestServer, handle: &str) -> (reqwest::Client, String) {
    let (client, response) = s.try_login(handle, PASSWORD).await;
    assert_eq!(response.status(), 303);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        location.starts_with("/login/two-factor"),
        "location: {location}"
    );
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("sf_login_challenge=")),
        "no challenge cookie: {cookies:?}"
    );
    assert!(
        !cookies.iter().any(|c| c.starts_with("sf_session=")),
        "session cookie before the second factor: {cookies:?}"
    );
    let page = get_text(&client, &s.url(&location)).await;
    let csrf = extract_input(&page, "_csrf");
    (client, csrf)
}

/// Submits the second factor and returns the response (303 "/" on success,
/// 401 on a refused code, 303 "/login" on a voided/expired challenge).
async fn second_factor(
    client: &reqwest::Client,
    s: &TestServer,
    csrf: &str,
    code: &str,
) -> reqwest::Response {
    client
        .post(s.url("/login/two-factor"))
        .form(&[("_csrf", csrf), ("next", "/"), ("code", code)])
        .send()
        .await
        .unwrap()
}

async fn audit_actions(s: &TestServer) -> Vec<String> {
    starforged_db::audit::recent(s.core.db(), 100)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrollment_login_recovery_and_replay() {
    let s = TestServer::start().await;
    let (settings, _, secret, codes, step) = enrolled(&s).await;
    let actions = audit_actions(&s).await;
    assert!(
        actions.iter().any(|a| a == "account.2fa_enabled"),
        "{actions:?}"
    );

    // The stored secret is sealed, never the base32 secret.
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let sealed: Option<String> = sqlx::query_scalar("SELECT totp_secret FROM users WHERE id = $1")
        .bind(alice.id)
        .fetch_one(s.core.db().pool())
        .await
        .unwrap();
    let sealed = sealed.unwrap();
    assert!(sealed.starts_with("v1:"), "{sealed}");
    assert!(
        !sealed.contains(&secret),
        "secret stored in clear: {sealed}"
    );

    // A recovery code logs in exactly once.
    let (client, csrf) = start_two_factor(&s, "alice").await;
    let ok = second_factor(&client, &s, &csrf, &codes[0]).await;
    assert_eq!(ok.status(), 303);
    assert_eq!(ok.headers()["location"], "/");
    assert!(
        !get_text(&client, &s.url("/settings/profile"))
            .await
            .is_empty()
    );

    let (client, csrf) = start_two_factor(&s, "alice").await;
    let reused = second_factor(&client, &s, &csrf, &codes[0]).await;
    assert_eq!(reused.status(), 401, "recovery code reused");

    // The next TOTP step logs in, and replaying that same code is refused.
    let next = step + 1;
    let (client, csrf) = start_two_factor(&s, "alice").await;
    let ok = second_factor(&client, &s, &csrf, code_at_step(&secret, next).as_str()).await;
    assert_eq!(ok.status(), 303);
    let (client, csrf) = start_two_factor(&s, "alice").await;
    let replay = second_factor(&client, &s, &csrf, code_at_step(&secret, next).as_str()).await;
    assert_eq!(replay.status(), 401, "TOTP step replayed");

    // CSRF is checked on the settings forms.
    let forged = settings
        .post(s.url("/settings/two-factor"))
        .form(&[("_csrf", "forged"), ("action", "enroll")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_failures_void_the_challenge() {
    let s = TestServer::start().await;
    let (_, _, secret, _, step) = enrolled(&s).await;
    let (client, csrf) = start_two_factor(&s, "alice").await;
    let valid = code_at_step(&secret, step + 1);
    let wrong = format!("{:06}", (valid.parse::<u32>().unwrap() + 1) % 1_000_000);
    for i in 0..5 {
        let rejected = second_factor(&client, &s, &csrf, &wrong).await;
        assert_eq!(rejected.status(), 401, "failure {i} not refused");
    }
    let after = second_factor(&client, &s, &csrf, &valid).await;
    assert_eq!(after.status(), 303);
    assert_eq!(
        after.headers()["location"],
        "/login",
        "challenge should be void"
    );
    let actions = audit_actions(&s).await;
    assert_eq!(
        actions.iter().filter(|a| *a == "login.2fa_failure").count(),
        5
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_challenge_is_refused() {
    let s = TestServer::start().await;
    let (_, _, secret, _, step) = enrolled(&s).await;
    let (client, csrf) = start_two_factor(&s, "alice").await;
    sqlx::query("UPDATE login_challenges SET expires_at = $1")
        .bind(0_i64)
        .execute(s.core.db().pool())
        .await
        .unwrap();
    let late = second_factor(&client, &s, &csrf, code_at_step(&secret, step + 1).as_str()).await;
    assert_eq!(late.status(), 303);
    assert_eq!(late.headers()["location"], "/login");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disable_needs_password_and_code() {
    let s = TestServer::start().await;
    let (client, csrf, secret, _, step) = enrolled(&s).await;
    let wrong = client
        .post(s.url("/settings/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "disable"),
            ("password", "wrong password"),
            ("code", code_at_step(&secret, step + 1).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 422);
    let done = client
        .post(s.url("/settings/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "disable"),
            ("password", PASSWORD),
            ("code", code_at_step(&secret, step + 1).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    let actions = audit_actions(&s).await;
    assert!(
        actions.iter().any(|a| a == "account.2fa_disabled"),
        "{actions:?}"
    );
    // The next sign-in is a plain password login again.
    let (_, response) = s.try_login("alice", PASSWORD).await;
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["location"], "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regenerate_invalidates_old_codes() {
    let s = TestServer::start().await;
    let (client, csrf, secret, old_codes, step) = enrolled(&s).await;
    let fresh = client
        .post(s.url("/settings/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "regenerate"),
            ("code", code_at_step(&secret, step + 1).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), 200);
    let shown = between(
        &fresh.text().await.unwrap(),
        r#"<pre class="recovery-codes">"#,
        "</pre>",
    );
    let new_codes: Vec<String> = shown.split_whitespace().map(str::to_owned).collect();
    assert_eq!(new_codes.len(), 10);
    assert!(!new_codes.iter().any(|c| old_codes.contains(c)));
    let actions = audit_actions(&s).await;
    assert!(
        actions
            .iter()
            .any(|a| a == "account.recovery_codes_regenerated"),
        "{actions:?}"
    );

    let (client, csrf) = start_two_factor(&s, "alice").await;
    let stale = second_factor(&client, &s, &csrf, &old_codes[0]).await;
    assert_eq!(stale.status(), 401, "old recovery code still worked");
    let (client, csrf) = start_two_factor(&s, "alice").await;
    let ok = second_factor(&client, &s, &csrf, &new_codes[0]).await;
    assert_eq!(ok.status(), 303);
    assert_eq!(ok.headers()["location"], "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_reset_and_guards() {
    let s = TestServer::start().await;
    let (_, _, _, _, _) = enrolled(&s).await;

    // Anonymous visitors are bounced to login for the settings page.
    let anon = s.browser();
    let bounced = anon
        .get(s.url("/settings/two-factor"))
        .send()
        .await
        .unwrap();
    assert_eq!(bounced.status(), 303);

    // Non-admins cannot see admin pages (404, like every admin page).
    let (alice_client, alice_csrf) = start_two_factor(&s, "alice").await;
    let forbidden = alice_client
        .get(s.url("/admin/users/alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 404);
    let non_admin_post = alice_client
        .post(s.url("/admin/users/alice/reset-2fa"))
        .form(&[("_csrf", alice_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(non_admin_post.status(), 404);

    // A site admin resets the user's 2FA (CSRF checked).
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let (admin, admin_csrf) = s.login("root").await;
    let forged = admin
        .post(s.url("/admin/users/alice/reset-2fa"))
        .form(&[("_csrf", "forged")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    let reset = admin
        .post(s.url("/admin/users/alice/reset-2fa"))
        .form(&[("_csrf", admin_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status(), 200);
    let actions = audit_actions(&s).await;
    assert!(actions.iter().any(|a| a == "user.2fa_reset"), "{actions:?}");
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    assert!(!s.core.totp_enabled(alice.id).await.unwrap());
    let (_, response) = s.try_login("alice", PASSWORD).await;
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["location"], "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_input_is_escaped() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let anon = s.browser();
    let csrf = extract_input(&get_text(&anon, &s.url("/login")).await, "_csrf");
    let body = anon
        .post(s.url("/login"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/"),
            ("login", "<script>alert(1)</script>"),
            ("password", "nope"),
        ])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!body.contains("<script>alert"), "{body}");
    assert!(body.contains("&#60;script&#62;alert(1)"), "{body}");
}
