//! Authentication sweep (M3d D4): the cross-path matrix over password login,
//! TOTP second factor, OIDC login, SSO-only mode, and suspension.
//!
//! The brief's checklist, pinned end to end:
//! - challenge isolation (cookie-bound, user-bound, no session before factor 2);
//! - open-redirect refusal on every `next` the login accepts;
//! - OIDC callback errors never reflect provider strings;
//! - PATs and the device flow keep working for 2FA users, and device approval
//!   needs a fully authenticated session;
//! - session list and revoke still work;
//! - cookie flags (`Secure` on https, `HttpOnly`, `SameSite=Lax`) on the new
//!   cookies;
//! - plus the sweep pins: replay refusal, challenge expiry and attempt caps,
//!   recovery-code single use, SSO linking edges, and CSRF on every auth form.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use common::fake_oidc::{CLIENT_ID, CLIENT_SECRET, FakeOidc, SUBJECT};
use common::*;
use serde_json::Value;
use starforged_core::accounts::CreateUser;
use starforged_core::totp::{base32, code_at};

fn now_step() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30
}

fn totp_code(secret_base32: &str, step: u64) -> String {
    let secret = base32::decode(secret_base32).expect("enrollment secret is base32");
    format!("{:06}", code_at(&secret, step))
}

/// The code for the next step: always inside the ±1 accepted window and
/// never the step already claimed at enrollment confirmation.
fn next_code(secret_base32: &str) -> String {
    totp_code(secret_base32, now_step() + 1)
}

/// Enrolls TOTP for `handle` (a password login in a fresh browser first) and
/// returns `(settings browser, settings csrf, secret, recovery codes, confirm step)`.
async fn enroll(
    s: &TestServer,
    handle: &str,
) -> (reqwest::Client, String, String, Vec<String>, u64) {
    s.user(handle).await;
    let (client, csrf) = s.login(handle).await;
    let page = get_text(&client, &s.url("/settings/two-factor")).await;
    assert!(page.contains("disabled"), "{page}");
    let enroll = client
        .post(s.url("/settings/two-factor"))
        .form(&[("_csrf", csrf.as_str()), ("action", "enroll")])
        .send()
        .await
        .unwrap();
    assert_eq!(enroll.status(), 200);
    let secret = between(
        &enroll.text().await.unwrap(),
        r#"<code class="totp-secret">"#,
        "</code>",
    );
    let step = now_step();
    let confirmed = client
        .post(s.url("/settings/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "confirm"),
            ("code", totp_code(&secret, step).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.status(), 200);
    let shown = between(
        &confirmed.text().await.unwrap(),
        r#"<pre class="recovery-codes">"#,
        "</pre>",
    );
    let codes: Vec<String> = shown.split_whitespace().map(str::to_owned).collect();
    assert_eq!(codes.len(), 10, "{shown}");
    (client, csrf, secret, codes, step)
}

/// Password login for a 2FA user: 303 to the second step, a challenge cookie,
/// and no session cookie. Returns the browser and the second-factor CSRF token.
async fn start_two_factor(s: &TestServer, handle: &str) -> (reqwest::Client, String) {
    let (client, response) = s.try_login(handle, PASSWORD).await;
    assert_eq!(response.status(), 303);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        location.starts_with("/login/two-factor"),
        "location: {location}"
    );
    let cookies = set_cookies(&response);
    assert!(
        cookies.iter().any(|c| c.starts_with("sf_login_challenge=")),
        "no challenge cookie: {cookies:?}"
    );
    assert!(
        !cookies.iter().any(|c| c.starts_with("sf_session=")),
        "session cookie before the second factor: {cookies:?}"
    );
    let page = get_text(&client, &s.url(&location)).await;
    (client, extract_input(&page, "_csrf"))
}

/// Submits the second factor; returns the response (303 "/" on success,
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

fn set_cookies(response: &reqwest::Response) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

/// The value of the cookie `name` in a response's `Set-Cookie` headers.
fn cookie_value(response: &reqwest::Response, name: &str) -> Option<String> {
    set_cookies(response).into_iter().find_map(|header| {
        let pair = header.split(';').next()?.trim().to_owned();
        let (n, v) = pair.split_once('=')?;
        (n == name).then(|| v.to_owned())
    })
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

/// The `Set-Cookie` header naming `name` that actually sets a value
/// (removal cookies carry an empty value with `Max-Age=0`).
fn setting_cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    set_cookies(response).into_iter().find(|header| {
        let Some(pair) = header.split(';').next() else {
            return false;
        };
        let Some((n, v)) = pair.trim().split_once('=') else {
            return false;
        };
        n == name && !v.is_empty()
    })
}

/// Asserts the login/session cookie flags the brief names.
fn assert_cookie_flags(cookie: &str, secure: bool) {
    assert!(cookie.contains("HttpOnly"), "not HttpOnly: {cookie}");
    assert!(
        cookie.contains("SameSite=Lax"),
        "not SameSite=Lax: {cookie}"
    );
    if secure {
        assert!(cookie.contains("Secure"), "no Secure flag: {cookie}");
    } else {
        assert!(!cookie.contains("Secure"), "unexpected Secure: {cookie}");
    }
}

/// A server with OIDC enabled, auto-create, and a registration mode.
async fn oidc_server_ex(fake: &FakeOidc, auto_create: bool, registration_mode: &str) -> TestServer {
    let mode = registration_mode.to_owned();
    TestServer::start_with(|config| {
        config.oidc.enabled = true;
        config.oidc.issuer = fake.issuer.clone();
        config.oidc.client_id = CLIENT_ID.into();
        config.oidc.client_secret = CLIENT_SECRET.into();
        config.oidc.auto_create = auto_create;
        config.registration.mode = mode;
    })
    .await
}

/// Through the browser: `GET /login/oidc`, the provider authorize redirect,
/// then the callback. Returns the browser and the callback response.
async fn browser_oidc_login(s: &TestServer) -> (reqwest::Client, reqwest::Response) {
    let client = s.browser();
    let begin = client.get(s.url("/login/oidc")).send().await.unwrap();
    assert_eq!(begin.status(), 303, "GET /login/oidc must redirect");
    let authorize_url = location(&begin);
    let back = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(back.status(), 303, "authorize must redirect back");
    let callback = location(&back);
    let response = client.get(&callback).send().await.unwrap();
    (client, response)
}

async fn user_with_email(
    s: &TestServer,
    handle: &str,
    email: &str,
) -> starforged_core::accounts::User {
    s.core
        .create_user(CreateUser {
            handle: handle.into(),
            email: Some(email.into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Starts a password login against a raw (cookie-less) client and returns the
/// challenge token, the anonymous CSRF cookie value, and the second-factor
/// CSRF token — the three cookie-bound ingredients a second browser lacks.
async fn raw_challenge(s: &TestServer, handle: &str) -> (String, String, String) {
    let raw = raw_client();
    let login_page = raw.get(s.url("/login")).send().await.unwrap();
    assert_eq!(login_page.status(), 200);
    let csrf_cookie = cookie_value(&login_page, "sf_login_csrf").unwrap();
    let csrf = extract_input(&login_page.text().await.unwrap(), "_csrf");
    let login = raw
        .post(s.url("/login"))
        .header("cookie", format!("sf_login_csrf={csrf_cookie}"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/"),
            ("login", handle),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 303);
    let challenge = cookie_value(&login, "sf_login_challenge").unwrap();
    let page_url = s.url(&location(&login));
    let page = raw
        .get(&page_url)
        .header(
            "cookie",
            format!("sf_login_csrf={csrf_cookie}; sf_login_challenge={challenge}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let two_factor_csrf = extract_input(&page.text().await.unwrap(), "_csrf");
    (challenge, csrf_cookie, two_factor_csrf)
}

fn raw_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Posts the second factor with hand-carried cookies, the way a browser would.
async fn raw_second_factor(
    s: &TestServer,
    csrf_cookie: &str,
    challenge: &str,
    csrf: &str,
    code: &str,
) -> reqwest::Response {
    raw_client()
        .post(s.url("/login/two-factor"))
        .header(
            "cookie",
            format!("sf_login_csrf={csrf_cookie}; sf_login_challenge={challenge}"),
        )
        .form(&[("_csrf", csrf), ("next", "/"), ("code", code)])
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn challenge_cannot_be_completed_by_another_browser() {
    let s = TestServer::start().await;
    let (_, _, secret, _, _) = enroll(&s, "alice").await;

    // The second-factor form is only reachable with the challenge cookie.
    let stranger = s.browser();
    let bounced = stranger
        .get(s.url("/login/two-factor"))
        .send()
        .await
        .unwrap();
    assert_eq!(bounced.status(), 303);
    assert_eq!(location(&bounced), "/login");

    // Even the correct code, submitted by a browser that holds no challenge
    // cookie (only its own anonymous CSRF), ends at /login, not a session.
    let page = get_text(&stranger, &s.url("/login")).await;
    let csrf = extract_input(&page, "_csrf");
    let attempted = stranger
        .post(s.url("/login/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/"),
            ("code", next_code(&secret).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(attempted.status(), 303);
    assert_eq!(location(&attempted), "/login");
    assert!(
        !set_cookies(&attempted)
            .iter()
            .any(|c| c.starts_with("sf_session=")),
        "another browser minted a session: {:?}",
        set_cookies(&attempted)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_users_challenge_cannot_finish_another_users_login() {
    let s = TestServer::start().await;
    let (_, _, alice_secret, _, _) = enroll(&s, "alice").await;
    let (_, _, bob_secret, _, _) = enroll(&s, "bob").await;

    let (alice_challenge, alice_csrf_cookie, alice_csrf) = raw_challenge(&s, "alice").await;
    let (bob_challenge, bob_csrf_cookie, bob_csrf) = raw_challenge(&s, "bob").await;

    // Bob's code on Alice's challenge and Alice's code on Bob's challenge are
    // both refused: the challenge names its user server-side.
    let crossed_bob = raw_second_factor(
        &s,
        &alice_csrf_cookie,
        &alice_challenge,
        &alice_csrf,
        next_code(&bob_secret).as_str(),
    )
    .await;
    assert_eq!(crossed_bob.status(), 401);
    let crossed_alice = raw_second_factor(
        &s,
        &bob_csrf_cookie,
        &bob_challenge,
        &bob_csrf,
        next_code(&alice_secret).as_str(),
    )
    .await;
    assert_eq!(crossed_alice.status(), 401);

    // Each challenge still completes as its own user (the refused crossings
    // must not have voided either challenge).
    let alice_done = raw_second_factor(
        &s,
        &alice_csrf_cookie,
        &alice_challenge,
        &alice_csrf,
        next_code(&alice_secret).as_str(),
    )
    .await;
    assert_eq!(alice_done.status(), 303);
    assert_eq!(location(&alice_done), "/");
    assert!(
        cookie_value(&alice_done, "sf_session").is_some(),
        "own challenge must mint a session"
    );
    let bob_done = raw_second_factor(
        &s,
        &bob_csrf_cookie,
        &bob_challenge,
        &bob_csrf,
        next_code(&bob_secret).as_str(),
    )
    .await;
    assert_eq!(bob_done.status(), 303);
    assert_eq!(location(&bob_done), "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn totp_replay_is_refused_and_recovery_codes_are_single_use() {
    let s = TestServer::start().await;
    let (_, _, secret, codes, _) = enroll(&s, "alice").await;
    let replayed = next_code(&secret);

    let (client, csrf) = start_two_factor(&s, "alice").await;
    assert_eq!(
        second_factor(&client, &s, &csrf, &replayed).await.status(),
        303
    );
    let (client, csrf) = start_two_factor(&s, "alice").await;
    assert_eq!(
        second_factor(&client, &s, &csrf, &replayed).await.status(),
        401,
        "the same TOTP step was accepted twice"
    );

    let (client, csrf) = start_two_factor(&s, "alice").await;
    assert_eq!(
        second_factor(&client, &s, &csrf, &codes[0]).await.status(),
        303
    );
    let (client, csrf) = start_two_factor(&s, "alice").await;
    assert_eq!(
        second_factor(&client, &s, &csrf, &codes[0]).await.status(),
        401,
        "the same recovery code was accepted twice"
    );
    let (client, csrf) = start_two_factor(&s, "alice").await;
    assert_eq!(
        second_factor(&client, &s, &csrf, &codes[1]).await.status(),
        303,
        "the next recovery code must still work"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_and_exhausted_challenges_are_refused() {
    let s = TestServer::start().await;
    let (_, _, secret, _, _) = enroll(&s, "alice").await;
    let valid = next_code(&secret);
    let wrong = format!("{:06}", (valid.parse::<u32>().unwrap() + 1) % 1_000_000);

    // Five failures void the challenge; the valid code is then refused.
    let (client, csrf) = start_two_factor(&s, "alice").await;
    for i in 0..5 {
        assert_eq!(
            second_factor(&client, &s, &csrf, &wrong).await.status(),
            401,
            "failure {i} not refused"
        );
    }
    let after = second_factor(&client, &s, &csrf, &valid).await;
    assert_eq!(after.status(), 303);
    assert_eq!(location(&after), "/login");

    // An expired challenge is refused even with the right code.
    let (client, csrf) = start_two_factor(&s, "alice").await;
    sqlx::query("UPDATE login_challenges SET expires_at = $1")
        .bind(0_i64)
        .execute(s.core.db().pool())
        .await
        .unwrap();
    let late = second_factor(&client, &s, &csrf, &valid).await;
    assert_eq!(late.status(), 303);
    assert_eq!(location(&late), "/login");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_redirects_are_refused_on_every_login_next() {
    let s = TestServer::start().await;
    s.user("alice").await;

    // The login page itself only ever renders a same-site next.
    let anon = s.browser();
    let page = get_text(&anon, &s.url("/login?next=https%3A%2F%2Fevil.example")).await;
    assert!(!page.contains("evil.example"), "next reflected: {page}");
    assert_eq!(extract_input(&page, "next"), "/");

    // Successful password logins land on "/" for off-site next values, and
    // keep same-site paths.
    for next in [
        "https://evil.example/steal",
        "//evil.example/steal",
        "/\\evil.example",
        "javascript:alert(1)",
        "/settings/profile",
    ] {
        let client = s.browser();
        let csrf = extract_input(&get_text(&client, &s.url("/login")).await, "_csrf");
        let response = client
            .post(s.url("/login"))
            .form(&[
                ("_csrf", csrf.as_str()),
                ("next", next),
                ("login", "alice"),
                ("password", PASSWORD),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303, "next={next}");
        let expected = if next == "/settings/profile" {
            "/settings/profile"
        } else {
            "/"
        };
        assert_eq!(location(&response), expected, "next={next}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_factor_next_is_also_checked_for_open_redirects() {
    let s = TestServer::start().await;
    let (_, _, secret, _, _) = enroll(&s, "alice").await;

    // The password step preserves only same-site next values …
    let (client, response) = s.try_login("alice", PASSWORD).await;
    assert!(
        location(&response).contains("next=/"),
        "{}",
        location(&response)
    );

    // … and an off-site next submitted at the second step becomes "/".
    let page = get_text(&client, &s.url("/login/two-factor")).await;
    let csrf = extract_input(&page, "_csrf");
    let done = client
        .post(s.url("/login/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "https://evil.example/steal"),
            ("code", next_code(&secret).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 303);
    assert_eq!(location(&done), "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_callback_errors_never_reflect_provider_strings() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, false, "open").await;

    let client = s.browser();
    let begin = client.get(s.url("/login/oidc")).send().await.unwrap();
    assert_eq!(begin.status(), 303);
    assert!(location(&begin).starts_with(&fake.issuer));

    // The provider's error string (here a script tag) never reaches the page,
    // and no session is minted on failure.
    let failed = client
        .get(s.url("/login/oidc/callback?error=%3Cscript%3Ealert(1)%3C%2Fscript%3E"))
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), 401);
    let no_session = cookie_value(&failed, "sf_session").is_none();
    let body = failed.text().await.unwrap();
    assert!(body.contains("Single sign-on failed"), "{body}");
    assert!(!body.contains("<script>alert"), "{body}");
    assert!(!body.contains("alert(1)"), "{body}");
    assert!(no_session, "a failed callback minted a session");

    // A forged state on an otherwise real provider round-trip gets the same
    // generic page.
    let begin = client.get(s.url("/login/oidc")).send().await.unwrap();
    let authorize_url = location(&begin);
    let back = client.get(&authorize_url).send().await.unwrap();
    let callback = location(&back);
    let (before, after) = callback.split_once("state=").unwrap();
    let end = after.find('&').unwrap_or(after.len());
    let forged = format!("{before}state=forged{}", &after[end..]);
    let bad_state = client.get(&forged).send().await.unwrap();
    assert_eq!(bad_state.status(), 401);
    let no_session = cookie_value(&bad_state, "sf_session").is_none();
    let body = bad_state.text().await.unwrap();
    assert!(body.contains("Single sign-on failed"), "{body}");
    assert!(no_session, "a bad-state callback minted a session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokens_and_device_flow_work_for_two_factor_users() {
    let s = TestServer::start().await;
    let (_, _, secret, _, _) = enroll(&s, "alice").await;

    let client = reqwest::Client::new();
    let code = client
        .post(s.url("/api/v1/oauth/device/code"))
        .form(&[("client_id", "starforge-cli"), ("scope", "session:upload")])
        .send()
        .await
        .unwrap();
    assert_eq!(code.status(), 200);
    let code: Value = code.json().await.unwrap();
    let device_code = code["device_code"].as_str().unwrap().to_owned();
    let user_code = code["user_code"].as_str().unwrap().to_owned();

    // A browser that has only the first factor (the challenge cookie) cannot
    // approve: the approval page needs the full session and bounces to login.
    let (pending, pending_csrf) = start_two_factor(&s, "alice").await;
    let gated = pending.get(s.url("/oauth/device")).send().await.unwrap();
    assert_eq!(gated.status(), 303);
    assert!(location(&gated).starts_with("/login"));

    // Polling before approval still pends.
    let pending_poll = client
        .post(s.url("/api/v1/oauth/token"))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code.as_str()),
            ("client_id", "starforge-cli"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(pending_poll.status(), 400);

    // Finish the second factor, then approve.
    let done = second_factor(&pending, &s, &pending_csrf, next_code(&secret).as_str()).await;
    assert_eq!(done.status(), 303);
    let page = get_text(
        &pending,
        &s.url(&format!("/oauth/device?user_code={user_code}")),
    )
    .await;
    assert!(page.contains(&user_code), "{page}");
    let csrf = extract_input(&page, "_csrf");
    let approved = pending
        .post(s.url("/oauth/device/approve"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("user_code", user_code.as_str()),
            ("decision", "approve"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status(), 200);
    assert!(
        approved
            .text()
            .await
            .unwrap()
            .to_lowercase()
            .contains("approved"),
        "no success banner"
    );

    // The granted device token works against the API.
    let granted = client
        .post(s.url("/api/v1/oauth/token"))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code.as_str()),
            ("client_id", "starforge-cli"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(granted.status(), 200);
    let body: Value = granted.json().await.unwrap();
    let access = body["access_token"].as_str().unwrap().to_owned();
    let whoami = client
        .get(s.url("/api/v1/user"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(whoami.status(), 200);
    assert!(whoami.text().await.unwrap().contains("alice"));

    // A PAT created from the 2FA-authenticated session works too.
    let tokens_page = get_text(&pending, &s.url("/settings/tokens")).await;
    let csrf = extract_input(&tokens_page, "_csrf");
    let created = pending
        .post(s.url("/settings/tokens"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "sweep-token"),
            ("scopes", "repo:read"),
            ("expires_days", "30"),
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
    let whoami = client
        .get(s.url("/api/v1/user"))
        .bearer_auth(&secret)
        .send()
        .await
        .unwrap();
    assert_eq!(whoami.status(), 200);
    assert!(whoami.text().await.unwrap().contains("alice"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_list_and_revoke_still_work_for_two_factor_users() {
    let s = TestServer::start().await;
    let (enroll_client, enroll_csrf, secret, codes, _) = enroll(&s, "alice").await;
    let logged_out = enroll_client
        .post(s.url("/logout"))
        .form(&[("_csrf", enroll_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(logged_out.status(), 303);

    // Two fully authenticated browsers => two sessions for the same user.
    // The second login uses a recovery code: each TOTP step is single-use,
    // and only one unclaimed future step is inside the accepted window.
    let (first, first_csrf) = start_two_factor(&s, "alice").await;
    assert_eq!(
        second_factor(&first, &s, &first_csrf, next_code(&secret).as_str())
            .await
            .status(),
        303
    );
    let (second, second_csrf) = start_two_factor(&s, "alice").await;
    assert_eq!(
        second_factor(&second, &s, &second_csrf, &codes[0])
            .await
            .status(),
        303
    );

    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    assert_eq!(s.core.list_sessions(&alice).await.unwrap().len(), 2);
    let page = get_text(&first, &s.url("/settings/sessions")).await;
    // The header carries its own "Sign out" button; count rows inside <main>.
    let main = page.split("<main>").nth(1).unwrap_or(&page);
    let rows = main.matches("Revoke</button>").count() + main.matches("Sign out</button>").count();
    assert_eq!(rows, 2, "session list must show both sessions: {page}");
    assert!(page.contains("this session"), "{page}");

    // Revoking the second browser's session kills that browser only.
    let sessions = s.core.list_sessions(&alice).await.unwrap();
    let csrf = extract_input(&page, "_csrf");
    let revoked = first
        .post(s.url(&format!("/settings/sessions/{}/revoke", sessions[0].id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 303);
    assert_eq!(s.core.list_sessions(&alice).await.unwrap().len(), 1);

    // The surviving browser still works; the revoked one bounces to login.
    // Whichever browser owned sessions[0] is now dead; the other is alive.
    let alive = first.get(s.url("/settings/profile")).send().await.unwrap();
    let dead = second.get(s.url("/settings/profile")).send().await.unwrap();
    let statuses = [alive.status(), dead.status()];
    assert_eq!(
        statuses.iter().filter(|st| **st == 200).count(),
        1,
        "exactly one browser must survive: {statuses:?}"
    );
    assert!(
        statuses.iter().any(|st| st.is_redirection()),
        "the revoked browser must bounce: {statuses:?}"
    );

    // Sign out everywhere else kills the remaining other browser too.
    let survivor = if alive.status() == 200 {
        &first
    } else {
        &second
    };
    let page = get_text(survivor, &s.url("/settings/sessions")).await;
    let csrf = extract_input(&page, "_csrf");
    let others = survivor
        .post(s.url("/settings/sessions/revoke-others"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(others.status(), 303);
    assert_eq!(s.core.list_sessions(&alice).await.unwrap().len(), 1);
    assert!(
        !get_text(survivor, &s.url("/settings/profile"))
            .await
            .is_empty(),
        "the survivor keeps its session"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookie_flags_on_session_challenge_and_oidc_cookies() {
    // Plain http: no Secure flag (the suite's TestServer speaks http).
    let s = TestServer::start().await;
    s.user("alice").await;
    let (_, response) = s.try_login("alice", PASSWORD).await;
    assert_eq!(response.status(), 303);
    let session = cookie_value(&response, "sf_session").expect("session cookie");
    let raw = set_cookies(&response)
        .into_iter()
        .find(|c| c.starts_with("sf_session="))
        .unwrap();
    assert_cookie_flags(&raw, false);
    let _ = session;

    // https base_url: every new cookie carries Secure.
    let fake = FakeOidc::start_es256().await;
    let https = TestServer::start_with(|config| {
        config.server.base_url = "https://forge.example.test".into();
        config.oidc.enabled = true;
        config.oidc.issuer = fake.issuer.clone();
        config.oidc.client_id = CLIENT_ID.into();
        config.oidc.client_secret = CLIENT_SECRET.into();
    })
    .await;

    // Raw client: the cookie store would (correctly) refuse to resend Secure
    // cookies over http, so carry them by hand and inspect Set-Cookie.
    let raw = raw_client();
    let login_page = raw.get(https.url("/login")).send().await.unwrap();
    let csrf_cookie = cookie_value(&login_page, "sf_login_csrf").unwrap();
    let csrf = extract_input(&login_page.text().await.unwrap(), "_csrf");

    https.user("alice").await;
    let login = raw
        .post(https.url("/login"))
        .header("cookie", format!("sf_login_csrf={csrf_cookie}"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/"),
            ("login", "alice"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 303);
    let session = setting_cookie(&login, "sf_session").expect("session cookie under https");
    assert_cookie_flags(&session, true);
    if let Some(csrf_cookie_hdr) = setting_cookie(&login, "sf_login_csrf") {
        assert_cookie_flags(&csrf_cookie_hdr, true);
    }

    // The 2FA challenge cookie carries the same flags. Enrollment goes
    // through the Core (a web session cannot be kept over plain http once
    // Secure cookies are set).
    let bob = https.user("bob").await;
    let enrollment = https.core.begin_totp_enrollment(&bob).await.unwrap();
    https
        .core
        .confirm_totp_enrollment(&bob, &totp_code(&enrollment.secret_base32, now_step()))
        .await
        .unwrap();
    let login_page = raw.get(https.url("/login")).send().await.unwrap();
    let csrf_cookie = cookie_value(&login_page, "sf_login_csrf").unwrap();
    let csrf = extract_input(&login_page.text().await.unwrap(), "_csrf");
    let challenge_login = raw
        .post(https.url("/login"))
        .header("cookie", format!("sf_login_csrf={csrf_cookie}"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/"),
            ("login", "bob"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(challenge_login.status(), 303);
    assert!(location(&challenge_login).starts_with("/login/two-factor"));
    assert!(
        cookie_value(&challenge_login, "sf_session").is_none(),
        "no session before the second factor"
    );
    let challenge = setting_cookie(&challenge_login, "sf_login_challenge")
        .expect("challenge cookie under https");
    assert_cookie_flags(&challenge, true);

    // … as does the OIDC challenge cookie.
    let begin = raw.get(https.url("/login/oidc")).send().await.unwrap();
    assert_eq!(begin.status(), 303);
    let oidc = setting_cookie(&begin, "sf_oidc_challenge").expect("oidc cookie under https");
    assert_cookie_flags(&oidc, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspended_users_cannot_log_in_on_any_path() {
    let s = TestServer::start().await;
    let admin = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();

    // Password login for a suspended user is refused (401, no session).
    let bob = s.user("bob").await;
    s.core.suspend_user(&admin, bob.id).await.unwrap();
    let (_, response) = s.try_login("bob", PASSWORD).await;
    assert_eq!(response.status(), 401);
    assert!(cookie_value(&response, "sf_session").is_none());

    // A suspended 2FA user gets neither a challenge nor a session.
    let (_, _, _, _, _) = enroll(&s, "carol").await;
    let carol = s.core.user_by_handle("carol").await.unwrap().unwrap();
    s.core.suspend_user(&admin, carol.id).await.unwrap();
    let (_, response) = s.try_login("carol", PASSWORD).await;
    assert_eq!(response.status(), 401);
    assert!(
        !set_cookies(&response)
            .iter()
            .any(|c| c.starts_with("sf_login_challenge=")),
        "suspended user was issued a challenge"
    );
    assert!(cookie_value(&response, "sf_session").is_none());

    // Suspension ends a live session immediately.
    s.user("eve").await;
    let (eve, _) = s.login("eve").await;
    let eve_user = s.core.user_by_handle("eve").await.unwrap().unwrap();
    s.core.suspend_user(&admin, eve_user.id).await.unwrap();
    let bounced = eve.get(s.url("/settings/profile")).send().await.unwrap();
    assert_eq!(bounced.status(), 303);
    assert!(location(&bounced).starts_with("/login"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspended_linked_oidc_user_is_refused() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, false, "open").await;
    let alice = user_with_email(&s, "alice", "fake-user@example.com").await;
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    assert_eq!(s.core.linked_identities(alice.id).await.unwrap().len(), 1);

    let admin = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    s.core.suspend_user(&admin, alice.id).await.unwrap();
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    let no_session = cookie_value(&response, "sf_session").is_none();
    let body = response.text().await.unwrap();
    assert!(body.contains("Single sign-on failed"), "{body}");
    assert!(no_session);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_is_required_on_every_auth_form() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (_, _, _, _, _) = enroll(&s, "dave").await;
    let (alice, _) = s.login("alice").await;
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let (root_browser, _) = s.login("root").await;
    let _ = root;

    // Anonymous forms: password login and the second-factor step.
    let anon = s.browser();
    let csrf = extract_input(&get_text(&anon, &s.url("/login")).await, "_csrf");
    assert_eq!(
        anon.post(s.url("/login"))
            .form(&[
                ("_csrf", "forged"),
                ("next", "/"),
                ("login", "alice"),
                ("password", PASSWORD),
            ])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "login without valid CSRF"
    );
    let (pending, _) = start_two_factor(&s, "dave").await;
    assert_eq!(
        pending
            .post(s.url("/login/two-factor"))
            .form(&[("_csrf", "forged"), ("next", "/"), ("code", "000000")])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "second factor without valid CSRF"
    );
    let _ = csrf;

    // Authenticated forms: 2FA settings, tokens, session revoke, logout,
    // device approval, and the admin 2FA reset. A forged token is 403 on each.
    assert_eq!(
        alice
            .post(s.url("/settings/two-factor"))
            .form(&[("_csrf", "forged"), ("action", "enroll")])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "two-factor settings without valid CSRF"
    );
    assert_eq!(
        alice
            .post(s.url("/settings/tokens"))
            .form(&[
                ("_csrf", "forged"),
                ("name", "x"),
                ("scopes", "repo:read"),
                ("expires_days", "30"),
            ])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "token create without valid CSRF"
    );
    assert_eq!(
        alice
            .post(s.url("/settings/sessions/revoke-others"))
            .form(&[("_csrf", "forged")])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "revoke-others without valid CSRF"
    );
    assert_eq!(
        alice
            .post(s.url("/settings/sessions/1/revoke"))
            .form(&[("_csrf", "forged")])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "session revoke without valid CSRF"
    );
    assert_eq!(
        alice
            .post(s.url("/logout"))
            .form(&[("_csrf", "forged")])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "logout without valid CSRF"
    );
    assert_eq!(
        alice
            .post(s.url("/oauth/device/approve"))
            .form(&[
                ("_csrf", "forged"),
                ("user_code", "XXXX-XXXX"),
                ("decision", "approve"),
            ])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "device approval without valid CSRF"
    );
    assert_eq!(
        root_browser
            .post(s.url("/admin/users/alice/reset-2fa"))
            .form(&[("_csrf", "forged")])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "admin 2FA reset without valid CSRF"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sso_linking_edge_cases() {
    let fake = FakeOidc::start_es256().await;

    // Unverified provider email: no link, no session, generic "no account".
    fake.set_claims(serde_json::json!({"email_verified": false}));
    let s = oidc_server_ex(&fake, false, "open").await;
    let alice = user_with_email(&s, "alice", "fake-user@example.com").await;
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    let body = response.text().await.unwrap();
    assert!(body.contains("No account for this sign-in"), "{body}");
    assert!(
        s.core.linked_identities(alice.id).await.unwrap().is_empty(),
        "an unverified email must not link"
    );

    // Verified email links the existing user; a second login goes direct.
    fake.set_claims(serde_json::json!({}));
    let s = oidc_server_ex(&fake, false, "open").await;
    let alice = user_with_email(&s, "alice", "fake-user@example.com").await;
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    let identities = s.core.linked_identities(alice.id).await.unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].subject, SUBJECT);

    // The linked user unlinks from settings (the password is another way in).
    let (browser, _) = s.login("alice").await;
    let page = get_text(&browser, &s.url("/settings/identities")).await;
    let csrf = extract_input(&page, "_csrf");
    let unlink_action = between(&page, r#"action="/settings/identities/"#, r#"/unlink""#);
    let unlink_url = s.url(&format!("/settings/identities/{unlink_action}/unlink"));
    assert_eq!(
        browser
            .post(&unlink_url)
            .form(&[("_csrf", "forged")])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "unlink without valid CSRF"
    );
    let removed = browser
        .post(&unlink_url)
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 200);
    assert!(removed.text().await.unwrap().contains("Sign-in removed"));
    assert!(
        s.core.linked_identities(alice.id).await.unwrap().is_empty(),
        "unlink did not remove the identity"
    );
    // A fresh OIDC login re-links by verified email (unlink is not a ban).
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    assert_eq!(s.core.linked_identities(alice.id).await.unwrap().len(), 1);

    // Auto-create with no password and one identity: unlinking is refused so
    // the account is not stranded.
    let s = oidc_server_ex(&fake, true, "open").await;
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    let created = s.core.user_by_handle("fake-user").await.unwrap().unwrap();
    let client = s.browser();
    // Re-login through the browser that already holds the session.
    let begin = client.get(s.url("/login/oidc")).send().await.unwrap();
    let authorize_url = location(&begin);
    let back = client.get(&authorize_url).send().await.unwrap();
    let callback = location(&back);
    let done = client.get(&callback).send().await.unwrap();
    assert_eq!(done.status(), 303);
    let page = get_text(&client, &s.url("/settings/identities")).await;
    assert!(page.contains(SUBJECT), "{page}");
    let csrf = extract_input(&page, "_csrf");
    let unlink_action = between(&page, r#"action="/settings/identities/"#, r#"/unlink""#);
    let refused = client
        .post(s.url(&format!("/settings/identities/{unlink_action}/unlink")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("only way to sign in"),
        "last-means unlink must be refused"
    );
    assert_eq!(s.core.linked_identities(created.id).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sso_only_mode_matrix() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, true, "sso").await;

    // Sign-up and invite acceptance are refused; the login page offers SSO.
    let join = s.browser().get(s.url("/join")).send().await.unwrap();
    assert_eq!(join.status(), 403);
    assert!(
        join.text().await.unwrap().contains("Sign-up is disabled"),
        "sso mode must refuse sign-up"
    );
    let login_page = get_text(&s.browser(), &s.url("/login")).await;
    assert!(login_page.contains("Sign in with SSO"), "{login_page}");

    // Auto-create is how new accounts arrive; the created account has no
    // password, so password login fails for it.
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    let created = s.core.user_by_handle("fake-user").await.unwrap().unwrap();
    assert!(created.email_verified, "the provider verified the email");
    let (_, response) = s.try_login("fake-user", PASSWORD).await;
    assert_eq!(
        response.status(),
        401,
        "an SSO-created account must not have a password"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sso_only_without_auto_create_gives_no_account() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, false, "sso").await;
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();

    // The bootstrap admin can still sign in with a password.
    let (_, response) = s.try_login("root", PASSWORD).await;
    assert_eq!(response.status(), 303);
    assert_eq!(location(&response), "/");

    // … but an unknown provider identity gets "no account" when auto-create
    // is off.
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    let body = response.text().await.unwrap();
    assert!(body.contains("No account for this sign-in"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sso_user_enrolls_totp_and_oidc_login_needs_second_factor() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, true, "sso").await;

    // First login auto-creates the account and hands back a full session.
    let (browser, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    assert!(cookie_value(&response, "sf_session").is_some());

    // Enroll TOTP from that session.
    let page = get_text(&browser, &s.url("/settings/two-factor")).await;
    let csrf = extract_input(&page, "_csrf");
    let enroll = browser
        .post(s.url("/settings/two-factor"))
        .form(&[("_csrf", csrf.as_str()), ("action", "enroll")])
        .send()
        .await
        .unwrap();
    assert_eq!(enroll.status(), 200);
    let secret = between(
        &enroll.text().await.unwrap(),
        r#"<code class="totp-secret">"#,
        "</code>",
    );
    let step = now_step();
    let confirmed = browser
        .post(s.url("/settings/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "confirm"),
            ("code", totp_code(&secret, step).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.status(), 200);

    // The next OIDC login stops at the second factor with no session, and
    // only the second factor opens it.
    let (browser, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    assert!(location(&response).starts_with("/login/two-factor"));
    assert!(
        cookie_value(&response, "sf_session").is_none(),
        "session before the second factor"
    );
    assert!(
        !set_cookies(&response)
            .iter()
            .any(|c| c.starts_with("sf_session="))
    );
    let page = get_text(&browser, &s.url("/login/two-factor")).await;
    let csrf = extract_input(&page, "_csrf");
    let done = second_factor(&browser, &s, &csrf, next_code(&secret).as_str()).await;
    assert_eq!(done.status(), 303);
    assert_eq!(location(&done), "/");
    assert!(cookie_value(&done, "sf_session").is_some());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_does_not_link_to_a_local_unverified_email() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, false, "open").await;
    // The provider verifies the email, but the local account's email was
    // never verified: linking must refuse, so the login gets "no account".
    let alice = s
        .core
        .create_user(CreateUser {
            handle: "alice".into(),
            email: Some("fake-user@example.com".into()),
            email_verified: false,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (_, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    let no_session = cookie_value(&response, "sf_session").is_none();
    let body = response.text().await.unwrap();
    assert!(body.contains("No account for this sign-in"), "{body}");
    assert!(
        s.core.linked_identities(alice.id).await.unwrap().is_empty(),
        "an unverified local email must not link"
    );
    assert!(no_session);
}
