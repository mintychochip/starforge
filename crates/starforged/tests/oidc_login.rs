//! OIDC verification core against the fake provider (M3d D2): the
//! authorization-code flow end to end at the `Core` level — begin builds
//! the provider URL, finish exchanges the code and verifies the token —
//! plus challenge single-use, state matching, and config validation. The
//! login UI lands in D3.

mod common;

use common::TestServer;
use common::fake_oidc::{CLIENT_ID, CLIENT_SECRET, FakeOidc, SUBJECT};
use starforged_core::oidc::OidcIntent;

fn query(url: &str, name: &str) -> String {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("{name} missing from {url}"))
}

/// A server with OIDC enabled against `fake`.
async fn oidc_server(fake: &FakeOidc) -> TestServer {
    TestServer::start_with(|config| {
        config.oidc.enabled = true;
        config.oidc.issuer = fake.issuer.clone();
        config.oidc.client_id = CLIENT_ID.into();
        config.oidc.client_secret = CLIENT_SECRET.into();
    })
    .await
}

/// Runs the authorize leg of `url` against the fake provider and returns
/// the `(code, state)` on the redirect back.
async fn authorize(url: &str) -> (String, String) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = client.get(url).send().await.unwrap();
    assert_eq!(response.status(), 303, "authorize must redirect");
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    (query(&location, "code"), query(&location, "state"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn es256_flow_begin_and_finish() {
    let fake = FakeOidc::start_es256().await;
    let server = oidc_server(&fake).await;

    let (challenge, url) = server.core.oidc_begin(OidcIntent::Login).await.unwrap();
    assert!(
        url.starts_with(&format!("{}/authorize?", fake.issuer)),
        "{url}"
    );
    assert_eq!(query(&url, "response_type"), "code");
    assert_eq!(query(&url, "client_id"), CLIENT_ID);
    assert_eq!(
        query(&url, "redirect_uri"),
        format!("{}/login/oidc/callback", server.base)
    );
    assert_eq!(query(&url, "code_challenge_method"), "S256");
    assert!(!query(&url, "state").is_empty());
    assert!(!query(&url, "nonce").is_empty());
    assert!(!query(&url, "code_challenge").is_empty());
    assert!(query(&url, "scope").contains("openid"));

    let (code, state) = authorize(&url).await;
    assert_eq!(state, query(&url, "state"));
    let claims = server
        .core
        .oidc_finish(&challenge, &code, &state)
        .await
        .unwrap();
    assert_eq!(claims.sub, SUBJECT);
    assert_eq!(claims.iss, fake.issuer);
    assert_eq!(claims.email.as_deref(), Some("fake-user@example.com"));
    assert_eq!(claims.email_verified, Some(true));

    // Single use: finishing the same challenge again is refused.
    assert!(
        server
            .core
            .oidc_finish(&challenge, &code, &state)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rs256_flow_begin_and_finish() {
    let fake = FakeOidc::start_rs256().await;
    let server = oidc_server(&fake).await;

    let (challenge, url) = server.core.oidc_begin(OidcIntent::Login).await.unwrap();
    let (code, state) = authorize(&url).await;
    let claims = server
        .core
        .oidc_finish(&challenge, &code, &state)
        .await
        .unwrap();
    assert_eq!(claims.sub, SUBJECT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_mismatch_is_refused() {
    let fake = FakeOidc::start_es256().await;
    let server = oidc_server(&fake).await;

    let (challenge, url) = server.core.oidc_begin(OidcIntent::Login).await.unwrap();
    let (code, _state) = authorize(&url).await;
    assert!(
        server
            .core
            .oidc_finish(&challenge, &code, "forged-state")
            .await
            .is_err()
    );
    // And the challenge is gone: even the right state now fails.
    let (_, state) = authorize(&url).await;
    assert!(
        server
            .core
            .oidc_finish(&challenge, &code, &state)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_challenge_is_refused() {
    let fake = FakeOidc::start_es256().await;
    let server = oidc_server(&fake).await;
    assert!(
        server
            .core
            .oidc_finish("no-such-challenge", "code", "state")
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_finish_proceeds_exactly_once() {
    let fake = FakeOidc::start_es256().await;
    let server = oidc_server(&fake).await;

    let (challenge, url) = server.core.oidc_begin(OidcIntent::Login).await.unwrap();
    let (code, state) = authorize(&url).await;
    let core = server.core.clone();
    let (first, second) = tokio::join!(
        core.oidc_finish(&challenge, &code, &state),
        core.oidc_finish(&challenge, &code, &state),
    );
    let successes = [first, second].into_iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "two concurrent callbacks with the same challenge proceed exactly once"
    );
}

#[test]
fn oidc_config_validation() {
    use starforged::config::{
        Config, DatabaseConfig, OidcConfig, SecurityConfig, ServerConfig, StorageConfig,
    };
    let config = |mut oidc: OidcConfig| Config {
        server: ServerConfig {
            http_addr: "127.0.0.1:0".into(),
            base_url: "http://127.0.0.1:0".into(),
        },
        database: DatabaseConfig::default(),
        storage: StorageConfig {
            data_dir: std::path::PathBuf::from("/srv/starforge"),
            index_dir: std::path::PathBuf::from("index"),
        },
        security: SecurityConfig {
            secret_key: "0".repeat(64),
        },
        mail: starforged::config::MailConfig::default(),
        registration: starforged::config::RegistrationConfig::default(),
        sessions: starforged::config::SessionsConfig::default(),
        webhooks: starforged::config::WebhooksConfig::default(),
        git: starforged::config::GitConfig::default(),
        remotes: starforged::config::RemotesConfig::default(),
        github: starforged::config::GithubConfig::default(),
        limits: starforged::config::LimitsConfig {
            login_per_ip_per_minute: 0,
            login_per_account_per_hour: 0,
            api_per_token_per_hour: 0,
            refs_for_new_changes_per_hour: 0,
        },
        ssh: starforged::config::SshConfig {
            listen: "127.0.0.1:0".to_owned(),
            host_key_path: std::path::PathBuf::from("ssh_host_ed25519_key"),
            ..Default::default()
        },
        oidc: std::mem::take(&mut oidc),
        log: starforged::config::LogConfig::default(),
        metrics: starforged::config::MetricsConfig::default(),
        sandbox: starforged_core::sandboxes::SandboxConfig::default(),
    };
    // Disabled OIDC needs nothing.
    assert!(config(OidcConfig::default()).validate().is_ok());
    // Enabled without issuer fails startup.
    let err = config(OidcConfig {
        enabled: true,
        ..OidcConfig::default()
    })
    .validate()
    .unwrap_err()
    .to_string();
    assert!(err.contains("oidc.issuer"), "{err}");
    // Enabled without a client id fails startup.
    let err = config(OidcConfig {
        enabled: true,
        issuer: "https://idp.example.com".into(),
        ..OidcConfig::default()
    })
    .validate()
    .unwrap_err()
    .to_string();
    assert!(err.contains("oidc.client_id"), "{err}");
    // A non-loopback http issuer is refused.
    let err = config(OidcConfig {
        enabled: true,
        issuer: "http://idp.example.com".into(),
        client_id: "client".into(),
        ..OidcConfig::default()
    })
    .validate()
    .unwrap_err()
    .to_string();
    assert!(err.contains("https"), "{err}");
    // Loopback http is fine for tests.
    assert!(
        config(OidcConfig {
            enabled: true,
            issuer: "http://127.0.0.1:8080".into(),
            client_id: "client".into(),
            ..OidcConfig::default()
        })
        .validate()
        .is_ok()
    );
    // The client secret never renders.
    let rendered = format!(
        "{:?}",
        config(OidcConfig {
            client_secret: "hunter2secret".into(),
            ..OidcConfig::default()
        })
    );
    assert!(!rendered.contains("hunter2secret"), "{rendered}");
}

// ===== D3: login, linking, auto-create, and SSO-only registration =====

use std::time::{SystemTime, UNIX_EPOCH};

use common::{PASSWORD, between, extract_input, get_text};
use starforged_core::accounts::CreateUser;
use starforged_core::oidc::OidcLoginOutcome;
use starforged_core::totp::{base32, code_at};

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

/// Through the browser: `GET /login/oidc`, then the provider authorize
/// redirect, then the callback. Returns the browser and the callback
/// response (303 to `/` or `/login/two-factor`, or the failure page).
async fn browser_oidc_login(s: &TestServer) -> (reqwest::Client, reqwest::Response) {
    let client = s.browser();
    let begin = client.get(s.url("/login/oidc")).send().await.unwrap();
    assert_eq!(begin.status(), 303, "GET /login/oidc must redirect");
    let authorize_url = begin.headers()["location"].to_str().unwrap().to_owned();
    let back = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(back.status(), 303, "authorize must redirect back");
    let callback = back.headers()["location"].to_str().unwrap().to_owned();
    let response = client.get(&callback).send().await.unwrap();
    (client, response)
}

async fn audit_actions(s: &TestServer) -> Vec<String> {
    starforged_db::audit::recent(s.core.db(), 200)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect()
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

/// Enrolls TOTP for the signed-in browser, returning the secret.
async fn enroll_totp(client: &reqwest::Client, s: &TestServer, csrf: &str) -> String {
    let enroll = client
        .post(s.url("/settings/two-factor"))
        .form(&[("_csrf", csrf), ("action", "enroll")])
        .send()
        .await
        .unwrap();
    assert_eq!(enroll.status(), 200);
    let body = enroll.text().await.unwrap();
    let secret = between(&body, r#"<code class="totp-secret">"#, "</code>");
    let confirmed = client
        .post(s.url("/settings/two-factor"))
        .form(&[
            ("_csrf", csrf),
            ("action", "confirm"),
            ("code", totp_code(&secret, now_step()).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.status(), 200);
    secret
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_email_links_existing_user_and_logs_in_again() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server(&fake).await;
    let alice = user_with_email(&s, "alice", "fake-user@example.com").await;

    let login_page = get_text(&s.browser(), &s.url("/login")).await;
    assert!(
        login_page.contains("Sign in with SSO"),
        "SSO button missing: {login_page}"
    );

    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/");
    let identities = s.core.linked_identities(alice.id).await.unwrap();
    assert_eq!(identities.len(), 1, "first login links by verified email");
    assert_eq!(identities[0].issuer, fake.issuer);
    assert_eq!(identities[0].subject, SUBJECT);
    let actions = audit_actions(&s).await;
    assert!(
        actions.iter().any(|a| a == "account.identity_linked"),
        "{actions:?}"
    );
    assert!(actions.iter().any(|a| a == "login.oidc"), "{actions:?}");

    // Already linked: a fresh browser logs straight in.
    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_email_does_not_link() {
    let fake = FakeOidc::start_es256().await;
    fake.set_claims(serde_json::json!({"email_verified": false}));
    let s = oidc_server(&fake).await;
    let alice = user_with_email(&s, "alice", "fake-user@example.com").await;

    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    let body = response.text().await.unwrap();
    assert!(body.contains("No account for this sign-in"), "{body}");
    assert!(
        s.core.linked_identities(alice.id).await.unwrap().is_empty(),
        "an unverified email must not link"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_create_makes_sanitized_deduplicated_user_without_password() {
    let fake = FakeOidc::start_es256().await;
    fake.set_claims(serde_json::json!({"preferred_username": "Fake User!"}));
    let s = oidc_server_ex(&fake, true, "open").await;
    // The sanitized base handle is taken, so auto-create deduplicates.
    s.user("fake-user").await;

    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    let created = s
        .core
        .user_by_handle("fake-user-2")
        .await
        .unwrap()
        .expect("auto-create deduplicates the handle");
    assert_eq!(created.email.as_deref(), Some("fake-user@example.com"));
    assert!(created.email_verified, "the provider verified the email");
    assert!(
        s.core
            .authenticate_password("fake-user-2", PASSWORD)
            .await
            .is_err(),
        "an SSO-created account has no password"
    );
    assert_eq!(s.core.linked_identities(created.id).await.unwrap().len(), 1);
    let actions = audit_actions(&s).await;
    assert!(actions.iter().any(|a| a == "login.oidc"), "{actions:?}");

    // And the new linked identity logs straight in next time.
    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspended_linked_user_is_refused() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server(&fake).await;
    let alice = user_with_email(&s, "alice", "fake-user@example.com").await;
    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);

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

    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    let body = response.text().await.unwrap();
    assert!(body.contains("Single sign-on failed"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn totp_user_passes_second_factor_after_oidc() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server(&fake).await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let secret = enroll_totp(&client, &s, &csrf).await;

    // Link the provider from settings.
    let page = get_text(&client, &s.url("/settings/identities")).await;
    let csrf = extract_input(&page, "_csrf");
    let link = client
        .post(s.url("/settings/identities/link"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(link.status(), 303, "link starts the provider flow");
    let authorize_url = link.headers()["location"].to_str().unwrap().to_owned();
    let back = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(back.status(), 303);
    let callback = back.headers()["location"].to_str().unwrap().to_owned();
    let done = client.get(&callback).send().await.unwrap();
    assert_eq!(done.status(), 303);
    assert_eq!(
        done.headers()["location"].to_str().unwrap(),
        "/settings/identities"
    );
    let page = get_text(&client, &s.url("/settings/identities")).await;
    assert!(page.contains(SUBJECT), "linked identity is listed: {page}");

    // A fresh OIDC login now stops at the second factor.
    let (client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(location.starts_with("/login/two-factor"), "{location}");
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("sf_login_challenge=")),
        "{cookies:?}"
    );
    assert!(
        !cookies.iter().any(|c| c.starts_with("sf_session=")),
        "no session before the second factor: {cookies:?}"
    );
    let page = get_text(&client, &s.url(&location)).await;
    let csrf = extract_input(&page, "_csrf");
    let done = client
        .post(s.url("/login/two-factor"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("next", "/"),
            // The enrollment confirm already claimed the current step, so
            // the login must use the next (unclaimed) step.
            ("code", totp_code(&secret, now_step() + 1).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 303);
    assert_eq!(done.headers()["location"].to_str().unwrap(), "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_link_then_unlink_and_csrf() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server(&fake).await;
    s.user("alice").await;
    let (client, _csrf) = s.login("alice").await;

    // CSRF: the link form without a token is refused.
    let forged = client
        .post(s.url("/settings/identities/link"))
        .form(&[("_csrf", "forged")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);

    let page = get_text(&client, &s.url("/settings/identities")).await;
    let csrf = extract_input(&page, "_csrf");
    let link = client
        .post(s.url("/settings/identities/link"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(link.status(), 303);
    let authorize_url = link.headers()["location"].to_str().unwrap().to_owned();
    let back = client.get(&authorize_url).send().await.unwrap();
    let callback = back.headers()["location"].to_str().unwrap().to_owned();
    let done = client.get(&callback).send().await.unwrap();
    assert_eq!(done.status(), 303);

    let page = get_text(&client, &s.url("/settings/identities")).await;
    assert!(page.contains(SUBJECT), "{page}");
    let unlink_action = between(&page, r#"action="/settings/identities/"#, r#"/unlink""#);
    let unlink_url = s.url(&format!("/settings/identities/{unlink_action}/unlink"));

    // CSRF on unlink too.
    let forged = client
        .post(&unlink_url)
        .form(&[("_csrf", "forged")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);

    let page = get_text(&client, &s.url("/settings/identities")).await;
    let csrf = extract_input(&page, "_csrf");
    let removed = client
        .post(&unlink_url)
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 200);
    let body = removed.text().await.unwrap();
    assert!(body.contains("Sign-in removed"), "{body}");
    assert!(!body.contains(SUBJECT), "unlinked identity is gone: {body}");
    let actions = audit_actions(&s).await;
    assert!(
        actions.iter().any(|a| a == "account.identity_linked"),
        "{actions:?}"
    );
    assert!(
        actions.iter().any(|a| a == "account.identity_unlinked"),
        "{actions:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_means_of_login_unlink_is_refused() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, true, "open").await;
    // Auto-create: no password, one identity — unlinking would strand it.
    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    let created = s.core.user_by_handle("fake-user").await.unwrap().unwrap();

    let login_page = get_text(&s.browser(), &s.url("/login")).await;
    assert!(login_page.contains("Sign in with SSO"));

    let (client, _csrf) = {
        // Log in through the browser that already has the session.
        let client = s.browser();
        let begin = client.get(s.url("/login/oidc")).send().await.unwrap();
        let authorize_url = begin.headers()["location"].to_str().unwrap().to_owned();
        let back = client.get(&authorize_url).send().await.unwrap();
        let callback = back.headers()["location"].to_str().unwrap().to_owned();
        let response = client.get(&callback).send().await.unwrap();
        assert_eq!(response.status(), 303);
        let page = get_text(&client, &s.url("/settings/identities")).await;
        let csrf = extract_input(&page, "_csrf");
        (client, csrf)
    };
    let page = get_text(&client, &s.url("/settings/identities")).await;
    assert!(page.contains(SUBJECT), "{page}");
    let unlink_action = between(&page, r#"action="/settings/identities/"#, r#"/unlink""#);
    let unlink_url = s.url(&format!("/settings/identities/{unlink_action}/unlink"));
    let refused = client
        .post(&unlink_url)
        .form(&[("_csrf", _csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    let body = refused.text().await.unwrap();
    assert!(body.contains("only way to sign in"), "{body}");
    assert_eq!(s.core.linked_identities(created.id).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sso_only_mode_refuses_sign_up_but_admin_password_login_works() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server_ex(&fake, true, "sso").await;
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

    // Sign-up is refused, with and without an invite.
    let join = s.browser().get(s.url("/join")).send().await.unwrap();
    assert_eq!(join.status(), 403);
    let body = join.text().await.unwrap();
    assert!(body.contains("Sign-up is disabled"), "{body}");
    let invite = s.core.create_invite(&admin, None).await.unwrap();
    let code = invite
        .link
        .split("invite=")
        .nth(1)
        .expect("invite link carries the code")
        .to_owned();
    let join = s
        .browser()
        .get(s.url(&format!("/join?invite={code}")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        join.status(),
        403,
        "invite acceptance is refused in sso mode"
    );

    // The bootstrap admin still signs in with a password.
    let (_client, response) = s.try_login("root", PASSWORD).await;
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/");

    // Auto-create still works.
    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 303);
    assert!(
        s.core.user_by_handle("fake-user").await.unwrap().is_some(),
        "sso mode auto-creates"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwks_redirect_off_https_is_refused() {
    let fake = FakeOidc::start_es256().await;
    fake.set_jwks_redirect(Some("http://example.com/jwks"));
    let s = oidc_server(&fake).await;
    let (challenge, url) = s.core.oidc_begin(OidcIntent::Login).await.unwrap();
    let (code, state) = authorize(&url).await;
    assert!(
        s.core.oidc_finish(&challenge, &code, &state).await.is_err(),
        "a JWKS redirect to a disallowed URL must fail the login"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_discovery_body_is_refused() {
    let fake = FakeOidc::start_es256().await;
    fake.set_discovery_pad(2 * 1024 * 1024);
    let s = oidc_server(&fake).await;
    assert!(
        s.core.oidc_discovery().await.is_err(),
        "an oversized provider body must fail, not be buffered whole"
    );
    assert!(
        s.core.oidc_begin(OidcIntent::Login).await.is_err(),
        "no login starts against an oversized discovery document"
    );
}

/// `Core::oidc_login` resolves claims the same way the browser path does
/// (the web tests above cover the HTTP legs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_outcome_no_account_without_auto_create() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server(&fake).await;
    let (challenge, url) = s.core.oidc_begin(OidcIntent::Login).await.unwrap();
    let (code, state) = authorize(&url).await;
    let claims = s.core.oidc_finish(&challenge, &code, &state).await.unwrap();
    let outcome = s
        .core
        .oidc_login(&claims, "test", "127.0.0.1")
        .await
        .unwrap();
    assert!(
        matches!(outcome, OidcLoginOutcome::NoAccount),
        "{outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_local_email_does_not_link() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server(&fake).await;
    // The provider verified the email, but the LOCAL account's address
    // is unverified: linking would bypass the EmailUnverified refusal.
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

    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    let body = response.text().await.unwrap();
    assert!(body.contains("No account for this sign-in"), "{body}");
    assert!(
        s.core.linked_identities(alice.id).await.unwrap().is_empty(),
        "an unverified local email must not link"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspended_email_match_inserts_no_identity() {
    let fake = FakeOidc::start_es256().await;
    let s = oidc_server(&fake).await;
    let alice = user_with_email(&s, "alice", "fake-user@example.com").await;
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
    // Suspend BEFORE any login, so the email-link path would insert.
    s.core.suspend_user(&admin, alice.id).await.unwrap();

    let (_client, response) = browser_oidc_login(&s).await;
    assert_eq!(response.status(), 401);
    assert!(
        s.core.linked_identities(alice.id).await.unwrap().is_empty(),
        "a refused suspended login must not insert an identity row"
    );
}
