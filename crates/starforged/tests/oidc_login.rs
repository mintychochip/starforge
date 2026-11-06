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
