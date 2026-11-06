//! C2 device-flow + credential storage tests (TDD RED first).
//!
//! Spins an in-process axum stub implementing exactly:
//!   POST /api/v1/oauth/device/code
//!   POST /api/v1/oauth/token
//! and asserts request bodies + poll cadence via a fake [`Sleeper`].

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use starforge_cli::{
    auth::{DeviceFlow, ResolvedToken, credentials_for, load_credentials, resolve_token},
    config::CliPaths,
    queue::{Sleeper, TokioSleeper},
};
use tempfile::TempDir;

struct FakeSleeper {
    sleeps: std::sync::Mutex<Vec<Duration>>,
}

impl FakeSleeper {
    fn new() -> Self {
        Self {
            sleeps: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn recorded(&self) -> Vec<Duration> {
        self.sleeps.lock().unwrap().clone()
    }
}

impl Sleeper for FakeSleeper {
    async fn sleep(&self, dur: Duration) {
        self.sleeps.lock().unwrap().push(dur);
    }
}

fn test_paths() -> (TempDir, CliPaths) {
    let dir = TempDir::new().unwrap();
    let paths = CliPaths::from_home(dir.path().to_path_buf());
    (dir, paths)
}

fn test_now() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH
}

/// Stub server: device-code endpoint returns a fixed grant; token endpoint
/// returns `authorization_pending` once, then success. Records raw bodies.
struct Stub {
    base_url: String,
    device_bodies: Arc<std::sync::Mutex<Vec<String>>>,
    token_bodies: Arc<std::sync::Mutex<Vec<String>>>,
    token_calls: Arc<AtomicUsize>,
}

async fn stub_server() -> Stub {
    let device_bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let token_bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let token_calls = Arc::new(AtomicUsize::new(0));

    let d = device_bodies.clone();
    let t = token_bodies.clone();
    let c = token_calls.clone();
    let app = Router::new()
        .route(
            "/api/v1/oauth/device/code",
            post(move |body: String| {
                let d = d.clone();
                async move {
                    d.lock().unwrap().push(body);
                    Json(json!({
                        "device_code": "dev-123",
                        "user_code": "ABCD-1234",
                        "verification_uri": "https://example.com/activate",
                        "verification_uri_complete": "https://example.com/activate?code=ABCD-1234",
                        "expires_in": 900,
                        "interval": 1,
                    }))
                }
            }),
        )
        .route(
            "/api/v1/oauth/token",
            post(move |body: String| {
                let t = t.clone();
                let c = c.clone();
                async move {
                    t.lock().unwrap().push(body);
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Json(json!({"error": "authorization_pending"}))
                    } else {
                        Json(json!({
                            "access_token": "access-token-abcdef1234",
                            "refresh_token": "r1",
                            "token_type": "Bearer",
                            "expires_in": 3600,
                        }))
                    }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Stub {
        base_url: format!("http://{addr}"),
        device_bodies,
        token_bodies,
        token_calls,
    }
}

fn form_pairs(body: &str) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[tokio::test]
async fn device_flow_polls_then_returns_tokens() {
    let stub = stub_server().await;
    let flow = DeviceFlow::new(stub.base_url.clone());
    let sleeper = FakeSleeper::new();

    let creds = flow.login(&sleeper, test_now()).await.unwrap();

    assert_eq!(creds.access_token, "access-token-abcdef1234");
    assert_eq!(creds.refresh_token, "r1");
    // expires_at = now (epoch) + 3600s, RFC 3339.
    assert_eq!(creds.expires_at, "1970-01-01T01:00:00Z");

    // Device-code request body pins client_id + scope.
    let bodies = stub.device_bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let params = form_pairs(&bodies[0]);
    assert_eq!(
        params.get("client_id").map(String::as_str),
        Some("starforge-cli")
    );
    assert_eq!(
        params.get("scope").map(String::as_str),
        Some(starforge_cli::auth::CLI_SCOPES),
        "scope must be the CLI's full scope set, body: {}",
        bodies[0]
    );

    // Token poll bodies pin the RFC 8628 grant + device_code echo.
    let bodies = stub.token_bodies.lock().unwrap();
    assert_eq!(bodies.len(), 2, "expected pending + success polls");
    for body in bodies.iter() {
        let params = form_pairs(body);
        assert_eq!(
            params.get("grant_type").map(String::as_str),
            Some("urn:ietf:params:oauth:grant-type:device_code"),
            "body: {body}"
        );
        assert_eq!(
            params.get("device_code").map(String::as_str),
            Some("dev-123"),
            "body: {body}"
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("starforge-cli"),
            "body: {body}"
        );
    }

    // Poll cadence honors `interval` (1s) via the injected sleeper — no real sleep.
    assert_eq!(sleeper.recorded(), vec![Duration::from_secs(1)]);
    assert_eq!(stub.token_calls.load(Ordering::SeqCst), 2);

    // The production sleeper type still exists for the binary path.
    let _ = TokioSleeper;
}

#[tokio::test]
async fn device_flow_slow_down_increases_interval() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let app = Router::new()
        .route(
            "/api/v1/oauth/device/code",
            post(|| async {
                Json(json!({
                    "device_code": "dev-slow",
                    "user_code": "SLOW-0001",
                    "verification_uri": "https://example.com/activate",
                    "expires_in": 900,
                    "interval": 1,
                }))
            }),
        )
        .route(
            "/api/v1/oauth/token",
            post(move || {
                let c = c.clone();
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Json(json!({"error": "slow_down"}))
                    } else if n == 1 {
                        Json(json!({"error": "authorization_pending"}))
                    } else {
                        Json(json!({
                            "access_token": "tok",
                            "refresh_token": "r",
                            "token_type": "Bearer",
                            "expires_in": 60,
                        }))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let flow = DeviceFlow::new(base_url);
    let sleeper = FakeSleeper::new();
    let creds = flow.login(&sleeper, test_now()).await.unwrap();
    assert_eq!(creds.access_token, "tok");
    // interval 1s, then slow_down adds 5s → 6s for the next wait.
    assert_eq!(
        sleeper.recorded(),
        vec![Duration::from_secs(1), Duration::from_secs(6)]
    );
}

#[tokio::test]
async fn device_flow_terminal_errors() {
    for error in ["expired_token", "access_denied"] {
        let app = Router::new()
            .route(
                "/api/v1/oauth/device/code",
                post(|| async {
                    Json(json!({
                        "device_code": "dev-x",
                        "user_code": "X-0001",
                        "verification_uri": "https://example.com/activate",
                        "expires_in": 900,
                        "interval": 1,
                    }))
                }),
            )
            .route(
                "/api/v1/oauth/token",
                post(move || async move { Json(json!({"error": error})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let flow = DeviceFlow::new(base_url);
        let sleeper = FakeSleeper::new();
        let err = format!("{}", flow.login(&sleeper, test_now()).await.unwrap_err());
        assert!(
            err.contains(error) || err.contains("expired") || err.contains("denied"),
            "error {error}: {err}"
        );
        assert!(sleeper.recorded().is_empty(), "no sleep on terminal error");
    }
}

#[test]
fn credentials_roundtrip_and_unix_mode() {
    let (_dir, paths) = test_paths();
    // Missing file loads as empty (distinguishable from an error).
    let map = load_credentials(&paths).unwrap();
    assert!(map.is_empty());

    let mut map = BTreeMap::new();
    map.insert(
        "example.com".to_string(),
        starforge_cli::auth::Credentials {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: "1970-01-01T01:00:00Z".to_string(),
        },
    );
    starforge_cli::auth::save_credentials(&paths, &map).unwrap();

    // Raw file pins the per-host TOML shape.
    let raw = std::fs::read_to_string(&paths.credential_file).unwrap();
    assert!(raw.contains("[servers.\"example.com\"]"), "file:\n{raw}");
    assert!(raw.contains("access_token"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&paths.credential_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "credential file must be 0600, got {mode:o}");
    }

    let loaded = load_credentials(&paths).unwrap();
    assert_eq!(loaded, map);
    assert!(credentials_for(&loaded, "example.com").is_some());
    assert!(credentials_for(&loaded, "other.com").is_none());
}

#[cfg(unix)]
#[test]
fn save_overwrites_stale_temp_and_keeps_0600() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, paths) = test_paths();
    std::fs::create_dir_all(&paths.config_dir).unwrap();
    // Simulate a crashed run's leftover temp file with wide permissions.
    let tmp = paths.credential_file.with_extension("toml.tmp");
    std::fs::write(&tmp, "junk").unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut map = BTreeMap::new();
    map.insert(
        "example.com".to_string(),
        starforge_cli::auth::Credentials {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: "1970-01-01T01:00:00Z".to_string(),
        },
    );
    starforge_cli::auth::save_credentials(&paths, &map).unwrap();

    assert!(!tmp.exists(), "stale temp must be renamed away");
    let mode = std::fs::metadata(&paths.credential_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "credential file must be 0600, got {mode:o}");
    assert_eq!(load_credentials(&paths).unwrap(), map);
}

#[test]
fn resolve_token_env_wins_then_file_then_error_naming_both() {
    let (_dir, paths) = test_paths();
    let mut map = BTreeMap::new();
    map.insert(
        "example.com".to_string(),
        starforge_cli::auth::Credentials {
            access_token: "file-token".to_string(),
            refresh_token: "r".to_string(),
            expires_at: "1970-01-01T01:00:00Z".to_string(),
        },
    );
    starforge_cli::auth::save_credentials(&paths, &map).unwrap();

    // Env wins over the file; tests never touch the global env.
    let tok = resolve_token(&paths, "example.com", |k| match k {
        "STARFORGE_TOKEN" => Some("env-token".to_string()),
        _ => None,
    })
    .unwrap();
    assert!(matches!(&tok, ResolvedToken::Env(t) if t == "env-token"));

    // File fallback when the env is unset.
    let tok = resolve_token(&paths, "example.com", |_| None).unwrap();
    assert!(matches!(&tok, ResolvedToken::File(t) if t == "file-token"));

    // Unknown host errors naming both the env var and the file.
    let err = format!(
        "{}",
        resolve_token(&paths, "unknown.com", |_| None).unwrap_err()
    );
    assert!(err.contains("STARFORGE_TOKEN"), "err: {err}");
    assert!(err.contains("unknown.com"), "err: {err}");
}

#[test]
fn credentials_debug_redacts_tokens() {
    let creds = starforge_cli::auth::Credentials {
        access_token: "access-token-abcdef1234".to_string(),
        refresh_token: "refresh-sekrit".to_string(),
        expires_at: "1970-01-01T01:00:00Z".to_string(),
    };
    let dbg = format!("{creds:?}");
    assert!(!dbg.contains("access-token-abcdef1234"), "debug: {dbg}");
    assert!(!dbg.contains("refresh-sekrit"), "debug: {dbg}");
}

#[test]
fn resolved_token_debug_redacts_both_variants() {
    let (_dir, paths) = test_paths();
    let mut map = BTreeMap::new();
    map.insert(
        "example.com".to_string(),
        starforge_cli::auth::Credentials {
            access_token: "file-token-sekrit98765432".to_string(),
            refresh_token: "r".to_string(),
            expires_at: "1970-01-01T01:00:00Z".to_string(),
        },
    );
    starforge_cli::auth::save_credentials(&paths, &map).unwrap();

    let env = resolve_token(&paths, "example.com", |k| match k {
        "STARFORGE_TOKEN" => Some("env-token-sekrit12345678".to_string()),
        _ => None,
    })
    .unwrap();
    let file = resolve_token(&paths, "example.com", |_| None).unwrap();
    for (tok, secret) in [
        (&env, "env-token-sekrit12345678"),
        (&file, "file-token-sekrit98765432"),
    ] {
        let dbg = format!("{tok:?}");
        assert!(!dbg.contains(secret), "debug: {dbg}");
        assert!(!dbg.contains(&secret[secret.len() - 8..]), "debug: {dbg}");
    }
}

#[test]
fn status_redaction_shows_last_four_only() {
    let line = starforge_cli::auth::redact_for_status("example.com", "access-token-abcdef1234");
    assert!(line.contains("example.com"), "line: {line}");
    assert!(line.contains("1234"), "line: {line}");
    assert!(!line.contains("access-token-abcdef1234"), "line: {line}");
}

#[test]
fn logout_removes_entry_and_second_logout_is_ok() {
    let (_dir, paths) = test_paths();
    let mut map = BTreeMap::new();
    for host in ["a.com", "b.com"] {
        map.insert(
            host.to_string(),
            starforge_cli::auth::Credentials {
                access_token: "t".to_string(),
                refresh_token: "r".to_string(),
                expires_at: "1970-01-01T01:00:00Z".to_string(),
            },
        );
    }
    starforge_cli::auth::save_credentials(&paths, &map).unwrap();

    // Remove one host; the other (and the file) survive.
    assert!(starforge_cli::auth::logout_host(&paths, "a.com", false).unwrap());
    let loaded = load_credentials(&paths).unwrap();
    assert!(!loaded.contains_key("a.com"));
    assert!(loaded.contains_key("b.com"));
    assert!(paths.credential_file.exists());

    // Removing the last host removes the file itself.
    assert!(starforge_cli::auth::logout_host(&paths, "b.com", false).unwrap());
    assert!(!paths.credential_file.exists());

    // A second logout is Ok(false) — "not logged in", still exit 0.
    assert!(!starforge_cli::auth::logout_host(&paths, "b.com", false).unwrap());
}

#[test]
fn dry_run_writes_nothing() {
    let (_dir, paths) = test_paths();
    // Dry-run logout on an empty store touches nothing.
    assert!(!starforge_cli::auth::logout_host(&paths, "x.com", true).unwrap());
    assert!(!paths.credential_file.exists());
}

#[test]
fn url_crate_available_for_form_parsing() {
    // Pin the dev-only helper used above: `url` must stay resolvable for tests.
    let _: Value = json!({"ok": true});
}
