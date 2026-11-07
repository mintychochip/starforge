//! `auth ssh-key add` tests: one-time `repo:write` approval, key posting,
//! stored credentials untouched, private-key refusal.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use starforge_cli::{
    auth::{Credentials, SSH_KEY_SCOPE, save_credentials},
    commands::sshkey::{add_ssh_key, resolve_public_key, ssh_remote_url},
    config::CliPaths,
    queue::Sleeper,
};
use tempfile::TempDir;

struct FakeSleeper;

impl FakeSleeper {
    fn new() -> Self {
        Self
    }
}

impl Sleeper for FakeSleeper {
    async fn sleep(&self, _dur: Duration) {}
}

fn test_paths() -> (TempDir, CliPaths) {
    let dir = TempDir::new().unwrap();
    let paths = CliPaths::from_home(dir.path().to_path_buf());
    (dir, paths)
}

fn test_now() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH
}

const PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq user@laptop";
const FINGERPRINT: &str = "SHA256:FakeFingerprint0123456789";

/// Stub server: device-code + token (immediate success), key registration
/// (records bodies + auth header), revocation (records bodies), and a
/// well-known document reporting an SSH base. `duplicate` makes the key
/// endpoint answer 422 already-in-use. `token_scope`/`token_type` shape the
/// token response so granted-scope and token-type checks are exercised.
struct Stub {
    base_url: String,
    device_bodies: Arc<std::sync::Mutex<Vec<String>>>,
    key_bodies: Arc<std::sync::Mutex<Vec<String>>>,
    key_auth: Arc<std::sync::Mutex<Vec<String>>>,
    revoke_bodies: Arc<std::sync::Mutex<Vec<String>>>,
    requests: Arc<std::sync::atomic::AtomicUsize>,
}

async fn stub_server(duplicate: bool) -> Stub {
    stub_server_custom(
        duplicate,
        Some(SSH_KEY_SCOPE.to_string()),
        "Bearer".to_string(),
    )
    .await
}

async fn stub_server_custom(
    duplicate: bool,
    token_scope: Option<String>,
    token_type: String,
) -> Stub {
    let device_bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let key_bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let key_auth = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let revoke_bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let d = device_bodies.clone();
    let k = key_bodies.clone();
    let a = key_auth.clone();
    let r = revoke_bodies.clone();
    let n = requests.clone();
    let nt = n.clone();
    let nk = n.clone();
    let nr = n.clone();
    let nw = n.clone();
    let app = Router::new()
        .route(
            "/api/v1/oauth/device/code",
            post(move |body: String| {
                let d = d.clone();
                let n = nt.clone();
                async move {
                    n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    d.lock().unwrap().push(body);
                    Json(json!({
                        "device_code": "dev-ssh",
                        "user_code": "SSH-KEYS",
                        "verification_uri": "https://example.com/activate",
                        "verification_uri_complete": "https://example.com/activate?code=SSH-KEYS",
                        "expires_in": 900,
                        "interval": 1,
                    }))
                }
            }),
        )
        .route(
            "/api/v1/oauth/token",
            post(move || {
                let n = n.clone();
                let token_scope = token_scope.clone();
                let token_type = token_type.clone();
                async move {
                    n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut body = json!({
                        "access_token": "one-time-token-xyz1234",
                        "refresh_token": "one-time-refresh",
                        "token_type": token_type,
                        "expires_in": 3600,
                    });
                    if let Some(scope) = token_scope {
                        body["scope"] = json!(scope);
                    }
                    Json(body)
                }
            }),
        )
        .route(
            "/api/v1/oauth/revoke",
            post(move |body: String| {
                let r = r.clone();
                let n = nr.clone();
                async move {
                    n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    r.lock().unwrap().push(body);
                    StatusCode::OK
                }
            }),
        )
        .route(
            "/api/v1/user/keys",
            post(move |headers: HeaderMap, body: String| {
                let k = k.clone();
                let a = a.clone();
                let n = nk.clone();
                async move {
                    n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let auth = headers
                        .get("authorization")
                        .map(|v| v.to_str().unwrap_or_default().to_string())
                        .unwrap_or_default();
                    a.lock().unwrap().push(auth);
                    k.lock().unwrap().push(body);
                    if duplicate {
                        (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(json!({"error": {"code": "invalid", "message": "this key is already in use"}})),
                        )
                    } else {
                        (
                            StatusCode::CREATED,
                            Json(json!({
                                "id": 7,
                                "title": "user@laptop",
                                "algorithm": "ssh-ed25519",
                                "fingerprint": FINGERPRINT,
                                "created_at": "2026-01-01T00:00:00Z",
                                "last_used_at": null,
                            })),
                        )
                    }
                }
            }),
        )
        .route(
            "/.well-known/starforge.json",
            get(move || {
                let n = nw.clone();
                async move {
                    n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(json!({
                        "starforge": "0.1.0",
                        "api_url": "http://127.0.0.1:1",
                        "ssh_url": "ssh://git@127.0.0.1:2222",
                    }))
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
        key_bodies,
        key_auth,
        revoke_bodies,
        requests,
    }
}

fn form_pairs(body: &str) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn write_pubkey(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
}

fn seed_credentials(paths: &CliPaths) {
    let mut map = BTreeMap::new();
    map.insert(
        "example.com".to_string(),
        Credentials {
            access_token: "stored-login-token".to_string(),
            refresh_token: "stored-refresh".to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        },
    );
    save_credentials(paths, &map).unwrap();
}

#[tokio::test]
async fn ssh_key_add_requests_repo_write_posts_key_and_keeps_credentials() {
    let (_dir, paths) = test_paths();
    seed_credentials(&paths);
    let before = std::fs::read(&paths.credential_file).unwrap();
    let pubkey_path = _dir.path().join("id_ed25519.pub");
    write_pubkey(&pubkey_path, PUBKEY);
    let stub = stub_server(false).await;
    let sleeper = FakeSleeper::new();

    let out = add_ssh_key(
        &paths,
        _dir.path(),
        Some(pubkey_path),
        Some(&stub.base_url),
        Some("user@laptop"),
        &sleeper,
        test_now(),
        false,
    )
    .await
    .unwrap();

    assert!(out.contains(FINGERPRINT), "output names fingerprint: {out}");
    assert!(out.contains("ssh-ed25519"), "output names algorithm: {out}");

    // Device flow requested exactly repo:write.
    let bodies = stub.device_bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let params = form_pairs(&bodies[0]);
    assert_eq!(
        params.get("scope").map(String::as_str),
        Some(SSH_KEY_SCOPE),
        "scope must be exactly repo:write, body: {}",
        bodies[0]
    );
    assert_eq!(SSH_KEY_SCOPE, "repo:write");
    drop(bodies);

    // Key body was posted with the one-time token.
    let keys = stub.key_bodies.lock().unwrap();
    assert_eq!(keys.len(), 1, "exactly one key post");
    let body: Value = serde_json::from_str(&keys[0]).unwrap();
    assert_eq!(body["key"], PUBKEY);
    assert_eq!(body["title"], "user@laptop");
    assert_eq!(
        stub.key_auth.lock().unwrap()[0],
        "Bearer one-time-token-xyz1234"
    );

    // The one-time refresh token was revoked after the key post.
    let revokes = stub.revoke_bodies.lock().unwrap();
    assert_eq!(
        revokes.len(),
        1,
        "exactly one revoke post, got: {revokes:?}"
    );
    let revoke_params = form_pairs(&revokes[0]);
    assert_eq!(
        revoke_params.get("token").map(String::as_str),
        Some("one-time-refresh"),
        "revoke must carry the refresh token, body: {}",
        revokes[0]
    );
    drop(revokes);

    // Stored credentials file is byte-identical.
    let after = std::fs::read(&paths.credential_file).unwrap();
    assert_eq!(after, before, "login token must be untouched");
}

#[tokio::test]
async fn ssh_key_add_reports_already_registered() {
    let (_dir, paths) = test_paths();
    let pubkey_path = _dir.path().join("id_ed25519.pub");
    write_pubkey(&pubkey_path, PUBKEY);
    let stub = stub_server(true).await;
    let sleeper = FakeSleeper::new();

    let err = add_ssh_key(
        &paths,
        _dir.path(),
        Some(pubkey_path),
        Some(&stub.base_url),
        None,
        &sleeper,
        test_now(),
        false,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("already registered"),
        "duplicate must report clearly, got: {err}"
    );
}

#[tokio::test]
async fn dry_run_performs_no_http() {
    let (_dir, paths) = test_paths();
    let pubkey_path = _dir.path().join("id_ed25519.pub");
    write_pubkey(&pubkey_path, PUBKEY);
    let stub = stub_server(false).await;
    let sleeper = FakeSleeper::new();

    let out = add_ssh_key(
        &paths,
        _dir.path(),
        Some(pubkey_path.clone()),
        Some(&stub.base_url),
        Some("user@laptop"),
        &sleeper,
        test_now(),
        true,
    )
    .await
    .unwrap();
    assert!(
        out.contains("would request"),
        "dry-run prints the plan: {out}"
    );
    assert_eq!(
        stub.requests.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "dry-run must perform no HTTP"
    );
}

#[tokio::test]
async fn wrong_granted_scope_is_an_error() {
    let (_dir, paths) = test_paths();
    let pubkey_path = _dir.path().join("id_ed25519.pub");
    write_pubkey(&pubkey_path, PUBKEY);
    let stub = stub_server_custom(false, Some("repo:read".to_string()), "Bearer".to_string()).await;
    let sleeper = FakeSleeper::new();

    let err = add_ssh_key(
        &paths,
        _dir.path(),
        Some(pubkey_path),
        Some(&stub.base_url),
        None,
        &sleeper,
        test_now(),
        false,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("scope"),
        "wrong granted scope must error, got: {err}"
    );
    assert_eq!(
        stub.key_bodies.lock().unwrap().len(),
        0,
        "no key post when the granted scope is wrong"
    );
}

#[tokio::test]
async fn wrong_token_type_is_an_error() {
    let (_dir, paths) = test_paths();
    let pubkey_path = _dir.path().join("id_ed25519.pub");
    write_pubkey(&pubkey_path, PUBKEY);
    let stub =
        stub_server_custom(false, Some(SSH_KEY_SCOPE.to_string()), "Basic".to_string()).await;
    let sleeper = FakeSleeper::new();

    let err = add_ssh_key(
        &paths,
        _dir.path(),
        Some(pubkey_path),
        Some(&stub.base_url),
        None,
        &sleeper,
        test_now(),
        false,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("token_type"),
        "wrong token_type must error, got: {err}"
    );
}

#[test]
fn private_key_path_is_refused_without_device_flow() {
    let (_dir, paths) = test_paths();
    // A bare private-key path (no .pub sibling) is refused unread.
    let private_path = _dir.path().join("id_ed25519");
    std::fs::write(
        &private_path,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nstuff\n",
    )
    .unwrap();
    let err = resolve_public_key(&paths.home, Some(private_path.clone())).unwrap_err();
    assert!(
        err.to_string().contains("private key"),
        "private path must be refused, got: {err}"
    );

    // A .pub path containing private material is refused too.
    let fake_pub = _dir.path().join("fake.pub");
    std::fs::write(&fake_pub, "-----BEGIN OPENSSH PRIVATE KEY-----\nstuff\n").unwrap();
    let err = resolve_public_key(&paths.home, Some(fake_pub)).unwrap_err();
    assert!(err.to_string().contains("private key"), "got: {err}");

    // Multi-line content (several keys) is refused.
    let multi = _dir.path().join("multi.pub");
    write_pubkey(&multi, &format!("{PUBKEY}\n{PUBKEY}\n"));
    let err = resolve_public_key(&paths.home, Some(multi)).unwrap_err();
    assert!(err.to_string().contains("one key per file"), "got: {err}");
}

#[test]
fn bare_path_falls_back_to_pub_sibling_and_default_order() {
    let (_dir, paths) = test_paths();
    let private = _dir.path().join("id_ed25519");
    let pub_sidecar = _dir.path().join("id_ed25519.pub");
    write_pubkey(&pub_sidecar, PUBKEY);
    let (resolved, key) = resolve_public_key(&paths.home, Some(private)).unwrap();
    assert_eq!(resolved, pub_sidecar);
    assert_eq!(key, PUBKEY);

    // Default discovery prefers id_ed25519.pub over the others.
    let ssh_dir = _dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    write_pubkey(&ssh_dir.join("id_rsa.pub"), PUBKEY);
    write_pubkey(&ssh_dir.join("id_ed25519.pub"), PUBKEY);
    let (resolved, _) = resolve_public_key(&paths.home, None).unwrap();
    assert_eq!(resolved, ssh_dir.join("id_ed25519.pub"));

    // No keys at all: a clear config error.
    let (empty_dir, empty_paths) = test_paths();
    let err = resolve_public_key(&empty_paths.home, None).unwrap_err();
    assert!(err.to_string().contains("no public key"), "got: {err}");
    drop(empty_dir);
}

#[test]
fn ssh_remote_url_form() {
    assert_eq!(
        ssh_remote_url("ssh://git@127.0.0.1:2222", "owner/repo").as_deref(),
        Some("ssh://git@127.0.0.1:2222/owner/repo.git")
    );
    assert_eq!(ssh_remote_url("", "owner/repo"), None);
    assert_eq!(ssh_remote_url("ssh://git@host:22/", ""), None);
}

#[test]
fn explicit_pubkey_path_is_read() {
    let (_dir, paths) = test_paths();
    let key_path: PathBuf = _dir.path().join("custom.pub");
    write_pubkey(&key_path, PUBKEY);
    let (resolved, key) = resolve_public_key(&paths.home, Some(key_path.clone())).unwrap();
    assert_eq!(resolved, key_path);
    assert_eq!(key, PUBKEY);
}
