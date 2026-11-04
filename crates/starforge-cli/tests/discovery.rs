//! C3 server-discovery tests (TDD RED first).
//!
//! In-process axum stubs serve `GET /.well-known/starforge.json`; temp git
//! repos supply remotes via the system `git` binary. No external network:
//! stub remotes use their own `http://127.0.0.1:<port>` authority, which the
//! resolver probes verbatim (documented in `discovery.rs`).

use std::{
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Router, response::IntoResponse, routing::get};
use starforge_cli::{
    discovery::{DiscoveryError, parse_well_known, resolve_server},
    git::{config_get, pick_remote, remotes},
};
use tempfile::TempDir;

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("git binary must exist");
    assert!(status.success(), "git {args:?} failed in {}", dir.display());
}

fn init_repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    dir
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// A port on localhost that is (almost surely) closed: bind `:0`, read the
/// port, drop the listener. Connection-refused, no external traffic.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
    // listener dropped here
}

#[derive(Clone)]
enum WellKnownMode {
    /// Serve the §7.6 shape; `api_url` is derived from the Host header so the
    /// test can bind `:0` and still assert the exact URL.
    Good {
        version: &'static str,
    },
    Malformed,
    MissingKey,
    NotFound,
}

struct Stub {
    base_url: String,
    hits: Arc<AtomicUsize>,
}

async fn well_known_stub(mode: WellKnownMode) -> Stub {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = Router::new().route(
        "/.well-known/starforge.json",
        get(move |headers: axum::http::HeaderMap| {
            let counter = counter.clone();
            let mode = mode.clone();
            async move {
                let host = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("127.0.0.1")
                    .to_string();
                counter.fetch_add(1, Ordering::SeqCst);
                match mode {
                    WellKnownMode::Good { version } => (
                        axum::http::StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "starforge": version,
                            "api_url": format!("http://{host}/api"),
                            "ssh_url": "ssh://git@example.com:2222",
                        })),
                    )
                        .into_response(),
                    WellKnownMode::Malformed => (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        "{not json",
                    )
                        .into_response(),
                    WellKnownMode::MissingKey => (
                        axum::http::StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "api_url": "http://127.0.0.1:9/api",
                            // no "starforge" key
                        })),
                    )
                        .into_response(),
                    WellKnownMode::NotFound => {
                        (axum::http::StatusCode::NOT_FOUND, "nope").into_response()
                    }
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Stub {
        base_url: format!("http://127.0.0.1:{port}"),
        hits,
    }
}

// (a) parse accepts the §7.6 shape.
#[test]
fn parse_well_known_accepts_shape() {
    let body = br#"{"starforge": "0.1.0", "api_url": "https://api.example.com", "ssh_url": "ssh://git@example.com:2222"}"#;
    let info = parse_well_known(body).expect("valid body must parse");
    assert_eq!(info.version, "0.1.0");
    assert_eq!(info.api_url, "https://api.example.com");
    assert_eq!(info.ssh_url, "ssh://git@example.com:2222");
}

// (a) parse rejects a body missing `api_url`, and malformed JSON.
#[test]
fn parse_well_known_rejects_missing_api_url() {
    let missing = br#"{"starforge": "0.1.0", "ssh_url": "ssh://x"}"#;
    assert!(parse_well_known(missing).is_err());
    assert!(parse_well_known(b"{not json").is_err());
    assert!(parse_well_known(b"").is_err());
}

// (e) `.git/config` parsing: `starforge.repo` + absent keys.
#[test]
fn git_config_reads_starforge_keys_and_absent_is_none() {
    let repo = init_repo();
    assert_eq!(config_get(repo.path(), "starforge.server").unwrap(), None);
    assert_eq!(config_get(repo.path(), "starforge.repo").unwrap(), None);
    git(
        repo.path(),
        &["config", "starforge.server", "https://api.example.com"],
    );
    git(repo.path(), &["config", "starforge.repo", "acme/app"]);
    assert_eq!(
        config_get(repo.path(), "starforge.server").unwrap(),
        Some("https://api.example.com".to_string())
    );
    assert_eq!(
        config_get(repo.path(), "starforge.repo").unwrap(),
        Some("acme/app".to_string())
    );
    assert_eq!(
        remotes(repo.path()).unwrap(),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn pick_remote_prefers_starforge_then_origin_then_upstream_then_first() {
    let mk = |name: &str| {
        (
            name.to_string(),
            format!("https://{name}.example.com/r.git"),
        )
    };
    assert_eq!(
        pick_remote(&[mk("origin"), mk("upstream"), mk("starforge")], None),
        Some(mk("starforge"))
    );
    assert_eq!(
        pick_remote(&[mk("upstream"), mk("origin")], None),
        Some(mk("origin"))
    );
    assert_eq!(
        pick_remote(&[mk("upstream"), mk("zzz")], None),
        Some(mk("upstream"))
    );
    assert_eq!(
        pick_remote(&[mk("upstream"), mk("zzz")], Some("zzz")),
        Some(mk("zzz"))
    );
    assert_eq!(
        pick_remote(&[mk("upstream"), mk("alpha")], None),
        Some(mk("upstream"))
    );
    assert_eq!(pick_remote(&[], None), None);
}

// (b) `origin` (stub) wins over a dead `backup` remote.
#[tokio::test]
async fn resolve_picks_origin_stub_over_dead_backup() {
    let stub = well_known_stub(WellKnownMode::Good { version: "0.1.0" }).await;
    let repo = init_repo();
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "origin",
            &format!("{}/owner/repo.git", stub.base_url),
        ],
    );
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "backup",
            &format!("http://127.0.0.1:{}/dead.git", closed_port()),
        ],
    );
    let (server, owner_repo, chosen) = resolve_server(&client(), repo.path()).await.unwrap();
    assert_eq!(server.api_url, format!("{}/api", stub.base_url));
    assert_eq!(server.version, "0.1.0");
    assert_eq!(owner_repo, "owner/repo");
    assert!(chosen.contains("127.0.0.1"), "chosen remote: {chosen}");
    assert_eq!(stub.hits.load(Ordering::SeqCst), 1);
}

// (b) `origin` preferred over `upstream` when both answer.
#[tokio::test]
async fn resolve_prefers_origin_over_upstream() {
    let a = well_known_stub(WellKnownMode::Good { version: "1" }).await;
    let b = well_known_stub(WellKnownMode::Good { version: "2" }).await;
    let repo = init_repo();
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "upstream",
            &format!("{}/u/r.git", b.base_url),
        ],
    );
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "origin",
            &format!("{}/o/r.git", a.base_url),
        ],
    );
    let (server, _, _) = resolve_server(&client(), repo.path()).await.unwrap();
    assert_eq!(server.version, "1");
    assert_eq!(server.api_url, format!("{}/api", a.base_url));
}

// (c) no config/preferred name: first well-known hit wins (dead first).
#[tokio::test]
async fn resolve_first_well_known_hit_wins() {
    let stub = well_known_stub(WellKnownMode::Good { version: "0.1.0" }).await;
    let repo = init_repo();
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "alpha",
            &format!("http://127.0.0.1:{}/a.git", closed_port()),
        ],
    );
    git(
        repo.path(),
        &["remote", "add", "beta", &format!("{}/b.git", stub.base_url)],
    );
    let (server, _, chosen) = resolve_server(&client(), repo.path()).await.unwrap();
    assert_eq!(server.api_url, format!("{}/api", stub.base_url));
    assert!(chosen.contains("/b.git"), "chosen: {chosen}");
}

// (a) config key wins without any HTTP call to the remote stub.
#[tokio::test]
async fn config_server_wins_without_http() {
    let remote_stub = well_known_stub(WellKnownMode::Good { version: "0.1.0" }).await;
    let cfg_stub = well_known_stub(WellKnownMode::Good { version: "9.9.9" }).await;
    let repo = init_repo();
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "origin",
            &format!("{}/o/r.git", remote_stub.base_url),
        ],
    );
    git(
        repo.path(),
        &["config", "starforge.server", &cfg_stub.base_url],
    );
    git(repo.path(), &["config", "starforge.repo", "acme/app"]);
    let (server, owner_repo, _) = resolve_server(&client(), repo.path()).await.unwrap();
    assert_eq!(server.version, "9.9.9");
    assert_eq!(server.api_url, format!("{}/api", cfg_stub.base_url));
    assert_eq!(owner_repo, "acme/app");
    assert_eq!(
        remote_stub.hits.load(Ordering::SeqCst),
        0,
        "remote stub must not be probed when starforge.server is set"
    );
}

// (d) missing key / malformed / 404 fall through to Unreachable naming hosts.
#[tokio::test]
async fn bad_well_known_falls_through_to_unreachable() {
    for mode in [
        WellKnownMode::MissingKey,
        WellKnownMode::Malformed,
        WellKnownMode::NotFound,
    ] {
        let stub = well_known_stub(mode).await;
        let repo = init_repo();
        git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                &format!("{}/o/r.git", stub.base_url),
            ],
        );
        let err = resolve_server(&client(), repo.path()).await.unwrap_err();
        match err {
            DiscoveryError::Unreachable(msg) => {
                assert!(msg.contains("127.0.0.1"), "message: {msg}");
            }
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }
}

// Fix round 1 (P2): userinfo embedded in `starforge.server` must never leak
// into errors, logs, or the returned chosen URL.
#[tokio::test]
async fn config_server_userinfo_never_leaks() {
    let port = closed_port();
    let repo = init_repo();
    git(
        repo.path(),
        &[
            "config",
            "starforge.server",
            &format!("http://alice:s3cret@127.0.0.1:{port}"),
        ],
    );
    let err = resolve_server(&client(), repo.path()).await.unwrap_err();
    match err {
        DiscoveryError::Unreachable(msg) => {
            assert!(msg.contains("127.0.0.1"), "message: {msg}");
            assert!(!msg.contains("alice"), "user leak: {msg}");
            assert!(!msg.contains("s3cret"), "password leak: {msg}");
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
}

// (e) file-only remote and no config: NoServer naming the repo.
#[tokio::test]
async fn file_only_remote_errors_no_server() {
    let repo = init_repo();
    git(
        repo.path(),
        &["remote", "add", "origin", "/tmp/some/path.git"],
    );
    let err = resolve_server(&client(), repo.path()).await.unwrap_err();
    match err {
        DiscoveryError::NoServer(msg) => {
            assert!(
                msg.contains(&repo.path().display().to_string()),
                "message: {msg}"
            );
        }
        other => panic!("expected NoServer, got {other:?}"),
    }
}
