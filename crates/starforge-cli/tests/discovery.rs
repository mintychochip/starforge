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
    discovery::{DiscoveryError, parse_well_known, remote_name_for_chosen, resolve_server},
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
    starforge_cli::discovery::forge_client(Duration::from_secs(5)).unwrap()
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
    /// test can bind `:0` and still assert the exact URL. Origin-only.
    Good {
        version: &'static str,
    },
    /// Serve the §7.6 shape with `api_url` = `{host}/` (trailing slash).
    GoodTrailingSlash,
    /// Serve the §7.6 shape with `api_url` = `{host}/api` (non-origin path).
    WithPath,
    /// Serve the §7.6 shape with an explicit `api_url` (cross-origin tests).
    CrossOrigin {
        api_url: String,
    },
    /// Respond 302 to `location` (must not be followed).
    RedirectTo {
        location: String,
    },
    /// Respond with an oversize (>64 KiB) body.
    Oversize,
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
                            "api_url": format!("http://{host}"),
                            "ssh_url": "ssh://git@example.com:2222",
                        })),
                    )
                        .into_response(),
                    WellKnownMode::GoodTrailingSlash => (
                        axum::http::StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "starforge": "0.1.0",
                            "api_url": format!("http://{host}/"),
                            "ssh_url": "ssh://git@example.com:2222",
                        })),
                    )
                        .into_response(),
                    WellKnownMode::WithPath => (
                        axum::http::StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "starforge": "0.1.0",
                            "api_url": format!("http://{host}/api"),
                            "ssh_url": "ssh://git@example.com:2222",
                        })),
                    )
                        .into_response(),
                    WellKnownMode::CrossOrigin { api_url } => (
                        axum::http::StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "starforge": "0.1.0",
                            "api_url": api_url,
                            "ssh_url": "ssh://git@example.com:2222",
                        })),
                    )
                        .into_response(),
                    WellKnownMode::RedirectTo { location } => (
                        axum::http::StatusCode::FOUND,
                        [(axum::http::header::LOCATION, location)],
                    )
                        .into_response(),
                    WellKnownMode::Oversize => (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        "x".repeat(70 * 1024),
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
// (a) parse accepts a missing or empty `ssh_url` (SSH-disabled servers send
// `""`; older servers may omit the field) and stores it as `""`.
#[test]
fn parse_well_known_accepts_missing_or_empty_ssh_url() {
    let missing = br#"{"starforge": "0.1.0", "api_url": "https://api.example.com"}"#;
    let info = parse_well_known(missing).expect("missing ssh_url must parse");
    assert_eq!(info.ssh_url, "");
    let empty = br#"{"starforge": "0.1.0", "api_url": "https://api.example.com", "ssh_url": ""}"#;
    let info = parse_well_known(empty).expect("empty ssh_url must parse");
    assert_eq!(info.ssh_url, "");
}
// Git ops must use the remote NAME behind the resolved (sanitized, display-
// only) URL: a credential-bearing remote keeps its userinfo, `pushurl`, and
// remote-scoped config when git runs against the name, never a bare URL.
#[test]
fn remote_name_for_chosen_maps_sanitized_url_back_to_name() {
    let remotes = vec![
        (
            "origin".to_string(),
            "http://me:tok@host/o/r.git".to_string(),
        ),
        ("backup".to_string(), "http://host2/o/r.git".to_string()),
    ];
    assert_eq!(
        remote_name_for_chosen(&remotes, "http://host/o/r.git").as_deref(),
        Some("origin")
    );
    // The `starforge.server`-wins win returns the server base, which is never
    // a remote URL: fall back to pick_remote's preferred name.
    assert_eq!(
        remote_name_for_chosen(&remotes, "http://host").as_deref(),
        Some("origin")
    );
    assert_eq!(remote_name_for_chosen(&[], "http://host"), None);
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
    assert_eq!(server.api_url, stub.base_url);
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
    assert_eq!(server.api_url, a.base_url);
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
    assert_eq!(server.api_url, stub.base_url);
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
    assert_eq!(server.api_url, cfg_stub.base_url);
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

/// PAT-in-username remotes (`https://ghp_xxx@host/o/r.git`) are the common CI
/// shape; the token is the username, so any userinfo must be stripped.
#[test]
fn sanitize_remote_url_strips_pathless_and_pat_usernames() {
    use starforge_cli::discovery::sanitize_remote_url;
    assert_eq!(
        sanitize_remote_url("https://ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/o/r.git"),
        "https://github.com/o/r.git"
    );
    assert_eq!(
        sanitize_remote_url("https://user:token@example.com/o/r.git"),
        "https://example.com/o/r.git"
    );
    assert_eq!(
        sanitize_remote_url("https://example.com/o/r.git"),
        "https://example.com/o/r.git"
    );
    // scp-style needs its user to stay.
    assert_eq!(
        sanitize_remote_url("git@github.com:o/r.git"),
        "git@github.com:o/r.git"
    );
}

// C1: `api_url` on another origin is refused and no request reaches it.
#[tokio::test]
async fn cross_origin_api_url_is_refused_and_other_host_not_contacted() {
    let attacker = well_known_stub(WellKnownMode::Good { version: "0.1.0" }).await;
    let victim = well_known_stub(WellKnownMode::CrossOrigin {
        api_url: attacker.base_url.clone(),
    })
    .await;
    let repo = init_repo();
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "origin",
            &format!("{}/o/r.git", victim.base_url),
        ],
    );
    let err = resolve_server(&client(), repo.path()).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(&format!(
            "server at {} advertises api_url {} on another origin; refusing (set git config starforge.server {} to trust it explicitly)",
            victim.base_url, attacker.base_url, attacker.base_url
        )),
        "message: {msg}"
    );
    assert_eq!(
        attacker.hits.load(Ordering::SeqCst),
        0,
        "no further request may reach the advertised host"
    );
    assert_eq!(victim.hits.load(Ordering::SeqCst), 1);
}

// C1: same origin with a trailing slash is accepted and normalized.
#[tokio::test]
async fn same_origin_trailing_slash_is_accepted_and_normalized() {
    let stub = well_known_stub(WellKnownMode::GoodTrailingSlash).await;
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
    let (server, _, _) = resolve_server(&client(), repo.path()).await.unwrap();
    assert_eq!(server.api_url, stub.base_url);
}

// C1: `api_url` with a non-origin path is refused.
#[tokio::test]
async fn api_url_with_path_is_refused() {
    let stub = well_known_stub(WellKnownMode::WithPath).await;
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
    assert!(
        err.to_string().contains("non-origin path"),
        "message: {err}"
    );
}

// I7: a redirect from the well-known endpoint is not followed.
#[tokio::test]
async fn well_known_redirect_is_not_followed() {
    let target = well_known_stub(WellKnownMode::Good { version: "0.1.0" }).await;
    let redirector = well_known_stub(WellKnownMode::RedirectTo {
        location: format!("{}/.well-known/starforge.json", target.base_url),
    })
    .await;
    let repo = init_repo();
    git(
        repo.path(),
        &[
            "remote",
            "add",
            "origin",
            &format!("{}/o/r.git", redirector.base_url),
        ],
    );
    let err = resolve_server(&client(), repo.path()).await.unwrap_err();
    assert!(
        matches!(err, DiscoveryError::Unreachable(_)),
        "expected Unreachable, got {err:?}"
    );
    assert_eq!(
        target.hits.load(Ordering::SeqCst),
        0,
        "redirect target must not be contacted"
    );
}

// I7: an oversize well-known body is refused.
#[tokio::test]
async fn oversize_well_known_body_is_refused() {
    let stub = well_known_stub(WellKnownMode::Oversize).await;
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
    assert!(err.to_string().contains("exceeds"), "message: {err}");
}

// I7: `http` is allowed only for loopback anchors (pure check fn).
#[test]
fn http_non_loopback_anchor_is_refused() {
    use starforge_cli::discovery::anchor_transport_allowed;
    assert!(anchor_transport_allowed("https://example.com"));
    assert!(anchor_transport_allowed("https://127.0.0.1:1234"));
    assert!(anchor_transport_allowed("http://127.0.0.1:1234"));
    assert!(anchor_transport_allowed("http://127.0.0.5:1234"));
    assert!(anchor_transport_allowed("http://localhost:1234"));
    assert!(anchor_transport_allowed("http://[::1]:1234"));
    assert!(!anchor_transport_allowed("http://example.com"));
    assert!(!anchor_transport_allowed("http://192.168.1.1"));
    assert!(!anchor_transport_allowed("http://10.0.0.1"));
    assert!(!anchor_transport_allowed("ftp://127.0.0.1"));
}

// C1: explicit `starforge.server` with matching origins works (anchor is
// the configured origin).
#[tokio::test]
async fn config_server_explicit_matching_origin_works() {
    let cfg_stub = well_known_stub(WellKnownMode::Good { version: "9.9.9" }).await;
    let repo = init_repo();
    git(
        repo.path(),
        &["config", "starforge.server", &cfg_stub.base_url],
    );
    git(repo.path(), &["config", "starforge.repo", "acme/app"]);
    let (server, owner_repo, chosen) = resolve_server(&client(), repo.path()).await.unwrap();
    assert_eq!(server.api_url, cfg_stub.base_url);
    assert_eq!(owner_repo, "acme/app");
    assert_eq!(chosen, cfg_stub.base_url);
}

// C1: the credential host key equals the pinned origin host.
#[tokio::test]
async fn token_host_key_equals_pinned_origin() {
    let stub = well_known_stub(WellKnownMode::Good { version: "0.1.0" }).await;
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
    let (server, _, _) = resolve_server(&client(), repo.path()).await.unwrap();
    assert_eq!(server.api_url, stub.base_url);
    let expected = stub.base_url.trim_start_matches("http://").to_string();
    assert_eq!(
        starforge_cli::cli::sync_host_key(&server.api_url),
        Some(expected)
    );
}

// IPv6: the anchor built from an IPv6-literal remote and the `api_url`
// origin must compare equal (both bracketed), so pinning does not refuse
// loopback IPv6 servers.
#[test]
fn ipv6_anchor_and_api_url_origins_match() {
    use starforge_cli::discovery::{pin_api_url, probe_base_for_remote};
    let anchor =
        probe_base_for_remote("http://[::1]:3000/o/r.git").expect("IPv6 remote must probe");
    assert_eq!(anchor, "http://[::1]:3000");
    assert_eq!(
        pin_api_url("http://[::1]:3000", &anchor).expect("same IPv6 origin must pin"),
        "http://[::1]:3000"
    );
    assert_eq!(
        pin_api_url("http://[::1]:3000/", &anchor).expect("trailing slash must pin"),
        "http://[::1]:3000"
    );
    assert!(pin_api_url("http://[::1]:3001", &anchor).is_err());
    assert!(pin_api_url("http://127.0.0.1:3000", &anchor).is_err());
    assert_eq!(
        starforge_cli::cli::sync_host_key(&anchor),
        Some("[::1]:3000".to_string())
    );
}
