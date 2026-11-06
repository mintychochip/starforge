//! Remotes security sweep (M4b I5): the outbound URL policy on every entry
//! point (import, pull, push; API and web), DNS-rebinding fail-closed via
//! address pinning, credential non-disclosure (responses, pages, audit rows,
//! stored `last_error`, `Debug` output), the 404/403 access matrix, CSRF on
//! every form, archived-repository refusals, and the secret-key-change case.

mod common;

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::crypto::CredentialBox;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::remotes::{
    FixedResolver, HostResolver, ImportAuth, ImportInput, PullMirrorInput, PushMirrorInput,
};
use starforged_core::tokens::Scope;
use starforged_git::remote::RemoteCreds;

const SECRET: &str = "sweep-secret-token-001x";

async fn api(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (u16, String, Value) {
    let req = match method {
        "PUT" => client.put(url),
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };
    let req = match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    };
    let req = match body {
        Some(b) => req.json(b),
        None => req,
    };
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    let text = res.text().await.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, text, v)
}

/// A `file://` source repository for the flag-on servers.
async fn source_url(dir: &std::path::Path, name: &str) -> String {
    let work = work_repo(dir, name, &[("README.md", "# src\n")]).await;
    format!("file://{}", work.display())
}

/// How many audit rows (action, target, or detail) contain `needle`.
async fn audit_contains(s: &TestServer, needle: &str) -> i64 {
    let pattern = format!("%{needle}%");
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE detail LIKE $1 OR target LIKE $1 OR action LIKE $1",
    )
    .bind(&pattern)
    .fetch_one(s.core.db().pool())
    .await
    .unwrap()
}

/// Polls the pull-mirror endpoint until `last_error` is non-empty.
async fn poll_pull_error(s: &TestServer, token: &str) -> Value {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let out = api(
            &client,
            "GET",
            &s.url("/api/v1/repos/alice/proj/mirror/pull"),
            Some(token),
            None,
        )
        .await;
        if !out.2["last_error"].as_str().unwrap_or("").is_empty() || Instant::now() > deadline {
            return out.2;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn url_policy_refuses_ssrf_targets_on_every_api_entry_point() {
    let s = TestServer::start_with(|_| {}).await;
    let alice = s.user("alice").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .create_org(
            &alice,
            starforged_core::orgs::NewOrgInput {
                handle: "acme".into(),
                display_name: String::new(),
                description: String::new(),
            },
        )
        .await
        .unwrap();

    // Loopback, link-local (incl. the metadata endpoint), private, shared
    // address space, IPv4-mapped IPv6, IPv6 loopback/unspecified, disallowed
    // schemes, local paths, dash-prefixed ssh option injection, and
    // whitespace/empty input — all refused under the production policy.
    const BAD: &[&str] = &[
        "https://127.0.0.1/x.git",
        "http://127.0.0.1/x.git",
        "ssh://git@127.0.0.1/x.git",
        "https://[::1]/x.git",
        "https://169.254.169.254/latest/meta-data/",
        "https://[fe80::1]/x.git",
        "https://10.0.0.1/x.git",
        "https://172.16.0.1/x.git",
        "https://192.168.1.1/x.git",
        "https://100.64.0.1/x.git",
        "https://[::ffff:127.0.0.1]/x.git",
        "https://[::ffff:10.0.0.1]/x.git",
        "https://0.0.0.0/x.git",
        "file:///srv/repos/x.git",
        "/srv/repos/x.git",
        "ext::sh -c 'id'",
        "fd::17",
        "git://git.example.com/x.git",
        "ftp://git.example.com/x.git",
        "-oProxyCommand=id",
        "-oProxyCommand=id@evil.com:repo",
        "ssh://-oProxyCommand=id@git.example.com/x.git",
        "ssh://git@-oProxyCommand=id/x.git",
        "git@-oProxyCommand=id:x.git",
        "https://git.example.com/x git",
        "",
    ];

    let client = reqwest::Client::new();
    for (i, bad) in BAD.iter().enumerate() {
        // Import at creation: 422 and no repository is left behind.
        let name = format!("imp{i}");
        let (status, text, _) = api(
            &client,
            "POST",
            &s.url("/api/v1/user/repos"),
            Some(&rw),
            Some(&json!({"name": name, "import": {"url": bad}})),
        )
        .await;
        assert_eq!(status, 422, "import create {bad:?}: {text}");
        let (status, _, _) = api(
            &client,
            "GET",
            &s.url(&format!("/api/v1/repos/alice/{name}")),
            Some(&rw),
            None,
        )
        .await;
        assert_eq!(status, 404, "refused import created a repository: {name}");

        // Pull mirror configuration.
        let (status, text, _) = api(
            &client,
            "PUT",
            &s.url("/api/v1/repos/alice/proj/mirror/pull"),
            Some(&rw),
            Some(&json!({"url": bad, "interval_secs": 300})),
        )
        .await;
        assert_eq!(status, 422, "pull mirror {bad:?}: {text}");
        let (status, _, _) = api(
            &client,
            "GET",
            &s.url("/api/v1/repos/alice/proj/mirror/pull"),
            Some(&rw),
            None,
        )
        .await;
        assert_eq!(status, 404, "refused pull mirror was stored: {bad:?}");

        // Push mirror addition.
        let (status, text, _) = api(
            &client,
            "POST",
            &s.url("/api/v1/repos/alice/proj/mirror/push"),
            Some(&rw),
            Some(&json!({"url": bad})),
        )
        .await;
        assert_eq!(status, 422, "push mirror {bad:?}: {text}");
        let (_, _, listed) = api(
            &client,
            "GET",
            &s.url("/api/v1/repos/alice/proj/mirror/push"),
            Some(&rw),
            None,
        )
        .await;
        assert!(
            listed.as_array().is_some_and(|a| a.is_empty()),
            "refused push mirror stored: {bad:?}"
        );
    }

    // The org repository-creation entry point (same `import` body) refuses
    // too, and so does import start with a replacement URL.
    for (i, bad) in [
        "file:///srv/x.git",
        "ext::sh -c 'id'",
        "https://[::ffff:10.0.0.1]/x.git",
        "-oProxyCommand=id",
    ]
    .iter()
    .enumerate()
    {
        let (status, text, _) = api(
            &client,
            "POST",
            &s.url("/api/v1/orgs/acme/repos"),
            Some(&rw),
            Some(&json!({"name": format!("oimp{i}"), "import": {"url": bad}})),
        )
        .await;
        assert_eq!(status, 422, "org import {bad:?}: {text}");
    }
}

/// A resolver that returns `first` on the save-time check and `rest`
/// afterwards — a DNS rebinding between policy check and git run.
struct FlipResolver {
    first: IpAddr,
    rest: IpAddr,
    flipped: AtomicBool,
}

impl HostResolver for FlipResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        if self.flipped.swap(true, Ordering::SeqCst) {
            Ok(vec![self.rest])
        } else {
            Ok(vec![self.first])
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_rebinding_fails_closed_and_pinning_is_used() {
    let s = TestServer::start_with(|_| {}).await;
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    let private: IpAddr = "10.0.0.1".parse().unwrap();

    // Save-time (public), run-time (private): the second check fails
    // closed, and the first pin points git at the public address.
    let flipping = FlipResolver {
        first: public,
        rest: private,
        flipped: AtomicBool::new(false),
    };
    let pinned = s
        .core
        .check_remote_url_with_resolver("https://git.example.com/x.git", &flipping)
        .expect("public resolution is allowed");
    assert_eq!(pinned.pinned_ip, Some(public));
    let args = pinned.config_args();
    assert!(
        args.iter()
            .any(|a| a == "http.curloptResolve=git.example.com:443:93.184.216.34"),
        "https pinning missing: {args:?}"
    );
    assert!(
        s.core
            .check_remote_url_with_resolver("https://git.example.com/x.git", &flipping)
            .is_err(),
        "rebound private resolution must fail closed"
    );

    // SSH pinning uses the same checked address with the original name.
    let flipping = FlipResolver {
        first: public,
        rest: private,
        flipped: AtomicBool::new(false),
    };
    let pinned = s
        .core
        .check_remote_url_with_resolver("ssh://git@git.example.com:2222/x.git", &flipping)
        .expect("public resolution is allowed");
    let ssh_args = pinned.ssh_args(None);
    assert!(
        ssh_args.iter().any(|a| a == "HostName=93.184.216.34"),
        "{ssh_args:?}"
    );
    assert!(
        ssh_args.iter().any(|a| a == "HostKeyAlias=git.example.com"),
        "{ssh_args:?}"
    );
    assert!(
        s.core
            .check_remote_url_with_resolver("ssh://git@git.example.com:2222/x.git", &flipping)
            .is_err(),
        "rebound private resolution must fail closed"
    );

    // A mixed resolution pins the first allowed address, never the private one.
    let mixed = FixedResolver {
        addrs: vec![private, public],
    };
    let pinned = s
        .core
        .check_remote_url_with_resolver("https://git.example.com/x.git", &mixed)
        .expect("mixed resolution pins the public address");
    assert_eq!(pinned.pinned_ip, Some(public));
    let only_private = FixedResolver {
        addrs: vec![private],
    };
    assert!(
        s.core
            .check_remote_url_with_resolver("https://git.example.com/x.git", &only_private)
            .is_err()
    );
    let none = FixedResolver { addrs: vec![] };
    assert!(
        s.core
            .check_remote_url_with_resolver("https://git.example.com/x.git", &none)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn userinfo_passwords_are_stripped_from_every_scheme() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let alice = s.user("alice").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let client = reqwest::Client::new();

    // http (loopback under the flag), ssh, and https userinfo passwords are
    // stripped; the stored/returned URL keeps only the username.
    for url in [
        "http://git:sweep-secret-token-001x@127.0.0.1:9/x.git",
        "ssh://git:sweep-secret-token-001x@127.0.0.1/x.git",
        "https://git:sweep-secret-token-001x@127.0.0.1/x.git",
    ] {
        let userinfo_url = url;
        let (status, text, v) = api(
            &client,
            "PUT",
            &s.url("/api/v1/repos/alice/proj/mirror/pull"),
            Some(&rw),
            Some(&json!({"url": userinfo_url})),
        )
        .await;
        assert_eq!(status, 200, "{url}: {text}");
        assert!(!text.contains(SECRET), "{url}: {text}");
        let stored = v["url"].as_str().unwrap_or("");
        assert!(!stored.contains(SECRET), "{stored}");
        assert!(stored.contains("git@127.0.0.1"), "{stored}");
    }

    // Push mirror and import creation agree.
    let (status, text, v) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        Some(&rw),
        Some(&json!({"url": "http://git:sweep-secret-token-001x@127.0.0.1:9/x.git"})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    assert!(!text.contains(SECRET));
    assert!(!v["url"].as_str().unwrap().contains(SECRET));

    let (status, text, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/user/repos"),
        Some(&rw),
        Some(&json!({"name": "stripped", "import": {"url": "http://git:sweep-secret-token-001x@127.0.0.1:9/x.git"}})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    assert!(!text.contains(SECRET));
    let (_, text, v) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/stripped/import"),
        Some(&rw),
        None,
    )
    .await;
    assert!(!text.contains(SECRET), "{text}");
    assert!(!v["url"].as_str().unwrap().contains(SECRET));

    // The stored row, the audit rows, and pull/push responses agree.
    let repo_id = v["repo_id"].as_i64().unwrap();
    let row = starforged_db::remotes::by_repo_role(s.core.db(), repo_id, "import")
        .await
        .unwrap()
        .unwrap();
    assert!(!row.url.contains(SECRET), "{}", row.url);
    assert_eq!(
        audit_contains(&s, SECRET).await,
        0,
        "audit rows must not carry the password"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_never_appear_in_responses_pages_audit_or_errors() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let upstream = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let up_alice = upstream.user("alice").await;
    upstream.repo(&up_alice, "proj", Visibility::Private).await;
    let alice = s.user("alice").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let client = reqwest::Client::new();

    // A failing (wrong-password) pull sync: the stored error, every response,
    // the settings page, and the audit log must not carry the secret.
    let url = upstream.git_url("alice", "proj", None);
    let (status, text, v) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&rw),
        Some(&json!({
            "url": url,
            "auth": {"kind": "https", "username": "git", "password": SECRET},
            "interval_secs": 300,
        })),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(!text.contains(SECRET), "{text}");
    assert_eq!(v["has_credentials"], true);
    assert!(
        v.get("sealed_secret").is_none() && v.get("password").is_none(),
        "{v}"
    );

    let done = poll_pull_error(&s, &rw).await;
    let error = done["last_error"].as_str().unwrap_or("");
    assert!(
        !error.is_empty(),
        "the failed sync must record an error: {done}"
    );
    assert!(!error.contains(SECRET), "stored last_error leaks: {error}");
    let (_, text, _) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&rw),
        None,
    )
    .await;
    assert!(!text.contains(SECRET), "{text}");
    assert_eq!(
        audit_contains(&s, SECRET).await,
        0,
        "audit rows must not carry the secret"
    );

    let row = starforged_db::remotes::by_repo_role(s.core.db(), repo.id, "pull")
        .await
        .unwrap()
        .unwrap();
    assert!(!row.url.contains(SECRET));
    let sealed = row.sealed_secret.as_deref().unwrap_or("");
    assert!(
        !sealed.is_empty() && !sealed.contains(SECRET),
        "sealed value must not contain the secret"
    );

    // The web page shows only the stored marker / public key, never the secret.
    let (browser, _) = s.login("alice").await;
    let page = get_text(&browser, &s.url("/alice/proj/settings/mirrors")).await;
    assert!(page.contains("Pull mirror"), "{page}");
    assert!(
        page.contains("stored"),
        "page shows the credentials-stored marker"
    );
    assert!(!page.contains(SECRET), "page leaks the mirror password");

    // SSH: the public key is shown; the private key is never disclosed.
    let (status, text, v) = api(
        &client,
        "POST",
        &s.url("/api/v1/user/repos"),
        Some(&rw),
        Some(&json!({"name": "sshimp", "import": {"url": "ssh://git@127.0.0.1/x.git", "auth": {"kind": "ssh"}}})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    let public = v["ssh_public_key"].as_str().unwrap_or("").to_owned();
    assert!(
        public.starts_with("ssh-ed25519 "),
        "public key expected: {public}"
    );
    assert!(!text.contains("PRIVATE KEY"), "{text}");
    let (_, text, v) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/sshimp/import"),
        Some(&rw),
        None,
    )
    .await;
    assert!(!text.contains("PRIVATE KEY"), "{text}");
    assert!(
        v["ssh_public_key"]
            .as_str()
            .unwrap_or("")
            .starts_with("ssh-ed25519 ")
    );
    assert_eq!(audit_contains(&s, "PRIVATE KEY").await, 0);
}

#[tokio::test]
async fn debug_output_redacts_secrets() {
    let basic = RemoteCreds::Basic {
        username: "git".to_owned(),
        password: SECRET.to_owned(),
    };
    assert!(!format!("{basic:?}").contains(SECRET), "{basic:?}");
    let key = RemoteCreds::SshKey {
        private_key: "OPENSSH PRIVATE sweep-key".to_owned(),
    };
    assert!(!format!("{key:?}").contains("OPENSSH PRIVATE"));
    let auth = ImportAuth::Https {
        username: "git".to_owned(),
        password: SECRET.to_owned(),
    };
    assert!(!format!("{auth:?}").contains(SECRET), "{auth:?}");
    // The wrapper inputs derive `Debug` over the auth value: redaction is
    // transitive, so a stray Debug print of a request body cannot leak.
    let import = ImportInput {
        url: "https://git.example.com/x.git".to_owned(),
        auth: auth.clone(),
    };
    assert!(!format!("{import:?}").contains(SECRET));
    let pull = PullMirrorInput {
        url: "https://git.example.com/x.git".to_owned(),
        auth: auth.clone(),
        interval_secs: 300,
    };
    assert!(!format!("{pull:?}").contains(SECRET));
    let push = PushMirrorInput {
        url: "https://git.example.com/x.git".to_owned(),
        auth,
    };
    assert!(!format!("{push:?}").contains(SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_key_change_makes_stored_credentials_unreadable() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let alice = s.user("alice").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();
    let url = source_url(dir.path(), "src").await;
    let client = reqwest::Client::new();

    let (status, text, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&rw),
        Some(&json!({
            "url": url,
            "auth": {"kind": "https", "username": "git", "password": SECRET},
            "interval_secs": 300,
        })),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(!text.contains(SECRET));

    // Simulate losing the original secret_key: reseal the row under a
    // different key. The correct box opens its own seals; the other box
    // cannot open them.
    let own = s.core.config().credential_box.seal(b"payload");
    assert!(s.core.config().credential_box.open(&own).is_ok());
    let wrong_box = CredentialBox::new(b"a-different-secret-key-material");
    assert!(wrong_box.open(&own).is_err());
    let foreign_seal = wrong_box.seal(SECRET.as_bytes());
    sqlx::query("UPDATE repo_remotes SET sealed_secret = $1 WHERE repo_id = $2 AND role = 'pull'")
        .bind(&foreign_seal)
        .bind(repo.id)
        .execute(s.core.db().pool())
        .await
        .unwrap();

    // The next run fails closed with the clear error, never a panic.
    let done = poll_pull_error(&s, &rw).await;
    let error = done["last_error"].as_str().unwrap_or("");
    assert!(
        error.contains("credentials unreadable; re-enter them"),
        "unreadable credentials must fail with guidance: {error}"
    );
    assert!(done["last_success_at"].is_null(), "{done}");

    // Re-entering credentials (PUT with a fresh secret) recovers: the sync
    // succeeds against the file source.
    let (status, text, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&rw),
        Some(&json!({
            "url": url,
            "auth": {"kind": "https", "username": "git", "password": SECRET},
            "interval_secs": 300,
        })),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let client2 = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let out = api(
            &client2,
            "GET",
            &s.url("/api/v1/repos/alice/proj/mirror/pull"),
            Some(&rw),
            None,
        )
        .await;
        if out.2["last_success_at"].is_number() || Instant::now() > deadline {
            assert!(
                out.2["last_success_at"].is_number(),
                "re-entered credentials recover: {}",
                out.2
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The same holds for an import: a tampered seal fails the import state
    // with the same guidance instead of a panic.
    let (status, text, v) = api(
        &client,
        "POST",
        &s.url("/api/v1/user/repos"),
        Some(&rw),
        Some(&json!({
            "name": "tampered",
            "import": {"url": url, "auth": {"kind": "https", "username": "git", "password": SECRET}},
        })),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    assert!(!text.contains(SECRET));
    let repo_id = v["id"].as_i64().unwrap();
    sqlx::query(
        "UPDATE repo_remotes SET sealed_secret = $1 WHERE repo_id = $2 AND role = 'import'",
    )
    .bind(&foreign_seal)
    .bind(repo_id)
    .execute(s.core.db().pool())
    .await
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let out = api(
            &client,
            "GET",
            &s.url("/api/v1/repos/alice/tampered/import"),
            Some(&rw),
            None,
        )
        .await;
        if out.2["state"].as_str() == Some("failed") || Instant::now() > deadline {
            assert_eq!(out.2["state"], "failed", "{}", out.2);
            let error = out.2["last_error"].as_str().unwrap_or("");
            assert!(
                error.contains("credentials unreadable; re-enter them"),
                "{error}"
            );
            assert!(!error.contains(SECRET));
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_and_import_access_matrix() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let mallory = s.user("mallory").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();
    let alice_tok = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let bob_tok = s.token(&bob, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let carol_tok = s.token(&carol, &[Scope::RepoRead]).await;
    let mallory_tok = s
        .token(&mallory, &[Scope::RepoRead, Scope::RepoWrite])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let url = source_url(dir.path(), "src").await;
    let client = reqwest::Client::new();

    // Alice configures the mirrors; bob/carol/mallory exist as principals.
    let (status, text, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&alice_tok),
        Some(&json!({"url": url, "interval_secs": 300})),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let (status, text, push_before) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        Some(&alice_tok),
        Some(&json!({"url": url})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    let push_id = push_before["id"].as_i64().unwrap();
    let (status, text, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/user/repos"),
        Some(&alice_tok),
        Some(&json!({"name": "imp", "import": {"url": url}})),
    )
    .await;
    assert_eq!(status, 201, "{text}");

    s.core
        .set_collaborator(&alice, "alice", "imp", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "imp", "carol", Permission::Read)
        .await
        .unwrap();

    // Reads: readers (owner, write, read collaborators) see mirrors;
    // a non-reader gets 404; unauthenticated gets 401.
    for (label, tok) in [
        ("owner", Some(alice_tok.as_str())),
        ("write", Some(bob_tok.as_str())),
        ("read", Some(carol_tok.as_str())),
        ("outsider", Some(mallory_tok.as_str())),
        ("anonymous", None),
    ] {
        let expected = match label {
            "owner" | "write" | "read" => 200,
            _ => 404,
        };
        for path in [
            "/api/v1/repos/alice/proj/mirror/pull",
            "/api/v1/repos/alice/proj/mirror/push",
            "/api/v1/repos/alice/imp/import",
        ] {
            let (status, text, _) = api(&client, "GET", &s.url(path), tok, None).await;
            assert_eq!(status, expected, "{label} GET {path}: {text}");
        }
    }

    // Mutations are maintain+: write/read collaborators get 403, the
    // outsider 404, anonymous 401 — and nothing changes.
    let delete_push = format!("/api/v1/repos/alice/proj/mirror/push/{push_id}");
    let sync_push = format!("/api/v1/repos/alice/proj/mirror/push/{push_id}/sync");
    let mutations: Vec<(&str, &str, Option<Value>)> = vec![
        (
            "PUT",
            "/api/v1/repos/alice/proj/mirror/pull",
            Some(json!({"url": url, "interval_secs": 300})),
        ),
        ("POST", "/api/v1/repos/alice/proj/mirror/pull/sync", None),
        (
            "POST",
            "/api/v1/repos/alice/proj/mirror/pull/enabled",
            Some(json!({"enabled": false})),
        ),
        ("DELETE", "/api/v1/repos/alice/proj/mirror/pull", None),
        (
            "POST",
            "/api/v1/repos/alice/proj/mirror/push",
            Some(json!({"url": url})),
        ),
        ("DELETE", &delete_push, None),
        ("POST", &sync_push, None),
        ("POST", "/api/v1/repos/alice/imp/import/start", None),
        ("DELETE", "/api/v1/repos/alice/imp/import", None),
    ];
    for (method, path, body) in &mutations {
        for (label, tok, expected) in [
            ("write", Some(bob_tok.as_str()), 403),
            ("read", Some(carol_tok.as_str()), 403),
            ("outsider", Some(mallory_tok.as_str()), 404),
            ("anonymous", None, 401),
        ] {
            let (status, text, _) = api(&client, method, &s.url(path), tok, body.as_ref()).await;
            assert_eq!(status, expected, "{label} {method} {path}: {text}");
        }
    }
    // Alice's configuration survived the below-threshold attempts.
    let (_, _, still) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(still["url"], url);

    // Alice is maintain+, so every mutation works for her (in a safe order).
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/pull/sync"),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url(&format!(
            "/api/v1/repos/alice/proj/mirror/push/{push_id}/sync"
        )),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/pull/enabled"),
        Some(&alice_tok),
        Some(&json!({"enabled": true})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _) = api(
        &client,
        "DELETE",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = api(
        &client,
        "DELETE",
        &s.url(&format!("/api/v1/repos/alice/proj/mirror/push/{push_id}")),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/imp/import/start"),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _) = api(
        &client,
        "DELETE",
        &s.url("/api/v1/repos/alice/imp/import"),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(status, 204);

    // A push-mirror id from another repository is indistinguishable from a
    // missing one (404), even for the owner.
    let (status, text, other) = api(
        &client,
        "POST",
        &s.url("/api/v1/user/repos"),
        Some(&alice_tok),
        Some(&json!({"name": "other"})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    assert!(other["id"].is_number());
    let (status, text, added) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/other/mirror/push"),
        Some(&alice_tok),
        Some(&json!({"url": url})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    let other_id = added["id"].as_i64().unwrap();
    let (status, _, _) = api(
        &client,
        "DELETE",
        &s.url(&format!("/api/v1/repos/alice/proj/mirror/push/{other_id}")),
        Some(&alice_tok),
        None,
    )
    .await;
    assert_eq!(status, 404, "cross-repository push-mirror ids must be 404");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archived_repos_refuse_remote_mutations_but_stay_readable() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let alice = s.user("alice").await;
    let carol = s.user("carol").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let ro = s.token(&carol, &[Scope::RepoRead]).await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let url = source_url(dir.path(), "src").await;
    let client = reqwest::Client::new();
    let (status, text, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&rw),
        Some(&json!({"url": url, "interval_secs": 300})),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let (status, text, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        Some(&rw),
        Some(&json!({"url": url})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    let (status, text, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/user/repos"),
        Some(&rw),
        Some(&json!({"name": "imp", "import": {"url": url}})),
    )
    .await;
    assert_eq!(status, 201, "{text}");

    s.core
        .set_collaborator(&alice, "alice", "imp", "carol", Permission::Read)
        .await
        .unwrap();

    s.core.archive_repo(&alice, "alice", "proj").await.unwrap();
    s.core.archive_repo(&alice, "alice", "imp").await.unwrap();

    for (method, path, body) in [
        (
            "PUT",
            "/api/v1/repos/alice/proj/mirror/pull",
            Some(json!({"url": url, "interval_secs": 300})),
        ),
        (
            "POST",
            "/api/v1/repos/alice/proj/mirror/push",
            Some(json!({"url": url})),
        ),
        ("POST", "/api/v1/repos/alice/imp/import/start", None),
    ] {
        let (status, text, _) = api(&client, method, &s.url(path), Some(&rw), body.as_ref()).await;
        assert_eq!(status, 422, "archived {method} {path}: {text}");
    }
    // Reads still work on an archived repository, for owner and readers.
    for tok in [Some(rw.as_str()), Some(ro.as_str())] {
        for path in [
            "/api/v1/repos/alice/proj/mirror/pull",
            "/api/v1/repos/alice/proj/mirror/push",
            "/api/v1/repos/alice/imp/import",
        ] {
            let (status, text, _) = api(&client, "GET", &s.url(path), tok, None).await;
            assert_eq!(status, 200, "archived GET {path}: {text}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_forms_enforce_csrf_and_policy() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let alice = s.user("alice").await;
    let _bob = s.user("bob").await;
    let _mallory = s.user("mallory").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let dir = tempfile::tempdir().unwrap();
    let url = source_url(dir.path(), "src").await;
    let client = reqwest::Client::new();
    let (status, text, push) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        Some(&rw),
        Some(&json!({"url": url})),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    let push_id = push["id"].as_i64().unwrap();
    let (status, text, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/user/repos"),
        Some(&rw),
        Some(&json!({"name": "imp", "import": {"url": url}})),
    )
    .await;
    assert_eq!(status, 201, "{text}");

    let (browser, csrf) = s.login("alice").await;
    // Every state-changing form refuses a wrong CSRF token with 403 and a
    // missing `_csrf` field with 422.
    let forms: Vec<(String, Vec<(&str, String)>)> = vec![
        (
            s.url("/new"),
            vec![
                ("name", "x".to_owned()),
                ("visibility", "private".to_owned()),
            ],
        ),
        (
            s.url("/alice/proj/settings/mirrors"),
            vec![("url", url.clone()), ("interval_secs", "300".to_owned())],
        ),
        (s.url("/alice/proj/settings/mirrors/sync"), vec![]),
        (s.url("/alice/proj/settings/mirrors/enabled"), vec![]),
        (s.url("/alice/proj/settings/mirrors/delete"), vec![]),
        (
            s.url("/alice/proj/settings/mirrors/push"),
            vec![("url", url.clone())],
        ),
        (
            s.url(&format!("/alice/proj/settings/mirrors/push/{push_id}/sync")),
            vec![],
        ),
        (
            s.url(&format!(
                "/alice/proj/settings/mirrors/push/{push_id}/delete"
            )),
            vec![],
        ),
        (s.url("/alice/imp/import/start"), vec![]),
        (s.url("/alice/imp/import/delete"), vec![]),
    ];
    for (target, extra) in &forms {
        let mut wrong = extra.clone();
        wrong.push(("_csrf", "wrong-csrf".to_owned()));
        let denied = browser
            .post(target.as_str())
            .form(&wrong)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 403, "wrong CSRF on {target}");
        let missing = browser
            .post(target.as_str())
            .form(extra)
            .send()
            .await
            .unwrap();
        assert!(
            matches!(missing.status().as_u16(), 403 | 422),
            "missing CSRF on {target}: {}",
            missing.status()
        );
    }

    // The new-repository form applies the URL policy (422) and, on the
    // error re-render, never echoes a password pasted in the URL.
    let refused = browser
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "blocked"),
            ("visibility", "private"),
            ("import_url", "ext::sh -c 'id'"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422, "ext:: import URL must be refused");
    let (status, _, _) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/blocked"),
        Some(&rw),
        None,
    )
    .await;
    assert_eq!(status, 404, "refused import created a repository");

    let refused = browser
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "blocked2"),
            ("visibility", "private"),
            (
                "import_url",
                "https://git:sweep-secret-token-001x@169.254.169.254/x.git",
            ),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        422,
        "metadata-host import URL must be refused"
    );
    let refused_text = refused.text().await.unwrap();
    assert!(
        !refused_text.contains(SECRET),
        "error re-render must not echo the URL password"
    );

    // The mirrors form applies the policy too: a refused URL re-renders 422.
    let refused = browser
        .post(s.url("/alice/proj/settings/mirrors"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("url", "https://[::ffff:10.0.0.1]/x.git"),
            ("interval_secs", "300"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        422,
        "mirrors form must apply the URL policy"
    );

    // The mirrors page shows the policy outcome and never a secret.
    // (Configure one pull mirror with credentials first.)
    let (status, text, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        Some(&rw),
        Some(&json!({
            "url": url,
            "auth": {"kind": "https", "username": "git", "password": SECRET},
            "interval_secs": 300,
        })),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(!text.contains(SECRET));
    let page = get_text(&browser, &s.url("/alice/proj/settings/mirrors")).await;
    assert!(page.contains("Pull mirror"), "{page}");
    assert!(!page.contains(SECRET), "page leaks the mirror password");

    // Access on the mirrors page: write collaborator 403, non-reader 404.
    let (bob_browser, _) = s.login("bob").await;
    let r = bob_browser
        .get(s.url("/alice/proj/settings/mirrors"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "below maintain gets 403");
    let (mallory_browser, _) = s.login("mallory").await;
    let r = mallory_browser
        .get(s.url("/alice/proj/settings/mirrors"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "non-reader gets 404");
}
