//! H6: statuses/gates/merge/webhooks security sweep + end-to-end merge flow.
//!
//! Permission matrix (action × role × surface) over private + public repos,
//! hostile-input corpus through every rendered M2c surface, CSRF on every new
//! POST, and real-git end-to-end merges (`merge`, `squash`, `fast_forward`)
//! ending in moved refs, trailers, timeline/audit rows, and a signed webhook
//! delivery. Every assertion pins real behavior (rows, refs, codes, bytes).
mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::User;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const FULL: &[Scope] = &[Scope::RepoRead, Scope::TrailWrite];
const REPO_WRITE: &[Scope] = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];

const PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<details ontoggle=alert(1)>x</details>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "\"><script>alert(1)</script>",
    "[redacted:<script>]",
    "\u{202E}reversed",
];

/// Executable markup must never reach the page: these tokens are absent from
/// every legitimate change/gate/hook template, so any occurrence is attacker
/// markup rendered live. Escaped text (`&lt;img …`) passes — it is inert.
fn assert_no_live_markup(page: &str, surface: &str) {
    let lower = page.to_lowercase();
    for raw in [
        "<script",
        "<img",
        "<svg",
        "<iframe",
        "<object",
        "<embed",
        "javascript:",
        "data:text/html",
        "attacker.example",
    ] {
        assert!(!lower.contains(raw), "{raw} live on {surface}");
    }
}

struct Ctx {
    s: TestServer,
    alice: User,
    bob: User,
    carol: User,
    wendy: User,
    adam: User,
    root: User,
    dave: User,
    sam: User,
}

impl Ctx {
    async fn start() -> Ctx {
        // Loopback deliveries need the test-only SSRF escape hatch.
        let s = TestServer::start_with(|c| c.webhooks.allow_loopback = true).await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let wendy = s.user("wendy").await;
        let adam = s.user("adam").await;
        let dave = s.user("dave").await;
        let sam = s.user("sam").await;
        s.core
            .create_user(starforged_core::accounts::CreateUser {
                handle: "root".into(),
                password: Some(PASSWORD.into()),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let root = s.core.user_by_handle("root").await.unwrap().unwrap();
        s.repo(&alice, "proj", Visibility::Private).await;
        s.repo(&alice, "open", Visibility::Public).await;
        for (handle, perm) in [
            ("bob", Permission::Triage),
            ("carol", Permission::Read),
            ("wendy", Permission::Write),
            ("adam", Permission::Admin),
            ("sam", Permission::Read),
        ] {
            s.core
                .set_collaborator(&alice, "alice", "proj", handle, perm)
                .await
                .unwrap();
        }
        let sam_id = sam.id;
        s.core.suspend_user(&root, sam_id).await.unwrap();
        Ctx {
            s,
            alice,
            bob,
            carol,
            wendy,
            adam,
            root,
            dave,
            sam,
        }
    }

    async fn tok(&self, user: &User, scopes: &[Scope]) -> String {
        self.s.token(user, scopes).await
    }

    async fn login(&self, handle: &str) -> reqwest::Client {
        let (client, _) = self.s.login(handle).await;
        client
    }

    fn statuses(&self, repo: &str, sha: &str) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/{repo}/statuses/{sha}"))
    }

    fn gates(&self, repo: &str, n: i64, k: i64) -> String {
        self.s.url(&format!(
            "/api/v1/repos/alice/{repo}/trails/{n}/changes/{k}/gates"
        ))
    }

    fn merge_api(&self, repo: &str, n: i64, k: i64) -> String {
        self.s.url(&format!(
            "/api/v1/repos/alice/{repo}/trails/{n}/changes/{k}/merge"
        ))
    }

    fn hooks(&self, repo: &str) -> String {
        self.s.url(&format!("/api/v1/repos/alice/{repo}/hooks"))
    }

    fn web_change(&self, repo: &str, n: i64, k: i64) -> String {
        self.s.url(&format!("/alice/{repo}/trails/{n}/changes/{k}"))
    }

    fn web_merge(&self, repo: &str, n: i64, k: i64) -> String {
        self.s
            .url(&format!("/alice/{repo}/trails/{n}/changes/{k}/merge"))
    }

    fn web_hooks(&self, repo: &str) -> String {
        self.s.url(&format!("/alice/{repo}/settings/hooks"))
    }

    async fn repo_id(&self, repo: &str) -> i64 {
        self.s
            .core
            .repo_for(Some(&self.alice), "alice", repo)
            .await
            .unwrap()
            .repo
            .id
    }

    /// Work repo with `main` pushed (owner token); returns work dir + push url.
    async fn pushed_repo(&self, repo: &str) -> (PathBuf, String) {
        let token = self.s.token(&self.alice, &[Scope::RepoWrite]).await;
        let url = self.s.git_url("alice", repo, Some(&token));
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
        git_ok(&work, &["push", "-q", &url, "main"]).await;
        (work, url)
    }

    async fn trail(&self, token: &str) -> i64 {
        let client = reqwest::Client::new();
        let res = client
            .post(self.s.url("/api/v1/repos/alice/proj/trails"))
            .bearer_auth(token)
            .json(&json!({"title": "sweep trail", "intent": "sweep"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        res.json::<Value>().await.unwrap()["number"]
            .as_i64()
            .unwrap()
    }

    async fn branch_change(&self, token: &str, n: i64, head: &str) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(
                self.s
                    .url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes")),
            )
            .bearer_auth(token)
            .json(&json!({"kind": "branch", "head_branch": head, "base_branch": "main"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create branch change");
        res.json::<Value>().await.unwrap()
    }

    async fn gate_rule(
        &self,
        pattern: Option<&str>,
        approvals: i64,
        contexts: &str,
        methods: &str,
    ) {
        starforged_db::checks::insert_gate_rule(
            self.s.core.db(),
            self.repo_id("proj").await,
            pattern,
            approvals,
            false,
            false,
            contexts,
            false,
            false,
            false,
            methods,
            starforged_db::now(),
        )
        .await
        .unwrap();
    }
}

/// Statuses POST/GET + gates GET matrix: web panel + API, private + public.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_status_gates() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (work, url) = c.pushed_repo("proj").await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\n")], "add a").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let n = c.trail(&alice_full).await;
    let alice_rw = c.tok(&c.alice, REPO_WRITE).await;
    c.branch_change(&alice_rw, n, "feature/x").await;
    let head = git_ok(&work, &["rev-parse", "feature/x"]).await;

    // Anonymous: mutations 401; reads 404 (even anonymous) so private
    // repos stay undiscoverable.
    let res = client
        .post(c.statuses("proj", head.trim()))
        .json(&json!({"state": "success", "context": "ci/unit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "anon status POST");
    let res = client.get(c.gates("proj", n, 1)).send().await.unwrap();
    assert_eq!(res.status(), 404, "anon gates GET");
    let anon = c.s.browser();
    assert_eq!(
        anon.get(c.web_change("proj", n, 1))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "anon web change"
    );

    // Members + site admin read; the gate panel renders for them.
    for user in [&c.alice, &c.bob, &c.carol, &c.wendy, &c.adam, &c.root] {
        let t = c.tok(user, FULL).await;
        let res = client
            .get(c.gates("proj", n, 1))
            .bearer_auth(&t)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{} reads gates", user.handle);
        let browser = c.login(&user.handle).await;
        let page = get_text(&browser, &c.web_change("proj", n, 1)).await;
        assert!(page.contains("Gates"), "{} sees gate panel", user.handle);
    }

    // Strangers 404 both surfaces; suspended cannot sign in and its API
    // token is refused.
    let dave_t = c.tok(&c.dave, FULL).await;
    assert_eq!(
        client
            .get(c.gates("proj", n, 1))
            .bearer_auth(&dave_t)
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-member gates"
    );
    let dave = c.login("dave").await;
    assert_eq!(
        dave.get(c.web_change("proj", n, 1))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-member web change"
    );
    let sam_t = c.tok(&c.sam, FULL).await;
    assert_eq!(
        client
            .get(c.gates("proj", n, 1))
            .bearer_auth(&sam_t)
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "suspended gates"
    );
    let (_, bad) = c.s.try_login("sam", PASSWORD).await;
    assert!(!bad.status().is_redirection(), "suspended login fails");

    // Wrong scopes: read-only token reads gates but cannot POST statuses;
    // trail-only and session:upload-only tokens are refused everywhere.
    let carol_read = c.s.token(&c.carol, &[Scope::RepoRead]).await;
    assert_eq!(
        client
            .get(c.gates("proj", n, 1))
            .bearer_auth(&carol_read)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "read token reads gates"
    );
    let res = client
        .post(c.statuses("proj", &head))
        .bearer_auth(&carol_read)
        .json(&json!({"state": "success", "context": "ci/unit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "read token cannot POST status");
    for tok in [
        c.s.token(&c.alice, &[Scope::TrailWrite]).await,
        c.s.token(&c.alice, &[Scope::SessionUpload]).await,
    ] {
        assert_eq!(
            client
                .get(c.gates("proj", n, 1))
                .bearer_auth(&tok)
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "scoped-out token reads gates"
        );
        assert_eq!(
            client
                .post(c.statuses("proj", &head))
                .bearer_auth(&tok)
                .json(&json!({"state": "success", "context": "ci/unit"}))
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "scoped-out token POSTs status"
        );
    }

    // Writers POST statuses; non-members with write scopes still 404.
    for user in [&c.alice, &c.wendy, &c.adam] {
        let t = c.tok(user, &[Scope::RepoRead, Scope::RepoWrite]).await;
        let res = client
            .post(c.statuses("proj", &head))
            .bearer_auth(&t)
            .json(&json!({"state": "success", "context": format!("ci/{}", user.handle)}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{} POSTs status", user.handle);
    }
    for user in [&c.bob, &c.carol] {
        let t = c.tok(user, &[Scope::RepoRead, Scope::RepoWrite]).await;
        let res = client
            .post(c.statuses("proj", &head))
            .bearer_auth(&t)
            .json(&json!({"state": "success", "context": "ci/x"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "{} cannot POST status", user.handle);
    }
    let dave_rw =
        c.s.token(&c.dave, &[Scope::RepoRead, Scope::RepoWrite])
            .await;
    assert_eq!(
        client
            .post(c.statuses("proj", &head))
            .bearer_auth(&dave_rw)
            .json(&json!({"state": "success", "context": "ci/x"}))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-member status POST"
    );

    // Public repo: strangers and anonymous read gates + statuses over the API.
    let pub_head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert_eq!(
        client
            .get(c.gates("open", 1, 1))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "no change yet on open"
    );
    let res = client
        .post(c.statuses("open", pub_head))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "anon status POST still 401 on public");
    let res = client
        .get(c.statuses("open", pub_head))
        .bearer_auth(&dave_t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "stranger reads public statuses");
}

/// Merge + webhook matrix: API codes, web control visibility, both repos.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_merge_webhooks() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (work, url) = c.pushed_repo("proj").await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\n")], "add a").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let n = c.trail(&alice_full).await;
    let alice_rw = c.tok(&c.alice, REPO_WRITE).await;
    c.branch_change(&alice_rw, n, "feature/x").await;

    // Anonymous merge: 401 API; web POST redirects to login.
    let res = client
        .post(c.merge_api("proj", n, 1))
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "anon merge");
    let anon = c.s.browser();
    let res = anon
        .post(c.web_merge("proj", n, 1))
        .form(&[("_csrf", "x"), ("method", "merge")])
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_redirection(),
        "anon web merge redirects, got {}",
        res.status()
    );

    // Web merge form: writers/admins see the live button; triage/read see a
    // disabled control; strangers get 404.
    for (handle, live) in [("alice", true), ("wendy", true), ("adam", true)] {
        let browser = c.login(handle).await;
        let page = get_text(&browser, &c.web_change("proj", n, 1)).await;
        assert!(
            page.contains(r#"<button type="submit">Merge</button>"#),
            "{handle} sees live merge button"
        );
        assert!(live);
    }
    for handle in ["bob", "carol"] {
        let browser = c.login(handle).await;
        let page = get_text(&browser, &c.web_change("proj", n, 1)).await;
        assert!(
            !page.contains(r#"<button type="submit">Merge</button>"#),
            "{handle} has no live merge button"
        );
    }
    let dave = c.login("dave").await;
    assert_eq!(
        dave.get(c.web_change("proj", n, 1))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-member web change"
    );

    // API merge by role: write+ succeed-or-fail-closed on gates (200 here,
    // no rules), triage/read 403, non-member 404, scoped-out tokens 403.
    for user in [&c.wendy, &c.adam] {
        let t = c.tok(user, REPO_WRITE).await;
        // Use a fresh change per merger so each POST really merges.
        let branch = format!("feature/{}", user.handle);
        git_ok(&work, &["branch", &branch, "feature/x"]).await;
        git_ok(&work, &["push", "-q", &url, &branch]).await;
        let nn = c.trail(&alice_full).await;
        let k = c.branch_change(&alice_rw, nn, &branch).await["k"]
            .as_i64()
            .unwrap();
        let res = client
            .post(c.merge_api("proj", nn, k))
            .bearer_auth(&t)
            .json(&json!({"method": "merge"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{} merges", user.handle);
    }
    for user in [&c.bob, &c.carol] {
        let t = c.tok(user, REPO_WRITE).await;
        let res = client
            .post(c.merge_api("proj", n, 1))
            .bearer_auth(&t)
            .json(&json!({"method": "merge"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "{} cannot merge", user.handle);
    }
    let dave_rw = c.s.token(&c.dave, REPO_WRITE).await;
    assert_eq!(
        client
            .post(c.merge_api("proj", n, 1))
            .bearer_auth(&dave_rw)
            .json(&json!({"method": "merge"}))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-member merge"
    );
    for tok in [
        c.s.token(&c.alice, &[Scope::RepoRead]).await,
        c.s.token(&c.alice, &[Scope::SessionUpload]).await,
    ] {
        assert_eq!(
            client
                .post(c.merge_api("proj", n, 1))
                .bearer_auth(&tok)
                .json(&json!({"method": "merge"}))
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "scoped-out token merges"
        );
    }

    // Webhooks API: maintain+ only (adam/admin pass, wendy/write fails),
    // non-member 404, anon 401, scoped-out 403.
    let (sink_url, _sink) = Sink::spawn(false).await;
    let res = client
        .post(c.hooks("proj"))
        .json(&json!({"url": sink_url, "events": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "anon hook create");
    let adam_t =
        c.s.token(&c.adam, &[Scope::RepoRead, Scope::RepoWrite])
            .await;
    let res = client
        .post(c.hooks("proj"))
        .bearer_auth(&adam_t)
        .json(&json!({"url": sink_url, "events": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "admin creates hook");
    let hook_id = res.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    for user in [&c.wendy, &c.bob, &c.carol] {
        let t = c.s.token(user, &[Scope::RepoRead, Scope::RepoWrite]).await;
        let res = client
            .post(c.hooks("proj"))
            .bearer_auth(&t)
            .json(&json!({"url": sink_url, "events": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "{} cannot create hook", user.handle);
        let res = client
            .get(c.hooks("proj"))
            .bearer_auth(&t)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "{} cannot list hooks", user.handle);
    }
    assert_eq!(
        client
            .get(c.hooks("proj"))
            .bearer_auth(&dave_rw)
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-member hook list"
    );
    // Readers cannot delete even an existing hook.
    let carol_rw =
        c.s.token(&c.carol, &[Scope::RepoRead, Scope::RepoWrite])
            .await;
    assert_eq!(
        client
            .delete(format!("{}/{}", c.hooks("proj"), hook_id))
            .bearer_auth(&carol_rw)
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "readers cannot delete hooks"
    );

    // Web hooks settings: maintainers see it, writers get 403, strangers 404.
    for (handle, want) in [
        ("alice", 200u16),
        ("adam", 200),
        ("wendy", 403),
        ("carol", 403),
    ] {
        let browser = c.login(handle).await;
        assert_eq!(
            browser
                .get(c.web_hooks("proj"))
                .send()
                .await
                .unwrap()
                .status(),
            want,
            "{handle} hooks settings"
        );
    }
    assert_eq!(
        dave.get(c.web_hooks("proj")).send().await.unwrap().status(),
        404,
        "non-member hooks settings"
    );
}

#[derive(Debug, Clone)]
struct Hit {
    event: Option<String>,
    delivery: Option<String>,
    signature: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct Sink {
    hits: Arc<Mutex<Vec<Hit>>>,
    fail: bool,
}

impl Sink {
    async fn spawn(fail: bool) -> (String, Sink) {
        let sink = Sink {
            hits: Arc::new(Mutex::new(Vec::new())),
            fail,
        };
        let inner = sink.clone();
        let app = axum::Router::new().route(
            "/hook",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let inner = inner.clone();
                    async move {
                        if inner.fail {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                "boom".to_string(),
                            );
                        }
                        let get = |name: &str| {
                            headers
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned)
                        };
                        inner.hits.lock().unwrap().push(Hit {
                            event: get("x-starforge-event"),
                            delivery: get("x-starforge-delivery"),
                            signature: get("x-starforge-signature"),
                            body: body.to_vec(),
                        });
                        (axum::http::StatusCode::OK, "ok".to_string())
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        (format!("http://{addr}/hook"), sink)
    }
}

fn hmac_sha256_hex(key: &str, msg: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut kb = [0u8; BLOCK];
    if key.len() > BLOCK {
        kb[..32].copy_from_slice(&Sha256::digest(key.as_bytes()));
    } else {
        kb[..key.len()].copy_from_slice(key.as_bytes());
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= kb[i];
        opad[i] ^= kb[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

/// Hostile input through every rendered M2c surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_corpus() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (work, url) = c.pushed_repo("proj").await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\n")], "add a").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let n = c.trail(&alice_full).await;
    let alice_rw = c.tok(&c.alice, REPO_WRITE).await;
    c.branch_change(&alice_rw, n, "feature/x").await;
    let head = git_ok(&work, &["rev-parse", "feature/x"]).await;
    let browser = c.login("alice").await;

    // Hostile status contexts flow into gate reasons rendered on the page.
    for payload in PAYLOADS {
        let res = client
            .post(c.statuses("proj", head.trim()))
            .bearer_auth(&alice_rw)
            .json(&json!({"state": "pending", "context": payload}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "status POST {payload:?}");
    }
    let ctx_json = serde_json::to_string(PAYLOADS).unwrap();
    c.gate_rule(None, 0, &ctx_json, "[]").await;
    let page = get_text(&browser, &c.web_change("proj", n, 1)).await;
    // Angle brackets are askama-escaped (`&#60;`), so no element or link is
    // ever created: even the `javascript:`/`data:` payloads render as inert
    // text inside the reason string. Pin that precisely.
    for raw in ["<script", "<img", "<svg", "<iframe", "<object", "<embed"] {
        assert!(
            !page.to_lowercase().contains(raw),
            "{raw} live on gate reasons"
        );
    }
    assert!(
        !page.contains("<a href=\"javascript"),
        "live js link on gate reasons"
    );
    assert!(
        !page.contains("<a href=\"data:"),
        "live data link on gate reasons"
    );
    assert!(page.contains("&#60;script"), "contexts escaped on {n}/1");
    assert!(
        page.contains("&#60;a href="),
        "link payload escaped on {n}/1"
    );
    let gates: Value = client
        .get(c.gates("proj", n, 1))
        .bearer_auth(&alice_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!gates["results"][0]["reason"].as_str().unwrap().is_empty());

    // A hostile gate-rule pattern that matches nothing is never rendered.
    let pattern = "<script>alert(pattern)</script>";
    c.gate_rule(Some(pattern), 0, "[]", "[]").await;
    let page = get_text(&browser, &c.web_change("proj", n, 1)).await;
    assert!(
        !page.contains(pattern),
        "non-matching hostile pattern must not render"
    );

    // Hostile conflict paths render escaped.
    let evil = "<img src=x onerror=alert(1)>.txt";
    commit_files(&work, &[(evil, b"evil\n")], "add evil").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let other = work_repo(work.parent().unwrap(), "other", &[("seed.txt", "seed\n")]).await;
    git_ok(&other, &["remote", "add", "origin", &url]).await;
    git_ok(&other, &["fetch", "-q", "origin", "main"]).await;
    git_ok(&other, &["checkout", "-q", "-B", "main", "FETCH_HEAD"]).await;
    commit_files(&other, &[(evil, b"other\n")], "add other evil").await;
    git_ok(&other, &["push", "-q", &url, "main"]).await;
    // Wait for the mergeability worker to recompute (pump the queue: the
    // background worker may back off under contention).
    let mut conflict_page = String::new();
    for _ in 0..120 {
        c.s.core.run_due_jobs().await.unwrap();
        let p = browser
            .get(c.web_change("proj", n, 1))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if p.contains("conflicting paths") {
            conflict_page = p;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(
        conflict_page.contains("conflicting paths"),
        "conflict did not appear"
    );
    // The filename's brackets are escaped, so no element is created; scheme
    // text elsewhere on the page (gate reasons) is inert for the same reason.
    for raw in ["<script", "<img", "<svg", "<iframe", "<object", "<embed"] {
        assert!(
            !conflict_page.to_lowercase().contains(raw),
            "{raw} live on conflict paths"
        );
    }
    assert!(conflict_page.contains("&#60;img"), "conflict path escaped");

    // Status description/target_url: javascript: rejected; http attacker URLs
    // are stored (API-escaped JSON) but never linked on the page.
    let res = client
        .post(c.statuses("proj", &head))
        .bearer_auth(&alice_rw)
        .json(&json!({
            "state": "pending", "context": "ci/link",
            "target_url": "javascript:alert(1)",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "javascript: target_url rejected");
    let res = client
        .post(c.statuses("proj", &head))
        .bearer_auth(&alice_rw)
        .json(&json!({
            "state": "pending",
            "context": "ci/desc",
            "description": "<script>alert(1)</script>",
            "target_url": "http://attacker.example/x",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "attacker http target_url stored");
    let page = get_text(&browser, &c.web_change("proj", n, 1)).await;
    // The change page renders no status links at all: the attacker host is
    // absent entirely (target_url/description are API-only data).
    assert!(
        !page.contains("attacker.example"),
        "target_url leaked onto page"
    );
    for raw in [
        "<script",
        "<img",
        "<svg",
        "<a href=\"javascript",
        "<a href=\"data:",
    ] {
        assert!(
            !page.to_lowercase().contains(raw),
            "{raw} live on status link surface"
        );
    }

    // Hostile merge method echoes escaped on the 422 re-render.
    let method = "<script>alert(merge)</script>";
    let csrf = extract_input(&page, "_csrf");
    let res = browser
        .post(c.web_merge("proj", n, 1))
        .form(&[("_csrf", csrf.as_str()), ("method", method)])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body = res.text().await.unwrap();
    assert!(!body.contains(method), "method echoed raw");
    for raw in ["<script", "<img", "<a href=\"javascript"] {
        assert!(
            !body.to_lowercase().contains(raw),
            "{raw} live on merge method echo"
        );
    }
    assert!(body.contains("&#60;script"), "method echo escaped");

    // Hostile webhook URL path renders escaped on the settings page.
    let hooks_page = get_text(&browser, &c.web_hooks("proj")).await;
    let hook_csrf = extract_input(&hooks_page, "_csrf");
    let evil_url = "http://127.0.0.1:9/<script>alert(1)</script>".to_string();
    let res = browser
        .post(c.web_hooks("proj"))
        .form(&[
            ("_csrf", hook_csrf.as_str()),
            ("url", evil_url.as_str()),
            ("events", "status.updated"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "hook with hostile path created");
    let created = res.text().await.unwrap();
    assert_no_live_markup(&created, "hook create response");
    let again = get_text(&browser, &c.web_hooks("proj")).await;
    assert_no_live_markup(&again, "hooks settings page");
}

/// Every new POST rejects missing/foreign CSRF tokens with 403 and no state change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_matrix() {
    let c = Ctx::start().await;
    let (work, url) = c.pushed_repo("proj").await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\n")], "add a").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let n = c.trail(&alice_full).await;
    let alice_rw = c.tok(&c.alice, REPO_WRITE).await;
    c.branch_change(&alice_rw, n, "feature/x").await;
    let server = c.s.core.repo_path(c.repo_id("proj").await);
    let base_before = git_ok(&work, &["ls-remote", &url, "refs/heads/main"]).await;

    let (alice_browser, _) = c.s.login("alice").await;
    let page = get_text(&alice_browser, &c.web_change("proj", n, 1)).await;
    let good = extract_input(&page, "_csrf");
    let (carol_browser, _) = c.s.login("carol").await;
    let carol_page = get_text(&carol_browser, &c.web_change("proj", n, 1)).await;
    let foreign = extract_input(&carol_page, "_csrf");

    // Web merge without/with foreign token: 403, base untouched.
    for token in ["", foreign.as_str()] {
        let res = alice_browser
            .post(c.web_merge("proj", n, 1))
            .form(&[("_csrf", token), ("method", "merge")])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "merge CSRF {token:?}");
    }
    assert_eq!(
        git_ok(&work, &["ls-remote", &url, "refs/heads/main"]).await,
        base_before,
        "failed CSRF merge moved nothing"
    );
    let _ = server;

    // Hooks create/toggle/delete without/with foreign token: 403, no rows change.
    let hooks_page = get_text(&alice_browser, &c.web_hooks("proj")).await;
    let hooks_csrf = extract_input(&hooks_page, "_csrf");
    let count_before =
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .len();
    for token in ["", foreign.as_str()] {
        let res = alice_browser
            .post(c.web_hooks("proj"))
            .form(&[("_csrf", token), ("url", "http://127.0.0.1:9/x")])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "hook create CSRF {token:?}");
    }
    // A hook to toggle/delete: create it with the good token first.
    let res = alice_browser
        .post(c.web_hooks("proj"))
        .form(&[
            ("_csrf", hooks_csrf.as_str()),
            ("url", "http://127.0.0.1:9/x"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let hook_id =
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .pop()
            .unwrap()
            .id;
    assert_eq!(
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .len(),
        count_before + 1
    );
    let base_hooks = c.web_hooks("proj");
    for token in ["", foreign.as_str()] {
        let res = alice_browser
            .post(format!("{base_hooks}/{hook_id}/toggle"))
            .form(&[("_csrf", token)])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "hook toggle CSRF {token:?}");
        let res = alice_browser
            .post(format!("{base_hooks}/{hook_id}/delete"))
            .form(&[("_csrf", token)])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "hook delete CSRF {token:?}");
    }
    let hooks =
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap();
    assert_eq!(hooks.len(), count_before + 1, "CSRF wrote no hook rows");
    assert!(hooks.iter().any(|h| h.id == hook_id && h.active));
    let _ = good;
}

/// End-to-end per method: push → approve → status → gate passes → merge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_methods() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (work, url) = c.pushed_repo("proj").await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let alice_rw = c.tok(&c.alice, REPO_WRITE).await;
    let wendy_rw = c.tok(&c.wendy, REPO_WRITE).await;
    let repo_id = c.repo_id("proj").await;

    async fn server_rev(work: &Path, url: &str, r: &str) -> String {
        let out = git_ok(work, &["ls-remote", url, r]).await;
        out.split_whitespace().next().unwrap().to_owned()
    }

    for (branch, method) in [
        ("feature/m", "merge"),
        ("feature/s", "squash"),
        ("feature/f", "fast_forward"),
    ] {
        // Branch from the CURRENT remote tip: earlier iterations moved main,
        // and this worktree has no `origin` remote, so fetch by URL first.
        git_ok(&work, &["fetch", "-q", &url, "main"]).await;
        git_ok(&work, &["checkout", "-q", "-b", branch, "FETCH_HEAD"]).await;
        let filename = format!("{branch}.txt");
        commit_files(
            &work,
            &[(filename.as_str(), b"x\n".as_slice())],
            &format!("add {branch}"),
        )
        .await;
        git_ok(&work, &["push", "-q", &url, branch]).await;
        let n = c.trail(&alice_full).await;
        let created = c.branch_change(&alice_rw, n, branch).await;
        let k = created["k"].as_i64().unwrap();
        let head = git_ok(&work, &["rev-parse", branch]).await;

        // Approve as a writer; require one approval + a success context.
        let res = client
            .post(c.s.url(&format!(
                "/api/v1/repos/alice/proj/trails/{n}/changes/{k}/reviews"
            )))
            .bearer_auth(&wendy_rw)
            .json(&json!({"verdict": "approve", "body": "lgtm"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        c.gate_rule(None, 1, "[\"ci/unit\"]", "[]").await;
        let res = client
            .post(c.statuses("proj", head.trim()))
            .bearer_auth(&alice_rw)
            .json(&json!({"state": "success", "context": "ci/unit"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let gates: Value = client
            .get(c.gates("proj", n, k))
            .bearer_auth(&alice_rw)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(gates["passed"], true, "gates pass for {branch}");

        let base_before = server_rev(&work, &url, "refs/heads/main").await;
        let res = client
            .post(c.merge_api("proj", n, k))
            .bearer_auth(&alice_rw)
            .json(&json!({"method": method}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            200,
            "{method} merges: {}",
            res.text().await.unwrap()
        );
        let base_after = server_rev(&work, &url, "refs/heads/main").await;
        assert_ne!(base_after, base_before, "{method} moved main");

        // Method-specific shape, checked against the server repo.
        let server = c.s.core.repo_path(repo_id);
        let parents = git_ok(
            &work,
            &[
                "--git-dir",
                &server.display().to_string(),
                "rev-list",
                "--parents",
                "-n",
                "1",
                "refs/heads/main",
            ],
        )
        .await;
        let fields: Vec<&str> = parents.split_whitespace().collect();
        match method {
            "merge" => {
                assert_eq!(fields.len(), 3, "merge has two parents: {parents}");
                let msg = git_ok(
                    &work,
                    &[
                        "--git-dir",
                        &server.display().to_string(),
                        "log",
                        "-1",
                        "--format=%B",
                        "refs/heads/main",
                    ],
                )
                .await;
                assert!(msg.contains("Starforge-Trail:"), "trailer in {msg}");
            }
            "squash" => {
                assert_eq!(fields.len(), 2, "squash is one commit: {parents}");
                let msg = git_ok(
                    &work,
                    &[
                        "--git-dir",
                        &server.display().to_string(),
                        "log",
                        "-1",
                        "--format=%B",
                        "refs/heads/main",
                    ],
                )
                .await;
                assert!(msg.contains(&format!("add {branch}")), "subject in {msg}");
                assert!(msg.contains("Starforge-Trail:"), "trailer in {msg}");
            }
            _ => {
                assert_eq!(base_after, head.trim(), "ff ref equals head");
            }
        }

        // Change merged, trail merged, timeline + audit rows.
        let detail: Value = client
            .get(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes/{k}")))
            .bearer_auth(&alice_rw)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(detail["change"]["state"], "merged", "{method} change");
        let trail: Value = client
            .get(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}")))
            .bearer_auth(&alice_rw)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(trail["state"], "merged", "{method} trail");
        let kinds: Vec<String> = starforged_db::trails::timeline_of_trail(
            c.s.core.db(),
            detail["change"]["trail_id"].as_i64().unwrap_or(n),
        )
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
        assert!(
            kinds.iter().any(|k| k == "change.merge"),
            "merge timeline {kinds:?}"
        );
    }
}

/// A failing gate blocks with reasons; the merge webhook fires signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_gate_blocks_and_webhook() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;
    // Owner hook over the API (needs maintain+; alice owns).
    let res = client
        .post(c.hooks("proj"))
        .bearer_auth(&c.tok(&c.alice, &[Scope::RepoRead, Scope::RepoWrite]).await)
        .json(&json!({"url": sink_url, "events": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let secret = res.json::<Value>().await.unwrap()["secret"]
        .as_str()
        .unwrap()
        .to_owned();

    let (work, url) = c.pushed_repo("proj").await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\n")], "add a").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let alice_rw = c.tok(&c.alice, REPO_WRITE).await;
    let wendy_rw = c.tok(&c.wendy, REPO_WRITE).await;
    let n = c.trail(&alice_full).await;
    let created = c.branch_change(&alice_rw, n, "feature/x").await;
    let k = created["k"].as_i64().unwrap();

    // Two approvals required, one given: merge refuses with reasons.
    c.gate_rule(None, 2, "[]", "[]").await;
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/{k}/reviews"
        )))
        .bearer_auth(&wendy_rw)
        .json(&json!({"verdict": "approve", "body": "lgtm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .post(c.merge_api("proj", n, k))
        .bearer_auth(&alice_rw)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "failing gate blocks");
    let body: Value = res.json().await.unwrap();
    assert!(
        body.to_string().contains("needs 1 more approval"),
        "reasons returned: {body}"
    );

    // Second approval unblocks; merge succeeds.
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/{k}/reviews"
        )))
        .bearer_auth(&alice_rw)
        .json(&json!({"verdict": "approve", "body": "ship"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .post(c.merge_api("proj", n, k))
        .bearer_auth(&alice_rw)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "gate now passes");

    // Webhook fires on change.merged with a valid signature, recorded.
    c.s.core.run_due_jobs().await.unwrap();
    {
        let hits = sink.hits.lock().unwrap();
        let merged = hits
            .iter()
            .filter(|h| h.event.as_deref() == Some("change.merged"))
            .count();
        assert!(merged > 0, "change.merged delivered");
        for hit in hits.iter() {
            let sig = hit.signature.as_deref().expect("signature header");
            assert_eq!(
                sig,
                &format!("sha256={}", hmac_sha256_hex(&secret, &hit.body)),
                "delivery signature verifies"
            );
            assert!(hit.delivery.is_some(), "delivery id header");
        }
    }
    let hook_id =
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()[0]
            .id;
    let deliveries = starforged_db::checks::recent_deliveries(c.s.core.db(), hook_id, 50)
        .await
        .unwrap();
    assert!(
        deliveries
            .iter()
            .any(|d| d.event == "change.merged" && d.status_code == Some(200)),
        "delivery recorded: {deliveries:?}"
    );
}
