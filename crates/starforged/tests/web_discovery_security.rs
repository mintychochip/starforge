//! K6: discovery + webhook security sweep.
//!
//! Permission matrix (new routes and forms × role × surface) over private,
//! internal, and public repos, the hostile-input corpus through every newly
//! rendered M2e field, CSRF on the new forms, archived-repo refusal, and one
//! end-to-end webhook flow covering all five event types with verified
//! signatures plus a redelivery. Every assertion pins real behavior (codes,
//! rows, bytes). Determinism: after a real `git push` the server's
//! post-receive work is awaited with the `delivered_until` poll (never bare
//! sleeps); API-driven steps need only one `run_due_jobs` drain.
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::User;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const FULL: &[Scope] = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
const READ_ONLY: &[Scope] = &[Scope::RepoRead];

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
/// every legitimate hook/delivery/trail/dashboard template, so any occurrence
/// is attacker markup rendered live. Escaped text (`&#60;img …`) passes — it
/// is inert — and so does a bare `javascript:` scheme inside escaped text;
/// only a live link (`<a href="javascript:…`) can execute.
fn assert_no_live_markup(page: &str, surface: &str) {
    let lower = page.to_lowercase();
    for raw in [
        "<script",
        "<img",
        "<svg",
        "<iframe",
        "<object",
        "<embed",
        "<a href=\"javascript",
        "<a href=\"data:",
        "attacker.example",
    ] {
        assert!(!lower.contains(raw), "{raw} live on {surface}");
    }
}

#[derive(Debug, Clone)]
struct Hit {
    event: Option<String>,
    delivery: Option<String>,
    signature: Option<String>,
    legacy_signature: Option<String>,
    user_agent: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct Sink {
    hits: Arc<Mutex<Vec<Hit>>>,
    /// When set, every POST answers 200 with this body and a hostile
    /// `x-evil` response header instead of `ok`.
    evil_body: Option<Vec<u8>>,
}

impl Sink {
    async fn spawn() -> (String, Sink) {
        Self::spawn_with(None).await
    }

    async fn spawn_with(evil_body: Option<Vec<u8>>) -> (String, Sink) {
        let sink = Sink {
            hits: Arc::new(Mutex::new(Vec::new())),
            evil_body,
        };
        let inner = sink.clone();
        let app = axum::Router::new().route(
            "/hook",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let inner = inner.clone();
                    async move {
                        let get = |name: &str| {
                            headers
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned)
                        };
                        inner.hits.lock().unwrap().push(Hit {
                            event: get("x-starforge-event"),
                            delivery: get("x-starforge-delivery"),
                            signature: get("x-starforge-signature-256"),
                            legacy_signature: get("x-starforge-signature"),
                            user_agent: get("user-agent"),
                            body: body.to_vec(),
                        });
                        if let Some(evil) = &inner.evil_body {
                            let mut map = axum::http::HeaderMap::new();
                            map.insert(
                                "x-evil",
                                "<script>alert(evil-header)</script>".parse().unwrap(),
                            );
                            return (
                                axum::http::StatusCode::OK,
                                map,
                                axum::body::Body::from(evil.clone()),
                            );
                        }
                        (
                            axum::http::StatusCode::OK,
                            axum::http::HeaderMap::new(),
                            axum::body::Body::from("ok"),
                        )
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

/// Verifies the delivery wire format over the exact body and returns the
/// parsed envelope.
fn check_delivery(hit: &Hit, secret: &str) -> Value {
    assert_eq!(
        hit.legacy_signature, None,
        "the old X-Starforge-Signature header must be absent"
    );
    let ua = hit.user_agent.as_deref().expect("User-Agent header");
    assert!(ua.starts_with("starforged/"), "User-Agent: {ua}");
    assert!(hit.delivery.is_some(), "delivery id header present");
    let sig = hit
        .signature
        .as_deref()
        .expect("X-Starforge-Signature-256 header");
    assert!(sig.starts_with("sha256="), "{sig}");
    assert_eq!(
        sig,
        &format!("sha256={}", hmac_sha256_hex(secret, &hit.body)),
        "signature verifies over the exact body"
    );
    serde_json::from_slice::<Value>(&hit.body).unwrap()
}

fn hits(sink: &Sink) -> usize {
    sink.hits.lock().unwrap().len()
}

/// One `run_due_jobs` drain plus the verified envelopes delivered since
/// `from`.
async fn delivered_from(c: &Ctx, sink: &Sink, secret: &str, from: usize) -> Vec<Value> {
    c.s.core.run_due_jobs().await.unwrap();
    sink.hits
        .lock()
        .unwrap()
        .iter()
        .skip(from)
        .map(|hit| check_delivery(hit, secret))
        .collect()
}

/// Polling variant of [`delivered_from`]: after a real `git push`, the
/// server's post-receive processing (which enqueues the push events) can
/// still be running when the push command returns, so one `run_due_jobs`
/// may find nothing to run. Loops `run_due_jobs` + collect with 50 ms
/// polls until `ready` holds or 10 s pass, then returns what arrived — the
/// caller's assert shows the real content on timeout.
async fn delivered_until(
    c: &Ctx,
    sink: &Sink,
    secret: &str,
    from: usize,
    mut ready: impl FnMut(&[Value]) -> bool,
) -> Vec<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        c.s.core.run_due_jobs().await.unwrap();
        let got: Vec<Value> = sink
            .hits
            .lock()
            .unwrap()
            .iter()
            .skip(from)
            .map(|hit| check_delivery(hit, secret))
            .collect();
        if ready(&got) || std::time::Instant::now() >= deadline {
            return got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

struct Ctx {
    s: TestServer,
    alice: User,
    bob: User,
    carol: User,
    wendy: User,
    mia: User,
    adam: User,
    root: User,
    dave: User,
}

impl Ctx {
    async fn start() -> Ctx {
        // Loopback deliveries need the test-only SSRF escape hatch.
        let s = TestServer::start_with(|c| c.webhooks.allow_loopback = true).await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let wendy = s.user("wendy").await;
        let mia = s.user("mia").await;
        let adam = s.user("adam").await;
        let dave = s.user("dave").await;
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
        for (repo, visibility) in [
            ("proj", Visibility::Private),
            ("innie", Visibility::Internal),
            ("open", Visibility::Public),
        ] {
            s.repo(&alice, repo, visibility).await;
            for (handle, perm) in [
                ("bob", Permission::Triage),
                ("carol", Permission::Read),
                ("wendy", Permission::Write),
                ("mia", Permission::Maintain),
                ("adam", Permission::Admin),
            ] {
                s.core
                    .set_collaborator(&alice, "alice", repo, handle, perm)
                    .await
                    .unwrap();
            }
        }
        Ctx {
            s,
            alice,
            bob,
            carol,
            wendy,
            mia,
            adam,
            root,
            dave,
        }
    }

    async fn tok(&self, user: &User, scopes: &[Scope]) -> String {
        self.s.token(user, scopes).await
    }

    fn hooks(&self, repo: &str) -> String {
        self.s.url(&format!("/api/v1/repos/alice/{repo}/hooks"))
    }

    fn assignees(&self, repo: &str, n: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/{repo}/trails/{n}/assignees"))
    }

    fn review_requests(&self, repo: &str, n: i64) -> String {
        self.s.url(&format!(
            "/api/v1/repos/alice/{repo}/trails/{n}/review-requests"
        ))
    }

    fn web_hooks(&self, repo: &str) -> String {
        self.s.url(&format!("/alice/{repo}/settings/hooks"))
    }

    fn web_delivery(&self, repo: &str, id: i64, row: i64) -> String {
        self.s.url(&format!(
            "/alice/{repo}/settings/hooks/{id}/deliveries/{row}"
        ))
    }

    fn web_trail(&self, repo: &str, n: i64) -> String {
        self.s.url(&format!("/alice/{repo}/trails/{n}"))
    }

    async fn create_hook(&self, token: &str, repo: &str, url: &str) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(self.hooks(repo))
            .bearer_auth(token)
            .json(&json!({"url": url, "events": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create hook in {repo}");
        res.json::<Value>().await.unwrap()
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

    /// Seeds one delivered `check` attempt for `hook_id` and returns the
    /// delivery row id.
    async fn seed_delivery(&self, repo: &str, hook_id: i64) -> i64 {
        use starforged_core::webhooks::HookEvent;
        let repo_id = self.repo_id(repo).await;
        self.s
            .core
            .dispatch_event(
                repo_id,
                HookEvent {
                    event: "check",
                    action: None,
                    cause: None,
                    sender: Some("alice".to_owned()),
                    subject: json!({"sha": "abc", "context": "ci", "state": "success"}),
                },
            )
            .await;
        self.s.core.run_due_jobs().await.unwrap();
        self.s
            .core
            .list_deliveries(&self.alice, "alice", repo, hook_id, None)
            .await
            .unwrap()
            .pop()
            .expect("seeded delivery row")
            .id
    }

    async fn create_trail(&self, token: &str, repo: &str, title: &str) -> i64 {
        let client = reqwest::Client::new();
        let res = client
            .post(self.s.url(&format!("/api/v1/repos/alice/{repo}/trails")))
            .bearer_auth(token)
            .json(&json!({"title": title, "intent": "sweep"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create trail in {repo}");
        res.json::<Value>().await.unwrap()["number"]
            .as_i64()
            .unwrap()
    }
}

/// Delivery log API matrix: list, detail, and redeliver need maintain+.
/// Non-readers get 404, never 403; below-threshold readers get 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_deliveries_api() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, _sink) = Sink::spawn().await;
    let alice_full = c.tok(&c.alice, FULL).await;

    let mut hooks = Vec::new();
    for repo in ["proj", "innie", "open"] {
        let created = c.create_hook(&alice_full, repo, &sink_url).await;
        let hook_id = created["id"].as_i64().unwrap();
        let row = c.seed_delivery(repo, hook_id).await;
        hooks.push((repo, hook_id, row));
    }

    // (user, expected on private, expected elsewhere)
    let roles: Vec<(&User, u16, u16)> = vec![
        (&c.dave, 404, 403),
        (&c.carol, 403, 403),
        (&c.bob, 403, 403),
        (&c.wendy, 403, 403),
        (&c.mia, 200, 200),
        (&c.adam, 200, 200),
        (&c.alice, 200, 200),
        (&c.root, 200, 200),
    ];
    for (repo, hook_id, row) in &hooks {
        let list = format!("{}/{hook_id}/deliveries", c.hooks(repo));
        let detail = format!("{list}/{row}");
        let redeliver = format!("{detail}/redeliver");
        for (user, want_private, want_else) in &roles {
            let want = if *repo == "proj" {
                *want_private
            } else {
                *want_else
            };
            let t = c.tok(user, FULL).await;
            let res = client.get(&list).bearer_auth(&t).send().await.unwrap();
            assert_eq!(
                res.status(),
                want,
                "{} lists deliveries in {repo}",
                user.handle
            );
            let res = client.get(&detail).bearer_auth(&t).send().await.unwrap();
            assert_eq!(
                res.status(),
                want,
                "{} reads delivery detail in {repo}",
                user.handle
            );
            let res = client
                .post(&redeliver)
                .bearer_auth(&t)
                .send()
                .await
                .unwrap();
            let want_redeliver = if want == 200 { 202 } else { want };
            assert_eq!(
                res.status(),
                want_redeliver,
                "{} redelivers in {repo}",
                user.handle
            );
            if want_redeliver == 202 {
                c.s.core.run_due_jobs().await.unwrap();
            }
        }
        let res = client.get(&list).send().await.unwrap();
        assert_eq!(res.status(), 401, "anon lists in {repo}");
        let res = client.get(&detail).send().await.unwrap();
        assert_eq!(res.status(), 401, "anon reads detail in {repo}");
        let res = client.post(&redeliver).send().await.unwrap();
        assert_eq!(res.status(), 401, "anon redelivers in {repo}");
    }

    // A read-scoped token cannot list even though carol reads the repo.
    let carol_read = c.tok(&c.carol, READ_ONLY).await;
    let res = client
        .get(format!("{}/{}/deliveries", c.hooks("proj"), hooks[0].1))
        .bearer_auth(&carol_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "read token cannot list deliveries");
}

/// Review-request API matrix: add and remove need triage+.
/// Non-readers get 404, never 403; below-threshold readers get 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_review_requests_api() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let alice_full = c.tok(&c.alice, FULL).await;
    let mut urls = Vec::new();
    for repo in ["proj", "innie", "open"] {
        let n = c.create_trail(&alice_full, repo, "matrix trail").await;
        urls.push((repo, c.review_requests(repo, n)));
    }

    let roles: Vec<(&User, u16, u16)> = vec![
        (&c.dave, 404, 403),
        (&c.carol, 403, 403),
        (&c.bob, 200, 200),
        (&c.wendy, 200, 200),
        (&c.mia, 200, 200),
        (&c.adam, 200, 200),
        (&c.alice, 200, 200),
        (&c.root, 200, 200),
    ];
    // Adds first (the first 200-role add lands, the rest are idempotent),
    // then removes (symmetric).
    for pass in ["add", "remove"] {
        for (repo, url) in &urls {
            for (user, want_private, want_else) in &roles {
                let want = if *repo == "proj" {
                    *want_private
                } else {
                    *want_else
                };
                let t = c.tok(user, FULL).await;
                let req = if pass == "add" {
                    client.post(url)
                } else {
                    client.delete(url)
                };
                let res = req
                    .bearer_auth(&t)
                    .json(&json!({"user": "wendy"}))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    res.status(),
                    want,
                    "{} {pass}s review request in {repo}",
                    user.handle
                );
            }
            let req = if pass == "add" {
                client.post(url)
            } else {
                client.delete(url)
            };
            let res = req.json(&json!({"user": "wendy"})).send().await.unwrap();
            assert_eq!(res.status(), 401, "anon {pass} in {repo}");
        }
    }

    // Unknown handles, strangers-as-target, and the author answer 422, never 404.
    let bob_t = c.tok(&c.bob, FULL).await;
    for (target, why) in [
        ("nosuchuser", "unknown handle"),
        ("dave", "non-member target"),
        ("alice", "author target"),
    ] {
        let res = client
            .post(&urls[0].1)
            .bearer_auth(&bob_t)
            .json(&json!({"user": target}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "{why} is 422");
    }
}

/// Web matrix: deliveries list/detail/redeliver form (maintain+),
/// review-request form (triage+), and the dashboard sections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_web() {
    let c = Ctx::start().await;
    let (sink_url, _sink) = Sink::spawn().await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let hook = c.create_hook(&alice_full, "proj", &sink_url).await;
    let hook_id = hook["id"].as_i64().unwrap();
    let row = c.seed_delivery("proj", hook_id).await;
    let open_hook = c.create_hook(&alice_full, "open", &sink_url).await;
    let open_hook_id = open_hook["id"].as_i64().unwrap();
    let open_row = c.seed_delivery("open", open_hook_id).await;
    let n = c
        .create_trail(&alice_full, "proj", "web matrix trail")
        .await;
    let open_n = c
        .create_trail(&alice_full, "open", "open matrix trail")
        .await;

    let anon = c.s.browser();
    // Anonymous web callers bounce to /login on signed-in routes; the
    // trail detail renders for readers only (404 on private, 200 on public).
    for url in [
        c.web_hooks("proj"),
        c.web_delivery("proj", hook_id, row),
        c.web_hooks("open"),
    ] {
        let res = anon.get(&url).send().await.unwrap();
        assert!(
            res.status().is_redirection(),
            "anon GET {url} redirects, got {}",
            res.status()
        );
    }
    assert_eq!(
        anon.get(c.web_trail("proj", n))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "anon cannot read the private trail"
    );
    assert_eq!(
        anon.get(c.web_trail("open", open_n))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "anon reads the public trail"
    );
    let res = anon
        .post(c.web_delivery("proj", hook_id, row) + "/redeliver")
        .form(&[("_csrf", "x")])
        .send()
        .await
        .unwrap();
    assert!(res.status().is_redirection(), "anon redeliver redirects");
    let res = anon
        .post(c.web_trail("proj", n) + "/review-requests")
        .form(&[("_csrf", "x"), ("action", "add"), ("handle", "wendy")])
        .send()
        .await
        .unwrap();
    assert!(res.status().is_redirection(), "anon review POST redirects");

    // (handle, list, detail, redeliver POST, review POST) on private proj.
    // Non-readers 404; below-threshold readers 403.
    for (handle, want_list, want_detail, want_redeliver, want_review) in [
        ("dave", 404, 404, 404, 404),
        ("carol", 403, 403, 403, 403),
        ("bob", 403, 403, 403, 303),
        ("wendy", 403, 403, 403, 303),
        ("mia", 200, 200, 303, 303),
        ("alice", 200, 200, 303, 303),
    ] {
        let (browser, csrf) = c.s.login(handle).await;
        let res = browser.get(c.web_hooks("proj")).send().await.unwrap();
        assert_eq!(res.status(), want_list, "{handle} GET hooks page (proj)");
        let res = browser
            .get(c.web_delivery("proj", hook_id, row))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            want_detail,
            "{handle} GET delivery detail (proj)"
        );
        // POSTs carry the caller's own valid CSRF, so the code pins the
        // permission check rather than CSRF.
        let res = browser
            .post(c.web_delivery("proj", hook_id, row) + "/redeliver")
            .form(&[("_csrf", csrf.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            want_redeliver,
            "{handle} POST redeliver (proj)"
        );
        if want_redeliver == 303 {
            c.s.core.run_due_jobs().await.unwrap();
        }
        let res = browser
            .post(c.web_trail("proj", n) + "/review-requests")
            .form(&[
                ("_csrf", csrf.as_str()),
                ("action", "add"),
                ("handle", "wendy"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            want_review,
            "{handle} POST review-request add (proj)"
        );
        if want_review == 303 {
            // Restore the idempotent pre-state for the next role.
            let res = browser
                .post(c.web_trail("proj", n) + "/review-requests")
                .form(&[
                    ("_csrf", csrf.as_str()),
                    ("action", "remove"),
                    ("handle", "wendy"),
                ])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 303, "{handle} POST review-request remove");
        }
    }

    // Public repo: dave reads, so the gates answer 403 instead of 404.
    let (dave, dave_csrf) = c.s.login("dave").await;
    assert_eq!(
        dave.get(c.web_hooks("open")).send().await.unwrap().status(),
        403,
        "dave GET hooks page (open)"
    );
    assert_eq!(
        dave.get(c.web_delivery("open", open_hook_id, open_row))
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "dave GET delivery detail (open)"
    );
    assert_eq!(
        dave.post(c.web_delivery("open", open_hook_id, open_row) + "/redeliver")
            .form(&[("_csrf", dave_csrf.as_str())])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "dave POST redeliver (open)"
    );
    assert_eq!(
        dave.post(c.web_trail("open", open_n) + "/review-requests")
            .form(&[
                ("_csrf", dave_csrf.as_str()),
                ("action", "add"),
                ("handle", "wendy")
            ])
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "dave POST review-request (open)"
    );
    // ... while the trail itself renders for a public reader.
    assert_eq!(
        dave.get(c.web_trail("open", open_n))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "dave reads the public trail"
    );

    // Dashboard sections: give bob an assignment and a review request, then
    // pin the role matrix (bob sees both, dave and anon see neither).
    let client = reqwest::Client::new();
    let res = client
        .post(c.assignees("proj", n))
        .bearer_auth(&alice_full)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "assign bob");
    let res = client
        .post(c.review_requests("proj", n))
        .bearer_auth(&alice_full)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "request bob");
    let page = anon
        .get(c.s.url("/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for section in [
        "Assigned to you",
        "Awaiting your review",
        "Your recent sessions",
    ] {
        assert!(!page.contains(section), "anon sees no {section}");
    }
    let (bob, _) = c.s.login("bob").await;
    let page = get_text(&bob, &c.s.url("/")).await;
    assert!(page.contains("Assigned to you"), "bob sees assignments");
    assert!(page.contains("Awaiting your review"), "bob sees requests");
    assert!(page.contains("web matrix trail"), "assigned trail listed");
    let page = get_text(&dave, &c.s.url("/")).await;
    for section in [
        "Assigned to you",
        "Awaiting your review",
        "Your recent sessions",
    ] {
        assert!(!page.contains(section), "dave sees no {section}");
    }
    assert!(
        !page.contains("web matrix trail"),
        "private trail hidden from dave"
    );
}

/// Dashboard sections show assigned Trails, pending review requests, and
/// recent sessions — and hide what the viewer can no longer read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_sections() {
    let c = Ctx::start().await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let bob_full = c.tok(&c.bob, FULL).await;

    // Private trail: assigned to bob, review requested from bob.
    let n = c
        .create_trail(&alice_full, "proj", "bob private work")
        .await;
    let client = reqwest::Client::new();
    let res = client
        .post(c.assignees("proj", n))
        .bearer_auth(&bob_full)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "assign bob");
    let res = client
        .post(c.review_requests("proj", n))
        .bearer_auth(&alice_full)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "request bob");

    // Public trail assigned to wendy: cross-repo rows reach her dashboard.
    let open_n = c
        .create_trail(&alice_full, "open", "wendy public work")
        .await;
    let res = client
        .post(c.assignees("open", open_n))
        .bearer_auth(&alice_full)
        .json(&json!({"user": "wendy"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "assign wendy on open");

    // Wendy (write) uploads and completes a session in proj.
    let upload = c.tok(&c.wendy, &[Scope::SessionUpload]).await;
    let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FD1";
    let res = client
        .put(c.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}")))
        .bearer_auth(&upload)
        .json(&session_meta(ulid, "wendy dashboard session"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "session meta");
    let (bytes, hash) = segment_payload(&[user_event(0)]);
    let res = client
        .put(c.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ulid}/segments/0"
        )))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "session segment");
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ulid}/complete"
        )))
        .bearer_auth(&upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "session complete");

    let (bob, _) = c.s.login("bob").await;
    let page = get_text(&bob, &c.s.url("/")).await;
    for section in ["Assigned to you", "Awaiting your review"] {
        assert!(page.contains(section), "bob sees {section}");
    }
    assert!(page.contains("bob private work"), "assigned trail listed");
    assert!(
        !page.contains("Your recent sessions"),
        "bob uploaded nothing, so no session section"
    );

    // Wendy sees her cross-repo assignment plus her own session.
    let (wendy, _) = c.s.login("wendy").await;
    let page = get_text(&wendy, &c.s.url("/")).await;
    assert!(page.contains("Your recent sessions"), "wendy sees sessions");
    assert!(
        page.contains("wendy dashboard session"),
        "own session listed"
    );
    assert!(
        page.contains("wendy public work"),
        "cross-repo assignment listed"
    );

    // Dave owns and collaborates on nothing, so his repo list is empty —
    // and he never sees bob's or wendy's rows.
    let (dave, _) = c.s.login("dave").await;
    let page = get_text(&dave, &c.s.url("/")).await;
    assert!(page.contains("No repositories yet"), "dave owns nothing");
    assert!(
        !page.contains("bob private work"),
        "private trail hidden from dave"
    );
    assert!(
        !page.contains("wendy dashboard session"),
        "private session hidden from dave"
    );
    for section in [
        "Assigned to you",
        "Awaiting your review",
        "Your recent sessions",
    ] {
        assert!(!page.contains(section), "dave sees no {section}");
    }
}

/// Hostile input through every newly rendered M2e field.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_corpus() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let alice_full = c.tok(&c.alice, FULL).await;
    let (browser, _) = c.s.login("alice").await;

    // Delivery response bodies and headers, plus the stored request headers
    // and body, all render escaped on the detail page.
    let evil: Vec<u8> = b"<script>alert(delivery)</script>".to_vec();
    let (evil_url, _evil) = Sink::spawn_with(Some(evil.clone())).await;
    let created = c.create_hook(&alice_full, "proj", &evil_url).await;
    let hook_id = created["id"].as_i64().unwrap();
    let row = c.seed_delivery("proj", hook_id).await;
    let page = get_text(&browser, &c.web_delivery("proj", hook_id, row)).await;
    assert_no_live_markup(&page, "delivery detail");
    assert!(page.contains("&#60;script"), "receiver body escaped");
    assert!(page.contains("x-evil"), "response headers rendered");

    // Reviewer handles render as inert text on the trail page.
    let n = c
        .create_trail(&alice_full, "proj", "reviewers render")
        .await;
    let res = client
        .post(c.review_requests("proj", n))
        .bearer_auth(&alice_full)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let page = get_text(&browser, &c.web_trail("proj", n)).await;
    assert_no_live_markup(&page, "trail reviewers");
    assert!(page.contains("bob"), "reviewer handle renders");

    // Hostile trail and session titles render escaped on the dashboard.
    // (Wendy holds write, so she can upload the sessions herself.)
    for payload in PAYLOADS {
        let t = c.create_trail(&alice_full, "proj", payload).await;
        let res = client
            .post(c.assignees("proj", t))
            .bearer_auth(&alice_full)
            .json(&json!({"user": "wendy"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "assign hostile-titled trail");
        let res = client
            .post(c.review_requests("proj", t))
            .bearer_auth(&alice_full)
            .json(&json!({"user": "wendy"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "request review on hostile-titled trail");
    }
    let upload = c.tok(&c.wendy, &[Scope::SessionUpload]).await;
    for (i, payload) in PAYLOADS.iter().enumerate() {
        let ulid = format!("01ARZ3NDEKTSV4RRFFQ69G5FE{i}");
        let res = client
            .put(c.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}")))
            .bearer_auth(&upload)
            .json(&session_meta(&ulid, payload))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "hostile-titled session meta {payload:?}");
        let (bytes, hash) = segment_payload(&[user_event(0)]);
        let res = client
            .put(c.s.url(&format!(
                "/api/v1/repos/alice/proj/sessions/{ulid}/segments/0"
            )))
            .bearer_auth(&upload)
            .header("X-Starforge-Blake3", &hash)
            .body(bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "hostile-titled session segment");
        let res = client
            .post(c.s.url(&format!(
                "/api/v1/repos/alice/proj/sessions/{ulid}/complete"
            )))
            .bearer_auth(&upload)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "hostile-titled session complete");
    }
    let (wendy, _) = c.s.login("wendy").await;
    let page = get_text(&wendy, &c.s.url("/")).await;
    assert_no_live_markup(&page, "dashboard");
    assert!(
        page.contains("&#60;script"),
        "hostile titles escaped on dashboard"
    );
}

/// Every new form refuses a forged CSRF token, and the state is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_matrix() {
    let c = Ctx::start().await;
    let (sink_url, _sink) = Sink::spawn().await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let created = c.create_hook(&alice_full, "proj", &sink_url).await;
    let hook_id = created["id"].as_i64().unwrap();
    let row = c.seed_delivery("proj", hook_id).await;
    let n = c.create_trail(&alice_full, "proj", "csrf trail").await;

    async fn delivery_rows(c: &Ctx, hook_id: i64) -> usize {
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap()
            .len()
    }
    async fn timeline_redelivered(c: &Ctx) -> usize {
        sqlx::query_as::<_, (String,)>(
            "SELECT kind FROM timeline_events WHERE kind = 'webhook.redelivered'",
        )
        .fetch_all(c.s.core.db().pool())
        .await
        .unwrap()
        .len()
    }

    let (alice_browser, _) = c.s.login("alice").await;
    let (_, carol_csrf) = c.s.login("carol").await;
    let rows_before = delivery_rows(&c, hook_id).await;
    // Redeliver without/with a foreign token: 403, no rows change.
    for token in ["", carol_csrf.as_str()] {
        let res = alice_browser
            .post(c.web_delivery("proj", hook_id, row) + "/redeliver")
            .form(&[("_csrf", token)])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "redeliver CSRF {token:?}");
    }
    assert_eq!(
        delivery_rows(&c, hook_id).await,
        rows_before,
        "no delivery rows written"
    );
    assert_eq!(
        timeline_redelivered(&c).await,
        0,
        "no redelivered timeline rows"
    );

    // Review-request add/remove without/with a foreign token: 403, and the
    // request list is unchanged.
    let (bob_browser, _) = c.s.login("bob").await;
    let client = reqwest::Client::new();
    let bob_t = c.tok(&c.bob, FULL).await;
    for token in ["", carol_csrf.as_str()] {
        for action in ["add", "remove"] {
            let res = bob_browser
                .post(c.web_trail("proj", n) + "/review-requests")
                .form(&[("_csrf", token), ("action", action), ("handle", "wendy")])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 403, "review {action} CSRF {token:?}");
        }
    }
    let detail: Value = client
        .get(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}")))
        .bearer_auth(&bob_t)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["review_requests"], json!([]), "no request written");
}

/// One scripted flow drives all five event types; every signature verifies,
/// and one redelivery replays an identical body under a new delivery id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_events_end_to_end() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn().await;
    let created = c
        .create_hook(&c.tok(&c.alice, FULL).await, "proj", &sink_url)
        .await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    let hook_id = created["id"].as_i64().unwrap();
    let repo_url = format!("{}/alice/proj", c.s.base);

    // Branch push (real git): main + feature/x.
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\nx\n")], "add x").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
    delivered_until(&c, &sink, &secret, 0, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 2
    })
    .await;

    let trail_rw = c.tok(&c.alice, &[Scope::RepoRead, Scope::TrailWrite]).await;
    let full = c.tok(&c.alice, FULL).await;
    // Trail open + edit.
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&trail_rw)
        .json(&json!({"title": "e2e trail", "intent": "prove five events"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let n = res.json::<Value>().await.unwrap()["number"]
        .as_i64()
        .unwrap();
    let res = client
        .patch(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}")))
        .bearer_auth(&trail_rw)
        .json(&json!({"title": "e2e trail renamed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "trail edit");
    // Review request.
    let res = client
        .post(c.review_requests("proj", n))
        .bearer_auth(&full)
        .json(&json!({"user": "wendy"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "request review from wendy");
    // Track the pushed branch as this trail's change.
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes")))
        .bearer_auth(&full)
        .json(&json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "track branch change");

    // A refs/for push ingests its own trail change (never a push event).
    commit_files(&work, &[("b.txt", b"unrelated\n")], "unrelated").await;
    let from = hits(&sink);
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main"]).await;
    delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().any(|b| {
            b["event"] == "trail" && b["action"] == "updated" && b["cause"] == "change_opened"
        })
    })
    .await;

    // A review, a status, and the merge that flips the first trail merged.
    let bob_t = c.tok(&c.bob, FULL).await;
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/1/reviews"
        )))
        .bearer_auth(&bob_t)
        .json(&json!({"verdict": "approve", "body": "lgtm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "submit review");
    let tip = git_ok(&work, &["rev-parse", "feature/x"]).await;
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/statuses/{}", tip.trim())))
        .bearer_auth(&full)
        .json(&json!({"state": "success", "context": "ci/unit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "post status");
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/1/merge"
        )))
        .bearer_auth(&full)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "merge: {}", res.text().await.unwrap());

    // A session upload + complete.
    let upload = c.tok(&c.alice, &[Scope::SessionUpload]).await;
    let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FC1";
    let res = client
        .put(c.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}")))
        .bearer_auth(&upload)
        .json(&session_meta(ulid, "e2e session"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "session meta");
    let (bytes, hash) = segment_payload(&[user_event(0)]);
    let res = client
        .put(c.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ulid}/segments/0"
        )))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "session segment");
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ulid}/complete"
        )))
        .bearer_auth(&upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "session complete");

    // Drain everything the API steps enqueued and prove the five types.
    c.s.core.run_due_jobs().await.unwrap();
    let got = delivered_from(&c, &sink, &secret, 0).await;
    let mut kinds: Vec<&str> = got.iter().map(|b| b["event"].as_str().unwrap()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(
        kinds,
        vec!["check", "push", "review", "session", "trail"],
        "all five types: {got:?}"
    );
    for body in &got {
        // D1: `action` and `cause` are always present, possibly null.
        assert!(
            body.as_object().unwrap().contains_key("action"),
            "action key present: {body}"
        );
        assert!(
            body.as_object().unwrap().contains_key("cause"),
            "cause key present: {body}"
        );
        assert_eq!(body["repository"]["url"], repo_url.as_str());
    }
    assert!(
        got.iter()
            .any(|b| b["event"] == "trail" && b["action"] == "merged"),
        "the completing merge emits merged: {got:?}"
    );
    assert!(
        got.iter()
            .any(|b| b["event"] == "session" && b["action"] == "uploaded"),
        "the session upload emits uploaded: {got:?}"
    );

    // One redelivery replays an identical body under a new delivery id.
    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();
    let check_row = rows
        .iter()
        .find(|r| r.event == "check")
        .expect("check row")
        .id;
    let before = hits(&sink);
    let original = sink.hits.lock().unwrap()[..before]
        .iter()
        .find(|h| h.event.as_deref() == Some("check"))
        .expect("check hit")
        .body
        .clone();
    let res = client
        .post(format!(
            "{}/{hook_id}/deliveries/{check_row}/redeliver",
            c.hooks("proj")
        ))
        .bearer_auth(&full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let new_id = res.json::<Value>().await.unwrap()["delivery_id"]
        .as_str()
        .unwrap()
        .to_owned();
    c.s.core.run_due_jobs().await.unwrap();
    let after = sink.hits.lock().unwrap().clone();
    assert_eq!(after.len(), before + 1, "redelivery reaches the receiver");
    let replay = &after[before];
    assert_eq!(replay.body, original, "identical body replayed");
    assert_eq!(replay.delivery.as_deref(), Some(new_id.as_str()));
    let body = check_delivery(replay, &secret);
    assert_eq!(body["event"], "check");
}

/// Archived repos refuse every new mutation, while reads keep working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archived_repo_refuses_mutations() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, _sink) = Sink::spawn().await;
    let alice_full = c.tok(&c.alice, FULL).await;
    let created = c.create_hook(&alice_full, "proj", &sink_url).await;
    let hook_id = created["id"].as_i64().unwrap();
    let row = c.seed_delivery("proj", hook_id).await;
    let n = c.create_trail(&alice_full, "proj", "doomed trail").await;

    c.s.core
        .archive_repo(&c.alice, "alice", "proj")
        .await
        .unwrap();

    // Review requests: API 422, web 400.
    for (method, url) in [
        ("POST", c.review_requests("proj", n)),
        ("DELETE", c.review_requests("proj", n)),
    ] {
        let req = if method == "POST" {
            client.post(&url)
        } else {
            client.delete(&url)
        };
        let res = req
            .bearer_auth(&alice_full)
            .json(&json!({"user": "wendy"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "archived {method} review-request");
    }
    let (browser, csrf) = c.s.login("alice").await;
    let res = browser
        .post(c.web_trail("proj", n) + "/review-requests")
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "add"),
            ("handle", "wendy"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400, "archived web review-request");

    // Redeliver: API 422, web 422 re-render.
    let res = client
        .post(format!(
            "{}/{hook_id}/deliveries/{row}/redeliver",
            c.hooks("proj")
        ))
        .bearer_auth(&alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "archived API redeliver");
    let res = browser
        .post(c.web_delivery("proj", hook_id, row) + "/redeliver")
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "archived web redeliver");

    // Reads still work on the archived repo.
    let res = client
        .get(format!("{}/{hook_id}/deliveries", c.hooks("proj")))
        .bearer_auth(&alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "archived list still reads");
    let res = client
        .get(format!("{}/{hook_id}/deliveries/{row}", c.hooks("proj")))
        .bearer_auth(&alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "archived detail still reads");
    assert_eq!(
        browser
            .get(c.web_delivery("proj", hook_id, row))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "archived web detail still reads"
    );
}

fn session_meta(ulid: &str, title: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": title,
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

/// One minimal valid `user_message` event line with sequence number `seq`.
fn user_event(seq: u64) -> String {
    format!(
        r#"{{"v":1,"seq":{seq},"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"hello {seq}"}}"#
    )
}

/// Compresses JSONL `lines` (newline-joined plus trailing newline) and returns
/// the bytes with their BLAKE3 hex, ready for a segment PUT.
fn segment_payload(lines: &[String]) -> (Vec<u8>, String) {
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    (bytes, hash)
}
