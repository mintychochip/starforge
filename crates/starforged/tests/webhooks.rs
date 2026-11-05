//! H5: webhooks — CRUD permissions, event filter, signed delivery, retry
//! ladder, disable, dead-endpoint safety, and a push→review→merge end-to-end.
mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

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
    /// When true every POST answers 500.
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

    fn events(&self) -> Vec<String> {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter_map(|h| h.event.clone())
            .collect()
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

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    alice_rw: String,
    bob_rw: String,
    carol_r: String,
    carol_rw: String,
}

impl Ctx {
    async fn start() -> Ctx {
        // The delivery SSRF gate denies loopback unless the test-only config
        // flag is set; the in-process receiver needs it.
        let s = TestServer::start_with(|c| c.webhooks.allow_loopback = true).await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        s.repo(&alice, "proj", Visibility::Private).await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Maintain)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        let rw = &[Scope::RepoRead, Scope::RepoWrite];
        Ctx {
            alice_rw: s.token(&alice, rw).await,
            bob_rw: s.token(&bob, rw).await,
            carol_r: s.token(&carol, &[Scope::RepoRead]).await,
            carol_rw: s.token(&carol, rw).await,
            s,
            alice,
        }
    }

    fn hooks(&self) -> String {
        self.s.url("/api/v1/repos/alice/proj/hooks")
    }

    async fn create_hook(&self, token: &str, url: &str, events: &[&str]) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(self.hooks())
            .bearer_auth(token)
            .json(&json!({"url": url, "events": events}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create hook");
        res.json::<Value>().await.unwrap()
    }

    async fn make_due(&self, kind: &str) {
        let now = starforged_db::now();
        sqlx::query("UPDATE jobs SET run_at = $1 WHERE kind = $2 AND state = 'queued'")
            .bind(now)
            .bind(kind)
            .execute(self.s.core.db().pool())
            .await
            .unwrap();
    }

    async fn webhook_jobs(&self) -> Vec<starforged_db::jobs::JobRow> {
        starforged_db::jobs::list_recent(self.s.core.db(), 50)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "webhook_delivery")
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crud_permissions_and_secret_shown_once() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, _sink) = Sink::spawn(false).await;

    // Anonymous create: 401.
    let res = client
        .post(c.hooks())
        .json(&json!({"url": sink_url, "events": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Read-scoped token: 403 even for reads (maintain+ only).
    let res = client
        .get(c.hooks())
        .bearer_auth(&c.carol_r)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Read-permission holder with a write token: 403 from Core.
    let res = client
        .post(c.hooks())
        .bearer_auth(&c.carol_rw)
        .json(&json!({"url": sink_url, "events": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Owner creates: 201 with the secret, exactly once.
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    assert!(!secret.is_empty(), "secret returned on create");
    assert_eq!(created["has_secret"], true);
    assert_eq!(created["active"], true);

    // Maintainer creates too.
    let bob_created = c
        .create_hook(&c.bob_rw, &sink_url, &["status.updated"])
        .await;
    assert!(bob_created["secret"].as_str().is_some());

    // List never contains any secret.
    let res = client
        .get(c.hooks())
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list = res.json::<Value>().await.unwrap();
    assert_eq!(list["hooks"].as_array().unwrap().len(), 2);
    let rendered = list.to_string();
    assert!(
        !rendered.contains(&secret),
        "secret must not appear in list"
    );
    assert!(
        !rendered.contains(bob_created["secret"].as_str().unwrap()),
        "second secret must not appear in list"
    );
    assert!(list["hooks"][0]["secret"].is_null());

    // Unknown event rejected: 422.
    let res = client
        .post(c.hooks())
        .bearer_auth(&c.alice_rw)
        .json(&json!({"url": sink_url, "events": ["nope"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Non-https, non-localhost rejected: 422.
    let res = client
        .post(c.hooks())
        .bearer_auth(&c.alice_rw)
        .json(&json!({"url": "http://example.com/hook", "events": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Disable via PATCH, then delete.
    let id = created["id"].as_i64().unwrap();
    let res = client
        .patch(format!("{}/{}", c.hooks(), id))
        .bearer_auth(&c.alice_rw)
        .json(&json!({"active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["active"], false);

    let res = client
        .delete(format!("{}/{}", c.hooks(), id))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "readers cannot delete hooks");

    let res = client
        .delete(format!("{}/{}", c.hooks(), id))
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn event_filter_and_signed_delivery() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;

    let created = c
        .create_hook(&c.alice_rw, &sink_url, &["status.updated"])
        .await;
    let secret = created["secret"].as_str().unwrap().to_owned();

    // A trail open must NOT fan out to this hook.
    let trail_token =
        c.s.token(&c.alice, &[Scope::RepoRead, Scope::TrailWrite])
            .await;
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&trail_token)
        .json(&json!({"title": "filtered", "intent": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // A status write must fan out.
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/statuses/{sha}")))
        .bearer_auth(&c.alice_rw)
        .json(&json!({"state": "success", "context": "ci/unit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    c.s.core.run_due_jobs().await.unwrap();
    let hits = sink.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1, "only the subscribed event delivers");
    let hit = &hits[0];
    assert_eq!(hit.event.as_deref(), Some("status.updated"));
    assert!(hit.delivery.is_some(), "delivery id header present");
    let body = serde_json::from_slice::<Value>(&hit.body).unwrap();
    assert_eq!(body["event"], "status.updated");
    assert_eq!(body["repo"], "alice/proj");
    assert_eq!(body["sha"], sha);
    assert_eq!(body["state"], "success");
    assert!(body["at"].is_number());
    let sig = hit.signature.as_deref().expect("signature header");
    assert!(sig.starts_with("sha256:"), "{sig}");
    assert_eq!(
        sig,
        &format!("sha256:{}", hmac_sha256_hex(&secret, &hit.body)),
        "signature verifies over the exact body"
    );

    // Delivery row recorded with the 2xx status.
    let hook_id = created["id"].as_i64().unwrap();
    let deliveries = starforged_db::checks::recent_deliveries(c.s.core.db(), hook_id, 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].event, "status.updated");
    assert_eq!(deliveries[0].status_code, Some(200));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_ladder_then_terminal_failure() {
    let c = Ctx::start().await;
    let (fail_url, _fail) = Sink::spawn(true).await;
    let created = c.create_hook(&c.alice_rw, &fail_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();

    // One event → one job.
    c.s.core
        .dispatch(1, "status.updated", json!({"sha": "a"}))
        .await;
    let jobs = c.webhook_jobs().await;
    assert_eq!(jobs.len(), 1);

    // Each 500 pushes the job down the ladder; drive it manually due.
    let expected_delays = [60, 300, 1800, 7200];
    for (i, delay) in expected_delays.iter().enumerate() {
        let before = starforged_db::now();
        c.s.core.run_due_jobs().await.unwrap();
        let row = starforged_db::jobs::by_id(c.s.core.db(), jobs[0].id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "queued", "attempt {} re-queued", i + 1);
        assert_eq!(row.attempts, (i + 1) as i64);
        let skew = row.run_at - before;
        assert!(
            skew >= *delay && skew <= *delay + 10,
            "backoff rung {} ≈ {delay}s, got skew {skew}",
            i + 1
        );
        // No delivery row until the terminal outcome.
        assert!(
            starforged_db::checks::recent_deliveries(c.s.core.db(), hook_id, 10)
                .await
                .unwrap()
                .is_empty()
        );
        c.make_due("webhook_delivery").await;
    }

    // The fifth attempt fails terminally: delivery recorded, hook marked.
    c.s.core.run_due_jobs().await.unwrap();
    let row = starforged_db::jobs::by_id(c.s.core.db(), jobs[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "done", "terminal failure completes the job");
    let deliveries = starforged_db::checks::recent_deliveries(c.s.core.db(), hook_id, 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert!(deliveries[0].status_code == Some(500));
    assert!(deliveries[0].error.as_deref().unwrap_or("").contains("500"));

    let hooks =
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap();
    let hook = hooks.iter().find(|h| h.id == hook_id).unwrap();
    assert_eq!(hook.last_status, Some(500));
    assert!(hook.last_error.as_deref().unwrap_or("").contains("500"));

    // webhook.failed timeline row exists (repo-scoped, no trail).
    let failed: Vec<(String,)> =
        sqlx::query_as("SELECT kind FROM timeline_events WHERE kind = 'webhook.failed'")
            .fetch_all(c.s.core.db().pool())
            .await
            .unwrap();
    assert!(!failed.is_empty(), "terminal failure writes webhook.failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disable_stops_delivery_and_dead_endpoint_does_not_wedge() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;

    // Disabled hook: dispatch enqueues nothing.
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let id = created["id"].as_i64().unwrap();
    let res = client
        .patch(format!("{}/{}", c.hooks(), id))
        .bearer_auth(&c.alice_rw)
        .json(&json!({"active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    c.s.core
        .dispatch(1, "status.updated", json!({"sha": "b"}))
        .await;
    c.s.core.run_due_jobs().await.unwrap();
    assert!(sink.hits.lock().unwrap().is_empty());
    assert!(c.webhook_jobs().await.is_empty());

    // Dead endpoint (nothing listening): drive to terminal, queue survives.
    let dead = c
        .create_hook(&c.alice_rw, "http://127.0.0.1:9/hook", &[])
        .await;
    let dead_id = dead["id"].as_i64().unwrap();
    c.s.core
        .dispatch(1, "status.updated", json!({"sha": "c"}))
        .await;
    for _ in 0..5 {
        c.s.core.run_due_jobs().await.unwrap();
        c.make_due("webhook_delivery").await;
    }
    c.s.core.run_due_jobs().await.unwrap();
    let deliveries = starforged_db::checks::recent_deliveries(c.s.core.db(), dead_id, 10)
        .await
        .unwrap();
    assert_eq!(
        deliveries.len(),
        1,
        "dead endpoint records terminal failure"
    );
    assert!(
        deliveries[0].status_code.is_none(),
        "transport error has no status"
    );

    // A healthy hook still delivers afterwards: the queue is not wedged.
    c.create_hook(&c.alice_rw, &sink_url, &["status.updated"])
        .await;
    c.s.core
        .dispatch(1, "status.updated", json!({"sha": "d"}))
        .await;
    c.s.core.run_due_jobs().await.unwrap();
    assert_eq!(sink.events(), vec!["status.updated".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_push_review_merge_fan_out() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();

    // Push main + feature, then drive the change lifecycle over HTTP.
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;

    let trail_rw =
        c.s.token(&c.alice, &[Scope::RepoRead, Scope::TrailWrite])
            .await;
    let full =
        c.s.token(
            &c.alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&trail_rw)
        .json(&json!({"title": "feature work", "intent": "ship it"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let n = res.json::<Value>().await.unwrap()["number"]
        .as_i64()
        .unwrap();

    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes")))
        .bearer_auth(&full)
        .json(&json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "{}", res.text().await.unwrap());

    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/1/reviews"
        )))
        .bearer_auth(&full)
        .json(&json!({"verdict": "approve", "body": "lgtm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    let sha = git_ok(&work, &["rev-parse", "feature/x"]).await;
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/statuses/{sha}")))
        .bearer_auth(&c.alice_rw)
        .json(&json!({"state": "success", "context": "ci/unit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/1/merge"
        )))
        .bearer_auth(&full)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());

    c.s.core.run_due_jobs().await.unwrap();
    let mut got = sink.events();
    got.sort();
    got.dedup();
    for want in [
        "trail.opened",
        "change.opened",
        "review.submitted",
        "change.merged",
        "status.updated",
    ] {
        assert!(got.contains(&want.to_string()), "missing {want} in {got:?}");
    }
    // Every delivery verifies against the hook secret from create.
    for hit in sink.hits.lock().unwrap().iter() {
        let sig = hit.signature.as_deref().expect("signature header");
        assert_eq!(
            sig,
            &format!("sha256:{}", hmac_sha256_hex(&secret, &hit.body)),
            "delivery signature verifies"
        );
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
        deliveries.len() >= 5,
        "one row per delivery: {deliveries:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_page_shows_secret_once() {
    let c = Ctx::start().await;
    let (sink_url, _sink) = Sink::spawn(false).await;

    // Writers see no hooks tab and get 403.
    let (walt_client, _) = c.s.login("carol").await;
    assert_eq!(
        walt_client
            .get(c.s.url("/alice/proj/settings/hooks"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let (mia, _) = c.s.login("alice").await;
    let page = get_text(&mia, &c.s.url("/alice/proj/settings/hooks")).await;
    assert!(page.contains("Webhooks"), "{page}");
    let csrf = extract_input(&page, "_csrf");

    // Create via the form: the secret shows once in the response...
    let res = mia
        .post(c.s.url("/alice/proj/settings/hooks"))
        .form(&HashMap::from([
            ("_csrf", csrf.as_str()),
            ("url", sink_url.as_str()),
            ("events", "status.updated"),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let created = res.text().await.unwrap();
    assert!(created.contains("secret"), "{created}");
    let secret = between(&created, "secret-", "-end");
    assert!(!secret.is_empty());

    // ...and never again.
    let again = get_text(&mia, &c.s.url("/alice/proj/settings/hooks")).await;
    assert!(!again.contains(&secret), "secret shown only once");
    assert!(again.contains(&sink_url));

    // Toggle disables, delete removes.
    let hooks =
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap();
    assert_eq!(hooks.len(), 1);
    let id = hooks[0].id;
    let toggle_csrf = extract_input(&again, "_csrf");
    let res = mia
        .post(c.s.url(&format!("/alice/proj/settings/hooks/{id}/toggle")))
        .form(&[("_csrf", toggle_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let res = mia
        .post(c.s.url(&format!("/alice/proj/settings/hooks/{id}/delete")))
        .form(&[("_csrf", toggle_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(
        c.s.core
            .list_webhooks(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .is_empty()
    );
}
