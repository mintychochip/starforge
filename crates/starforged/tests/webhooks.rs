//! Webhooks: CRUD permissions, secret-once, the spec §10.4 event model
//! (five event types, one envelope, `X-Starforge-Signature-256`), signed
//! delivery, the retry ladder, disable, dead-endpoint safety, and a
//! push→review→merge end-to-end.
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
    legacy_signature: Option<String>,
    user_agent: Option<String>,
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
                            signature: get("x-starforge-signature-256"),
                            legacy_signature: get("x-starforge-signature"),
                            user_agent: get("user-agent"),
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

    fn bodies(&self) -> Vec<Value> {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| serde_json::from_slice::<Value>(&h.body).unwrap())
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

/// Verifies the delivery wire format (spec D1): the new signature header over
/// the exact body, no legacy header, a `starforged/` user agent. Returns the
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

/// The D1 envelope shared by every event: the subject lives under the key
/// named by `event`, `action`/`cause` are always present (possibly null),
/// `at` is RFC 3339 UTC, and `sender` names the acting user.
fn check_envelope(
    body: &Value,
    event: &str,
    action: Option<&str>,
    cause: Option<&str>,
    sender: &str,
    repo_url: &str,
) -> Value {
    assert_eq!(body["event"], event);
    match action {
        Some(a) => assert_eq!(body["action"], a),
        None => assert!(body["action"].is_null(), "action is null: {body}"),
    }
    match cause {
        Some(c) => assert_eq!(body["cause"], c),
        None => assert!(body["cause"].is_null(), "cause is null: {body}"),
    }
    let at = body["at"].as_str().expect("at is a string");
    assert!(
        at.contains('T') && at.ends_with('Z'),
        "at is RFC 3339 UTC: {at}"
    );
    assert_eq!(body["sender"], json!({"handle": sender}));
    assert_eq!(body["repository"]["owner"], "alice");
    assert_eq!(body["repository"]["name"], "proj");
    assert_eq!(body["repository"]["full_name"], "alice/proj");
    assert_eq!(body["repository"]["url"], repo_url);
    let subject = body[event].clone();
    assert!(subject.is_object(), "subject under '{event}': {body}");
    subject
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
    let bob_created = c.create_hook(&c.bob_rw, &sink_url, &["check"]).await;
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
async fn hook_create_rejects_legacy_event_names() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, _sink) = Sink::spawn(false).await;

    // Every legacy name is unknown now: a clean cutover, no dual support.
    for legacy in [
        "trail.opened",
        "trail.closed",
        "change.opened",
        "revision.pushed",
        "review.submitted",
        "change.merged",
        "status.updated",
    ] {
        let res = client
            .post(c.hooks())
            .bearer_auth(&c.alice_rw)
            .json(&json!({"url": sink_url, "events": [legacy]}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "legacy event {legacy} rejected");
    }

    // The five spec types are accepted.
    for events in [
        vec!["push"],
        vec!["trail"],
        vec!["review"],
        vec!["check"],
        vec!["session"],
        vec!["trail", "check"],
    ] {
        let res = client
            .post(c.hooks())
            .bearer_auth(&c.alice_rw)
            .json(&json!({"url": sink_url, "events": events}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "events {events:?} accepted");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn event_filter_and_signed_delivery() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;

    let created = c.create_hook(&c.alice_rw, &sink_url, &["check"]).await;
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
    assert_eq!(res.status(), 201);

    c.s.core.run_due_jobs().await.unwrap();
    let hits = sink.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1, "only the subscribed event delivers");
    let hit = &hits[0];
    assert_eq!(hit.event.as_deref(), Some("check"));
    let body = check_delivery(hit, &secret);
    let repo_url = format!("{}/alice/proj", c.s.base);
    let subject = check_envelope(&body, "check", None, None, "alice", &repo_url);
    assert_eq!(subject["sha"], sha);
    assert_eq!(subject["context"], "ci/unit");
    assert_eq!(subject["state"], "success");
    assert_eq!(subject["creator"], "alice");

    // Delivery row recorded with the 2xx status.
    let hook_id = created["id"].as_i64().unwrap();
    let deliveries = starforged_db::checks::recent_deliveries(c.s.core.db(), hook_id, 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].event, "check");
    assert_eq!(deliveries[0].status_code, Some(200));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn emitters_deliver_the_spec_envelope() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    let repo_url = format!("{}/alice/proj", c.s.base);

    // Push the branches every change below tracks.
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    for branch in ["feature/a", "feature/c1", "feature/c2"] {
        git_ok(&work, &["checkout", "-q", "-b", branch]).await;
        commit_files(&work, &[("a.txt", format!("{branch}\n").as_bytes())], "add").await;
    }
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &url,
            "main",
            "feature/a",
            "feature/c1",
            "feature/c2",
        ],
    )
    .await;
    // The push scan runs asynchronously after `git push` returns; its
    // branch-move pass must finish before any change exists, or it would
    // append a second revision. Push events are emitted in the same pass,
    // so four delivered push events mean the scan is done.
    let pushed = delivered_until(&c, &sink, &secret, 0, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 4
    })
    .await;
    assert_eq!(
        pushed.iter().filter(|b| b["event"] == "push").count(),
        4,
        "one push event per pushed ref: {pushed:?}"
    );
    let tip_a = git_ok(&work, &["rev-parse", "feature/a"])
        .await
        .trim()
        .to_owned();

    let trail_rw =
        c.s.token(&c.alice, &[Scope::RepoRead, Scope::TrailWrite])
            .await;
    let full =
        c.s.token(
            &c.alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;

    // Trail A: open, one branch change, review, status, merge (flips merged).
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&trail_rw)
        .json(&json!({"title": "feature work", "intent": "ship it"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let a = res.json::<Value>().await.unwrap()["number"]
        .as_i64()
        .unwrap();
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{a}/changes")))
        .bearer_auth(&full)
        .json(&json!({"kind": "branch", "head_branch": "feature/a", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let opened = res.json::<Value>().await.unwrap();
    // Proves the current revision before the default review below: with the
    // initial scan drained above, the new change opens at revision 1.
    assert_eq!(
        opened["current_revision"], 1,
        "new change opens at revision 1: {opened:?}"
    );
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{a}/changes/1/reviews"
        )))
        .bearer_auth(&full)
        .json(&json!({"verdict": "approve", "body": "lgtm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/statuses/{tip_a}")))
        .bearer_auth(&c.alice_rw)
        .json(&json!({"state": "success", "context": "ci/unit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    // A new commit on the tracked branch appends revision 2. It is empty
    // on purpose: a content change would move main's tree on merge and
    // poison trail C's later merge (both sides would differ from base A1).
    // The pointer-based wait proves the scan landed before asserting.
    git_ok(&work, &["checkout", "-q", "feature/a"]).await;
    git_ok(&work, &["commit", "-q", "--allow-empty", "-m", "a v2"]).await;
    git_ok(&work, &["push", "-q", &url, "feature/a"]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let trail_row = starforged_db::trails::trail_by_number(c.s.core.db(), repo_id, a)
        .await
        .unwrap()
        .expect("trail A exists");
    let change_id = starforged_db::changes::changes_of_trail(c.s.core.db(), trail_row.id)
        .await
        .unwrap()
        .iter()
        .find(|row| row.number == 1)
        .expect("change 1 exists")
        .id;
    wait_for_current_revision(&c.s, change_id, 2).await;
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{a}/changes/1/merge"
        )))
        .bearer_auth(&full)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());

    // Trail B: open, then close.
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&trail_rw)
        .json(&json!({"title": "wontfix", "intent": "no"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let b = res.json::<Value>().await.unwrap()["number"]
        .as_i64()
        .unwrap();
    c.s.core
        .set_trail_state(&c.alice, "alice", "proj", b, "closed")
        .await
        .unwrap();

    // Trail C: two changes; merging the first leaves the trail open.
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&trail_rw)
        .json(&json!({"title": "two changes", "intent": "both"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let n = res.json::<Value>().await.unwrap()["number"]
        .as_i64()
        .unwrap();
    for head in ["feature/c1", "feature/c2"] {
        let res = client
            .post(c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes")))
            .bearer_auth(&full)
            .json(&json!({"kind": "branch", "head_branch": head, "base_branch": "main"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "{}", res.text().await.unwrap());
    }
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
    let hits = sink.hits.lock().unwrap().clone();
    let bodies: Vec<Value> = hits
        .iter()
        .map(|hit| check_delivery(hit, &secret))
        .collect();
    // Every delivery carries the spec envelope with the right subject key.
    let find = |event: &str, action: Option<&str>, cause: Option<&str>| -> Value {
        bodies
            .iter()
            .find(|b| {
                b["event"] == event
                    && match action {
                        Some(a) => b["action"] == a,
                        None => b["action"].is_null(),
                    }
                    && match cause {
                        Some(x) => b["cause"] == x,
                        None => b["cause"].is_null(),
                    }
            })
            .unwrap_or_else(|| panic!("missing {event}/{action:?}/{cause:?} in {bodies:?}"))
            .clone()
    };

    let subject = check_envelope(
        &find("trail", Some("opened"), None),
        "trail",
        Some("opened"),
        None,
        "alice",
        &repo_url,
    );
    assert_eq!(subject["number"], a);
    assert_eq!(subject["title"], "feature work");
    assert_eq!(subject["state"], "open");
    assert_eq!(subject["author"], "alice");
    assert_eq!(subject["url"], format!("{repo_url}/trails/{a}"));
    assert!(subject.get("change").is_none());

    // Opening a branch change emits exactly one trail event.
    let opened_change: Vec<&Value> = bodies
        .iter()
        .filter(|b| {
            b["event"] == "trail"
                && b["action"] == "updated"
                && b["cause"] == "change_opened"
                && b["trail"]["number"] == a
        })
        .collect();
    assert_eq!(
        opened_change.len(),
        1,
        "opening a change emits exactly one event: {bodies:?}"
    );
    let subject = check_envelope(
        opened_change[0],
        "trail",
        Some("updated"),
        Some("change_opened"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["number"], a);
    assert_eq!(subject["change"]["k"], 1);
    assert_eq!(subject["change"]["revision"], 1);

    // revision_pushed fires only for the deliberate second push: exactly
    // one, with revision 2.
    let pushed: Vec<&Value> = bodies
        .iter()
        .filter(|b| {
            b["event"] == "trail"
                && b["action"] == "updated"
                && b["cause"] == "revision_pushed"
                && b["trail"]["number"] == a
        })
        .collect();
    assert_eq!(pushed.len(), 1, "exactly one revision_pushed: {bodies:?}");
    let subject = check_envelope(
        pushed[0],
        "trail",
        Some("updated"),
        Some("revision_pushed"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["number"], a);
    assert_eq!(subject["change"]["k"], 1);
    assert_eq!(subject["change"]["revision"], 2);

    let subject = check_envelope(
        &find("review", Some("submitted"), None),
        "review",
        Some("submitted"),
        None,
        "alice",
        &repo_url,
    );
    assert_eq!(subject["trail"], a);
    assert_eq!(subject["change"], 1);
    assert_eq!(subject["revision"], 1);
    assert_eq!(subject["verdict"], "approve");
    assert_eq!(subject["author"], "alice");
    assert_eq!(subject["body"], "lgtm");

    let subject = check_envelope(
        &find("check", None, None),
        "check",
        None,
        None,
        "alice",
        &repo_url,
    );
    assert_eq!(subject["sha"], tip_a);
    assert_eq!(subject["context"], "ci/unit");
    assert_eq!(subject["state"], "success");
    assert_eq!(subject["creator"], "alice");

    // The merge that empties the trail emits exactly one event: merged.
    let merged = bodies
        .iter()
        .filter(|b| b["event"] == "trail" && b["action"] == "merged")
        .count();
    assert_eq!(merged, 1, "exactly one merged event: {bodies:?}");
    let subject = check_envelope(
        &find("trail", Some("merged"), None),
        "trail",
        Some("merged"),
        None,
        "alice",
        &repo_url,
    );
    assert_eq!(subject["number"], a);
    assert_eq!(subject["state"], "merged");
    assert_eq!(subject["change"]["k"], 1);

    let subject = check_envelope(
        &find("trail", Some("closed"), None),
        "trail",
        Some("closed"),
        None,
        "alice",
        &repo_url,
    );
    assert_eq!(subject["number"], b);

    // Merging one of two open changes keeps the trail open: updated.
    let subject = check_envelope(
        &find("trail", Some("updated"), Some("change_merged")),
        "trail",
        Some("updated"),
        Some("change_merged"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["number"], n);
    assert_eq!(subject["state"], "open");
    assert_eq!(subject["change"]["k"], 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_ladder_then_terminal_failure() {
    let c = Ctx::start().await;
    let (fail_url, _fail) = Sink::spawn(true).await;
    let created = c.create_hook(&c.alice_rw, &fail_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();

    // One event → one job.
    use starforged_core::webhooks::HookEvent;
    c.s.core
        .dispatch_event(
            1,
            HookEvent {
                event: "check",
                action: None,
                cause: None,
                sender: None,
                subject: json!({"sha": "a"}),
            },
        )
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
        // Every attempt writes exactly one row: attempts 1..=i+1 logged,
        // all under one delivery id.
        let logged = starforged_db::checks::recent_deliveries(c.s.core.db(), hook_id, 10)
            .await
            .unwrap();
        assert_eq!(logged.len(), i + 1, "one row per attempt");
        let mut attempts: Vec<i64> = logged.iter().map(|d| d.attempt.unwrap()).collect();
        attempts.sort_unstable();
        assert_eq!(attempts, (1..=(i as i64 + 1)).collect::<Vec<_>>());
        assert!(logged.iter().all(|d| d.status_code == Some(500)));
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
    assert_eq!(deliveries.len(), 5, "one row per attempt: {deliveries:?}");
    let mut attempts: Vec<i64> = deliveries.iter().map(|d| d.attempt.unwrap()).collect();
    attempts.sort_unstable();
    assert_eq!(attempts, vec![1, 2, 3, 4, 5]);
    let first = deliveries[0].delivery_id.clone().unwrap();
    assert!(
        deliveries
            .iter()
            .all(|d| d.delivery_id.as_deref() == Some(first.as_str()))
    );
    assert!(deliveries.iter().all(|d| d.status_code == Some(500)));
    let newest = deliveries
        .iter()
        .max_by_key(|d| d.attempt.unwrap())
        .unwrap();
    assert!(newest.error.as_deref().unwrap_or("").contains("500"));

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
    use starforged_core::webhooks::HookEvent;
    c.s.core
        .dispatch_event(
            1,
            HookEvent {
                event: "check",
                action: None,
                cause: None,
                sender: None,
                subject: json!({"sha": "b"}),
            },
        )
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
        .dispatch_event(
            1,
            HookEvent {
                event: "check",
                action: None,
                cause: None,
                sender: None,
                subject: json!({"sha": "c"}),
            },
        )
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
        5,
        "dead endpoint logs every attempt, then goes terminal"
    );
    assert!(
        deliveries[0].status_code.is_none(),
        "transport error has no status"
    );

    // A healthy hook still delivers afterwards: the queue is not wedged.
    c.create_hook(&c.alice_rw, &sink_url, &["check"]).await;
    c.s.core
        .dispatch_event(
            1,
            HookEvent {
                event: "check",
                action: None,
                cause: None,
                sender: None,
                subject: json!({"sha": "d"}),
            },
        )
        .await;
    c.s.core.run_due_jobs().await.unwrap();
    assert_eq!(sink.events(), vec!["check".to_string()]);
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
    // The push's two events (main + feature/x creates) arrive asynchronously;
    // wait for them before driving the lifecycle over HTTP.
    let pushed = delivered_until(&c, &sink, &secret, 0, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 2
    })
    .await;
    assert_eq!(
        pushed.iter().filter(|b| b["event"] == "push").count(),
        2,
        "one push event per created branch: {pushed:?}"
    );

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
    assert_eq!(res.status(), 201);

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
    for want in ["trail", "review", "check"] {
        assert!(got.contains(&want.to_string()), "missing {want} in {got:?}");
    }
    // Trail, review, and check events all verify against the hook secret.
    for hit in sink.hits.lock().unwrap().iter() {
        check_delivery(hit, &secret);
    }
    // The single-change merge flips the trail: exactly one merged event.
    let bodies = sink.bodies();
    assert_eq!(
        bodies
            .iter()
            .filter(|b| b["event"] == "trail" && b["action"] == "merged")
            .count(),
        1,
        "exactly one merged event: {bodies:?}"
    );
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
    // The five spec event types are the subscription checkboxes.
    for event in ["push", "trail", "review", "check", "session"] {
        assert!(page.contains(&format!("value=\"{event}\"")), "{page}");
    }
    let csrf = extract_input(&page, "_csrf");

    // Create via the form: the secret shows once in the response...
    let res = mia
        .post(c.s.url("/alice/proj/settings/hooks"))
        .form(&HashMap::from([
            ("_csrf", csrf.as_str()),
            ("url", sink_url.as_str()),
            ("events", "check"),
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

/// Pointer-based wait for a change's current revision: the revision row
/// lands before the change's current-revision pointer moves, so a bare row
/// count can read stale. Same approach as web_changes.rs.
async fn wait_for_current_revision(s: &TestServer, change_id: i64, expected: i64) {
    let start = std::time::Instant::now();
    loop {
        let pointed = starforged_db::changes::change_by_id(s.core.db(), change_id)
            .await
            .unwrap()
            .and_then(|row| row.current_revision_id);
        let number = match pointed {
            Some(id) => starforged_db::changes::revision_by_id(s.core.db(), id)
                .await
                .unwrap()
                .map(|row| row.number),
            None => None,
        };
        if number == Some(expected) {
            return;
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "timed out waiting for current revision {expected}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Drains due webhook jobs and returns the verified envelopes delivered
/// since `from` (index into `sink.hits`).
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
/// sleeps until `ready` holds or 10 s pass, then returns what arrived —
/// the caller's assert shows the real content on timeout.
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

fn hits(sink: &Sink) -> usize {
    sink.hits.lock().unwrap().len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_edit_ready_reopen_events() {
    let c = Ctx::start().await;
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    let repo_url = format!("{}/alice/proj", c.s.base);
    let core = &c.s.core;

    let t = core
        .create_trail(&c.alice, "alice", "proj", "orig", "why")
        .await
        .unwrap();
    let mut from = hits(&sink);
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["event"], json!("trail"));
    assert_eq!(got[0]["action"], json!("opened"));
    from = hits(&sink);

    // Title edit -> updated/edited.
    core.update_trail(
        &c.alice,
        "alice",
        "proj",
        t.number,
        Some("renamed"),
        None,
        None,
    )
    .await
    .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1, "one event per edit: {got:?}");
    let subject = check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("edited"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["title"], "renamed");
    from = hits(&sink);

    // Idempotent repeat -> nothing.
    core.update_trail(
        &c.alice,
        "alice",
        "proj",
        t.number,
        Some("renamed"),
        None,
        None,
    )
    .await
    .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(got.is_empty(), "idempotent edit emits nothing: {got:?}");

    // Intent edit -> updated/edited.
    core.update_trail(
        &c.alice,
        "alice",
        "proj",
        t.number,
        None,
        Some("new why"),
        None,
    )
    .await
    .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("edited"),
        "alice",
        &repo_url,
    );
    from = hits(&sink);

    // Title + ready in one call -> exactly one event, and ready wins.
    core.update_trail(
        &c.alice,
        "alice",
        "proj",
        t.number,
        Some("v2"),
        Some("w2"),
        Some(true),
    )
    .await
    .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1, "one event for a multi-field update: {got:?}");
    check_envelope(&got[0], "trail", Some("ready"), None, "alice", &repo_url);
    from = hits(&sink);

    // Ready cleared -> updated/ready_cleared.
    core.update_trail(&c.alice, "alice", "proj", t.number, None, None, Some(false))
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("ready_cleared"),
        "alice",
        &repo_url,
    );
    from = hits(&sink);

    // Close (K1) then reopen -> updated/reopened. Reopening again -> nothing.
    core.set_trail_state(&c.alice, "alice", "proj", t.number, "closed")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    check_envelope(&got[0], "trail", Some("closed"), None, "alice", &repo_url);
    from = hits(&sink);
    core.set_trail_state(&c.alice, "alice", "proj", t.number, "open")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1, "reopen emits one event: {got:?}");
    let subject = check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("reopened"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["state"], "open");
    from = hits(&sink);
    core.set_trail_state(&c.alice, "alice", "proj", t.number, "open")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(
        got.is_empty(),
        "reopening an open trail emits nothing: {got:?}"
    );
    let _ = from;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_label_assignee_change_state_events() {
    let c = Ctx::start().await;
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    let repo_url = format!("{}/alice/proj", c.s.base);
    let core = &c.s.core;
    let bob = core
        .user_by_handle("bob")
        .await
        .unwrap()
        .expect("bob exists");

    let t = core
        .create_trail(&c.alice, "alice", "proj", "labeled", "why")
        .await
        .unwrap();
    let mut from = hits(&sink);
    delivered_from(&c, &sink, &secret, from).await;
    from = hits(&sink);

    core.add_label(&c.alice, "alice", "proj", t.number, "Bug")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("labeled"),
        "alice",
        &repo_url,
    );
    from = hits(&sink);
    // Duplicate add is a no-op row-wise, so it dispatches nothing.
    core.add_label(&c.alice, "alice", "proj", t.number, "bug")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(got.is_empty(), "duplicate label emits nothing: {got:?}");
    core.remove_label(&c.alice, "alice", "proj", t.number, "BUG")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("unlabeled"),
        "alice",
        &repo_url,
    );
    from = hits(&sink);
    core.remove_label(&c.alice, "alice", "proj", t.number, "bug")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(
        got.is_empty(),
        "removing a missing label emits nothing: {got:?}"
    );

    core.add_assignee(&c.alice, "alice", "proj", t.number, "bob")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("assigned"),
        "alice",
        &repo_url,
    );
    from = hits(&sink);
    core.add_assignee(&c.alice, "alice", "proj", t.number, "BOB")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(got.is_empty(), "duplicate assignee emits nothing: {got:?}");
    core.remove_assignee(&c.alice, "alice", "proj", t.number, "bob")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1);
    check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("unassigned"),
        "alice",
        &repo_url,
    );
    from = hits(&sink);

    // A branch change gives close/reopen something to point at.
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/k"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/k"]).await;
    // The push scan runs asynchronously; wait for both push events before
    // the change exists, so no late scan revision can pollute the exact
    // counts below.
    delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 2
    })
    .await;
    core.create_branch_change(&c.alice, "alice", "proj", t.number, "feature/k", "main")
        .await
        .unwrap();
    // Drain the creation events (trail opened, change opened): `from`
    // counts delivered hits, and these jobs are still pending.
    delivered_from(&c, &sink, &secret, from).await;
    from = hits(&sink);

    core.set_change_state(&c.alice, "alice", "proj", t.number, 1, "closed")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1, "change close emits one event: {got:?}");
    let subject = check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("change_closed"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["change"]["k"], 1);
    assert_eq!(subject["change"]["revision"], 1);
    from = hits(&sink);
    core.set_change_state(&c.alice, "alice", "proj", t.number, 1, "open")
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1, "change reopen emits one event: {got:?}");
    let subject = check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("change_reopened"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["change"]["k"], 1);
    let _ = (bob, from);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_dismissal_events() {
    let c = Ctx::start().await;
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    let repo_url = format!("{}/alice/proj", c.s.base);
    let core = &c.s.core;
    let bob = core
        .user_by_handle("bob")
        .await
        .unwrap()
        .expect("bob exists");

    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/d"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/d"]).await;
    let mut from = hits(&sink);
    // The push scan runs asynchronously; wait for both push events before
    // the change exists, so no late scan revision can move the review off
    // revision 1 or pollute the exact counts below.
    delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 2
    })
    .await;

    let t = core
        .create_trail(&c.alice, "alice", "proj", "dismiss", "why")
        .await
        .unwrap();
    core.create_branch_change(&c.alice, "alice", "proj", t.number, "feature/d", "main")
        .await
        .unwrap();
    let (review, _) = core
        .submit_review(
            &c.alice,
            "alice",
            "proj",
            t.number,
            1,
            None,
            "approve",
            "lgtm",
            None,
            &[],
        )
        .await
        .unwrap();
    // Drain the creation events (trail opened, change opened): `from`
    // counts delivered hits, and these jobs are still pending.
    delivered_from(&c, &sink, &secret, from).await;
    from = hits(&sink);

    // Explicit dismissal names the dismisser as sender.
    core.dismiss_review(&bob, "alice", "proj", t.number, 1, review.id)
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1, "explicit dismissal emits one event: {got:?}");
    assert!(
        got[0]["sender"] == json!({"handle": "bob"}),
        "sender is the dismisser: {got:?}"
    );
    let subject = check_envelope(&got[0], "review", Some("dismissed"), None, "bob", &repo_url);
    assert_eq!(subject["id"], review.id);
    assert_eq!(subject["trail"], t.number);
    assert_eq!(subject["change"], 1);
    assert_eq!(subject["revision"], 1);
    assert_eq!(subject["verdict"], "approve");
    assert_eq!(subject["state"], "dismissed");
    assert_eq!(subject["author"], "alice");
    assert_eq!(subject["body"], "lgtm");
    from = hits(&sink);
    // Dismissing again is a no-op row-wise, so it dispatches nothing.
    core.dismiss_review(&bob, "alice", "proj", t.number, 1, review.id)
        .await
        .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(got.is_empty(), "repeat dismissal emits nothing: {got:?}");

    // Automatic dismiss-on-push: sender is null, one event per dismissed review.
    let repo_id = core
        .repo_for(Some(&c.alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    starforged_db::checks::insert_gate_rule(
        core.db(),
        repo_id,
        None,
        1,
        true,
        false,
        "[]",
        false,
        false,
        false,
        "[]",
        false,
        false,
        false,
        starforged_db::now(),
    )
    .await
    .unwrap();
    let (review2, _) = core
        .submit_review(
            &c.alice,
            "alice",
            "proj",
            t.number,
            1,
            None,
            "approve",
            "still lgtm",
            None,
            &[],
        )
        .await
        .unwrap();
    delivered_from(&c, &sink, &secret, from).await;
    from = hits(&sink);
    let (zero, one) = ("0".repeat(40), "1".repeat(40));
    core.record_branch_move(
        repo_id,
        "feature/d",
        Some(zero.as_str()),
        &one,
        Some(bob.id),
    )
    .await
    .unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    let dismissed: Vec<&Value> = got
        .iter()
        .filter(|b| b["event"] == "review" && b["action"] == "dismissed")
        .collect();
    assert_eq!(dismissed.len(), 1, "one auto-dismissal event: {got:?}");
    assert!(
        dismissed[0]["sender"].is_null(),
        "auto-dismissal sender is null: {got:?}"
    );
    assert_eq!(dismissed[0]["review"]["id"], review2.id);
    assert_eq!(dismissed[0]["review"]["revision"], 1);
    assert_eq!(dismissed[0]["review"]["author"], "alice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_events_cover_create_update_delete_tag_and_skip_non_branch_refs() {
    let c = Ctx::start().await;
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    let repo_url = format!("{}/alice/proj", c.s.base);
    let core = &c.s.core;

    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/p"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/p"]).await;
    let tip1 = git_ok(&work, &["rev-parse", "feature/p"])
        .await
        .trim()
        .to_owned();
    let got = delivered_until(&c, &sink, &secret, 0, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 2
    })
    .await;
    let pushes: Vec<&Value> = got.iter().filter(|b| b["event"] == "push").collect();
    assert_eq!(
        pushes.len(),
        2,
        "one push event per created branch: {got:?}"
    );
    for body in &pushes {
        assert!(body["action"].is_null(), "push action is null: {body}");
        assert!(body["cause"].is_null(), "push cause is null: {body}");
        let subject = check_envelope(body, "push", None, None, "alice", &repo_url);
        assert_eq!(subject["created"], true);
        assert_eq!(subject["deleted"], false);
        assert_eq!(subject["before"], "0".repeat(40));
        assert_eq!(subject["pusher"], "alice");
    }
    let mut from = hits(&sink);

    // Branch update.
    commit_files(&work, &[("a.txt", b"one\ntwo\nthree\n")], "add three").await;
    git_ok(&work, &["push", "-q", &url, "feature/p"]).await;
    let tip2 = git_ok(&work, &["rev-parse", "feature/p"])
        .await
        .trim()
        .to_owned();
    let got = delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 1
    })
    .await;
    let pushes: Vec<&Value> = got.iter().filter(|b| b["event"] == "push").collect();
    assert_eq!(pushes.len(), 1, "one push event for the update: {got:?}");
    let subject = check_envelope(pushes[0], "push", None, None, "alice", &repo_url);
    assert_eq!(subject["ref"], "refs/heads/feature/p");
    assert_eq!(subject["before"], tip1);
    assert_eq!(subject["after"], tip2);
    assert_eq!(subject["created"], false);
    assert_eq!(subject["deleted"], false);
    from = hits(&sink);

    // Tag push.
    git_ok(&work, &["tag", "v1"]).await;
    git_ok(&work, &["push", "-q", &url, "tag", "v1"]).await;
    let tag_sha = git_ok(&work, &["rev-list", "-n", "1", "v1"])
        .await
        .trim()
        .to_owned();
    let got = delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 1
    })
    .await;
    let pushes: Vec<&Value> = got.iter().filter(|b| b["event"] == "push").collect();
    assert_eq!(pushes.len(), 1, "tag pushes emit push: {got:?}");
    let subject = check_envelope(pushes[0], "push", None, None, "alice", &repo_url);
    assert_eq!(subject["ref"], "refs/tags/v1");
    assert_eq!(subject["after"], tag_sha);
    assert_eq!(subject["created"], true);
    assert_eq!(subject["deleted"], false);
    from = hits(&sink);

    // Branch delete.
    git_ok(&work, &["push", "-q", &url, ":refs/heads/feature/p"]).await;
    let got = delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 1
    })
    .await;
    let pushes: Vec<&Value> = got.iter().filter(|b| b["event"] == "push").collect();
    assert_eq!(pushes.len(), 1, "branch deletes emit push: {got:?}");
    let subject = check_envelope(pushes[0], "push", None, None, "alice", &repo_url);
    assert_eq!(subject["ref"], "refs/heads/feature/p");
    assert_eq!(subject["before"], tip2);
    assert_eq!(subject["after"], "0".repeat(40));
    assert_eq!(subject["created"], false);
    assert_eq!(subject["deleted"], true);
    from = hits(&sink);

    // A refs/for push ingests a trail change and never emits push. Opening
    // the agit change emits exactly one trail event.
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main"]).await;
    delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().any(|b| {
            b["event"] == "trail" && b["action"] == "updated" && b["cause"] == "change_opened"
        })
    })
    .await;
    // One more drain: the open and its (removed) double would arrive
    // together, so count only after everything due has landed.
    c.s.core.run_due_jobs().await.unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(
        got.len(),
        1,
        "opening an agit change emits exactly one event: {got:?}"
    );
    assert!(
        got.iter().all(|b| b["event"] != "push"),
        "refs/for pushes never emit push: {got:?}"
    );
    let subject = check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("change_opened"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["change"]["k"], 1);
    assert_eq!(subject["change"]["revision"], 1);
    from = hits(&sink);

    // A second refs/for push with new content appends revision 2 to the
    // same change: exactly one revision_pushed.
    commit_files(&work, &[("a.txt", b"one\ntwo\nthree\nfour\n")], "add four").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main"]).await;
    delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().any(|b| {
            b["event"] == "trail" && b["action"] == "updated" && b["cause"] == "revision_pushed"
        })
    })
    .await;
    c.s.core.run_due_jobs().await.unwrap();
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(
        got.len(),
        1,
        "a second agit push emits exactly one event: {got:?}"
    );
    let subject = check_envelope(
        &got[0],
        "trail",
        Some("updated"),
        Some("revision_pushed"),
        "alice",
        &repo_url,
    );
    assert_eq!(subject["change"]["k"], 1);
    assert_eq!(subject["change"]["revision"], 2);
    from = hits(&sink);

    // Server-side trail refs and refs/for names never emit push, even direct.
    let repo_id = core
        .repo_for(Some(&c.alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    core.record_push(
        repo_id,
        Some(&c.alice),
        &[
            starforged_core::changes::RefUpdate {
                name: "refs/trails/1/1/head".into(),
                old: "0".repeat(40),
                new: tip1.clone(),
            },
            starforged_core::changes::RefUpdate {
                name: "refs/for/main".into(),
                old: "0".repeat(40),
                new: tip1.clone(),
            },
        ],
    )
    .await;
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(
        got.iter().all(|b| b["event"] != "push"),
        "server trail refs never emit push: {got:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_upload_quarantine_publish_events() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;
    // Sessions publish only on public repos.
    c.s.repo(&c.alice, "pub", Visibility::Public).await;
    let created = {
        let res = client
            .post(c.s.url("/api/v1/repos/alice/pub/hooks"))
            .bearer_auth(&c.alice_rw)
            .json(&json!({"url": sink_url, "events": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        res.json::<Value>().await.unwrap()
    };
    let secret = created["secret"].as_str().unwrap().to_owned();
    let repo_url = format!("{}/alice/pub", c.s.base);
    let upload = c.s.token(&c.alice, &[Scope::SessionUpload]).await;

    let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
    let title = "Secret Project Alpha";
    let quarantining = json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": title,
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 1, "output": 2, "cache_read": 3, "cache_write": 4, "reasoning": 5},
        "files_touched": ["src/file with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 inside.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    });
    let res = client
        .put(c.s.url(&format!("/api/v1/repos/alice/pub/sessions/{ulid}")))
        .bearer_auth(&upload)
        .json(&quarantining)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());
    let got = delivered_from(&c, &sink, &secret, 0).await;
    let quarantined: Vec<&Value> = got
        .iter()
        .filter(|b| b["event"] == "session" && b["action"] == "quarantined")
        .collect();
    assert_eq!(
        quarantined.len(),
        1,
        "quarantine at ingest emits once: {got:?}"
    );
    assert!(
        quarantined[0]["sender"].is_null(),
        "quarantine sender is null: {got:?}"
    );
    let subject = check_envelope_session(quarantined[0], "quarantined", &repo_url);
    assert_eq!(subject["ulid"], ulid);
    assert_eq!(subject["uploader"], "alice");
    assert_eq!(subject["agent"], "claude-code");
    assert_eq!(subject["quarantine_state"], "quarantined");
    let mut from = hits(&sink);

    // Complete -> uploaded, with the uploader as sender.
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/pub/sessions/{ulid}/complete")))
        .bearer_auth(&upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());
    let got = delivered_from(&c, &sink, &secret, from).await;
    let uploaded: Vec<&Value> = got
        .iter()
        .filter(|b| b["event"] == "session" && b["action"] == "uploaded")
        .collect();
    assert_eq!(uploaded.len(), 1, "complete emits uploaded once: {got:?}");
    let subject = check_envelope_session(uploaded[0], "uploaded", &repo_url);
    assert_eq!(subject["ulid"], ulid);
    assert_eq!(subject["lifecycle_state"], "complete");
    assert_eq!(uploaded[0]["sender"], json!({"handle": "alice"}));
    from = hits(&sink);
    // Idempotent re-complete emits nothing.
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/pub/sessions/{ulid}/complete")))
        .bearer_auth(&upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert!(
        got.iter()
            .all(|b| !(b["event"] == "session" && b["action"] == "uploaded")),
        "re-complete emits nothing: {got:?}"
    );
    from = hits(&sink);

    // Publish -> published, with the acting user as sender.
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/pub/sessions/{ulid}/publish")))
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());
    let got = delivered_from(&c, &sink, &secret, from).await;
    let published: Vec<&Value> = got
        .iter()
        .filter(|b| b["event"] == "session" && b["action"] == "published")
        .collect();
    assert_eq!(published.len(), 1, "publish emits published once: {got:?}");
    let subject = check_envelope_session(published[0], "published", &repo_url);
    assert_eq!(subject["visibility"], "published");
    assert_eq!(published[0]["sender"], json!({"handle": "alice"}));

    // Session payloads carry identifiers and state only: no title, no
    // quarantine reason, no transcript text anywhere in any session body.
    for hit in sink.hits.lock().unwrap().iter() {
        let raw = String::from_utf8_lossy(&hit.body);
        let body: Value = serde_json::from_slice(&hit.body).unwrap();
        if body["event"] != "session" {
            continue;
        }
        assert!(!raw.contains(title), "session body leaks the title: {raw}");
        assert!(
            !raw.contains("known-token"),
            "session body leaks the quarantine reason: {raw}"
        );
        assert!(
            !raw.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            "session body leaks file text: {raw}"
        );
        let keys: Vec<&str> = body["session"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "agent",
                "lifecycle_state",
                "quarantine_state",
                "ulid",
                "uploader",
                "visibility"
            ],
            "exact session subject: {raw}"
        );
    }
}

/// Session envelope check: like [`check_envelope`] but the sender varies by
/// transition (uploader, null, actor), so only the subject is pinned here.
fn check_envelope_session<'a>(body: &'a Value, action: &str, repo_url: &str) -> &'a Value {
    assert_eq!(body["event"], "session");
    assert_eq!(body["action"], action);
    assert!(body["cause"].is_null(), "session cause is null: {body}");
    assert_eq!(body["repository"]["full_name"], "alice/pub");
    assert_eq!(body["repository"]["url"], repo_url);
    &body["session"]
}

// ==== K3: per-attempt delivery log + redelivery (plus subscription-invalid fold-in) ====

use std::sync::atomic::{AtomicUsize, Ordering};

/// A receiver that fails the first `fail_first` POSTs with 500, then answers
/// 200 with `success_body`. Records every hit's headers and raw body.
#[derive(Clone)]
struct FlakySink {
    hits: Arc<Mutex<Vec<Hit>>>,
    remaining_failures: Arc<AtomicUsize>,
    success_body: Vec<u8>,
}

impl FlakySink {
    async fn spawn(fail_first: usize, success_body: Vec<u8>) -> (String, FlakySink) {
        let sink = FlakySink {
            hits: Arc::new(Mutex::new(Vec::new())),
            remaining_failures: Arc::new(AtomicUsize::new(fail_first)),
            success_body,
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
                        let hit = Hit {
                            event: get("x-starforge-event"),
                            delivery: get("x-starforge-delivery"),
                            signature: get("x-starforge-signature-256"),
                            legacy_signature: get("x-starforge-signature"),
                            user_agent: get("user-agent"),
                            body: body.to_vec(),
                        };
                        if inner.remaining_failures.load(Ordering::SeqCst) > 0 {
                            inner.remaining_failures.fetch_sub(1, Ordering::SeqCst);
                            inner.hits.lock().unwrap().push(hit);
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                axum::body::Body::from("boom"),
                            );
                        }
                        inner.hits.lock().unwrap().push(hit);
                        (
                            axum::http::StatusCode::OK,
                            axum::body::Body::from(inner.success_body.clone()),
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

async fn dispatch_check(c: &Ctx) {
    use starforged_core::webhooks::HookEvent;
    c.s.core
        .dispatch_event(
            1,
            HookEvent {
                event: "check",
                action: None,
                cause: None,
                sender: Some("alice".to_owned()),
                subject: json!({"sha": "abc", "context": "ci", "state": "success"}),
            },
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_attempt_rows_two_failures_then_success() {
    let c = Ctx::start().await;
    // The sink answers 20 KiB on success; only the first 16 KiB is stored.
    let (sink_url, sink) = FlakySink::spawn(2, vec![b'x'; 20 * 1024]).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();
    let secret = created["secret"].as_str().unwrap().to_owned();

    dispatch_check(&c).await;
    // Fail, fail, succeed: drive the ladder manually due.
    c.s.core.run_due_jobs().await.unwrap();
    c.make_due("webhook_delivery").await;
    c.s.core.run_due_jobs().await.unwrap();
    c.make_due("webhook_delivery").await;
    c.s.core.run_due_jobs().await.unwrap();

    assert_eq!(sink.hits.lock().unwrap().len(), 3);
    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();
    assert_eq!(rows.len(), 3, "one row per attempt: {rows:?}");
    // Newest first.
    assert_eq!(rows[0].attempt, 3);
    assert_eq!(rows[1].attempt, 2);
    assert_eq!(rows[2].attempt, 1);
    let first_delivery = rows[2].delivery_id.clone();
    assert!(!first_delivery.is_empty());
    assert!(rows.iter().all(|r| r.delivery_id == first_delivery));
    assert_eq!(rows[2].status_code, Some(500));
    assert_eq!(rows[1].status_code, Some(500));
    assert_eq!(rows[0].status_code, Some(200));
    for row in &rows {
        assert_eq!(row.event, "check");
        assert!(row.duration_ms >= 0, "duration recorded: {row:?}");
        assert!(!row.redelivery);
        let detail =
            c.s.core
                .get_delivery(&c.alice, "alice", "proj", hook_id, row.id)
                .await
                .unwrap();
        let headers: Value = serde_json::from_str(&detail.request_headers).unwrap();
        let sig = headers["x-starforge-signature-256"]
            .as_str()
            .expect("stored request headers carry the signature");
        assert_eq!(
            sig,
            &format!(
                "sha256={}",
                hmac_sha256_hex(&secret, detail.request_body.as_bytes())
            )
        );
        assert!(!detail.request_body.is_empty(), "request body stored");
        let stored = detail.response_body.as_deref().unwrap_or("");
        assert!(stored.len() <= 16 * 1024, "response body capped at 16 KiB");
        assert!(
            !stored.is_empty() || detail.summary.status_code != Some(200),
            "2xx stores its body: {detail:?}"
        );
    }
    // The terminal success stored only the first 16 KiB of the 20 KiB body.
    let detail =
        c.s.core
            .get_delivery(&c.alice, "alice", "proj", hook_id, rows[0].id)
            .await
            .unwrap();
    assert_eq!(
        detail.response_body.as_deref().unwrap_or("").len(),
        16 * 1024
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_denial_writes_error_row_with_request() {
    let c = Ctx::start().await;
    let (sink_url, _sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();
    // Point the hook at a denied address straight in the db (create-time
    // validation would 422 it); the sealed secret stays valid.
    sqlx::query("UPDATE webhooks SET url = $1 WHERE id = $2")
        .bind("http://10.0.0.1/hook")
        .bind(hook_id)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    dispatch_check(&c).await;
    c.s.core.run_due_jobs().await.unwrap();
    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status_code, None);
    assert!(!rows[0].error.as_deref().unwrap_or("").is_empty());
    let detail =
        c.s.core
            .get_delivery(&c.alice, "alice", "proj", hook_id, rows[0].id)
            .await
            .unwrap();
    assert!(
        !detail.request_body.is_empty(),
        "denied attempt stores its request"
    );
    assert!(!detail.request_headers.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeliver_replays_body_under_new_id() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();
    let secret = created["secret"].as_str().unwrap().to_owned();
    dispatch_check(&c).await;
    c.s.core.run_due_jobs().await.unwrap();
    assert_eq!(sink.hits.lock().unwrap().len(), 1);

    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);

    // Redeliver over the API: 202 with a new delivery id.
    let res = client
        .post(format!(
            "{}/{}/deliveries/{}/redeliver",
            c.hooks(),
            hook_id,
            rows[0].id
        ))
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let redelivered: Value = res.json().await.unwrap();
    let new_id = redelivered["delivery_id"].as_str().unwrap().to_owned();
    assert_ne!(new_id, rows[0].delivery_id);

    c.s.core.run_due_jobs().await.unwrap();
    let hits = sink.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 2, "redelivery reaches the receiver");
    assert_eq!(hits[0].body, hits[1].body, "identical body replayed");
    assert_eq!(hits[1].delivery.as_deref(), Some(new_id.as_str()));
    let body: Value = check_delivery(&hits[1], &secret);
    assert_eq!(body["event"], "check");

    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].delivery_id, new_id);
    assert!(rows[0].redelivery);

    // Exactly one timeline row and one audit row per redelivery.
    let timeline: Vec<(String,)> =
        sqlx::query_as("SELECT kind FROM timeline_events WHERE kind = 'webhook.redelivered'")
            .fetch_all(c.s.core.db().pool())
            .await
            .unwrap();
    assert_eq!(timeline.len(), 1);
    let audit: Vec<(String,)> =
        sqlx::query_as("SELECT action FROM audit_log WHERE action = 'webhook.redelivered'")
            .fetch_all(c.s.core.db().pool())
            .await
            .unwrap();
    assert_eq!(audit.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeliver_refuses_bad_states() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (sink_url, _sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();
    dispatch_check(&c).await;
    c.s.core.run_due_jobs().await.unwrap();
    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();
    let redeliver = |token: &str| {
        client
            .post(format!(
                "{}/{}/deliveries/{}/redeliver",
                c.hooks(),
                hook_id,
                rows[0].id
            ))
            .bearer_auth(token)
            .send()
    };

    // Below maintain: 403.
    let res = redeliver(&c.carol_rw).await.unwrap();
    assert_eq!(res.status(), 403);

    // Inactive hook: 422.
    let res = client
        .patch(format!("{}/{}", c.hooks(), hook_id))
        .bearer_auth(&c.alice_rw)
        .json(&json!({"active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = redeliver(&c.alice_rw).await.unwrap();
    assert_eq!(res.status(), 422);

    // Reactivate, then archive the repo: 422.
    let res = client
        .patch(format!("{}/{}", c.hooks(), hook_id))
        .bearer_auth(&c.alice_rw)
        .json(&json!({"active": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    c.s.core
        .archive_repo(&c.alice, "alice", "proj")
        .await
        .unwrap();
    let res = redeliver(&c.alice_rw).await.unwrap();
    assert_eq!(res.status(), 422);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_subscriptions_receive_nothing_and_report() {
    let c = Ctx::start().await;
    let (sink_url, sink) = Sink::spawn(false).await;
    // A hook whose stored subscription names no known event, and one whose
    // stored cell is not JSON at all (written straight to the db, bypassing
    // the create-time validation).
    let sealed = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let hook_id = sealed["id"].as_i64().unwrap();
    sqlx::query("UPDATE webhooks SET events = $1 WHERE id = $2")
        .bind(r#"["foo"]"#)
        .bind(hook_id)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    let other = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let other_id = other["id"].as_i64().unwrap();
    sqlx::query("UPDATE webhooks SET events = $1 WHERE id = $2")
        .bind("not json")
        .bind(other_id)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();

    dispatch_check(&c).await;
    c.s.core.run_due_jobs().await.unwrap();
    assert!(
        sink.hits.lock().unwrap().is_empty(),
        "invalid subscriptions receive nothing"
    );

    for id in [hook_id, other_id] {
        let hooks =
            c.s.core
                .list_webhooks(Some(&c.alice), "alice", "proj")
                .await
                .unwrap();
        let hook = hooks.iter().find(|h| h.id == id).unwrap();
        assert!(hook.events.is_empty(), "invalid reads as no events");
        assert!(hook.subscription_invalid, "invalid is reported");
    }
    let client = reqwest::Client::new();
    let res = client
        .get(c.hooks())
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list: Value = res.json().await.unwrap();
    for hook in list["hooks"].as_array().unwrap() {
        assert_eq!(hook["events"], json!([]));
        assert_eq!(hook["subscription_invalid"], true);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_detail_page_escapes_receiver_body() {
    let c = Ctx::start().await;
    let evil = "<script>alert(1)</script>".as_bytes().to_vec();
    let (sink_url, _sink) = FlakySink::spawn(0, evil).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();
    dispatch_check(&c).await;
    c.s.core.run_due_jobs().await.unwrap();
    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);

    let (browser, _) = c.s.login("alice").await;
    let page = get_text(
        &browser,
        &c.s.url(&format!(
            "/alice/proj/settings/hooks/{}/deliveries/{}",
            hook_id, rows[0].id
        )),
    )
    .await;
    assert!(
        page.contains("&#60;script&#62;"),
        "receiver body is escaped: {page}"
    );
    assert!(
        !page.contains("<script>alert(1)"),
        "raw receiver body never renders: {page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeliver_form_requires_csrf() {
    let c = Ctx::start().await;
    let (sink_url, _sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let hook_id = created["id"].as_i64().unwrap();
    dispatch_check(&c).await;
    c.s.core.run_due_jobs().await.unwrap();
    let rows =
        c.s.core
            .list_deliveries(&c.alice, "alice", "proj", hook_id, None)
            .await
            .unwrap();

    let (browser, _) = c.s.login("alice").await;
    let res = browser
        .post(c.s.url(&format!(
            "/alice/proj/settings/hooks/{}/deliveries/{}/redeliver",
            hook_id, rows[0].id
        )))
        .form(&[("unrelated", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "redeliver without CSRF is forbidden");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_delivery_implies_its_revisions_exist() {
    // D1: the scan records branch moves BEFORE fanning out `push`, so a
    // delivered `push` event implies the push's revisions exist. Three
    // sequential head pushes make a pre-fix ordering slip near-certain to
    // surface: each round waits for its push delivery, then asserts the
    // current revision with no further polling.
    let c = Ctx::start().await;
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &["push"]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();

    let token =
        c.s.token(&c.alice, &[Scope::RepoRead, Scope::RepoWrite])
            .await;
    let url = c.s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/k"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/k"]).await;

    let t =
        c.s.core
            .create_trail(&c.alice, "alice", "proj", "k work", "why")
            .await
            .unwrap();
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", t.number, "feature/k", "main")
        .await
        .unwrap();
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let trail = starforged_db::trails::trail_by_number(c.s.core.db(), repo_id, t.number)
        .await
        .unwrap()
        .unwrap();
    let change = starforged_db::changes::change_by_trail_number(c.s.core.db(), trail.id, 1)
        .await
        .unwrap()
        .unwrap();

    // Drain setup jobs (notably the creation mergeability run) so the
    // delivery polls below observe only this test's pushes.
    c.s.core.run_due_jobs().await.unwrap();

    let mut from = hits(&sink);
    for i in 0..5 {
        commit_files(
            &work,
            &[("round.txt", format!("round {i}\n").as_bytes())],
            &format!("round {i}"),
        )
        .await;
        // The tip SHA is known before the push, so nothing after the
        // delivery may touch the network or the clock.
        let new_tip = git_ok(&work, &["rev-parse", "HEAD"])
            .await
            .trim()
            .to_owned();
        git_ok(&work, &["push", "-q", &url, "feature/k"]).await;
        let got = delivered_until(&c, &sink, &secret, from, |got| {
            got.iter()
                .any(|b| b["event"] == "push" && b["push"]["after"] == new_tip)
        })
        .await;
        assert!(
            got.iter()
                .any(|b| b["event"] == "push" && b["push"]["after"] == new_tip),
            "round {i}: the push event for {new_tip} never arrived: {got:?}"
        );
        from = hits(&sink);
        // IMMEDIATELY: no polling, no sleeps. The delivery may only exist
        // once the scan has recorded the revision.
        let pointed = starforged_db::changes::change_by_id(c.s.core.db(), change.id)
            .await
            .unwrap()
            .unwrap()
            .current_revision_id
            .expect("round {i}: the change points at a revision");
        let head = starforged_db::changes::revision_by_id(c.s.core.db(), pointed)
            .await
            .unwrap()
            .unwrap()
            .head_sha;
        assert_eq!(
            head, new_tip,
            "round {i}: a delivered push implies its revision exists"
        );
    }
}

/// M2f F6 (RED): pending drafts dispatch nothing; submitting the draft
/// emits exactly one `review`/`submitted` event and one timeline row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_review_emits_single_submit_event() {
    let c = Ctx::start().await;
    let (sink_url, sink) = Sink::spawn(false).await;
    let created = c.create_hook(&c.alice_rw, &sink_url, &[]).await;
    let secret = created["secret"].as_str().unwrap().to_owned();
    let repo_url = format!("{}/alice/proj", c.s.base);
    let core = &c.s.core;
    let carol = core
        .user_by_handle("carol")
        .await
        .unwrap()
        .expect("carol exists");
    let carol_rw =
        c.s.token(&carol, &[Scope::RepoRead, Scope::TrailWrite])
            .await;

    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/p"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/p"]).await;
    let mut from = hits(&sink);
    delivered_until(&c, &sink, &secret, from, |got| {
        got.iter().filter(|b| b["event"] == "push").count() == 2
    })
    .await;

    let t = core
        .create_trail(&c.alice, "alice", "proj", "pending", "why")
        .await
        .unwrap();
    core.create_branch_change(&c.alice, "alice", "proj", t.number, "feature/p", "main")
        .await
        .unwrap();
    delivered_from(&c, &sink, &secret, from).await;
    from = hits(&sink);

    // Two pending comments dispatch nothing.
    let client = reqwest::Client::new();
    let threads = c.s.url(&format!(
        "/api/v1/repos/alice/proj/trails/{}/changes/1/threads",
        t.number
    ));
    for body in ["draft one", "draft two"] {
        let res = client
            .post(&threads)
            .bearer_auth(&carol_rw)
            .json(&json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 1, "body": body, "pending": true}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "pending {body}");
    }
    core.run_due_jobs().await.unwrap();
    assert_eq!(hits(&sink), from, "pending drafts dispatch nothing");

    // Submitting converts the draft with exactly one event.
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{}/changes/1/reviews",
            t.number
        )))
        .bearer_auth(&carol_rw)
        .json(&json!({"verdict": "approve", "body": "lgtm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "submit");
    let submitted: Value = res.json().await.unwrap();
    let review_id = submitted["id"].as_i64().unwrap();
    assert_eq!(
        submitted["threads"].as_array().unwrap().len(),
        2,
        "the draft threads attach to the submitted review: {submitted}"
    );
    let got = delivered_from(&c, &sink, &secret, from).await;
    assert_eq!(got.len(), 1, "submit emits one event: {got:?}");
    let subject = check_envelope(
        &got[0],
        "review",
        Some("submitted"),
        None,
        "carol",
        &repo_url,
    );
    assert_eq!(subject["id"], review_id);
    assert_eq!(subject["trail"], t.number);
    assert_eq!(subject["change"], 1);
    assert_eq!(subject["revision"], 1);
    assert_eq!(subject["verdict"], "approve");
    assert_eq!(subject["state"], "submitted");
    assert_eq!(subject["author"], "carol");
    assert_eq!(subject["body"], "lgtm");

    let trail = starforged_db::trails::trail_by_number(
        core.db(),
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id,
        t.number,
    )
    .await
    .unwrap()
    .expect("trail");
    let timeline = starforged_db::trails::timeline_of_trail(core.db(), trail.id)
        .await
        .unwrap();
    assert_eq!(
        timeline
            .iter()
            .filter(|e| e.kind == "review.submitted")
            .count(),
        1,
        "one submitted row: {:?}",
        timeline.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>()
    );
}
