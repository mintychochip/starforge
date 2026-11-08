//! Notification routes: inbox list/read/read-all, repo watch toggles, and
//! Trail subscription toggles over the JSON API.

mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use time::format_description::well_known::Rfc3339;

struct Ctx {
    s: TestServer,
    alice_token: String,
    bob_token: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice_user = s.user("alice").await;
        let bob_user = s.user("bob").await;
        s.repo(&alice_user, "proj", Visibility::Private).await;
        s.core
            .set_collaborator(&alice_user, "alice", "proj", "bob", Permission::Triage)
            .await
            .unwrap();
        let alice_token = s
            .token(&alice_user, &[Scope::RepoRead, Scope::TrailWrite])
            .await;
        let bob_token = s
            .token(&bob_user, &[Scope::RepoRead, Scope::TrailWrite])
            .await;
        Ctx {
            s,
            alice_token,
            bob_token,
        }
    }

    fn trails(&self) -> String {
        self.s.url("/api/v1/repos/alice/proj/trails")
    }

    fn comments(&self, n: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/trails/{n}/comments"))
    }

    async fn create_trail(&self, title: &str) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(self.trails())
            .bearer_auth(&self.alice_token)
            .json(&json!({"title": title, "intent": "do the thing"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create trail");
        res.json::<Value>().await.unwrap()
    }

    async fn comment(&self, n: i64, body: &str) {
        let client = reqwest::Client::new();
        let res = client
            .post(self.comments(n))
            .bearer_auth(&self.bob_token)
            .json(&json!({"body": body}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "post comment");
    }

    async fn notifications(&self, token: &str, query: &str) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .get(self.s.url(&format!("/api/v1/user/notifications{query}")))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap();
        (status, body)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comment_notifies_author_then_read_flows() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let trail = c.create_trail("First trail").await;
    let n = trail["number"].as_i64().unwrap();

    // Opening the trail notifies watchers only: the author has no entry yet.
    let (_, body) = c.notifications(&c.alice_token, "").await;
    assert!(body["notifications"].as_array().unwrap().is_empty());

    c.comment(n, "hello there").await;

    let (status, body) = c.notifications(&c.alice_token, "").await;
    assert_eq!(status, 200);
    let rows = body["notifications"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "one comment notification: {body}");
    let note = &rows[0];
    assert_eq!(note["kind"], "comment");
    assert_eq!(note["repository"], "alice/proj");
    assert_eq!(note["trail_number"], n);
    assert_eq!(note["title"], "First trail");
    assert_eq!(note["actor"], "bob");
    assert_eq!(note["read"], false);
    assert_eq!(note["url"], c.s.url(&format!("/alice/proj/trails/{n}")));
    let created = note["created_at"].as_str().unwrap();
    assert!(
        time::OffsetDateTime::parse(created, &Rfc3339).is_ok(),
        "created_at is RFC 3339: {created}"
    );
    let id = note["id"].as_i64().unwrap();

    // Marking read flips the flag; the unread list empties but `all=1` keeps it.
    let res = client
        .post(c.s.url(&format!("/api/v1/user/notifications/{id}/read")))
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["id"], id);
    assert_eq!(body["read"], true);

    let (_, body) = c.notifications(&c.alice_token, "").await;
    assert!(body["notifications"].as_array().unwrap().is_empty());
    let (_, body) = c.notifications(&c.alice_token, "?all=true").await;
    assert_eq!(body["notifications"].as_array().unwrap().len(), 1);
    assert_eq!(body["notifications"][0]["read"], true);

    // Another comment, then read-all marks it and reports the count.
    c.comment(n, "second note").await;
    let res = client
        .post(c.s.url("/api/v1/user/notifications/read-all"))
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["marked"], 1, "read-all count: {body}");

    let (_, body) = c.notifications(&c.alice_token, "").await;
    assert!(body["notifications"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_users_notification_is_404_and_anon_is_401() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let trail = c.create_trail("First trail").await;
    let n = trail["number"].as_i64().unwrap();
    c.comment(n, "hello there").await;

    let (_, body) = c.notifications(&c.alice_token, "").await;
    let id = body["notifications"][0]["id"].as_i64().unwrap();

    let res = client
        .post(c.s.url(&format!("/api/v1/user/notifications/{id}/read")))
        .bearer_auth(&c.bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404, "bob cannot read alice's notification");

    let res = client
        .get(c.s.url("/api/v1/user/notifications"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "no token answers 401");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_subscription_roundtrip_and_bad_mode() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let url = c.s.url("/api/v1/repos/alice/proj/subscription");

    let res = client
        .get(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.json::<Value>().await.unwrap();
    assert!(body["mode"].is_null(), "no watch row initially: {body}");

    let res = client
        .put(&url)
        .bearer_auth(&c.alice_token)
        .json(&json!({"mode": "watching"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["mode"], "watching");

    let res = client
        .get(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["mode"], "watching");

    let res = client
        .put(&url)
        .bearer_auth(&c.alice_token)
        .json(&json!({"mode": "ignoring"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["mode"], "ignoring");

    let res = client
        .put(&url)
        .bearer_auth(&c.alice_token)
        .json(&json!({"mode": "sometimes"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "unknown mode is 422");

    let res = client
        .delete(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204, "delete is 204");

    let res = client
        .get(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    let body = res.json::<Value>().await.unwrap();
    assert!(body["mode"].is_null(), "watch row gone: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_subscription_toggle_and_default() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let trail = c.create_trail("First trail").await;
    let n = trail["number"].as_i64().unwrap();
    let url =
        c.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}/subscription"));

    // The author participates, so the default is subscribed.
    let res = client
        .get(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["subscribed"], true, "participation default: {body}");

    let res = client
        .put(&url)
        .bearer_auth(&c.alice_token)
        .json(&json!({"subscribed": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["subscribed"], false);

    let res = client
        .get(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["subscribed"], false);

    let res = client
        .delete(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204, "delete is 204");

    let res = client
        .get(&url)
        .bearer_auth(&c.alice_token)
        .send()
        .await
        .unwrap();
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(
        body["subscribed"], true,
        "delete returns to the participation default: {body}"
    );
}
