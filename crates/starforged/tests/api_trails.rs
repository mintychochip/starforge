mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Permission;
use starforged_core::tokens::Scope;
use time::format_description::well_known::Rfc3339;

const BOGUS: &str = "sfp_0000000000000000000000000000000000000000000000000000000000000000";

struct Ctx {
    s: TestServer,
    read: String,
    trail_only: String,
    composed: String,
    triage: String,
    stranger: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        s.repo(
            &alice,
            "proj",
            starforged_core::permission::Visibility::Private,
        )
        .await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Triage)
            .await
            .unwrap();
        let read = s.token(&alice, &[Scope::RepoRead]).await;
        let trail_only = s.token(&alice, &[Scope::TrailWrite]).await;
        let composed = s.token(&alice, &[Scope::RepoRead, Scope::TrailWrite]).await;
        let triage = s.token(&bob, &[Scope::RepoRead, Scope::TrailWrite]).await;
        let stranger = s.token(&carol, &[Scope::RepoRead, Scope::TrailWrite]).await;
        Ctx {
            s,
            read,
            trail_only,
            composed,
            triage,
            stranger,
        }
    }

    fn trails(&self) -> String {
        self.s.url("/api/v1/repos/alice/proj/trails")
    }

    fn trail(&self, n: i64) -> String {
        self.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}"))
    }

    async fn create(&self, title: &str) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(self.trails())
            .bearer_auth(&self.composed)
            .json(&json!({"title": title, "intent": "do the thing"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create {title}");
        res.json::<Value>().await.unwrap()
    }
}

/// Asserts `v` is an RFC 3339 string and returns it parsed.
fn rfc3339(v: &Value) -> time::OffsetDateTime {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("expected RFC 3339 string, got {v}"));
    time::OffsetDateTime::parse(s, &Rfc3339).unwrap_or_else(|_| panic!("not RFC 3339: {s}"))
}

fn error(res: Value) -> (String, String) {
    let code = res["error"]["code"].as_str().unwrap_or("").to_owned();
    let message = res["error"]["message"].as_str().unwrap_or("").to_owned();
    (code, message)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // Anonymous on a private repo: reads 404, mutations 401.
    let anon_get = client.get(c.trails()).send().await.unwrap();
    assert_eq!(anon_get.status(), 404);
    let anon_post = client
        .post(c.trails())
        .json(&json!({"title": "t", "intent": "i"}))
        .send()
        .await
        .unwrap();
    assert_eq!(anon_post.status(), 401);

    // Bogus token: 401 everywhere.
    let bogus_get = client
        .get(c.trails())
        .bearer_auth(BOGUS)
        .send()
        .await
        .unwrap();
    assert_eq!(bogus_get.status(), 401);
    let bogus_post = client
        .post(c.trails())
        .bearer_auth(BOGUS)
        .json(&json!({"title": "t", "intent": "i"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bogus_post.status(), 401);

    // Read token: GET 200, mutations 403 naming the missing scope.
    let get = client
        .get(c.trails())
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let post = client
        .post(c.trails())
        .bearer_auth(&c.read)
        .json(&json!({"title": "t", "intent": "i"}))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 403);
    let (code, message) = error(post.json().await.unwrap());
    assert_eq!(code, "forbidden");
    assert!(message.contains("trail:write"), "message: {message}");

    // A trail to exercise sub-resources.
    let created = c.create("first").await;
    assert_eq!(created["number"], 1);

    // Read token on the label route: 403 as well.
    let label_post = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/1/labels"))
        .bearer_auth(&c.read)
        .json(&json!({"name": "bug"}))
        .send()
        .await
        .unwrap();
    assert_eq!(label_post.status(), 403);

    // Trail-write-only token cannot read (it lacks repo:read): 403.
    let scoped_get = client
        .get(c.trails())
        .bearer_auth(&c.trail_only)
        .send()
        .await
        .unwrap();
    assert_eq!(scoped_get.status(), 403);

    // Non-member with full-looking scopes: 404, never 403 (no leak).
    let stranger_get = client
        .get(c.trails())
        .bearer_auth(&c.stranger)
        .send()
        .await
        .unwrap();
    assert_eq!(stranger_get.status(), 404);
    let stranger_post = client
        .post(c.trails())
        .bearer_auth(&c.stranger)
        .json(&json!({"title": "t", "intent": "i"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stranger_post.status(), 404);

    // Triage member: 200 on reads and label writes.
    let triage_get = client
        .get(c.trails())
        .bearer_auth(&c.triage)
        .send()
        .await
        .unwrap();
    assert_eq!(triage_get.status(), 200);
    let triage_label = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/1/labels"))
        .bearer_auth(&c.triage)
        .json(&json!({"name": "bug"}))
        .send()
        .await
        .unwrap();
    assert_eq!(triage_label.status(), 200);

    // Unknown trail number: 404 for members.
    let missing = client
        .get(c.trail(999))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_numbers_and_full_shape() {
    let c = Ctx::start().await;

    let first = c.create("first trail").await;
    assert_eq!(first["number"], 1);
    assert_eq!(first["title"], "first trail");
    assert_eq!(first["intent"], "do the thing");
    assert_eq!(first["state"], "open");
    assert_eq!(first["ready"], false);
    assert_eq!(first["author"], "alice");
    assert_eq!(first["labels"], json!([]));
    assert_eq!(first["assignees"], json!([]));
    rfc3339(&first["created_at"]);
    rfc3339(&first["updated_at"]);
    assert!(first["closed_at"].is_null());
    assert!(first["merged_at"].is_null());

    let second = c.create("second trail").await;
    assert_eq!(second["number"], 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_title_ready_and_state() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    c.create("patch me").await;

    let patched = client
        .patch(c.trail(1))
        .bearer_auth(&c.composed)
        .json(&json!({"title": "patched", "ready": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), 200);
    let body = patched.json::<Value>().await.unwrap();
    assert_eq!(body["title"], "patched");
    assert_eq!(body["ready"], true);

    let closed = client
        .patch(c.trail(1))
        .bearer_auth(&c.composed)
        .json(&json!({"state": "closed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(closed.status(), 200);
    let body = closed.json::<Value>().await.unwrap();
    assert_eq!(body["state"], "closed");
    rfc3339(&body["closed_at"]);

    // The merge path owns `merged`: the service message surfaces verbatim.
    let merged = client
        .patch(c.trail(1))
        .bearer_auth(&c.composed)
        .json(&json!({"state": "merged"}))
        .send()
        .await
        .unwrap();
    assert_eq!(merged.status(), 422);
    let (code, message) = error(merged.json().await.unwrap());
    assert_eq!(code, "invalid");
    assert_eq!(message, "merged is set by the merge path");

    // Unknown number patches 404.
    let missing = client
        .patch(c.trail(999))
        .bearer_auth(&c.composed)
        .json(&json!({"title": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_detail_shape() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    c.create("detail").await;

    let res = client
        .get(c.trail(1))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.json::<Value>().await.unwrap();
    // Flattened trail fields plus discussion.
    assert_eq!(body["number"], 1);
    assert_eq!(body["title"], "detail");
    assert_eq!(body["author"], "alice");
    assert_eq!(body["comments"], json!([]));
    let timeline = body["timeline"].as_array().unwrap();
    assert!(!timeline.is_empty());
    let event = &timeline[0];
    assert_eq!(event["kind"], "trail.open");
    assert_eq!(event["actor"], "alice");
    assert!(event["payload"].is_object());
    rfc3339(&event["created_at"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comments_roundtrip_and_edit_auth() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    c.create("discuss").await;

    let posted = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/1/comments"))
        .bearer_auth(&c.composed)
        .json(&json!({"body": "first thought"}))
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 201);
    let comment = posted.json::<Value>().await.unwrap();
    assert_eq!(comment["author"], "alice");
    assert_eq!(comment["body"], "first thought");
    rfc3339(&comment["created_at"]);
    assert!(comment["edited_at"].is_null());
    let id = comment["id"].as_i64().unwrap();

    let listed = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails/1/comments"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);
    let listed = listed.json::<Value>().await.unwrap();
    assert_eq!(listed["comments"].as_array().unwrap().len(), 1);

    // Triage Bob is neither author nor admin: 403.
    let bob_edit = client
        .patch(c.s.url(&format!("/api/v1/repos/alice/proj/trails/1/comments/{id}")))
        .bearer_auth(&c.triage)
        .json(&json!({"body": "hijacked"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bob_edit.status(), 403);

    // The author can edit; edited_at stamps the edit.
    let edit = client
        .patch(c.s.url(&format!("/api/v1/repos/alice/proj/trails/1/comments/{id}")))
        .bearer_auth(&c.composed)
        .json(&json!({"body": "second thought"}))
        .send()
        .await
        .unwrap();
    assert_eq!(edit.status(), 200);
    let edited = edit.json::<Value>().await.unwrap();
    assert_eq!(edited["body"], "second thought");
    rfc3339(&edited["edited_at"]);

    // The detail route reflects the edit.
    let detail = client
        .get(c.trail(1))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let detail = detail.json::<Value>().await.unwrap();
    assert_eq!(detail["comments"][0]["body"], "second thought");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn labels_add_remove_idempotent() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    c.create("labelled").await;
    let url = c.s.url("/api/v1/repos/alice/proj/trails/1/labels");

    let added = client
        .post(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"name": "Bug"}))
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 200);
    assert_eq!(
        added.json::<Value>().await.unwrap()["labels"],
        json!(["bug"])
    );

    // Re-adding is a no-op with the same shape.
    let again = client
        .post(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"name": "bug"}))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);
    assert_eq!(
        again.json::<Value>().await.unwrap()["labels"],
        json!(["bug"])
    );

    let removed = client
        .delete(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"name": "bug"}))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 200);
    assert_eq!(removed.json::<Value>().await.unwrap()["labels"], json!([]));

    // Removing again stays 200 with the same shape.
    let removed_again = client
        .delete(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"name": "bug"}))
        .send()
        .await
        .unwrap();
    assert_eq!(removed_again.status(), 200);
    assert_eq!(
        removed_again.json::<Value>().await.unwrap()["labels"],
        json!([])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assignees_stranger_rejected() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    c.create("assigned").await;
    let url = c.s.url("/api/v1/repos/alice/proj/trails/1/assignees");

    // Carol exists but is not a member of this repo: 422.
    let stranger = client
        .post(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"user": "carol"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stranger.status(), 422);
    let (code, _) = error(stranger.json().await.unwrap());
    assert_eq!(code, "invalid");

    // Unknown handles resolve to a 422, not a 404.
    let unknown = client
        .post(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"user": "nosuchuser"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 422);

    // Bob is a member: add, re-add (idempotent), remove.
    let added = client
        .post(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 200);
    assert_eq!(
        added.json::<Value>().await.unwrap()["assignees"],
        json!(["bob"])
    );
    let removed = client
        .delete(&url)
        .bearer_auth(&c.composed)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 200);
    assert_eq!(
        removed.json::<Value>().await.unwrap()["assignees"],
        json!([])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pagination_and_filters() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    for n in 1..=35 {
        c.create(&format!("trail {n:02}")).await;
    }

    // Default page: 30 trails, cursor at the last number.
    let first = client
        .get(c.trails())
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first = first.json::<Value>().await.unwrap();
    assert_eq!(first["trails"].as_array().unwrap().len(), 30);
    assert_eq!(first["trails"][0]["number"], 1);
    assert_eq!(first["next_after"], 30);

    // Following the cursor returns the tail with no further page.
    let tail = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?after=30"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(tail.status(), 200);
    let tail = tail.json::<Value>().await.unwrap();
    let numbers: Vec<i64> = tail["trails"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["number"].as_i64().unwrap())
        .collect();
    assert_eq!(numbers, vec![31, 32, 33, 34, 35]);
    assert!(tail["next_after"].is_null());

    // Explicit windowed page.
    let window = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?limit=10&after=10"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    let window = window.json::<Value>().await.unwrap();
    assert_eq!(window["trails"].as_array().unwrap().len(), 10);
    assert_eq!(window["trails"][0]["number"], 11);
    assert_eq!(window["next_after"], 20);

    // State filter: close trail 1 first.
    client
        .patch(c.trail(1))
        .bearer_auth(&c.composed)
        .json(&json!({"state": "closed"}))
        .send()
        .await
        .unwrap();
    let closed = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?state=closed"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    let closed = closed.json::<Value>().await.unwrap();
    assert_eq!(closed["trails"].as_array().unwrap().len(), 1);
    assert_eq!(closed["trails"][0]["number"], 1);

    // Invalid state is a 422.
    let bad_state = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?state=bogus"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_state.status(), 422);

    // Label filter.
    client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/2/labels"))
        .bearer_auth(&c.composed)
        .json(&json!({"name": "bug"}))
        .send()
        .await
        .unwrap();
    let by_label = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?label=bug"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    let by_label = by_label.json::<Value>().await.unwrap();
    assert_eq!(by_label["trails"].as_array().unwrap().len(), 1);
    assert_eq!(by_label["trails"][0]["number"], 2);

    // Assignee + author filters; unknown handles list empty, never 404.
    client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/3/assignees"))
        .bearer_auth(&c.composed)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    let by_assignee = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?assignee=bob"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    let by_assignee = by_assignee.json::<Value>().await.unwrap();
    assert_eq!(by_assignee["trails"].as_array().unwrap().len(), 1);
    assert_eq!(by_assignee["trails"][0]["number"], 3);

    let by_author = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?author=alice&limit=100"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(
        by_author.json::<Value>().await.unwrap()["trails"]
            .as_array()
            .unwrap()
            .len(),
        35
    );
    let unknown_author = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?author=nosuchuser"))
        .bearer_auth(&c.read)
        .send()
        .await
        .unwrap();
    assert_eq!(unknown_author.status(), 200);
    assert_eq!(
        unknown_author.json::<Value>().await.unwrap()["trails"],
        json!([])
    );
}
