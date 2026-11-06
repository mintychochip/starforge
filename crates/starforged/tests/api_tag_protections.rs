//! B2: tag-protection management API. Real HTTP against an in-process
//! server: the reader-list / maintain-mutate permission shape (404/403
//! matrix), create→list→delete round-trip, validation rejections,
//! archived-repo behavior, and exactly one audit row per mutation.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::CreateUser;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    carol_read: String,
    dave_triage: String,
    erin_write: String,
    bob_full: String,
    bob_read_only: String,
    alice_full: String,
    frank_full: String,
    gus_full: String,
    gus_repo_only: String,
    gus_trail_only: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let dave = s.user("dave").await;
        let erin = s.user("erin").await;
        let gus = s.user("gus").await;
        s.core
            .create_user(CreateUser {
                handle: "frank".into(),
                password: Some(PASSWORD.into()),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let frank = s.core.user_by_handle("frank").await.unwrap().unwrap();
        s.repo(&alice, "proj", Visibility::Private).await;
        s.repo(&alice, "open", Visibility::Public).await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Maintain)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "dave", Permission::Triage)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "erin", Permission::Write)
            .await
            .unwrap();
        let read = &[Scope::RepoRead];
        let full = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
        Ctx {
            carol_read: s.token(&carol, full).await,
            dave_triage: s.token(&dave, full).await,
            erin_write: s.token(&erin, full).await,
            bob_full: s.token(&bob, full).await,
            bob_read_only: s.token(&bob, read).await,
            alice_full: s.token(&alice, full).await,
            frank_full: s.token(&frank, full).await,
            gus_full: s.token(&gus, full).await,
            gus_repo_only: s.token(&gus, &[Scope::RepoRead, Scope::RepoWrite]).await,
            gus_trail_only: s.token(&gus, &[Scope::RepoRead, Scope::TrailWrite]).await,
            s,
            alice,
        }
    }

    fn tags(&self) -> String {
        self.s.url("/api/v1/repos/alice/proj/tag-protections")
    }

    fn tags_open(&self) -> String {
        self.s.url("/api/v1/repos/alice/open/tag-protections")
    }

    fn tag(&self, id: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/tag-protections/{id}"))
    }

    async fn create(&self, token: &str, body: &Value) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .post(self.tags())
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(json!({}));
        (status, body)
    }

    async fn audit_count(&self, action: &str, target: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1 AND target = $2")
            .bind(action)
            .bind(target)
            .fetch_one(self.s.core.db().pool())
            .await
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tag_protection_list_is_open_to_readers_mutations_maintain_only() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // Anonymous list on a private repo: 404 (never a leak-shaped 403).
    let res = client.get(c.tags()).send().await.unwrap();
    assert_eq!(res.status(), 404);

    // Anonymous list on a public repo: 200.
    let res = client.get(c.tags_open()).send().await.unwrap();
    assert_eq!(res.status(), 200);

    // Anonymous create: 401.
    let res = client
        .post(c.tags())
        .json(&json!({"pattern": "v*"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Outsiders 404 on reads and mutations (a scope-missing token 403s).
    let res = client
        .get(c.tags())
        .bearer_auth(&c.gus_repo_only)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let (status, _) = c.create(&c.gus_repo_only, &json!({"pattern": "v*"})).await;
    assert_eq!(status, 404);
    let (status, _) = c.create(&c.gus_trail_only, &json!({"pattern": "v*"})).await;
    assert_eq!(status, 403, "mutations need the repo:write scope");

    // Every repository reader (read, triage, write) may list.
    for token in [&c.carol_read, &c.dave_triage, &c.erin_write] {
        let res = client
            .get(c.tags())
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "any reader may list tag protections");
    }

    // A maintainer holding only `repo:read` may list but not mutate.
    let res = client
        .get(c.tags())
        .bearer_auth(&c.bob_read_only)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let (status, _) = c.create(&c.bob_read_only, &json!({"pattern": "v*"})).await;
    assert_eq!(status, 403);

    // Below-maintain readers mutate nothing: create and delete are 403.
    let (status, created) = c.create(&c.alice_full, &json!({"pattern": "v*"})).await;
    assert_eq!(status, 201);
    let id = created["id"].as_i64().unwrap();
    for token in [&c.carol_read, &c.dave_triage, &c.erin_write] {
        let (status, _) = c.create(token, &json!({"pattern": "r*"})).await;
        assert_eq!(status, 403, "creates need maintain");
        let res = client
            .delete(c.tag(id))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "deletes need maintain");
    }

    // Maintain, owner, and site admin can create.
    for token in [&c.bob_full, &c.alice_full, &c.frank_full] {
        let (status, _) = c.create(token, &json!({"pattern": "v*"})).await;
        assert!(
            status == 201 || status == 409,
            "maintain+ creates: {status}"
        );
    }

    // Unknown ids are 404 for readers of the API …
    let res = client
        .delete(c.tag(999_999))
        .bearer_auth(&c.bob_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    // … and for outsiders with a scoped token.
    let res = client
        .delete(c.tag(999_999))
        .bearer_auth(&c.gus_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tag_protection_round_trip_and_validation() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // Create → list → delete round-trip.
    let (status, created) = c.create(&c.alice_full, &json!({"pattern": "v*"})).await;
    assert_eq!(status, 201);
    let id = created["id"].as_i64().unwrap();
    assert_eq!(created["pattern"], "v*");
    let res = client
        .get(c.tags())
        .bearer_auth(&c.bob_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let listed = res.json::<Value>().await.unwrap();
    assert_eq!(listed["tag_protections"].as_array().unwrap().len(), 1);
    assert_eq!(listed["tag_protections"][0]["pattern"], "v*");
    let target = format!("tag_protection:alice/proj#{id}");

    // Rejections: misspelled fields, missing/null/empty patterns, bad
    // characters, and duplicates.
    for body in [
        json!({"patterns": "v*"}),
        json!({}),
        json!({"pattern": null}),
        json!({"pattern": ""}),
        json!({"pattern": "   "}),
        json!({"pattern": "v/1.0 (final)"}),
        json!({"pattern": "v*"}),
    ] {
        let (status, _) = c.create(&c.alice_full, &body).await;
        assert!(
            status == 422 || status == 409,
            "bad tag-protection body {body} must be 422 or 409, got {status}"
        );
    }

    // Exactly one audit row per mutation.
    assert_eq!(c.audit_count("tag_protection.created", &target).await, 1);
    let res = client
        .delete(c.tag(id))
        .bearer_auth(&c.bob_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(c.audit_count("tag_protection.deleted", &target).await, 1);
    let res = client
        .get(c.tags())
        .bearer_auth(&c.alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.json::<Value>().await.unwrap()["tag_protections"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archived_repos_refuse_tag_mutations_but_keep_reads() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let (status, created) = c.create(&c.alice_full, &json!({"pattern": "v*"})).await;
    assert_eq!(status, 201);
    let id = created["id"].as_i64().unwrap();

    c.s.core
        .archive_repo(&c.alice, "alice", "proj")
        .await
        .unwrap();

    // Reads still work on an archived repo.
    let res = client
        .get(c.tags())
        .bearer_auth(&c.bob_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Mutations are refused.
    let (status, refused) = c.create(&c.alice_full, &json!({"pattern": "r*"})).await;
    assert_eq!(status, 422);
    assert!(refused.to_string().contains("archived"), "{refused}");
    let res = client
        .delete(c.tag(id))
        .bearer_auth(&c.alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Refused mutations write no audit rows.
    assert_eq!(
        c.audit_count("tag_protection.created", "tag_protection:alice/proj#0")
            .await,
        0
    );
}
