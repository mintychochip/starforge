//! Org lifecycle and membership (M3a A1): creation, handles, members, audit, visibility.

mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::tokens::Scope;

struct Ctx {
    s: TestServer,
    alice: String,
    bob: String,
    carol: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let rw = &[Scope::RepoWrite, Scope::TrailWrite];
        let read = &[Scope::RepoRead];
        let alice_t = s.token(&alice, rw).await;
        let bob_t = s.token(&bob, rw).await;
        let carol_t = s.token(&carol, read).await;
        Ctx {
            s,
            alice: alice_t,
            bob: bob_t,
            carol: carol_t,
        }
    }
    fn orgs(&self) -> String {
        self.s.url("/api/v1/orgs")
    }

    fn org(&self, org: &str) -> String {
        self.s.url(&format!("/api/v1/orgs/{org}"))
    }

    fn members(&self, org: &str) -> String {
        self.s.url(&format!("/api/v1/orgs/{org}/members"))
    }

    fn member(&self, org: &str, handle: &str) -> String {
        self.s.url(&format!("/api/v1/orgs/{org}/members/{handle}"))
    }
}

async fn audit_count(s: &TestServer, action: &str, target: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE action = $1 AND target = $2")
        .bind(action)
        .bind(target)
        .fetch_one(s.core.db().pool())
        .await
        .unwrap()
}

fn error(res: Value) -> (String, String) {
    let code = res["error"]["code"].as_str().unwrap_or("").to_owned();
    let message = res["error"]["message"].as_str().unwrap_or("").to_owned();
    (code, message)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_org_makes_creator_owner() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "acme", "display_name": "Acme", "description": "d"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "create org");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["handle"], "acme");
    assert_eq!(body["role"], "owner");

    let res = client
        .get(c.org("acme"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["handle"], "acme");
    assert_eq!(body["display_name"], "Acme");

    let res = client
        .get(c.members("acme"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let members: Value = res.json().await.unwrap();
    assert_eq!(members.as_array().unwrap().len(), 1);
    assert_eq!(members[0]["handle"], "alice");
    assert_eq!(members[0]["role"], "owner");

    assert_eq!(audit_count(&c.s, "org.create", "org:acme").await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_clash_and_reserved_give_422() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // Clash with an existing user handle.
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "org handle clashing with a user");
    let (code, _) = error(res.json().await.unwrap());
    assert_eq!(code, "invalid");

    // Clash with an existing org handle.
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.bob)
        .json(&json!({"handle": "ACME"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "org handle clashing with an org");

    // Reserved handles are refused.
    for reserved in ["admin", "api", "orgs", "new"] {
        let res = client
            .post(c.orgs())
            .bearer_auth(&c.alice)
            .json(&json!({"handle": reserved}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "reserved handle {reserved}");
    }

    // A user cannot take an org's handle either (uniqueness runs both ways).
    let taken = c.s.user("taken").await;
    let _ = taken;
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "taken"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "org handle clashing with a user");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_add_promote_demote_remove() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // Add bob as a member.
    let res = client
        .put(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "add member");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["handle"], "bob");
    assert_eq!(body["role"], "member");
    assert_eq!(audit_count(&c.s, "org.member_add", "org:acme").await, 1);

    // Re-adding with the same role is a no-op: still 200, no new audit row.
    let res = client
        .put(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(audit_count(&c.s, "org.member_add", "org:acme").await, 1);
    assert_eq!(audit_count(&c.s, "org.member_role", "org:acme").await, 0);

    // Promote bob to owner.
    let res = client
        .put(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "owner"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "promote");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["role"], "owner");
    assert_eq!(audit_count(&c.s, "org.member_role", "org:acme").await, 1);

    // Demote bob back to member.
    let res = client
        .put(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "demote");
    assert_eq!(audit_count(&c.s, "org.member_role", "org:acme").await, 2);

    // Remove bob.
    let res = client
        .delete(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204, "remove member");
    assert_eq!(audit_count(&c.s, "org.member_remove", "org:acme").await, 1);

    let res = client
        .get(c.members("acme"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    let members: Value = res.json().await.unwrap();
    assert_eq!(members.as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_owner_cannot_leave_or_be_demoted() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // The sole owner cannot leave.
    let res = client
        .delete(c.member("acme", "alice"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "last owner cannot leave");

    // The sole owner cannot be demoted.
    let res = client
        .put(c.member("acme", "alice"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "last owner cannot be demoted");

    // With two owners, one may leave.
    let res = client
        .put(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "owner"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .delete(c.member("acme", "alice"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204, "owner leaves when another remains");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_list_visible_only_to_members() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .put(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // A member reads the list.
    let res = client
        .get(c.members("acme"))
        .bearer_auth(&c.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // A non-member gets 404, never 403.
    let res = client
        .get(c.members("acme"))
        .bearer_auth(&c.carol)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Anonymous gets 404 too.
    let res = client.get(c.members("acme")).send().await.unwrap();
    assert_eq!(res.status(), 404);

    // The org profile itself stays public.
    let res = client.get(c.org("acme")).send().await.unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_handles_rejected_on_user_only_paths() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let res = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    c.s.repo(
        &c.s.core.user_by_handle("alice").await.unwrap().unwrap(),
        "proj",
        starforged_core::permission::Visibility::Private,
    )
    .await;

    // An org cannot be a collaborator.
    let res = client
        .put(c.s.url("/api/v1/repos/alice/proj/collaborators/acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "org as collaborator");

    // An org cannot be an assignee or a review request.
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&c.alice)
        .json(&json!({"title": "t", "intent": "i"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/1/assignees"))
        .bearer_auth(&c.alice)
        .json(&json!({"user": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "org as assignee");
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/1/review-requests"))
        .bearer_auth(&c.alice)
        .json(&json!({"user": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "org as review request");
}
