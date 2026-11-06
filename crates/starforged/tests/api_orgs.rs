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

impl Ctx {
    fn teams(&self, org: &str) -> String {
        self.s.url(&format!("/api/v1/orgs/{org}/teams"))
    }

    fn team(&self, org: &str, team: &str) -> String {
        self.s.url(&format!("/api/v1/orgs/{org}/teams/{team}"))
    }

    fn team_members(&self, org: &str, team: &str) -> String {
        self.s
            .url(&format!("/api/v1/orgs/{org}/teams/{team}/members"))
    }

    fn team_member(&self, org: &str, team: &str, handle: &str) -> String {
        self.s
            .url(&format!("/api/v1/orgs/{org}/teams/{team}/members/{handle}"))
    }

    fn team_repos(&self, org: &str, team: &str) -> String {
        self.s
            .url(&format!("/api/v1/orgs/{org}/teams/{team}/repos"))
    }

    fn team_repo(&self, org: &str, team: &str, repo: &str) -> String {
        self.s
            .url(&format!("/api/v1/orgs/{org}/teams/{team}/repos/{repo}"))
    }

    async fn org_with_team(&self) -> reqwest::Client {
        let client = reqwest::Client::new();
        let res = client
            .post(self.orgs())
            .bearer_auth(&self.alice)
            .json(&json!({"handle": "acme"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        let res = client
            .put(self.member("acme", "bob"))
            .bearer_auth(&self.alice)
            .json(&json!({"role": "member"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        client
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_crud_owner_creates_member_forbidden() {
    let c = Ctx::start().await;
    let client = c.org_with_team().await;

    // An owner creates a team.
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "Dev Team", "description": "d", "permission": "write", "all_repos": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "owner creates team");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["name"], "Dev Team");
    assert_eq!(body["slug"], "dev-team");
    assert_eq!(body["permission"], "write");
    assert_eq!(body["all_repos"], true);
    assert_eq!(
        audit_count(&c.s, "team.create", "team:acme/dev-team").await,
        1
    );

    // A plain member cannot create a team.
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.bob)
        .json(&json!({"name": "Other", "permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "member cannot create team");

    // Members list teams; outsiders get 404.
    let res = client
        .get(c.teams("acme"))
        .bearer_auth(&c.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let teams: Value = res.json().await.unwrap();
    assert_eq!(teams.as_array().unwrap().len(), 1);
    let res = client
        .get(c.teams("acme"))
        .bearer_auth(&c.carol)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // The team itself is member-only too.
    let res = client
        .get(c.team("acme", "dev-team"))
        .bearer_auth(&c.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .get(c.team("acme", "dev-team"))
        .bearer_auth(&c.carol)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // A member cannot rename the team; the owner can, and the slug follows.
    let res = client
        .patch(c.team("acme", "dev-team"))
        .bearer_auth(&c.bob)
        .json(&json!({"name": "Ops"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "member cannot rename team");
    let res = client
        .patch(c.team("acme", "dev-team"))
        .bearer_auth(&c.alice)
        .json(&json!({"description": "new"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        audit_count(&c.s, "team.update", "team:acme/dev-team").await,
        1
    );

    // A member cannot delete the team either.
    let res = client
        .delete(c.team("acme", "dev-team"))
        .bearer_auth(&c.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "member cannot delete team");
    let res = client
        .delete(c.team("acme", "dev-team"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(
        audit_count(&c.s, "team.delete", "team:acme/dev-team").await,
        1
    );
    let res = client
        .get(c.team("acme", "dev-team"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_team_creates_report_one_clash() {
    let c = Ctx::start().await;
    let client = c.org_with_team().await;
    let req = || {
        client
            .post(c.teams("acme"))
            .bearer_auth(&c.alice)
            .json(&json!({"name": "Dev", "permission": "write"}))
    };
    let (a, b) = tokio::join!(req().send(), req().send());
    let mut statuses = [a.unwrap().status(), b.unwrap().status()];
    statuses.sort();
    assert_eq!(
        statuses,
        [
            reqwest::StatusCode::CREATED,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY
        ]
    );
    assert_eq!(audit_count(&c.s, "team.create", "team:acme/dev").await, 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_duplicate_name_case_insensitive_gives_422() {
    let c = Ctx::start().await;
    let client = c.org_with_team().await;
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "Dev Team", "permission": "write"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    for name in ["dev team", "DEV TEAM", "Dev Team"] {
        let res = client
            .post(c.teams("acme"))
            .bearer_auth(&c.alice)
            .json(&json!({"name": name, "permission": "read"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "duplicate team name {name:?}");
    }
    assert_eq!(
        audit_count(&c.s, "team.create", "team:acme/dev-team").await,
        1
    );

    // Renaming another team onto the name collides too.
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "Ops", "permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .patch(c.team("acme", "ops"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "DEV TEAM"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "rename onto existing team name");

    // Bad names and permissions are 422 as well.
    for name in ["", "no/slash", "tab\there"] {
        let res = client
            .post(c.teams("acme"))
            .bearer_auth(&c.alice)
            .json(&json!({"name": name, "permission": "read"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "bad team name {name:?}");
    }
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "Fine", "permission": "superadmin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "bad team permission");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_member_must_be_org_member() {
    let c = Ctx::start().await;
    let client = c.org_with_team().await;
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "Dev", "permission": "write"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // Carol is not an org member: 422, not 404 — the team exists, she cannot join it.
    let res = client
        .put(c.team_member("acme", "dev", "carol"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "non-org-member cannot join team");

    // Bob is an org member: add works, and is a no-op the second time.
    let res = client
        .put(c.team_member("acme", "dev", "bob"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        audit_count(&c.s, "team.member_add", "team:acme/dev").await,
        1
    );
    let res = client
        .put(c.team_member("acme", "dev", "bob"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        audit_count(&c.s, "team.member_add", "team:acme/dev").await,
        1,
        "no audit for no-op add"
    );

    // A plain member cannot manage team membership.
    let res = client
        .put(c.team_member("acme", "dev", "carol"))
        .bearer_auth(&c.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Removing someone who was never added is 404 and writes nothing.
    let res = client
        .delete(c.team_member("acme", "dev", "carol"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(
        audit_count(&c.s, "team.member_remove", "team:acme/dev").await,
        0
    );

    let res = client
        .delete(c.team_member("acme", "dev", "bob"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(
        audit_count(&c.s, "team.member_remove", "team:acme/dev").await,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_repo_must_be_owned_by_the_org() {
    let c = Ctx::start().await;
    let client = c.org_with_team().await;
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "Dev", "permission": "write"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // `proj` exists but belongs to alice, not the org: 422.
    c.s.repo(
        &c.s.core.user_by_handle("alice").await.unwrap().unwrap(),
        "proj",
        starforged_core::permission::Visibility::Private,
    )
    .await;
    let res = client
        .put(c.team_repo("acme", "dev", "proj"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "another owner's repo cannot join team");

    // Move it into the org the way A3's repository creation will; now it joins.
    let org_id = c.s.core.org(None, "acme").await.unwrap().id;
    let repo_id: i64 = sqlx::query_scalar("SELECT id FROM repos WHERE lower_name = 'proj'")
        .fetch_one(c.s.core.db().pool())
        .await
        .unwrap();
    sqlx::query("UPDATE repos SET owner_id = $1 WHERE id = $2")
        .bind(org_id)
        .bind(repo_id)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    let res = client
        .put(c.team_repo("acme", "dev", "proj"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(audit_count(&c.s, "team.repo_add", "team:acme/dev").await, 1);

    // Re-adding is a no-op: still 204, no new audit row.
    let res = client
        .put(c.team_repo("acme", "dev", "proj"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(
        audit_count(&c.s, "team.repo_add", "team:acme/dev").await,
        1,
        "no audit for no-op repo add"
    );

    // Unknown repositories are 404.
    let res = client
        .put(c.team_repo("acme", "dev", "missing"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    let res = client
        .delete(c.team_repo("acme", "dev", "proj"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(
        audit_count(&c.s, "team.repo_remove", "team:acme/dev").await,
        1
    );
    let res = client
        .delete(c.team_repo("acme", "dev", "proj"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // The repo list reflects links, and outsiders get 404 on it.
    let res = client
        .put(c.team_repo("acme", "dev", "proj"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let res = client
        .get(c.team_repos("acme", "dev"))
        .bearer_auth(&c.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let repos: Value = res.json().await.unwrap();
    assert_eq!(repos.as_array().unwrap().len(), 1);
    assert_eq!(repos[0]["full_name"], "acme/proj");
    let res = client
        .get(c.team_repos("acme", "dev"))
        .bearer_auth(&c.carol)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_member_removal_drops_team_memberships() {
    let c = Ctx::start().await;
    let client = c.org_with_team().await;
    let res = client
        .post(c.teams("acme"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "Dev", "permission": "write", "all_repos": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .put(c.team_member("acme", "dev", "bob"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Removing bob from the org drops him from the team with one audit row.
    let res = client
        .delete(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(audit_count(&c.s, "org.member_remove", "org:acme").await, 1);
    let res = client
        .get(c.team_members("acme", "dev"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let members: Value = res.json().await.unwrap();
    assert!(
        members.as_array().unwrap().is_empty(),
        "team membership left behind: {members}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_demote_and_remove_keep_one_owner() {
    // Two owners race: Alice demotes Bob while Bob removes Alice — and, in
    // alternating rounds, both owners leave at once. Exactly one call wins
    // and one owner remains; the org is never orphaned.
    for i in 0..20 {
        if i % 2 == 0 {
            demote_vs_remove(i).await;
        } else {
            leave_vs_leave(i).await;
        }
    }

    async fn two_owners(i: u32) -> (Ctx, reqwest::Client, String) {
        let c = Ctx::start().await;
        let client = reqwest::Client::new();
        let org = format!("acme{i}");
        let res = client
            .post(c.orgs())
            .bearer_auth(&c.alice)
            .json(&json!({"handle": &org}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        let res = client
            .put(c.member(&org, "bob"))
            .bearer_auth(&c.alice)
            .json(&json!({"role": "owner"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        (c, client, org)
    }

    async fn check_one_owner(c: &Ctx, org: &str) {
        let alice = c.s.core.user_by_handle("alice").await.unwrap().unwrap();
        let bob = c.s.core.user_by_handle("bob").await.unwrap().unwrap();
        let alice_role = c.s.core.org(Some(&alice), org).await.unwrap().viewer_role;
        let bob_role = c.s.core.org(Some(&bob), org).await.unwrap().viewer_role;
        let owners = [&alice_role, &bob_role]
            .into_iter()
            .filter(|r| **r == Some(starforged_core::orgs::OrgRole::Owner))
            .count();
        assert_eq!(
            owners, 1,
            "exactly one owner remains: {alice_role:?} / {bob_role:?}"
        );
        let target = format!("org:{org}");
        let changes = audit_count(&c.s, "org.member_role", &target).await
            + audit_count(&c.s, "org.member_remove", &target).await;
        assert_eq!(changes, 1, "the loser writes no audit row");
    }

    fn check_loser<E: std::fmt::Debug>(r: &Result<E, starforged_core::CoreError>) {
        // Either guard may fire: the last-owner guard (422) when the loser
        // still held owner rights, or `Forbidden` when the winner's commit
        // landed first and the loser was no longer an owner.
        if let Err(e) = r {
            assert!(
                matches!(
                    e,
                    starforged_core::CoreError::Invalid(_) | starforged_core::CoreError::Forbidden
                ),
                "loser gets 422 or 403, not {e:?}"
            );
        }
    }

    async fn demote_vs_remove(i: u32) {
        let (c, _client, org) = two_owners(i).await;
        let alice = c.s.core.user_by_handle("alice").await.unwrap().unwrap();
        let bob = c.s.core.user_by_handle("bob").await.unwrap().unwrap();
        let (demote, remove) = tokio::join!(
            c.s.core
                .set_org_member(&alice, &org, "bob", starforged_core::orgs::OrgRole::Member),
            c.s.core.remove_org_member(&bob, &org, "alice"),
        );
        assert!(
            demote.is_ok() ^ remove.is_ok(),
            "exactly one wins: {demote:?} / {remove:?}"
        );
        check_loser(&demote);
        check_loser(&remove);
        check_one_owner(&c, &org).await;
    }

    async fn leave_vs_leave(i: u32) {
        let (c, _client, org) = two_owners(100 + i).await;
        let alice = c.s.core.user_by_handle("alice").await.unwrap().unwrap();
        let bob = c.s.core.user_by_handle("bob").await.unwrap().unwrap();
        let (a, b) = tokio::join!(
            c.s.core.remove_org_member(&alice, &org, "alice"),
            c.s.core.remove_org_member(&bob, &org, "bob"),
        );
        assert!(a.is_ok() ^ b.is_ok(), "exactly one wins: {a:?} / {b:?}");
        check_loser(&a);
        check_loser(&b);
        check_one_owner(&c, &org).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_member_adds_are_idempotent() {
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

    let alice = c.s.core.user_by_handle("alice").await.unwrap().unwrap();
    // Two racing adds of Carol both succeed with a single audit row.
    let (first, second) = tokio::join!(
        c.s.core.set_org_member(
            &alice,
            "acme",
            "carol",
            starforged_core::orgs::OrgRole::Member
        ),
        c.s.core.set_org_member(
            &alice,
            "acme",
            "carol",
            starforged_core::orgs::OrgRole::Member
        ),
    );
    assert!(first.is_ok() && second.is_ok(), "{first:?} / {second:?}");
    assert_eq!(audit_count(&c.s, "org.member_add", "org:acme").await, 1);
}

// --- A3: org repositories, transfer support, org deletion, team races. -----

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_owner_creates_repo_and_member_is_refused() {
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

    // A plain member cannot create repositories in the org.
    let res = client
        .put(c.member("acme", "bob"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let denied = client
        .post(c.s.url("/api/v1/orgs/acme/repos"))
        .bearer_auth(&c.bob)
        .json(&json!({"name": "nope", "visibility": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403, "plain member cannot create org repos");

    // An org owner creates `acme/proj` through the API.
    let created = client
        .post(c.s.url("/api/v1/orgs/acme/repos"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "proj", "visibility": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "owner creates org repo");
    let body: Value = created.json().await.unwrap();
    assert_eq!(body["full_name"], "acme/proj");
    assert_eq!(body["permission"], "admin");

    // A team member with `read` can clone it over HTTP.
    let res = client
        .post(c.s.url("/api/v1/orgs/acme/teams"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "devs", "permission": "read", "all_repos": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .put(c.member("acme", "carol"))
        .bearer_auth(&c.alice)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .put(c.s.url("/api/v1/orgs/acme/teams/devs/members/carol"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &c.s.git_url("acme", "proj", Some(&c.alice)),
            "main",
        ],
    )
    .await;
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &c.s.git_url("acme", "proj", Some(&c.carol)),
            "carol-clone",
        ],
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("carol-clone").join("README.md")).unwrap(),
        "# proj\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_deletion_needs_an_empty_namespace() {
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
    let created = client
        .post(c.s.url("/api/v1/orgs/acme/repos"))
        .bearer_auth(&c.alice)
        .json(&json!({"name": "proj", "visibility": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    let blocked = client
        .delete(c.org("acme"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(
        blocked.status(),
        422,
        "an org with a repo cannot be deleted"
    );

    // A soft-deleted repository inside the grace period still blocks.
    c.s.core
        .delete_repo(
            &c.s.core.user_by_handle("alice").await.unwrap().unwrap(),
            "acme",
            "proj",
            "acme/proj",
        )
        .await
        .unwrap();
    let blocked = client
        .delete(c.org("acme"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 422, "a soft-deleted repo still blocks");

    // Restoring, then transferring the repository out, frees the org.
    let alice_user = c.s.core.user_by_handle("alice").await.unwrap().unwrap();
    let repo_id: i64 = sqlx::query_scalar(
        "SELECT r.id FROM repos r JOIN owners o ON o.id = r.owner_id WHERE o.handle = 'acme' AND r.lower_name = 'proj'",
    )
    .fetch_one(c.s.core.db().pool())
    .await
    .unwrap();
    c.s.core.restore_repo(&alice_user, repo_id).await.unwrap();
    let moved = client
        .post(c.s.url("/api/v1/repos/acme/proj/transfer"))
        .bearer_auth(&c.alice)
        .json(&json!({"new_owner": "alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), 200, "transfer the last repo out");
    let deleted = client
        .delete(c.org("acme"))
        .bearer_auth(&c.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 204, "empty org deletes");
    assert_eq!(audit_count(&c.s, "org.delete", "org:acme").await, 1);
    assert_eq!(
        client
            .get(c.org("acme"))
            .bearer_auth(&c.alice)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let recreated = client
        .post(c.orgs())
        .bearer_auth(&c.alice)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(recreated.status(), 201, "deletion frees the handle");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn racing_team_creates_share_one_url() {
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
    let alice = c.s.core.user_by_handle("alice").await.unwrap().unwrap();
    // `a-b` and `a b` slug to the same URL but differ as lower names: the
    // UNIQUE constraint alone would admit both, so the per-org lock must
    // serialize them.
    let new_team = |name: &str| starforged_core::orgs::NewTeamInput {
        name: name.into(),
        description: String::new(),
        permission: "read".into(),
        all_repos: true,
    };
    let (first, second) = tokio::join!(
        c.s.core.create_team(&alice, "acme", new_team("a-b")),
        c.s.core.create_team(&alice, "acme", new_team("a b")),
    );
    assert!(
        first.is_ok() ^ second.is_ok(),
        "exactly one wins: {first:?} / {second:?}"
    );
    for r in [&first, &second] {
        if let Err(e) = r {
            assert!(
                matches!(e, starforged_core::CoreError::Invalid(_)),
                "loser gets 422, not {e:?}"
            );
        }
    }
    let teams = c.s.core.teams(&alice, "acme").await.unwrap();
    assert_eq!(teams.len(), 1, "one URL per team: {teams:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn racing_team_renames_conflict_as_422() {
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
    let alice = c.s.core.user_by_handle("alice").await.unwrap().unwrap();
    let new_team = |name: &str| starforged_core::orgs::NewTeamInput {
        name: name.into(),
        description: String::new(),
        permission: "read".into(),
        all_repos: true,
    };
    c.s.core
        .create_team(&alice, "acme", new_team("alpha"))
        .await
        .unwrap();
    c.s.core
        .create_team(&alice, "acme", new_team("beta"))
        .await
        .unwrap();
    let patch = || starforged_core::orgs::TeamPatch {
        name: Some("gamma".into()),
        description: None,
        permission: None,
        all_repos: None,
    };
    let (first, second) = tokio::join!(
        c.s.core.update_team(&alice, "acme", "alpha", patch()),
        c.s.core.update_team(&alice, "acme", "beta", patch()),
    );
    assert!(
        first.is_ok() ^ second.is_ok(),
        "exactly one wins: {first:?} / {second:?}"
    );
    for r in [&first, &second] {
        if let Err(e) = r {
            assert!(
                matches!(e, starforged_core::CoreError::Invalid(_)),
                "loser gets 422, not {e:?}"
            );
        }
    }
    let teams = c.s.core.teams(&alice, "acme").await.unwrap();
    assert_eq!(teams.len(), 2);
    assert_eq!(
        teams.iter().filter(|t| t.slug == "gamma").count(),
        1,
        "one team owns the slug: {teams:?}"
    );
}
