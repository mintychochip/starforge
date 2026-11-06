mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_repositories_and_collaborators() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;
    let read = s.token(&alice, &[Scope::RepoRead]).await;
    let bob_read = s.token(&bob, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();
    let api = |path: &str| s.url(&format!("/api/v1{path}"));

    let anonymous = client.get(api("/user")).send().await.unwrap();
    assert_eq!(anonymous.status(), 401);
    assert_eq!(anonymous.headers()["www-authenticate"], "Bearer");
    assert_eq!(
        anonymous.json::<Value>().await.unwrap()["error"]["code"],
        "unauthenticated"
    );
    assert_eq!(
        client
            .get(api("/user"))
            .bearer_auth("sfp_bogus")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let me: Value = client
        .get(api("/user"))
        .bearer_auth(&write)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["handle"], "alice");

    let forbidden = client
        .post(api("/user/repos"))
        .bearer_auth(&read)
        .json(&json!({"name": "proj"}))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 403);
    let created = client
        .post(api("/user/repos"))
        .bearer_auth(&write)
        .json(&json!({"name": "proj"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let repo: Value = created.json().await.unwrap();
    assert_eq!(repo["full_name"], "alice/proj");
    assert_eq!(repo["visibility"], "private");
    assert_eq!(repo["permission"], "admin");
    assert_eq!(repo["clone_url"], format!("{}/alice/proj.git", s.base));
    let duplicate = client
        .post(api("/user/repos"))
        .bearer_auth(&write)
        .json(&json!({"name": "PROJ"}))
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 409);
    let malformed = client
        .post(api("/user/repos"))
        .bearer_auth(&write)
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 422);
    assert_eq!(
        malformed.json::<Value>().await.unwrap()["error"]["code"],
        "invalid"
    );

    assert_eq!(
        client
            .get(api("/repos/alice/proj"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(api("/repos/alice/proj"))
            .bearer_auth(&bob_read)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let grant = client
        .put(api("/repos/alice/proj/collaborators/bob"))
        .bearer_auth(&write)
        .json(&json!({"permission": "triage"}))
        .send()
        .await
        .unwrap();
    assert_eq!(grant.status(), 204);
    let seen: Value = client
        .get(api("/repos/alice/proj"))
        .bearer_auth(&bob_read)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(seen["permission"], "triage");
    let list: Value = client
        .get(api("/repos/alice/proj/collaborators"))
        .bearer_auth(&write)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list, json!([{"handle": "bob", "permission": "triage"}]));
    let bad_level = client
        .put(api("/repos/alice/proj/collaborators/bob"))
        .bearer_auth(&write)
        .json(&json!({"permission": "owner"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_level.status(), 422);
    assert_eq!(
        client
            .delete(api("/repos/alice/proj/collaborators/bob"))
            .bearer_auth(&write)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        client
            .delete(api("/repos/alice/proj/collaborators/bob"))
            .bearer_auth(&write)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let unknown = client.get(api("/nope")).send().await.unwrap();
    assert_eq!(unknown.status(), 404);
    assert_eq!(
        unknown.json::<Value>().await.unwrap()["error"]["code"],
        "not_found"
    );
}

// --- A3: repository transfer between users and orgs. -------------------------

async fn transfer_audit_count(s: &TestServer, target: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'repo.transfer' AND target = $1",
    )
    .bind(target)
    .fetch_one(s.core.db().pool())
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_transfer_between_user_and_org() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let alice_t = s
        .token(&alice, &[Scope::RepoWrite, Scope::TrailWrite])
        .await;
    let client = reqwest::Client::new();
    let api = |path: &str| s.url(&format!("/api/v1{path}"));

    let res = client
        .post(api("/orgs"))
        .bearer_auth(&alice_t)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .post(api("/user/repos"))
        .bearer_auth(&alice_t)
        .json(&json!({"name": "proj", "visibility": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    // Bob collaborates with read; he will also get a team grant below.
    let res = client
        .put(api("/repos/alice/proj/collaborators/bob"))
        .bearer_auth(&alice_t)
        .json(&json!({"permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let res = client
        .put(api("/orgs/acme/members/bob"))
        .bearer_auth(&alice_t)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .post(api("/orgs/acme/teams"))
        .bearer_auth(&alice_t)
        .json(&json!({"name": "devs", "permission": "write", "all_repos": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .put(api("/orgs/acme/teams/devs/members/bob"))
        .bearer_auth(&alice_t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // User to org: the actor owns the org.
    let moved = client
        .post(api("/repos/alice/proj/transfer"))
        .bearer_auth(&alice_t)
        .json(&json!({"new_owner": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), 200, "transfer user -> org");
    let body: Value = moved.json().await.unwrap();
    assert_eq!(body["full_name"], "acme/proj");
    assert_eq!(transfer_audit_count(&s, "repo:acme/proj").await, 1);
    // Bob's team write grant covers the repository in its new home.
    let access = s.core.repo_for(Some(&bob), "acme", "proj").await.unwrap();
    assert_eq!(
        access.permission,
        starforged_core::permission::Permission::Write
    );

    // Org to user: team grants from the old org disappear, collaborators stay.
    let moved = client
        .post(api("/repos/acme/proj/transfer"))
        .bearer_auth(&alice_t)
        .json(&json!({"new_owner": "alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), 200, "transfer org -> user");
    let body: Value = moved.json().await.unwrap();
    assert_eq!(body["full_name"], "alice/proj");
    let access = s.core.repo_for(Some(&bob), "alice", "proj").await.unwrap();
    assert_eq!(
        access.permission,
        starforged_core::permission::Permission::Read,
        "team grant is gone, collaborator grant stays"
    );
    let members: Value = client
        .get(api("/repos/alice/proj/collaborators"))
        .bearer_auth(&alice_t)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        members
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["handle"] == "bob")
    );
    assert_eq!(transfer_audit_count(&s, "repo:alice/proj").await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_transfer_rejects_bad_targets_and_non_admins() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let alice_t = s.token(&alice, &[Scope::RepoWrite]).await;
    let bob_t = s.token(&bob, &[Scope::RepoWrite]).await;
    let bob_r = s.token(&bob, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();
    let api = |path: &str| s.url(&format!("/api/v1{path}"));

    let res = client
        .post(api("/orgs"))
        .bearer_auth(&alice_t)
        .json(&json!({"handle": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    for repo in ["proj", "other"] {
        let res = client
            .post(api("/user/repos"))
            .bearer_auth(&alice_t)
            .json(&json!({"name": repo, "visibility": "private"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }
    // A clashing name at the target: create `acme/proj` first.
    let res = client
        .post(api("/orgs/acme/repos"))
        .bearer_auth(&alice_t)
        .json(&json!({"name": "proj", "visibility": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let clash = client
        .post(api("/repos/alice/proj/transfer"))
        .bearer_auth(&alice_t)
        .json(&json!({"new_owner": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(clash.status(), 422, "a name clash gives 422");

    // Bob reads `alice/other` but is not an admin there.
    let res = client
        .put(api("/repos/alice/other/collaborators/bob"))
        .bearer_auth(&alice_t)
        .json(&json!({"permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let denied = client
        .post(api("/repos/alice/other/transfer"))
        .bearer_auth(&bob_r)
        .json(&json!({"new_owner": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403, "a non-admin gets 403");

    // Bob cannot move his own repository into an org he does not own.
    let res = client
        .post(api("/user/repos"))
        .bearer_auth(&bob_t)
        .json(&json!({"name": "mine", "visibility": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let foreign = client
        .post(api("/repos/bob/mine/transfer"))
        .bearer_auth(&bob_t)
        .json(&json!({"new_owner": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), 403, "a foreign org gives 403");

    // An unknown target is 404.
    let ghost = client
        .post(api("/repos/alice/other/transfer"))
        .bearer_auth(&alice_t)
        .json(&json!({"new_owner": "ghost"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ghost.status(), 404);
}
