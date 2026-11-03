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
