//! B3: the branch protection settings page. Round trip through the page
//! forms (every gate field, every push field, the allow-list, tag add and
//! remove) with each step reflected in the API GET, plus validation,
//! access, and escaping.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::orgs::{NewOrgInput, NewTeamInput, OrgRole};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::Scope;

fn protection_url(s: &TestServer, owner: &str, repo: &str) -> String {
    s.url(&format!("/{owner}/{repo}/settings/protection"))
}
async fn api_rules(s: &TestServer, token: &str) -> Value {
    let res = reqwest::Client::new()
        .get(s.url("/api/v1/repos/acme/proj/gate-rules"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    body["gate_rules"].clone()
}

async fn api_tags(s: &TestServer, token: &str) -> Value {
    let res = reqwest::Client::new()
        .get(s.url("/api/v1/repos/acme/proj/tag-protections"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    body["tag_protections"].clone()
}

async fn setup_org_repo(s: &TestServer) {
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.user("carol").await;
    s.core
        .create_org(
            &alice,
            NewOrgInput {
                handle: "acme".into(),
                display_name: "Acme".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    s.core
        .set_org_member(&alice, "acme", "bob", OrgRole::Member)
        .await
        .unwrap();
    s.core
        .set_org_member(&alice, "acme", "carol", OrgRole::Member)
        .await
        .unwrap();
    s.core
        .create_repo(
            &alice,
            "acme",
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "acme", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .create_team(
            &alice,
            "acme",
            NewTeamInput {
                name: "Releases".into(),
                description: String::new(),
                permission: "write".into(),
                all_repos: false,
            },
        )
        .await
        .unwrap();
    s.core
        .set_team_member(&alice, "acme", "releases", "bob")
        .await
        .unwrap();
}

fn full_rule_form(csrf: &str) -> Vec<(&str, &str)> {
    vec![
        ("_csrf", csrf),
        ("pattern", "main"),
        ("required_approvals", "2"),
        ("dismiss_on_push", "true"),
        ("block_on_request_changes", "true"),
        ("required_contexts", "ci/unit, ci/lint"),
        ("require_up_to_date", "true"),
        ("require_threads_resolved", "true"),
        ("require_session_evidence", "true"),
        ("allowed_methods", "merge, squash"),
        ("block_direct_push", "true"),
        ("block_force_push", "true"),
        ("block_deletion", "true"),
        ("push_users", "bob"),
        ("push_teams", "releases"),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protection_page_round_trip() {
    let s = TestServer::start().await;
    setup_org_repo(&s).await;
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let (alice_client, csrf) = s.login("alice").await;
    let page = protection_url(&s, "acme", "proj");

    // The page lists rules by pattern with an empty starting state.
    let body = get_text(&alice_client, &page).await;
    assert!(body.contains("Branch protection"), "{body}");
    assert!(body.contains("No branch rules yet"), "{body}");

    // Create a rule with every field through the page form.
    let saved = alice_client
        .post(&page)
        .form(&full_rule_form(&csrf))
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    assert_eq!(
        saved.headers()["location"],
        "/acme/proj/settings/protection"
    );

    // The API GET reflects every gate field, every push field, and the
    // allow-list.
    let rules = api_rules(&s, &token).await;
    assert_eq!(rules.as_array().unwrap().len(), 1);
    let rule = &rules[0];
    assert_eq!(rule["pattern"], "main");
    assert_eq!(rule["required_approvals"], 2);
    assert_eq!(rule["dismiss_on_push"], true);
    assert_eq!(rule["block_on_request_changes"], true);
    assert_eq!(rule["required_contexts"], json!(["ci/unit", "ci/lint"]));
    assert_eq!(rule["require_up_to_date"], true);
    assert_eq!(rule["require_threads_resolved"], true);
    assert_eq!(rule["require_session_evidence"], true);
    assert_eq!(rule["allowed_methods"], json!(["merge", "squash"]));
    assert_eq!(rule["block_direct_push"], true);
    assert_eq!(rule["block_force_push"], true);
    assert_eq!(rule["block_deletion"], true);
    assert_eq!(rule["push_allowlist"]["users"], json!(["bob"]));
    assert_eq!(rule["push_allowlist"]["teams"], json!(["releases"]));
    let id = rule["id"].as_i64().unwrap();

    // The page shows the stored rule with its restrictions and allow-list.
    let body = get_text(&alice_client, &page).await;
    assert!(body.contains("ci/unit"), "{body}");
    assert!(body.contains("bob"), "{body}");
    assert!(body.contains("releases"), "{body}");

    // Edit the rule: new approvals, new contexts, fewer methods, and the
    // deletion block lifted. Absent checkboxes mean false (full spec).
    let edit_url = s.url(&format!("/acme/proj/settings/protection/rules/{id}"));
    let saved = alice_client
        .post(&edit_url)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("pattern", "main"),
            ("required_approvals", "1"),
            ("block_on_request_changes", "true"),
            ("required_contexts", "ci/unit"),
            ("allowed_methods", "merge"),
            ("block_direct_push", "true"),
            ("block_force_push", "true"),
            ("push_users", "bob"),
            ("push_teams", "releases"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    let rules = api_rules(&s, &token).await;
    assert_eq!(rules.as_array().unwrap().len(), 1);
    assert_eq!(rules[0]["required_approvals"], 1);
    assert_eq!(rules[0]["dismiss_on_push"], false);
    assert_eq!(rules[0]["required_contexts"], json!(["ci/unit"]));
    assert_eq!(rules[0]["allowed_methods"], json!(["merge"]));
    assert_eq!(rules[0]["require_up_to_date"], false);
    assert_eq!(rules[0]["require_threads_resolved"], false);
    assert_eq!(rules[0]["require_session_evidence"], false);
    assert_eq!(rules[0]["block_direct_push"], true);
    assert_eq!(rules[0]["block_force_push"], true);
    assert_eq!(rules[0]["block_deletion"], false);

    // Add an allow-listed user and remove the team through the edit form.
    let saved = alice_client
        .post(&edit_url)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("pattern", "main"),
            ("required_approvals", "1"),
            ("push_users", "bob, carol"),
            ("push_teams", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    let rules = api_rules(&s, &token).await;
    assert_eq!(rules[0]["push_allowlist"]["users"], json!(["bob", "carol"]));
    assert_eq!(
        rules[0]["push_allowlist"]["teams"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Remove the users again and restore the team.
    let saved = alice_client
        .post(&edit_url)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("pattern", "main"),
            ("required_approvals", "1"),
            ("push_users", ""),
            ("push_teams", "releases"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    let rules = api_rules(&s, &token).await;
    assert_eq!(
        rules[0]["push_allowlist"]["users"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(rules[0]["push_allowlist"]["teams"], json!(["releases"]));

    // Delete the rule; the API list is empty again.
    let delete_url = s.url(&format!("/acme/proj/settings/protection/rules/{id}/delete"));
    let deleted = alice_client
        .post(&delete_url)
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 303);
    let rules = api_rules(&s, &token).await;
    assert_eq!(rules.as_array().unwrap().len(), 0);

    // Tag protections: add and remove through the page, reflected in the API.
    let tags_url = s.url("/acme/proj/settings/protection/tags");
    let added = alice_client
        .post(&tags_url)
        .form(&[("_csrf", csrf.as_str()), ("pattern", "v*")])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    let tags = api_tags(&s, &token).await;
    assert_eq!(tags.as_array().unwrap().len(), 1);
    assert_eq!(tags[0]["pattern"], "v*");
    let tag_id = tags[0]["id"].as_i64().unwrap();
    let body = get_text(&alice_client, &page).await;
    assert!(body.contains("v*"), "{body}");
    let removed = alice_client
        .post(s.url(&format!(
            "/acme/proj/settings/protection/tags/{tag_id}/delete"
        )))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 303);
    let tags = api_tags(&s, &token).await;
    assert_eq!(tags.as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protection_page_validation() {
    let s = TestServer::start().await;
    setup_org_repo(&s).await;
    let (alice_client, csrf) = s.login("alice").await;
    let page = protection_url(&s, "acme", "proj");

    // An invalid pattern re-renders with 422 and the error.
    let bad = alice_client
        .post(&page)
        .form(&[("_csrf", csrf.as_str()), ("pattern", "no spaces here")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
    assert!(bad.text().await.unwrap().contains("pattern"));

    // An unknown handle re-renders with 422 and the error.
    let bad = alice_client
        .post(&page)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("pattern", "main"),
            ("push_users", "nosuchuser"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
    assert!(bad.text().await.unwrap().contains("nosuchuser"));

    // Nothing was stored.
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    assert_eq!(api_rules(&s, &token).await.as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protection_page_access() {
    let s = TestServer::start().await;
    setup_org_repo(&s).await;
    s.user("dave").await;
    let page = protection_url(&s, "acme", "proj");

    // Non-readers get 404, never 403.
    let (dave, _) = s.login("dave").await;
    assert_eq!(dave.get(&page).send().await.unwrap().status(), 404);

    // Write users get 403 on the page and on every mutation.
    let (bob, bob_csrf) = s.login("bob").await;
    assert_eq!(bob.get(&page).send().await.unwrap().status(), 403);
    let refused = bob
        .post(&page)
        .form(&[("_csrf", bob_csrf.as_str()), ("pattern", "main")])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);

    // A forged CSRF token is refused with 403 and leaves state unchanged.
    let (alice_client, csrf) = s.login("alice").await;
    let forged = alice_client
        .post(&page)
        .form(&[("_csrf", "wrong"), ("pattern", "main")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let token = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    assert_eq!(api_rules(&s, &token).await.as_array().unwrap().len(), 0);

    // Archived repositories refuse mutations.
    s.core.archive_repo(&alice, "acme", "proj").await.unwrap();
    let refused = alice_client
        .post(&page)
        .form(&full_rule_form(&csrf))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    assert!(refused.text().await.unwrap().contains("archived"));
    assert_eq!(api_rules(&s, &token).await.as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protection_page_escapes_hostile_input() {
    let s = TestServer::start().await;
    setup_org_repo(&s).await;
    let (alice_client, csrf) = s.login("alice").await;
    let page = protection_url(&s, "acme", "proj");

    // A hostile pattern is refused, and the 422 re-render escapes it.
    let bad = alice_client
        .post(&page)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("pattern", "<script>alert(1)</script>"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
    let body = bad.text().await.unwrap();
    assert!(!body.contains("<script>alert(1)</script>"), "{body}");
    assert!(body.contains("&#60;script&#62;"), "{body}");

    // A hostile context name is stored but renders escaped, never as HTML.
    let saved = alice_client
        .post(&page)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("pattern", "escape-me"),
            ("required_contexts", "<script>alert(1)</script>"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    let body = get_text(&alice_client, &page).await;
    assert!(!body.contains("<script>alert(1)</script>"), "{body}");
    assert!(
        body.contains("&#60;script&#62;alert(1)&#60;/script&#62;"),
        "{body}"
    );
}
