//! M2e K5: dashboard discovery. Signed-in users see Trails assigned to
//! them, Trails awaiting their review, and their recent sessions across
//! repositories; losing access hides rows immediately, and anonymous
//! visitors see no change.
mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use starforged_core::ingest::IngestAuth;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const ULID_NORMAL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FVA";
const ULID_QUARANTINED: &str = "01ARZ3NDEKTSV4RRFFQ69G5FVB";
const ULID_UNPUBLISHED: &str = "01ARZ3NDEKTSV4RRFFQ69G5FVC";

/// A realistic `ghp_` classic token: trips the known-token rule when it
/// appears in metadata strings, so the session quarantines on upsert.
const PLANTED_TOKEN: &str = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ12";

fn meta_body(ulid: &str, title: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "1.0"},
        "models": ["opus"],
        "title": title,
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

async fn upload_and_complete(
    s: &TestServer,
    token: &str,
    owner: &str,
    repo: &str,
    ulid: &str,
    title: &str,
) {
    let client = reqwest::Client::new();
    let created = client
        .put(s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}")))
        .bearer_auth(token)
        .json(&meta_body(ulid, title))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "upload {ulid} to {owner}/{repo}");
    let done = client
        .post(s.url(&format!(
            "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/complete"
        )))
        .bearer_auth(token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200, "complete {ulid}");
}

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    bob: starforged_core::accounts::User,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        s.user("carol").await;
        s.repo(&bob, "proj", Visibility::Private).await;
        s.repo(&bob, "lab", Visibility::Private).await;
        s.repo(&bob, "open", Visibility::Public).await;
        s.core
            .set_collaborator(&bob, "bob", "proj", "alice", Permission::Write)
            .await
            .unwrap();
        s.core
            .set_collaborator(&bob, "bob", "lab", "alice", Permission::Read)
            .await
            .unwrap();
        s.core
            .set_collaborator(&bob, "bob", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        Ctx { s, alice, bob }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_shows_assigned_requested_and_sessions() {
    let c = Ctx::start().await;
    // Trails in two repos: P1/L1 assigned to alice, P2/L2 awaiting her review.
    for (repo, title) in [("proj", "proj job"), ("lab", "lab job")] {
        c.s.core
            .create_trail(&c.bob, "bob", repo, title, "intent")
            .await
            .unwrap();
    }
    for (repo, title) in [("proj", "proj review"), ("lab", "lab review")] {
        c.s.core
            .create_trail(&c.bob, "bob", repo, title, "intent")
            .await
            .unwrap();
    }
    c.s.core
        .add_assignee(&c.bob, "bob", "proj", 1, "alice")
        .await
        .unwrap();
    c.s.core
        .add_assignee(&c.bob, "bob", "lab", 1, "alice")
        .await
        .unwrap();
    c.s.core
        .request_review(&c.bob, "bob", "proj", 2, "alice")
        .await
        .unwrap();
    c.s.core
        .request_review(&c.bob, "bob", "lab", 2, "alice")
        .await
        .unwrap();

    // Alice's own uploads to proj: one normal, one quarantined by the
    // planted token in its title.
    let upload = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    upload_and_complete(&c.s, &upload, "bob", "proj", ULID_NORMAL, "widget work").await;
    upload_and_complete(
        &c.s,
        &upload,
        "bob",
        "proj",
        ULID_QUARANTINED,
        &format!("widget work {PLANTED_TOKEN}"),
    )
    .await;
    let row = starforged_db::sessions::session_by_ulid(
        c.s.core.db(),
        c.s.core
            .repo_for(Some(&c.alice), "bob", "proj")
            .await
            .unwrap()
            .repo
            .id,
        ULID_QUARANTINED,
    )
    .await
    .unwrap()
    .expect("quarantined session row");
    assert_eq!(row.quarantine, "quarantined");

    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.s.url("/")).await;
    assert!(page.contains("Assigned to you"), "assigned section");
    assert!(page.contains("Awaiting your review"), "review section");
    assert!(page.contains("Your recent sessions"), "sessions section");
    for link in [
        "/bob/proj/trails/1",
        "/bob/lab/trails/1",
        "/bob/proj/trails/2",
        "/bob/lab/trails/2",
    ] {
        assert!(page.contains(link), "dashboard links {link}");
    }
    for ulid in [ULID_NORMAL, ULID_QUARANTINED] {
        assert!(
            page.contains(&format!("/bob/proj/sessions/{ulid}")),
            "dashboard links session {ulid}"
        );
    }

    // A closed Trail drops out of the assigned section.
    c.s.core
        .set_trail_state(&c.bob, "bob", "proj", 1, "closed")
        .await
        .unwrap();
    let page = get_text(&alice, &c.s.url("/")).await;
    assert!(!page.contains("/bob/proj/trails/1"), "closed trails hide");
    assert!(page.contains("/bob/lab/trails/1"), "other repos stay");

    // Removing alice from proj hides that repo's Trails and her sessions there.
    c.s.core
        .remove_collaborator(&c.bob, "bob", "proj", "alice")
        .await
        .unwrap();
    let page = get_text(&alice, &c.s.url("/")).await;
    assert!(!page.contains("/bob/proj/trails/2"), "proj trails hide");
    assert!(!page.contains(ULID_NORMAL), "proj sessions hide");
    assert!(!page.contains(ULID_QUARANTINED), "quarantined hides too");
    assert!(page.contains("/bob/lab/trails/1"), "lab rows stay");
    assert!(page.contains("/bob/lab/trails/2"), "lab reviews stay");

    // The quarantined session is hers, so it appears for her; bob (the repo
    // owner) and carol (a reader) never uploaded it, so it stays off their
    // dashboards even though bob could read it.
    let (bob, _) = c.s.login("bob").await;
    let (carol, _) = c.s.login("carol").await;
    for (client, who) in [(&bob, "bob"), (&carol, "carol")] {
        let other = get_text(client, &c.s.url("/")).await;
        assert!(
            !other.contains(ULID_QUARANTINED),
            "{who} must not see alice's quarantined session"
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_hides_unpublished_non_member_session() {
    let c = Ctx::start().await;
    // Alice authors an open change on the public repo as a non-member: a
    // refs/for push, which anyone_with_read admits for any reader.
    let read = c.s.token(&c.alice, &[Scope::RepoRead]).await;
    // The public repo needs a `main` branch before refs/for can target it.
    let seed = c.s.token(&c.bob, &[Scope::RepoWrite]).await;
    let seed_tmp = tempfile::tempdir().unwrap();
    let seed_work = work_repo(seed_tmp.path(), "seed", &[("README.md", "# open\n")]).await;
    git_ok(
        &seed_work,
        &[
            "push",
            "-q",
            &c.s.git_url("bob", "open", Some(&seed)),
            "main",
        ],
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# open\n")]).await;
    let push = git(
        &work,
        &[
            "push",
            &c.s.git_url("bob", "open", Some(&read)),
            "HEAD:refs/for/main/alice-topic",
        ],
    )
    .await;
    assert!(push.status.success(), "refs/for push: {push:?}");
    let repo_id =
        c.s.core
            .repo_for(Some(&c.bob), "bob", "open")
            .await
            .unwrap()
            .repo
            .id;
    let start = std::time::Instant::now();
    loop {
        if starforged_db::changes::open_agit_change(
            c.s.core.db(),
            repo_id,
            c.alice.id,
            "main",
            "alice-topic",
            None,
        )
        .await
        .unwrap()
        .is_some()
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "open change never appeared"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Her unpublished upload to that repo is hers but unreadable to her
    // under §6.4 rule 2 (public + unpublished + non-member): the dashboard
    // omits it. HTTP upload would 403 without Write, so the row goes
    // through Core exactly as such an upload would store it.
    let access =
        c.s.core
            .repo_for(Some(&c.alice), "bob", "open")
            .await
            .unwrap();
    let auth = IngestAuth {
        user: c.alice.clone(),
        access,
    };
    let meta = serde_json::to_value(meta_body(ULID_UNPUBLISHED, "unpublished work")).unwrap();
    c.s.core
        .upsert_session_meta(&auth, ULID_UNPUBLISHED, &meta)
        .await
        .unwrap();
    c.s.core
        .complete_session(&auth, ULID_UNPUBLISHED)
        .await
        .unwrap();

    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.s.url("/")).await;
    assert!(
        !page.contains(ULID_UNPUBLISHED),
        "rule-2 session must not appear"
    );
    assert!(
        !page.contains("Your recent sessions"),
        "empty sessions section is omitted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_dashboard_is_unchanged() {
    let c = Ctx::start().await;
    let anon = c.s.browser();
    let page = get_text(&anon, &c.s.url("/")).await;
    assert!(page.contains("Starforge"));
    for section in [
        "Assigned to you",
        "Awaiting your review",
        "Your recent sessions",
    ] {
        assert!(!page.contains(section), "anonymous sees no {section}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_lists_org_repositories() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    let alice_t = s.token(&alice, &[Scope::RepoWrite]).await;
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
        .put(api("/orgs/acme/members/bob"))
        .bearer_auth(&alice_t)
        .json(&json!({"role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .post(api("/orgs/acme/repos"))
        .bearer_auth(&alice_t)
        .json(&json!({"name": "proj", "visibility": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // The org base permission makes bob a member: the repo is on his dashboard.
    let res = client
        .patch(api("/orgs/acme"))
        .bearer_auth(&alice_t)
        .json(&json!({"base_permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let (bob_browser, _) = s.login("bob").await;
    let page = get_text(&bob_browser, &s.url("/")).await;
    assert!(
        page.contains("/acme/proj"),
        "base-permission repo is listed"
    );

    // With no base permission, a team grant still lists it.
    let res = client
        .patch(api("/orgs/acme"))
        .bearer_auth(&alice_t)
        .json(&json!({"base_permission": "none"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let page = get_text(&bob_browser, &s.url("/")).await;
    assert!(!page.contains("/acme/proj"), "no grant, no listing");
    let res = client
        .post(api("/orgs/acme/teams"))
        .bearer_auth(&alice_t)
        .json(&json!({"name": "devs", "permission": "read", "all_repos": true}))
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
    let page = get_text(&bob_browser, &s.url("/")).await;
    assert!(page.contains("/acme/proj"), "team-grant repo is listed");
}
