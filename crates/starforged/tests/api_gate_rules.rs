//! H7: gate-rule management API. Real HTTP against an in-process server:
//! permission matrix, create→list→update→delete round-trip, validation
//! rejections, timeline rows, and a created rule blocking a change page.
mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::CreateUser;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use tokio::time::sleep;

const SCAN_TIMEOUT: Duration = Duration::from_secs(20);

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    carol_read: String,
    carol_trail: String,
    dave_trail: String,
    erin_trail: String,
    bob_trail: String,
    bob_repo_only: String,
    bob_trail_only: String,
    alice_trail: String,
    frank_trail: String,
    gus_trail: String,
    gus_repo_only: String,
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
        // Mutations need `repo:write` (H7 ruling), so maintainer tokens carry
        // all three scopes; `*_trail_only` tokens pin the no-`repo:write` case.
        let read = &[Scope::RepoRead];
        let trail = &[Scope::RepoRead, Scope::TrailWrite];
        let full = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
        Ctx {
            carol_read: s.token(&carol, read).await,
            carol_trail: s.token(&carol, trail).await,
            dave_trail: s.token(&dave, trail).await,
            erin_trail: s.token(&erin, trail).await,
            bob_trail: s.token(&bob, full).await,
            bob_repo_only: s.token(&bob, &[Scope::RepoRead, Scope::RepoWrite]).await,
            bob_trail_only: s.token(&bob, trail).await,
            alice_trail: s.token(&alice, full).await,
            frank_trail: s.token(&frank, full).await,
            gus_trail: s.token(&gus, trail).await,
            gus_repo_only: s.token(&gus, &[Scope::RepoRead, Scope::RepoWrite]).await,
            s,
            alice,
        }
    }

    fn rules(&self) -> String {
        self.s.url("/api/v1/repos/alice/proj/gate-rules")
    }

    fn rule(&self, id: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/gate-rules/{id}"))
    }

    async fn create(&self, token: &str, body: &Value) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .post(self.rules())
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(json!({}));
        (status, body)
    }
}

fn valid_body() -> Value {
    json!({
        "pattern": "main",
        "required_approvals": 1,
        "dismiss_on_push": false,
        "block_on_request_changes": true,
        "required_contexts": [],
        "require_up_to_date": false,
        "require_threads_resolved": false,
        "require_session_evidence": false,
        "allowed_methods": [],
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permission_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // Anonymous list on a private repo: 404 (never a leak-shaped 403).
    let res = client.get(c.rules()).send().await.unwrap();
    assert_eq!(res.status(), 404);

    // Anonymous create: 401.
    let res = client
        .post(c.rules())
        .json(&valid_body())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Outsider reads 404; an outsider holding `repo:write` still 404s on
    // mutations (never a leak-shaped 403), while a scope-missing token 403s.
    let res = client
        .get(c.rules())
        .bearer_auth(&c.gus_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let (status, _) = c.create(&c.gus_repo_only, &valid_body()).await;
    assert_eq!(status, 404);
    let (status, _) = c.create(&c.gus_trail, &valid_body()).await;
    assert_eq!(status, 403, "mutation without repo:write scope must be 403");

    // Readers and below read fine but cannot mutate.
    for token in [&c.carol_read, &c.carol_trail, &c.dave_trail, &c.erin_trail] {
        let res = client
            .get(c.rules())
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let (status, _) = c.create(token, &valid_body()).await;
        assert_eq!(status, 403, "mutation below maintain must be 403");
    }

    // Read-scoped token cannot mutate even for the owner: 403 (scope).
    let res = client
        .post(c.rules())
        .bearer_auth(&c.carol_read)
        .json(&valid_body())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Scope matrix: a maintainer holding only `repo:write` can mutate, while
    // a maintainer holding only `trail:write` cannot.
    let (status, scoped) = c.create(&c.bob_repo_only, &valid_body()).await;
    assert_eq!(status, 201, "repo:write suffices for mutations: {scoped}");
    let scoped_id = scoped["id"].as_i64().unwrap();
    let res = client
        .delete(c.rule(scoped_id))
        .bearer_auth(&c.bob_repo_only)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let (status, _) = c.create(&c.bob_trail_only, &valid_body()).await;
    assert_eq!(status, 403, "mutations need the repo:write scope");

    // Maintain, owner, and site admin can create.
    for token in [&c.bob_trail, &c.alice_trail, &c.frank_trail] {
        let (status, body) = c.create(token, &valid_body()).await;
        assert_eq!(status, 201, "{body}");
        let id = body["id"].as_i64().unwrap();
        // Below maintain, PATCH/DELETE are refused …
        let res = client
            .patch(c.rule(id))
            .bearer_auth(&c.erin_trail)
            .json(&json!({"required_approvals": 2}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403);
        let res = client
            .delete(c.rule(id))
            .bearer_auth(&c.erin_trail)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403);
        // … while maintain+ succeeds.
        let res = client
            .patch(c.rule(id))
            .bearer_auth(token)
            .json(&json!({"required_approvals": 2}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(res.json::<Value>().await.unwrap()["required_approvals"], 2);
        let res = client
            .delete(c.rule(id))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);
    }

    // Unknown ids are 404, not 403-shaped, for readers …
    let res = client
        .patch(c.rule(999_999))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"required_approvals": 2}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let res = client
        .delete(c.rule(999_999))
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    // … and for scoped non-readers too (a token without the scope 403s).
    let res = client
        .patch(c.rule(999_999))
        .bearer_auth(&c.gus_repo_only)
        .json(&json!({"required_approvals": 2}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let res = client
        .patch(c.rule(999_999))
        .bearer_auth(&c.gus_trail)
        .json(&json!({"required_approvals": 2}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_list_update_delete_round_trip() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let (status, created) = c
        .create(
            &c.bob_trail,
            &json!({
                "pattern": "release/*",
                "required_approvals": 2,
                "dismiss_on_push": true,
                "block_on_request_changes": false,
                "required_contexts": ["ci/unit"],
                "require_up_to_date": true,
                "require_threads_resolved": true,
                "require_session_evidence": false,
                "allowed_methods": ["merge", "squash"],
            }),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_i64().unwrap();
    assert_eq!(created["pattern"], "release/*");
    assert_eq!(created["required_approvals"], 2);
    assert_eq!(created["dismiss_on_push"], true);
    assert_eq!(created["block_on_request_changes"], false);
    assert_eq!(created["required_contexts"], json!(["ci/unit"]));
    assert_eq!(created["require_up_to_date"], true);
    assert_eq!(created["require_threads_resolved"], true);
    assert_eq!(created["require_session_evidence"], false);
    assert_eq!(created["allowed_methods"], json!(["merge", "squash"]));

    let res = client
        .get(c.rules())
        .bearer_auth(&c.carol_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list = res.json::<Value>().await.unwrap();
    assert_eq!(list["gate_rules"].as_array().unwrap().len(), 1);
    assert_eq!(list["gate_rules"][0]["id"], id);

    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({
            "pattern": "main",
            "required_approvals": 0,
            "dismiss_on_push": false,
            "allowed_methods": ["fast_forward"],
            "required_contexts": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let updated = res.json::<Value>().await.unwrap();
    assert_eq!(updated["pattern"], "main");
    assert_eq!(updated["required_approvals"], 0);
    assert_eq!(updated["dismiss_on_push"], false);
    assert_eq!(updated["allowed_methods"], json!(["fast_forward"]));
    assert_eq!(updated["required_contexts"], json!([]));

    let res = client
        .delete(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    let res = client
        .get(c.rules())
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.json::<Value>().await.unwrap()["gate_rules"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_rejections() {
    let c = Ctx::start().await;

    // Bad patterns: shell metacharacters, spaces, and over-length.
    for pattern in [
        json!("main; rm -rf"),
        json!("has space"),
        json!("a$b"),
        json!("x".repeat(101)),
    ] {
        let mut body = valid_body();
        body["pattern"] = pattern.clone();
        let (status, rejected) = c.create(&c.bob_trail, &body).await;
        assert_eq!(
            status, 422,
            "pattern {pattern} must be rejected: {rejected}"
        );
    }

    // Approvals outside 0..=20.
    for approvals in [json!(-1), json!(21)] {
        let mut body = valid_body();
        body["required_approvals"] = approvals.clone();
        let (status, rejected) = c.create(&c.bob_trail, &body).await;
        assert_eq!(
            status, 422,
            "approvals {approvals} must be rejected: {rejected}"
        );
    }

    // Unknown merge methods.
    let mut body = valid_body();
    body["allowed_methods"] = json!(["teleport"]);
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "{rejected}");

    // Empty contexts and over-long ones. The message names the field.
    let mut body = valid_body();
    body["required_contexts"] = json!([""]);
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "{rejected}");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("required_contexts"),
        "{rejected}"
    );
    let mut body = valid_body();
    body["pattern"] = json!("has space");
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "{rejected}");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pattern"),
        "{rejected}"
    );
    let mut body = valid_body();
    body["required_contexts"] = json!(["x".repeat(256)]);
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "{rejected}");
    // The 255-char boundary is accepted.
    let mut body = valid_body();
    body["pattern"] = json!("ctx-boundary");
    body["required_contexts"] = json!(["x".repeat(255)]);
    let (status, created) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 201, "{created}");

    // PATCH validates too.
    let (status, created) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_i64().unwrap();
    let client = reqwest::Client::new();
    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"pattern": "no spaces here"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Boundaries that must pass: distinct globs, 0 and 20 approvals, and
    // every known method.
    for pattern in ["release/*", "feat-?", "main"] {
        let mut body = valid_body();
        body["pattern"] = json!(format!("{pattern}-ok"));
        let (status, accepted) = c.create(&c.bob_trail, &body).await;
        assert_eq!(status, 201, "pattern {pattern} must pass: {accepted}");
    }
    for approvals in [json!(0), json!(20)] {
        let mut body = valid_body();
        body["pattern"] = json!(format!("approvals-{}", approvals.as_i64().unwrap()));
        body["required_approvals"] = approvals.clone();
        let (status, accepted) = c.create(&c.bob_trail, &body).await;
        assert_eq!(status, 201, "approvals {approvals} must pass: {accepted}");
    }
    let mut body = valid_body();
    body["pattern"] = json!("all-methods");
    body["allowed_methods"] = json!(["merge", "squash", "fast_forward"]);
    let (status, accepted) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 201, "{accepted}");

    // A misspelled field is a 422, never a silently weaker gate.
    let mut body = valid_body();
    body["pattern"] = json!("typo-check");
    body["required_approval"] = json!(2);
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "unknown field must be rejected: {rejected}");

    // PATCH `null` for a non-pattern field is a 422.
    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"required_approvals": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_and_null_patterns_read_back_null_and_collide() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // `""` is stored as NULL and reads back as null.
    let mut body = valid_body();
    body["pattern"] = json!("");
    let (status, created) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["pattern"], Value::Null);
    let empty_id = created["id"].as_i64().unwrap();

    // An explicit `null` collides with it: one rule per normalized pattern.
    let mut body = valid_body();
    body["pattern"] = Value::Null;
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 409, "{rejected}");

    // After deleting the `""` rule, `null` inserts and reads back as null.
    let res = client
        .delete(c.rule(empty_id))
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let (status, created) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["pattern"], Value::Null);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_pattern_conflicts_on_create_and_update() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let (status, first) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 201, "{first}");
    let mut second = valid_body();
    second["pattern"] = json!("release/*");
    let (status, created) = c.create(&c.bob_trail, &second).await;
    assert_eq!(status, 201, "{created}");
    let other = created["id"].as_i64().unwrap();

    // Same pattern again is a 409.
    let (status, rejected) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 409, "{rejected}");

    // Updating another rule onto an occupied pattern is a 409 too.
    let res = client
        .patch(c.rule(other))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"pattern": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);

    // … while moving onto a free pattern succeeds.
    let res = client
        .patch(c.rule(other))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"pattern": "hotfix/*"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["pattern"], "hotfix/*");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archived_repo_refuses_every_mutation() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let (status, created) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_i64().unwrap();
    c.s.core
        .archive_repo(&c.alice, "alice", "proj")
        .await
        .unwrap();

    // Reads still work on an archived repo.
    let res = client
        .get(c.rules())
        .bearer_auth(&c.carol_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // … but every mutation is refused with the webhook-style error.
    let (status, refused) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 422, "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("archived"),
        "{refused}"
    );
    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"required_approvals": 2}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let res = client
        .delete(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Refused mutations write no timeline rows.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM timeline_events WHERE kind LIKE 'gate_rule.%'")
            .fetch_one(c.s.core.db().pool())
            .await
            .unwrap();
    assert_eq!(count, 1, "only the pre-archive create was recorded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_repo_lists_anonymously() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Maintain)
        .await
        .unwrap();
    let token = s.token(&bob, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let client = reqwest::Client::new();
    let url = s.url("/api/v1/repos/alice/proj/gate-rules");
    let res = client
        .post(&url)
        .bearer_auth(&token)
        .json(&valid_body())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.json::<Value>().await.unwrap()["gate_rules"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Anonymous mutations are still 401, not a free pass.
    let res = client.post(&url).json(&valid_body()).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutations_write_timeline_rows() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let (status, created) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_i64().unwrap();

    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"required_approvals": 3}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .delete(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, payload FROM timeline_events WHERE kind LIKE 'gate_rule.%' ORDER BY id ASC",
    )
    .fetch_all(c.s.core.db().pool())
    .await
    .unwrap();
    let kinds: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "gate_rule.created",
            "gate_rule.updated",
            "gate_rule.deleted"
        ],
        "{kinds:?}"
    );
    for (_, payload) in &rows {
        let event: Value = serde_json::from_str(payload).unwrap();
        assert_eq!(event["id"], id, "payload carries the id: {payload}");
        assert_eq!(
            event["pattern"], "main",
            "payload carries the pattern: {payload}"
        );
    }
    // Exactly one audit row per mutation, on the same target as the timeline.
    for action in [
        "gate_rule.created",
        "gate_rule.updated",
        "gate_rule.deleted",
    ] {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1 AND target = $2")
                .bind(action)
                .bind(format!("gate_rule:alice/proj#{id}"))
                .fetch_one(c.s.core.db().pool())
                .await
                .unwrap();
        assert_eq!(count, 1, "{action} audited once");
    }
}

/// Pushes the work repo's HEAD as `refs/for/<target>`; returns the pushed SHA.
async fn push_for(work: &Path, url: &str, target: &str) -> String {
    git_ok(
        work,
        &["push", "-q", url, &format!("HEAD:refs/for/{target}")],
    )
    .await;
    git_ok(work, &["rev-parse", "HEAD"]).await.trim().to_owned()
}

async fn setup_pushed_repo(
    s: &TestServer,
    alice: &starforged_core::accounts::User,
) -> (PathBuf, String) {
    let token = s.token(alice, &[Scope::RepoWrite]).await;
    let url = s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    (work, url)
}

async fn wait_for_change(s: &TestServer, repo_id: i64, user_id: i64, base: &str, topic: &str) {
    let start = Instant::now();
    loop {
        let found = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            user_id,
            base,
            topic,
            None,
        )
        .await
        .unwrap();
        if found.is_some() {
            return;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "timed out waiting for open change {base}/{topic}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn push_revision(
    s: &TestServer,
    alice: &starforged_core::accounts::User,
    repo_id: i64,
    work: &Path,
    url: &str,
    topic: &str,
) {
    commit_files(work, &[("feature.txt", b"hello feature\n")], "add feature").await;
    push_for(work, url, &format!("main/{topic}")).await;
    wait_for_change(s, repo_id, alice.id, "main", topic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_rule_blocks_the_change_page_gate_panel() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(&c.s, &c.alice, repo_id, &work, &url, "feat").await;

    // A rule requiring one approval on the change's base branch, via the API.
    let (status, created) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 201, "{created}");

    let (browser, _) = c.s.login("alice").await;
    let page = get_text(&browser, &c.s.url("/alice/proj/trails/1/changes/1")).await;
    assert!(page.contains("Gates"), "gate panel:\n{page}");
    assert!(page.contains("Gates failing"), "failing banner:\n{page}");
    assert!(
        page.contains("needs 1 more approval"),
        "gate reason:\n{page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_refused_until_rule_is_satisfiable() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(&c.s, &c.alice, repo_id, &work, &url, "feat").await;

    // The rule demands one approval, so the merge is refused while Gates fail.
    let (status, created) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_i64().unwrap();
    let client = reqwest::Client::new();
    let merge_url = c.s.url("/api/v1/repos/alice/proj/trails/1/changes/1/merge");
    let res = client
        .post(&merge_url)
        .bearer_auth(&c.bob_trail)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "failing gates must refuse the merge");

    // Relaxing the rule to zero approvals lets the same merge succeed.
    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"required_approvals": 0}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .post(&merge_url)
        .bearer_auth(&c.bob_trail)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "satisfiable gates must merge");
    assert_eq!(res.json::<Value>().await.unwrap()["method"], "merge");
}

/// A control character inside a required context rejects the rule (422) and
/// stores nothing: gate contexts surface in CLI output like status contexts.
/// The message states the real reason with the entry Debug-escaped, so no raw
/// newline reaches the error text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_character_context_rejected_and_stores_nothing() {
    let c = Ctx::start().await;
    let mut body = valid_body();
    body["pattern"] = json!("ctx-control");
    body["required_contexts"] = json!(["ci/\nunit"]);
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "{rejected}");
    let message = rejected["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("control characters"),
        "message must state the real reason: {rejected}"
    );
    assert!(
        !message.contains('\n'),
        "message must not carry a raw newline: {rejected:?}"
    );
    assert!(
        message.contains("ci/\\nunit"),
        "entry must show escaped: {rejected:?}"
    );

    let client = reqwest::Client::new();
    let res = client
        .get(c.rules())
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list = res.json::<Value>().await.unwrap();
    assert!(
        list["gate_rules"].as_array().unwrap().is_empty(),
        "rejected rule wrote no row: {list}"
    );
}

/// The push-restriction fields and the allow-list round-trip through the
/// DTO on create, list, and update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protection_fields_round_trip() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let mut body = valid_body();
    body["block_direct_push"] = json!(true);
    body["block_force_push"] = json!(true);
    body["block_deletion"] = json!(false);
    body["push_allowlist"] = json!({"users": ["erin"], "teams": []});
    let (status, created) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["block_direct_push"], true);
    assert_eq!(created["block_force_push"], true);
    assert_eq!(created["block_deletion"], false);
    assert_eq!(
        created["push_allowlist"],
        json!({"users": ["erin"], "teams": []})
    );
    let id = created["id"].as_i64().unwrap();

    let res = client
        .get(c.rules())
        .bearer_auth(&c.carol_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list = res.json::<Value>().await.unwrap();
    assert_eq!(
        list["gate_rules"][0]["push_allowlist"],
        json!({"users": ["erin"], "teams": []})
    );

    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({
            "block_deletion": true,
            "push_allowlist": {"users": [], "teams": []},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let updated = res.json::<Value>().await.unwrap();
    assert_eq!(updated["block_deletion"], true);
    assert_eq!(updated["block_direct_push"], true, "absent fields stay");
    assert_eq!(
        updated["push_allowlist"],
        json!({"users": [], "teams": []}),
        "a present allow-list replaces the whole list"
    );
}

/// Unknown handles, unknown teams, and team entries on a user-owned
/// repository are all 422 and store nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protection_allowlist_validation() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let mut body = valid_body();
    body["pattern"] = json!("allow-unknown-user");
    body["push_allowlist"] = json!({"users": ["nobody"], "teams": []});
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "{rejected}");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nobody"),
        "{rejected}"
    );

    // Team entries need an org-owned repository: on a user-owned repo any
    // team entry is 422.
    let mut body = valid_body();
    body["pattern"] = json!("allow-team-user-repo");
    body["push_allowlist"] = json!({"users": [], "teams": ["releases"]});
    let (status, rejected) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 422, "{rejected}");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("org-owned"),
        "{rejected}"
    );

    // On an org-owned repository an unknown slug names the team.
    use starforged_core::orgs::{NewOrgInput, OrgRole};
    use starforged_core::permission::Visibility;
    use starforged_core::repos::CreateRepo;
    c.s.core
        .create_org(
            &c.alice,
            NewOrgInput {
                handle: "acme".into(),
                display_name: "Acme".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    c.s.core
        .set_org_member(&c.alice, "acme", "bob", OrgRole::Member)
        .await
        .unwrap();
    c.s.core
        .create_repo(
            &c.alice,
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
    let res = client
        .post(c.s.url("/api/v1/repos/acme/proj/gate-rules"))
        .bearer_auth(&c.alice_trail)
        .json(&json!({
            "pattern": "allow-unknown-team",
            "push_allowlist": {"users": [], "teams": ["nope"]},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let rejected = res.json::<Value>().await.unwrap();
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nope"),
        "{rejected}"
    );

    // A PATCH with an unknown handle is likewise refused.
    let (status, created) = c.create(&c.bob_trail, &valid_body()).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_i64().unwrap();
    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"push_allowlist": {"users": ["ghost"], "teams": []}}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    let res = client
        .get(c.rules())
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    let list = res.json::<Value>().await.unwrap();
    assert_eq!(list["gate_rules"].as_array().unwrap().len(), 1);
    assert_eq!(
        list["gate_rules"][0]["push_allowlist"],
        json!({"users": [], "teams": []}),
        "rejected writes store nothing"
    );
}

/// Protection changes write exactly one audit row per mutation, and a
/// no-op update writes neither timeline nor audit rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protection_changes_audit_once_and_noops_write_nothing() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let mut body = valid_body();
    body["block_direct_push"] = json!(true);
    body["push_allowlist"] = json!({"users": ["erin"], "teams": []});
    let (status, created) = c.create(&c.bob_trail, &body).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_i64().unwrap();
    let target = format!("gate_rule:alice/proj#{id}");

    async fn audit_count(c: &Ctx, action: &str, target: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1 AND target = $2")
            .bind(action)
            .bind(target)
            .fetch_one(c.s.core.db().pool())
            .await
            .unwrap()
    }
    async fn timeline_count(c: &Ctx, kind: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM timeline_events WHERE kind = $1")
            .bind(kind)
            .fetch_one(c.s.core.db().pool())
            .await
            .unwrap()
    }
    assert_eq!(audit_count(&c, "gate_rule.created", &target).await, 1);

    // Repeating the same state is a no-op: 200, but no new rows.
    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({
            "block_direct_push": true,
            "push_allowlist": {"users": ["erin"], "teams": []},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(audit_count(&c, "gate_rule.updated", &target).await, 0);
    assert_eq!(timeline_count(&c, "gate_rule.updated").await, 0);

    // A real change writes exactly one row of each.
    let res = client
        .patch(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .json(&json!({"block_force_push": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(audit_count(&c, "gate_rule.updated", &target).await, 1);
    assert_eq!(timeline_count(&c, "gate_rule.updated").await, 1);

    let res = client
        .delete(c.rule(id))
        .bearer_auth(&c.bob_trail)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(audit_count(&c, "gate_rule.deleted", &target).await, 1);
}
