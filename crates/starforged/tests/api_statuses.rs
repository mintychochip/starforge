//! H2: commit status API + combined status. Real HTTP against an
//! in-process server (follows `api_trails.rs` / `api_changes.rs`).
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Permission;
use starforged_core::tokens::Scope;
use time::format_description::well_known::Rfc3339;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccc";
const SHA_FRESH: &str = "0123456789abcdef0123456789abcdef01234567";

struct Ctx {
    s: TestServer,
    alice_repo: String,
    carol_read: String,
    dave_read: String,
    dave_repo: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let carol = s.user("carol").await;
        let dave = s.user("dave").await;
        s.repo(
            &alice,
            "proj",
            starforged_core::permission::Visibility::Private,
        )
        .await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        Ctx {
            alice_repo: s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await,
            carol_read: s.token(&carol, &[Scope::RepoRead]).await,
            dave_read: s.token(&dave, &[Scope::RepoRead]).await,
            dave_repo: s.token(&dave, &[Scope::RepoRead, Scope::RepoWrite]).await,
            s,
        }
    }

    fn statuses(&self, sha: &str) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/statuses/{sha}"))
    }

    fn combined(&self, sha: &str) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/commits/{sha}/status"))
    }
}

/// Asserts `v` is an RFC 3339 string and returns it parsed.
fn rfc3339(v: &Value) -> time::OffsetDateTime {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("expected RFC 3339 string, got {v}"));
    time::OffsetDateTime::parse(s, &Rfc3339).unwrap_or_else(|_| panic!("not RFC 3339: {s}"))
}

fn post_body(state: &str, context: &str) -> Value {
    json!({"state": state, "context": context})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // Anonymous POST: 401.
    let res = client
        .post(c.statuses(SHA_A))
        .json(&post_body("pending", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Read-scoped token POST: 403 (lacks repo:write).
    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.carol_read)
        .json(&post_body("pending", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Read-scoped token GET: 200.
    let res = client
        .get(c.statuses(SHA_A))
        .bearer_auth(&c.carol_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Write token POST: 200.
    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .json(&post_body("pending", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // Non-member GET on a private repo: 404.
    let res = client
        .get(c.statuses(SHA_A))
        .bearer_auth(&c.dave_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Non-member POST with a write-scoped token: 404 (no read, so no repo).
    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.dave_repo)
        .json(&post_body("pending", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Bad sha: 422 on both POST and GET.
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/statuses/not-a-sha"))
        .bearer_auth(&c.alice_repo)
        .json(&post_body("pending", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let res = client
        .get(c.s.url("/api/v1/repos/alice/proj/statuses/not-a-sha"))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Bad state: 422.
    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .json(&post_body("bogus", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Bad context (empty and over 255 chars): 422.
    for context in ["", &"c".repeat(256)] {
        let res = client
            .post(c.statuses(SHA_A))
            .bearer_auth(&c.alice_repo)
            .json(&post_body("pending", context))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "context {context:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upsert_same_context_replaces_latest() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    for state in ["pending", "success"] {
        let res = client
            .post(c.statuses(SHA_B))
            .bearer_auth(&c.alice_repo)
            .json(&post_body(state, "ci/unit"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }

    let res = client
        .get(c.statuses(SHA_B))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let rows = body["statuses"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "one row per (sha, context): {body}");
    assert_eq!(rows[0]["state"], "success");
    assert_eq!(rows[0]["context"], "ci/unit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_contexts_both_returned() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    for context in ["ci/a", "ci/b"] {
        let res = client
            .post(c.statuses(SHA_C))
            .bearer_auth(&c.alice_repo)
            .json(&post_body("success", context))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }

    let res = client
        .get(c.statuses(SHA_C))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let rows = body["statuses"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{body}");
    let contexts: Vec<&str> = rows
        .iter()
        .map(|r| r["context"].as_str().unwrap())
        .collect();
    assert_eq!(contexts, ["ci/a", "ci/b"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_precedence_across_contexts() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let sha = "dddddddddddddddddddddddddddddddddddddddd";

    async fn combined(client: &reqwest::Client, c: &Ctx, sha: &str) -> Value {
        let res = client
            .get(c.combined(sha))
            .bearer_auth(&c.alice_repo)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        res.json().await.unwrap()
    }

    async fn post(client: &reqwest::Client, c: &Ctx, sha: &str, state: &str, context: &str) {
        let res = client
            .post(c.statuses(sha))
            .bearer_auth(&c.alice_repo)
            .json(&post_body(state, context))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }

    post(&client, &c, sha, "pending", "ci/a").await;
    post(&client, &c, sha, "success", "ci/b").await;
    let body = combined(&client, &c, sha).await;
    assert_eq!(body["state"], "pending", "{body}");
    assert_eq!(body["total_count"], 2, "{body}");

    post(&client, &c, sha, "failure", "ci/c").await;
    let body = combined(&client, &c, sha).await;
    assert_eq!(body["state"], "failure", "{body}");
    assert_eq!(body["total_count"], 3, "{body}");

    post(&client, &c, sha, "error", "ci/d").await;
    let body = combined(&client, &c, sha).await;
    assert_eq!(body["state"], "error", "{body}");
    assert_eq!(body["total_count"], 4, "{body}");
    assert_eq!(body["statuses"].as_array().unwrap().len(), 4, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_unknown_sha_is_pending_empty() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let res = client
        .get(c.combined(SHA_FRESH))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["state"], "pending", "{body}");
    assert_eq!(body["total_count"], 0, "{body}");
    assert_eq!(body["statuses"].as_array().unwrap().len(), 0, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_timestamps_parse() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .json(&json!({
            "state": "pending",
            "context": "ci/ts",
            "target_url": "https://ci.example.test/job/1",
            "description": "running",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let created: Value = res.json().await.unwrap();
    rfc3339(&created["created_at"]);
    rfc3339(&created["updated_at"]);
    assert_eq!(created["target_url"], "https://ci.example.test/job/1");
    assert_eq!(created["description"], "running");

    let res = client
        .get(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    for row in body["statuses"].as_array().unwrap() {
        rfc3339(&row["created_at"]);
        rfc3339(&row["updated_at"]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_target_url_rejected() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"state": "pending", "context": "ci/x", "target_url": "ftp://x.test/y"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
}

/// H2 bounds: context 1–255 chars, `target_url` ≤ 2048, description ≤ 1024.
/// Rejections are 422 and write no row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_field_length_bounds() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // Context: 255 accepted, 256 rejected.
    let res = client
        .post(c.statuses(SHA_FRESH))
        .bearer_auth(&c.alice_repo)
        .json(&post_body("pending", &"c".repeat(255)))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "context of 255 chars is accepted");
    for context in ["c".repeat(256)] {
        let res = client
            .post(c.statuses(SHA_FRESH))
            .bearer_auth(&c.alice_repo)
            .json(&post_body("pending", &context))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "context of 256 chars is rejected");
    }
    let body: Value = client
        .get(c.statuses(SHA_FRESH))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = body["statuses"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "rejected context wrote no row: {body}");
    assert_eq!(rows[0]["context"], "c".repeat(255));

    // `target_url`: 2048 accepted, 2049 rejected, no row written.
    let base = "http://x.test/";
    let ok_url = format!("{base}{}", "y".repeat(2048 - base.len()));
    assert_eq!(ok_url.chars().count(), 2048);
    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"state": "pending", "context": "ci/url", "target_url": ok_url}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "target_url of 2048 chars is accepted");
    let long_url = format!("{base}{}", "y".repeat(2049 - base.len()));
    let res = client
        .post(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"state": "pending", "context": "ci/url-long", "target_url": long_url}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "target_url of 2049 chars is rejected");
    let body: Value = client
        .get(c.statuses(SHA_A))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = body["statuses"].as_array().unwrap();
    assert!(
        rows.iter().all(|r| r["context"] != "ci/url-long"),
        "rejected target_url wrote no row: {body}"
    );

    // Description: 1024 accepted, 1025 rejected, no row written.
    let res = client
        .post(c.statuses(SHA_B))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"state": "pending", "context": "ci/desc", "description": "d".repeat(1024)}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "description of 1024 chars is accepted");
    let res = client
        .post(c.statuses(SHA_B))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"state": "pending", "context": "ci/desc-long", "description": "d".repeat(1025)}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "description of 1025 chars is rejected");
    let body: Value = client
        .get(c.statuses(SHA_B))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = body["statuses"].as_array().unwrap();
    assert!(
        rows.iter().all(|r| r["context"] != "ci/desc-long"),
        "rejected description wrote no row: {body}"
    );
}

/// D10: `GET …/commits/{ref}/status` resolves SHAs, branches (including names
/// with slashes, percent-encoded), and annotated tags; a branch shadows a tag
/// of the same name; unknown refs are 404 and the old route is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_by_ref() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let url = c.s.git_url("alice", "proj", Some(&c.alice_repo));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("b.txt", b"two\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let feature_tip = git_ok(&work, &["rev-parse", "HEAD"]).await;
    let feature_tip = feature_tip.trim();
    let main_tip = git_ok(&work, &["rev-parse", "main"]).await;
    let main_tip = main_tip.trim();
    // Annotated tag on main, plus a branch and a tag sharing one name.
    git_ok(&work, &["tag", "-a", "v1", "-m", "release", "main"]).await;
    git_ok(&work, &["push", "-q", &url, "tag", "v1"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "dupe"]).await;
    git_ok(&work, &["push", "-q", &url, "dupe"]).await;
    git_ok(&work, &["tag", "dupe", "main"]).await;
    git_ok(&work, &["push", "-q", &url, "tag", "dupe"]).await;

    async fn post(client: &reqwest::Client, c: &Ctx, sha: &str, state: &str, context: &str) {
        let res = client
            .post(c.statuses(sha))
            .bearer_auth(&c.alice_repo)
            .json(&post_body(state, context))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }
    post(&client, &c, main_tip, "success", "ci/main").await;
    post(&client, &c, feature_tip, "failure", "ci/feature").await;

    async fn get(client: &reqwest::Client, c: &Ctx, reference: &str) -> (u16, Value) {
        let res = client
            .get(c.s.url(&format!(
                "/api/v1/repos/alice/proj/commits/{reference}/status"
            )))
            .bearer_auth(&c.alice_repo)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    // By SHA: the peeled commit's statuses.
    let (status, body) = get(&client, &c, main_tip).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sha"], main_tip);
    assert_eq!(body["state"], "success", "{body}");
    assert_eq!(body["total_count"], 1, "{body}");

    // By branch; a slash arrives percent-encoded.
    let (status, body) = get(&client, &c, "main").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sha"], main_tip, "{body}");
    let (status, body) = get(&client, &c, "feature%2Fx").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sha"], feature_tip, "{body}");
    assert_eq!(body["state"], "failure", "{body}");

    // By annotated tag: the peeled commit.
    let (status, body) = get(&client, &c, "v1").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sha"], main_tip, "{body}");

    // A branch shadows a tag of the same name.
    let (status, body) = get(&client, &c, "dupe").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sha"], feature_tip, "{body}");

    // Unknown branch and unknown SHA behave: 404, and pending with zero rows.
    let (status, _) = get(&client, &c, "nope").await;
    assert_eq!(status, 404);
    let (status, body) = get(&client, &c, SHA_FRESH).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "pending", "{body}");
    assert_eq!(body["total_count"], 0, "{body}");

    // The old combined-status route is gone.
    let res = client
        .get(c.s.url(&format!(
            "/api/v1/repos/alice/proj/commits/{main_tip}/combined-status"
        )))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

/// D11: every API error body carries `"details": null`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_envelope_carries_details() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();

    // 401: anonymous status POST.
    let res = client
        .post(c.statuses(SHA_A))
        .json(&post_body("pending", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "unauthenticated", "{body}");
    assert_eq!(body["error"].get("details"), Some(&Value::Null), "{body}");

    // 422: bad SHA.
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/statuses/not-a-sha"))
        .bearer_auth(&c.alice_repo)
        .json(&post_body("pending", "ci/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid", "{body}");
    assert_eq!(body["error"].get("details"), Some(&Value::Null), "{body}");

    // 404: non-member read on a private repo.
    let res = client
        .get(c.statuses(SHA_A))
        .bearer_auth(&c.dave_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found", "{body}");
    assert_eq!(body["error"].get("details"), Some(&Value::Null), "{body}");
}
