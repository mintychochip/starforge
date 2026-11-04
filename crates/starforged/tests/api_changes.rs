//! M2b G4: changes/reviews/threads service + REST API. Real git over HTTP,
//! in-process server (follows `push_changes.rs` / `api_trails.rs` conventions).
mod common;

use std::path::PathBuf;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;
use starforged_db::{changes as db_changes, trails as db_trails};

const BOGUS: &str = "sfp_0000000000000000000000000000000000000000000000000000000000000000";
const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "test session",
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

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    alice_rw: String,
    bob_rw: String,
    carol_rw: String,
    erin_rw: String,
    dave_rw: String,
    alice_read: String,
    alice_trail_only: String,
    alice_upload: String,
    alice_repo: String,
    frank_repo: String,
}
impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let erin = s.user("erin").await;
        let dave = s.user("dave").await;
        let frank = s.user("frank").await;
        s.repo(&alice, "proj", Visibility::Private).await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Triage)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "erin", Permission::Read)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "frank", Permission::Write)
            .await
            .unwrap();
        let scopes = &[Scope::RepoRead, Scope::TrailWrite];
        Ctx {
            alice_rw: s.token(&alice, scopes).await,
            bob_rw: s.token(&bob, scopes).await,
            carol_rw: s.token(&carol, scopes).await,
            erin_rw: s.token(&erin, scopes).await,
            dave_rw: s.token(&dave, scopes).await,
            alice_read: s.token(&alice, &[Scope::RepoRead]).await,
            alice_trail_only: s.token(&alice, &[Scope::TrailWrite]).await,
            alice_upload: s.token(&alice, &[Scope::SessionUpload]).await,
            alice_repo: s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await,
            frank_repo: s.token(&frank, &[Scope::RepoRead, Scope::RepoWrite]).await,
            s,
            alice,
        }
    }

    fn trails(&self) -> String {
        self.s.url("/api/v1/repos/alice/proj/trails")
    }

    fn changes(&self, n: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes"))
    }

    fn change(&self, n: i64, k: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes/{k}"))
    }

    async fn trail(&self) -> i64 {
        let client = reqwest::Client::new();
        let res = client
            .post(self.trails())
            .bearer_auth(&self.alice_rw)
            .json(&json!({"title": "feature work", "intent": "ship it"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        res.json::<Value>().await.unwrap()["number"]
            .as_i64()
            .unwrap()
    }

    /// Pushes `main` plus a two-commit `feature/x` (text edits only) and
    /// returns the working copy.
    async fn push_basic(&self) -> PathBuf {
        let url = self.s.git_url(
            "alice",
            "proj",
            Some(&self.s.token(&self.alice, &[Scope::RepoWrite]).await),
        );
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
        git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
        commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
        commit_files(&work, &[("b.txt", b"bee\n")], "add bee").await;
        git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
        work
    }

    async fn create_branch_change(&self, n: i64, token: &str) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(self.changes(n))
            .bearer_auth(token)
            .json(&json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "main"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create branch change");
        res.json::<Value>().await.unwrap()
    }
}

fn error(res: Value) -> (String, String) {
    let code = res["error"]["code"].as_str().unwrap_or("").to_owned();
    let message = res["error"]["message"].as_str().unwrap_or("").to_owned();
    (code, message)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_change_create_list_close_reopen() {
    let c = Ctx::start().await;
    c.push_basic().await;
    let n = c.trail().await;
    let client = reqwest::Client::new();

    // Triage creates: 201 with the full shape, k = 1 on a fresh trail.
    let created = c.create_branch_change(n, &c.bob_rw).await;
    assert_eq!(created["k"], 1);
    assert_eq!(created["trail"], n);
    assert_eq!(created["kind"], "branch");
    assert_eq!(created["head_branch"], "feature/x");
    assert_eq!(created["base_branch"], "main");
    assert_eq!(created["current_revision"], 1);
    assert_eq!(created["state"], "open");
    assert_eq!(created["creator"], "bob");
    assert!(created["mergeability"].is_string(), "{created}");
    assert!(created["conflict_paths"].is_array(), "{created}");
    assert!(created["created_at"].is_string(), "{created}");
    assert!(created["updated_at"].is_string(), "{created}");

    // A reader cannot create a branch change.
    let denied = client
        .post(c.changes(n))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    // Unknown head branch and head == base are 422, never 404/500.
    for body in [
        json!({"kind": "branch", "head_branch": "nope", "base_branch": "main"}),
        json!({"kind": "branch", "head_branch": "main", "base_branch": "main"}),
        json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "nope"}),
    ] {
        let res = client
            .post(c.changes(n))
            .bearer_auth(&c.bob_rw)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "{body}");
        assert_eq!(error(res.json().await.unwrap()).0, "invalid");
    }

    // List round-trips the one change.
    let list = client
        .get(c.changes(n))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let list: Value = list.json().await.unwrap();
    assert_eq!(list["changes"].as_array().unwrap().len(), 1);
    assert_eq!(list["changes"][0]["k"], 1);

    // Detail carries change + revisions + selected + discussion + capabilities.
    let detail = client
        .get(c.change(n, 1))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let detail: Value = detail.json().await.unwrap();
    assert_eq!(detail["change"]["k"], 1);
    assert_eq!(detail["revisions"].as_array().unwrap().len(), 1);
    assert_eq!(detail["selected"]["r"], 1);
    assert_eq!(detail["reviews"].as_array().unwrap().len(), 0);
    assert_eq!(detail["threads"].as_array().unwrap().len(), 0);
    assert_eq!(detail["can_review"], true);
    assert_eq!(detail["can_triage"], false);
    assert_eq!(detail["can_close"], false);
    let triage_detail: Value = client
        .get(c.change(n, 1))
        .bearer_auth(&c.bob_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(triage_detail["can_triage"], true);
    assert_eq!(triage_detail["can_close"], true);

    // Unknown change and unknown revision are 404.
    for url in [c.change(n, 99), format!("{}?rev=99", c.change(n, 1))] {
        let res = client
            .get(url)
            .bearer_auth(&c.carol_rw)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404);
    }

    // A non-creator reader cannot close; merged is rejected for everyone.
    let carol_close = client
        .patch(c.change(n, 1))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"state": "closed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(carol_close.status(), 403);
    let merged = client
        .patch(c.change(n, 1))
        .bearer_auth(&c.bob_rw)
        .json(&json!({"state": "merged"}))
        .send()
        .await
        .unwrap();
    assert_eq!(merged.status(), 422);
    let bogus = client
        .patch(c.change(n, 1))
        .bearer_auth(&c.bob_rw)
        .json(&json!({"state": "archived"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bogus.status(), 422);

    // The creator may close/reopen even after losing triage (read is enough).
    c.s.core
        .set_collaborator(&c.alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let close = client
        .patch(c.change(n, 1))
        .bearer_auth(&c.bob_rw)
        .json(&json!({"state": "closed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(close.status(), 200);
    assert_eq!(close.json::<Value>().await.unwrap()["state"], "closed");
    let carol_reopen = client
        .patch(c.change(n, 1))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"state": "open"}))
        .send()
        .await
        .unwrap();
    assert_eq!(carol_reopen.status(), 403);
    // The POST /state alias behaves the same.
    let reopen = client
        .post(format!("{}/state", c.change(n, 1)))
        .bearer_auth(&c.bob_rw)
        .json(&json!({"state": "open"}))
        .send()
        .await
        .unwrap();
    assert_eq!(reopen.status(), 200);
    assert_eq!(reopen.json::<Value>().await.unwrap()["state"], "open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reviews_verdicts_session_validation_and_dismiss() {
    let c = Ctx::start().await;
    c.push_basic().await;
    let n = c.trail().await;
    c.create_branch_change(n, &c.bob_rw).await;
    let client = reqwest::Client::new();
    let reviews = format!("{}/reviews", c.change(n, 1));

    // Any reader may submit any verdict; all three record.
    for verdict in ["approve", "request_changes", "comment"] {
        let res = client
            .post(&reviews)
            .bearer_auth(&c.carol_rw)
            .json(&json!({"verdict": verdict, "body": format!("looks {verdict}")}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "{verdict}");
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["verdict"], verdict);
        assert_eq!(body["revision"], 1);
        assert_eq!(body["author"], "carol");
        assert_eq!(body["state"], "submitted");
        assert!(body["id"].is_number());
    }

    // Bad verdicts, empty bodies, and oversized bodies are 422.
    for body in [
        json!({"verdict": "ship-it", "body": "x"}),
        json!({"verdict": "approve", "body": ""}),
        json!({"verdict": "approve", "body": "  "}),
        json!({"verdict": "approve", "body": "x".repeat(65_537)}),
    ] {
        let res = client
            .post(&reviews)
            .bearer_auth(&c.carol_rw)
            .json(&body)
            .send()
            .await
            .unwrap();
        let dbg = format!("{body:?}");
        assert_eq!(res.status(), 422, "{}", &dbg[..dbg.len().min(64)]);
    }

    // A session must be a ULID that exists in this repo: malformed,
    // unknown, and cross-repo values are all 422.
    for session in ["not-a-ulid", ULID_A, "01ARZ3NDEKTSV4RRFFQ69G5FA0"] {
        let res = client
            .post(&reviews)
            .bearer_auth(&c.carol_rw)
            .json(&json!({"verdict": "comment", "body": "s?", "session": session}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "{session}");
    }

    // A real session links; a quarantined one is rejected; releasing unblocks.
    let put = client
        .put(c.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_A}")))
        .bearer_auth(&c.alice_upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 201);
    let linked = client
        .post(&reviews)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"verdict": "approve", "body": "agent did it", "session": ULID_A}))
        .send()
        .await
        .unwrap();
    assert_eq!(linked.status(), 201);
    assert_eq!(linked.json::<Value>().await.unwrap()["session"], ULID_A);

    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let row = db_sessions::session_by_ulid(c.s.core.db(), repo_id, ULID_A)
        .await
        .unwrap()
        .expect("session row");
    db_sessions::set_quarantine(c.s.core.db(), row.id, "quarantined", "secret", "rule")
        .await
        .unwrap();
    let quarantined = client
        .post(&reviews)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"verdict": "approve", "body": "q", "session": ULID_A}))
        .send()
        .await
        .unwrap();
    assert_eq!(quarantined.status(), 422);
    db_sessions::set_quarantine(c.s.core.db(), row.id, "released", "", "")
        .await
        .unwrap();
    let released = client
        .post(&reviews)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"verdict": "approve", "body": "r", "session": ULID_A}))
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), 201);

    // Reviews list in submission order.
    let list: Value = client
        .get(&reviews)
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let all = list["reviews"].as_array().unwrap();
    assert_eq!(all.len(), 5);
    assert_eq!(all[0]["verdict"], "approve");
    assert_eq!(all[1]["verdict"], "request_changes");

    // Dismiss needs triage: the author alone gets 403.
    let id = all[0]["id"].as_i64().unwrap();
    let author_dismiss = client
        .post(format!("{reviews}/{id}/dismiss"))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(author_dismiss.status(), 403);
    let triage_dismiss = client
        .post(format!("{reviews}/{id}/dismiss"))
        .bearer_auth(&c.bob_rw)
        .send()
        .await
        .unwrap();
    assert_eq!(triage_dismiss.status(), 200);
    assert_eq!(
        triage_dismiss.json::<Value>().await.unwrap()["state"],
        "dismissed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn threads_create_list_resolve_comment_with_outdated() {
    let c = Ctx::start().await;
    let work = c.push_basic().await;
    let n = c.trail().await;
    c.create_branch_change(n, &c.bob_rw).await;
    let client = reqwest::Client::new();
    let threads = format!("{}/threads", c.change(n, 1));

    // Any reader may open a thread; the first comment is the body.
    let opened = client
        .post(&threads)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 2, "body": "nit: split"}))
        .send()
        .await
        .unwrap();
    assert_eq!(opened.status(), 201);
    let opened: Value = opened.json().await.unwrap();
    assert_eq!(opened["path"], "a.txt");
    assert_eq!(opened["side"], "head");
    assert_eq!(opened["revision"], 1);
    assert_eq!(opened["resolved"], false);
    assert_eq!(opened["outdated"], false);
    assert_eq!(opened["comments"].as_array().unwrap().len(), 1);
    assert_eq!(opened["comments"][0]["body"], "nit: split");
    let tid = opened["id"].as_i64().unwrap();

    // Anchors are validated: side, positivity, ordering, and span.
    for body in [
        json!({"path": "a.txt", "side": "left", "start_line": 1, "end_line": 1, "body": "x"}),
        json!({"path": "a.txt", "side": "head", "start_line": 0, "end_line": 1, "body": "x"}),
        json!({"path": "a.txt", "side": "head", "start_line": 2, "end_line": 1, "body": "x"}),
        json!({"path": "", "side": "head", "start_line": 1, "end_line": 1, "body": "x"}),
        json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 2000, "body": "x"}),
        json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 1, "body": ""}),
    ] {
        let res = client
            .post(&threads)
            .bearer_auth(&c.carol_rw)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "{body}");
    }

    // Resolve needs the author or triage: a fellow reader gets 403.
    let stranger_resolve = client
        .post(format!("{threads}/{tid}/resolve"))
        .bearer_auth(&c.erin_rw)
        .json(&json!({"resolved": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(stranger_resolve.status(), 403);
    let author_resolve = client
        .post(format!("{threads}/{tid}/resolve"))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"resolved": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(author_resolve.status(), 200);
    assert_eq!(
        author_resolve.json::<Value>().await.unwrap()["resolved"],
        true
    );
    let triage_reopen = client
        .post(format!("{threads}/{tid}/resolve"))
        .bearer_auth(&c.bob_rw)
        .json(&json!({"resolved": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(triage_reopen.status(), 200);
    assert_eq!(
        triage_reopen.json::<Value>().await.unwrap()["resolved"],
        false
    );

    // Any reader may comment; review links must belong to the change.
    let review_id = client
        .post(format!("{}/reviews", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"verdict": "comment", "body": "noting"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let comment = client
        .post(format!("{threads}/{tid}/comments"))
        .bearer_auth(&c.erin_rw)
        .json(&json!({"body": "agree", "review_id": review_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(comment.status(), 201);
    assert_eq!(
        comment.json::<Value>().await.unwrap()["review_id"],
        review_id
    );
    let bad_link = client
        .post(format!("{threads}/{tid}/comments"))
        .bearer_auth(&c.erin_rw)
        .json(&json!({"body": "x", "review_id": 9999}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_link.status(), 422);

    // A second revision makes anchor-1 threads outdated when lines vanish.
    commit_files(&work, &[("a.txt", b"only\n")], "shrink a").await;
    let new_tip = git_ok(&work, &["rev-parse", "feature/x"]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    c.s.core
        .record_branch_move(repo_id, "feature/x", None, new_tip.trim())
        .await
        .unwrap();
    let stale = client
        .post(&threads)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"revision": 1, "path": "a.txt", "side": "head", "start_line": 1, "end_line": 2, "body": "old lines"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 201);
    assert_eq!(stale.json::<Value>().await.unwrap()["outdated"], true);
    let fresh = client
        .post(&threads)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 1, "body": "new"}))
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), 201);
    assert_eq!(fresh.json::<Value>().await.unwrap()["outdated"], false);

    // Lists show every thread with its comments.
    let list: Value = client
        .get(&threads)
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let all = list["threads"].as_array().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0]["comments"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revision_detail_diff_binary_and_cap() {
    let c = Ctx::start().await;
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    let mut binary = vec![0u8; 512];
    binary[0] = b'P';
    binary[100] = 0;
    let mut big = String::new();
    for i in 0..8000 {
        big.push_str(&format!(
            "line {i:06} with enough padding to fill the diff output\n"
        ));
    }
    commit_files(
        &work,
        &[
            ("b.txt", b"bee\n"),
            ("0logo.bin", &binary),
            ("big.txt", big.as_bytes()),
        ],
        "add bundle",
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;

    let n = c.trail().await;
    c.create_branch_change(n, &c.bob_rw).await;
    let client = reqwest::Client::new();

    // The revision list has the single first revision.
    let revs: Value = client
        .get(format!("{}/revisions", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revs["revisions"].as_array().unwrap().len(), 1);
    assert_eq!(revs["revisions"][0]["r"], 1);

    // Detail returns changed files with add/modify/delete status and hunks;
    // the binary file ships metadata with empty hunks and the diff is capped.
    let detail: Value = client
        .get(format!("{}/revisions/1", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["revision"]["r"], 1);
    assert!(detail["revision"]["head_sha"].is_string());
    let files = detail["files"].as_array().unwrap();
    let by_path = |p: &str| {
        files
            .iter()
            .find(|f| f["path"] == p)
            .unwrap_or_else(|| panic!("missing file {p}: {files:?}"))
            .clone()
    };
    let modified = by_path("a.txt");
    assert_eq!(modified["status"], "modified");
    assert_eq!(modified["binary"], false);
    assert!(
        !modified["hunks"].as_array().unwrap().is_empty(),
        "{modified}"
    );
    let added = by_path("b.txt");
    assert_eq!(added["status"], "added");
    let blob = by_path("0logo.bin");
    assert_eq!(blob["binary"], true);
    assert!(
        blob["hunks"].as_array().unwrap().is_empty(),
        "binary files carry no hunks: {blob}"
    );
    assert_eq!(detail["truncated"], true);
    assert_eq!(detail["revision"]["r"], 1);

    // The dedicated diff route mirrors the embedded files.
    let diff: Value = client
        .get(format!("{}/diff", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(diff["truncated"], true);
    assert_eq!(
        diff["files"].as_array().unwrap().len(),
        files.len(),
        "diff route matches revision detail"
    );

    // The mergeability worker resolves clean against the untouched main.
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let trail = db_trails::trail_by_number(c.s.core.db(), repo_id, n)
        .await
        .unwrap()
        .expect("trail");
    let change = db_changes::change_by_trail_number(c.s.core.db(), trail.id, 1)
        .await
        .unwrap()
        .expect("change");
    c.s.core.recompute_mergeability(change.id).await.unwrap();
    let detail: Value = client
        .get(c.change(n, 1))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["change"]["mergeability"], "clean");
    assert_eq!(
        detail["selected"]["mergeability"], "clean",
        "the revision snapshot records the first verdict"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_status_matrix() {
    let c = Ctx::start().await;
    c.push_basic().await;
    let n = c.trail().await;
    let client = reqwest::Client::new();

    // Anonymous on a private repo: reads 404, mutations 401.
    let anon_get = client.get(c.changes(n)).send().await.unwrap();
    assert_eq!(anon_get.status(), 404);
    let anon_post = client
        .post(c.changes(n))
        .json(&json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(anon_post.status(), 401);

    // Bogus tokens are 401 everywhere.
    for req in [
        client.get(c.changes(n)),
        client.post(c.changes(n)),
        client.get(c.change(n, 1)),
    ] {
        let res = req.bearer_auth(BOGUS).send().await.unwrap();
        assert_eq!(res.status(), 401);
    }

    // repo:read alone: reads fine, mutations name the missing trail:write scope.
    let read_get = client
        .get(c.changes(n))
        .bearer_auth(&c.alice_read)
        .send()
        .await
        .unwrap();
    assert_eq!(read_get.status(), 200);
    let read_post = client
        .post(c.changes(n))
        .bearer_auth(&c.alice_read)
        .json(&json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(read_post.status(), 403);
    let (code, message) = error(read_post.json().await.unwrap());
    assert_eq!(code, "forbidden");
    assert!(message.contains("trail:write"), "{message}");

    // trail:write alone cannot read (it lacks repo:read).
    let scoped_get = client
        .get(c.changes(n))
        .bearer_auth(&c.alice_trail_only)
        .send()
        .await
        .unwrap();
    assert_eq!(scoped_get.status(), 403);

    // A stranger with full-looking scopes leaks nothing: 404, never 403.
    for url in [c.changes(n), c.change(n, 1)] {
        let res = client
            .get(url)
            .bearer_auth(&c.dave_rw)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404);
    }
    let stranger_post = client
        .post(c.changes(n))
        .bearer_auth(&c.dave_rw)
        .json(&json!({"kind": "branch", "head_branch": "feature/x", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stranger_post.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refs_for_access_patch_matrix() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let repo = c.s.url("/api/v1/repos/alice/proj");

    // The owner (maintain+) flips the mode; the value echoes back.
    let patched = client
        .patch(&repo)
        .bearer_auth(&c.alice_repo)
        .json(&json!({"refs_for_access": "members"}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), 200);
    assert_eq!(
        patched.json::<Value>().await.unwrap()["refs_for_access"],
        "members"
    );

    // A writer is below maintain: 403. Unknown values and missing fields: 422.
    let writer = client
        .patch(&repo)
        .bearer_auth(&c.frank_repo)
        .json(&json!({"refs_for_access": "anyone_with_read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(writer.status(), 403);
    for body in [json!({"refs_for_access": "everyone"}), json!({})] {
        let res = client
            .patch(&repo)
            .bearer_auth(&c.alice_repo)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422, "{body}");
    }

    // repo:read alone cannot change settings (it lacks repo:write).
    let read_scoped = client
        .patch(&repo)
        .bearer_auth(&c.alice_read)
        .json(&json!({"refs_for_access": "anyone_with_read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(read_scoped.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pagination_limits() {
    let c = Ctx::start().await;
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
    for b in ["f1", "f2", "f3"] {
        git_ok(&work, &["checkout", "-q", "-b", &format!("feature/{b}")]).await;
        commit_files(&work, &[("a.txt", format!("one\n{b}\n").as_bytes())], b).await;
        git_ok(&work, &["checkout", "-q", "main"]).await;
    }
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &url,
            "main",
            "feature/f1",
            "feature/f2",
            "feature/f3",
        ],
    )
    .await;

    let n = c.trail().await;
    let client = reqwest::Client::new();
    for b in ["f1", "f2", "f3"] {
        let res = client
            .post(c.changes(n))
            .bearer_auth(&c.bob_rw)
            .json(&json!({"kind": "branch", "head_branch": format!("feature/{b}"), "base_branch": "main"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "{b}");
    }
    // One thread + one review give the review/thread lists something to trim.
    client
        .post(format!("{}/reviews", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"verdict": "comment", "body": "one"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{}/reviews", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"verdict": "comment", "body": "two"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{}/threads", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .json(
            &json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 1, "body": "t1"}),
        )
        .send()
        .await
        .unwrap();
    client
        .post(format!("{}/threads", c.change(n, 1)))
        .bearer_auth(&c.carol_rw)
        .json(
            &json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 1, "body": "t2"}),
        )
        .send()
        .await
        .unwrap();

    let list: Value = client
        .get(format!("{}?limit=2", c.changes(n)))
        .bearer_auth(&c.carol_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["changes"].as_array().unwrap().len(), 2);
    for (url, key) in [
        (format!("{}/reviews?limit=1", c.change(n, 1)), "reviews"),
        (format!("{}/threads?limit=1", c.change(n, 1)), "threads"),
        (format!("{}/revisions?limit=5", c.change(n, 1)), "revisions"),
    ] {
        let res: Value = client
            .get(&url)
            .bearer_auth(&c.carol_rw)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(res[key].as_array().unwrap().len(), 1, "{url}");
    }

    // Non-positive limits are rejected, not silently clamped.
    for url in [
        format!("{}?limit=0", c.changes(n)),
        format!("{}/reviews?limit=-3", c.change(n, 1)),
    ] {
        let res = client
            .get(url)
            .bearer_auth(&c.carol_rw)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 422);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn thread_outdated_counts_final_line_without_newline() {
    let c = Ctx::start().await;
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/eol"]).await;
    // No trailing newline: two lines in two bytes of newline.
    commit_files(&work, &[("noeol.txt", b"l1\nl2")], "add noeol").await;
    commit_files(&work, &[("other.txt", b"other\n")], "add other").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/eol"]).await;

    let n = c.trail().await;
    let client = reqwest::Client::new();
    let res = client
        .post(c.changes(n))
        .bearer_auth(&c.bob_rw)
        .json(&json!({"kind": "branch", "head_branch": "feature/eol", "base_branch": "main"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // A second revision so anchor-1 threads exercise the outdated path.
    commit_files(&work, &[("third.txt", b"third\n")], "add third").await;
    git_ok(&work, &["push", "-q", &url, "feature/eol"]).await;
    let new_tip = git_ok(&work, &["rev-parse", "feature/eol"]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    c.s.core
        .record_branch_move(repo_id, "feature/eol", None, new_tip.trim())
        .await
        .unwrap();

    let threads = format!("{}/threads", c.change(n, 1));
    // The last line (line 2, no trailing newline) still exists → not outdated.
    let at_last = client
        .post(&threads)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"revision": 1, "path": "noeol.txt", "side": "head", "start_line": 2, "end_line": 2, "body": "last"}))
        .send()
        .await
        .unwrap();
    assert_eq!(at_last.status(), 201);
    assert_eq!(at_last.json::<Value>().await.unwrap()["outdated"], false);
    // One line past the end no longer exists → outdated.
    let past_end = client
        .post(&threads)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"revision": 1, "path": "noeol.txt", "side": "head", "start_line": 3, "end_line": 3, "body": "past"}))
        .send()
        .await
        .unwrap();
    assert_eq!(past_end.status(), 201);
    assert_eq!(past_end.json::<Value>().await.unwrap()["outdated"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolve_thread_idempotent_writes_one_event() {
    let c = Ctx::start().await;
    c.push_basic().await;
    let n = c.trail().await;
    c.create_branch_change(n, &c.bob_rw).await;
    let client = reqwest::Client::new();
    let threads = format!("{}/threads", c.change(n, 1));
    let tid = client
        .post(&threads)
        .bearer_auth(&c.carol_rw)
        .json(&json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 2, "body": "nit"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    let resolved_events = || async {
        let repo_id =
            c.s.core
                .repo_for(Some(&c.alice), "alice", "proj")
                .await
                .unwrap()
                .repo
                .id;
        let trail = db_trails::trail_by_number(c.s.core.db(), repo_id, n)
            .await
            .unwrap()
            .expect("trail");
        starforged_db::trails::timeline_of_trail(c.s.core.db(), trail.id)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "thread.resolved")
            .collect::<Vec<_>>()
    };

    for body in [json!({"resolved": true}), json!({"resolved": true})] {
        let res = client
            .post(format!("{threads}/{tid}/resolve"))
            .bearer_auth(&c.carol_rw)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(res.json::<Value>().await.unwrap()["resolved"], true);
    }
    let events = resolved_events().await;
    assert_eq!(events.len(), 1, "a no-op resolve writes no second event");
    let payload: Value = serde_json::from_str(&events[0].payload).unwrap();
    assert_eq!(payload["thread"], tid);
    assert_eq!(payload["resolved"], true);

    // A real flip still writes.
    let reopen = client
        .post(format!("{threads}/{tid}/resolve"))
        .bearer_auth(&c.carol_rw)
        .json(&json!({"resolved": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(reopen.status(), 200);
    assert_eq!(resolved_events().await.len(), 2);
}
