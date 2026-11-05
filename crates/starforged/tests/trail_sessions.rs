//! Task F2: Trail commits, Trail↔session links, and the has-sessions filter.
//!
//! Recording: revisions record their commits with subjects; the 250-row cap
//! holds; the hourly backfill records an unrecorded revision and sets the
//! flag. Linking through commits resolves whichever side (upload or push)
//! arrives first. Explicit links enforce triage-or-author-self, the 50-link
//! cap, same-repo readability, and archived refusal. Every session surface
//! applies §6.4 for the viewer, including `has_sessions` in SQL.
mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use starforged_core::jobs::Job;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";

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
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    repo_id: i64,
    alice_full: String,
    bob_triage: String,
    carol_read: String,
    upload_alice: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        s.repo(&alice, "proj", Visibility::Private).await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Triage)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        let repo_id = s
            .core
            .repo_for(Some(&alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
        let alice_full = s
            .token(
                &alice,
                &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
            )
            .await;
        let bob_triage = s.token(&bob, &[Scope::RepoRead, Scope::TrailWrite]).await;
        let carol_read = s.token(&carol, &[Scope::RepoRead, Scope::TrailWrite]).await;
        let upload_alice = s.token(&alice, &[Scope::SessionUpload]).await;
        Ctx {
            s,
            alice,
            repo_id,
            alice_full,
            bob_triage,
            carol_read,
            upload_alice,
        }
    }

    async fn create_trail(&self, title: &str) -> i64 {
        let client = reqwest::Client::new();
        let res = client
            .post(self.s.url("/api/v1/repos/alice/proj/trails"))
            .bearer_auth(&self.alice_full)
            .json(&json!({"title": title, "intent": "do the thing"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create trail {title}");
        res.json::<Value>().await.unwrap()["number"]
            .as_i64()
            .unwrap()
    }

    async fn upload(&self, token: &str, ulid: &str) -> i64 {
        let client = reqwest::Client::new();
        let put = client
            .put(
                self.s
                    .url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}")),
            )
            .bearer_auth(token)
            .json(&meta_body(ulid))
            .send()
            .await
            .unwrap();
        assert!(put.status().is_success(), "upload {ulid}: {}", put.status());
        starforged_db::sessions::session_by_ulid(self.s.core.db(), self.repo_id, ulid)
            .await
            .unwrap()
            .unwrap()
            .id
    }

    async fn claim(&self, token: &str, ulid: &str, sha: &str) {
        let client = reqwest::Client::new();
        let res = client
            .post(self.s.url(&format!("/api/v1/repos/alice/proj/sessions/{ulid}/links")))
            .bearer_auth(token)
            .json(&json!({"links": [{"sha": sha, "confidence": "exact", "seq_start": 0, "seq_end": 5}]}))
            .send()
            .await
            .unwrap();
        assert!(
            res.status().is_success(),
            "claim {ulid} {sha}: {}",
            res.status()
        );
    }

    async fn sessions(&self, token: Option<&str>, n: i64) -> (reqwest::StatusCode, Value) {
        let client = reqwest::Client::new();
        let mut req = client.get(
            self.s
                .url(&format!("/api/v1/repos/alice/proj/trails/{n}/sessions")),
        );
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.unwrap();
        let status = res.status();
        let body = res.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn link(&self, token: &str, n: i64, ulid: &str) -> (reqwest::StatusCode, Value) {
        let client = reqwest::Client::new();
        let res = client
            .post(
                self.s
                    .url(&format!("/api/v1/repos/alice/proj/trails/{n}/sessions")),
            )
            .bearer_auth(token)
            .json(&json!({"session": ulid}))
            .send()
            .await
            .unwrap();
        let status = res.status();
        let body = res.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn unlink(&self, token: &str, n: i64, ulid: &str) -> (reqwest::StatusCode, Value) {
        let client = reqwest::Client::new();
        let res = client
            .delete(self.s.url(&format!(
                "/api/v1/repos/alice/proj/trails/{n}/sessions/{ulid}"
            )))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = res.status();
        let body = res.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn commit_rows(&self, revision_id: i64) -> Vec<(String, String, i64)> {
        sqlx::query_as::<_, (String, String, i64)>(
            "SELECT sha, subject, position FROM revision_commits WHERE revision_id = $1 ORDER BY position ASC",
        )
        .bind(revision_id)
        .fetch_all(self.s.core.db().pool())
        .await
        .unwrap()
    }

    async fn flag(&self, revision_id: i64) -> i64 {
        sqlx::query_scalar("SELECT commits_recorded FROM revisions WHERE id = $1")
            .bind(revision_id)
            .fetch_one(self.s.core.db().pool())
            .await
            .unwrap()
    }

    async fn timeline_kinds(&self, token: &str, n: i64) -> Vec<String> {
        let client = reqwest::Client::new();
        let detail = client
            .get(self.s.url(&format!("/api/v1/repos/alice/proj/trails/{n}")))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        detail["timeline"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap().to_owned())
            .collect()
    }
}

/// Pushes `main`, then a `feature/x` branch with one commit per subject, and
/// opens a branch change on trail `n` via Core (synchronous, recorded inline).
/// Returns `(head_sha, revision_id)` of the new revision.
async fn push_and_open(c: &Ctx, n: i64, commits: &[&str]) -> (String, i64) {
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let url = c.s.git_url("alice", "proj", Some(&c.alice_full));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    for subject in commits {
        let content = format!("{subject}\n");
        commit_files(&work, &[("a.txt", content.as_bytes())], subject).await;
    }
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let head = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", n, "feature/x", "main")
        .await
        .unwrap();
    let change_row =
        starforged_db::changes::open_branch_changes(c.s.core.db(), c.repo_id, "feature/x")
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
    let revision = starforged_db::changes::latest_revision_of_change(c.s.core.db(), change_row.id)
        .await
        .unwrap()
        .unwrap();
    (head, revision.id)
}

async fn wait_for_revisions(s: &TestServer, change_id: i64, expected: usize) {
    for _ in 0..200 {
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), change_id)
            .await
            .unwrap();
        if revs.len() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("revisions never reached {expected} for change {change_id}");
}

/// A revision's commits are recorded with subjects; position 0 is the head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_revision_commits_with_subjects() {
    let c = Ctx::start().await;
    let n = c.create_trail("commits").await;
    let (head, revision_id) = push_and_open(&c, n, &["add two", "add three"]).await;
    let rows = c.commit_rows(revision_id).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].0, head, "position 0 is the head");
    assert_eq!(rows[0].1, "add three");
    assert_eq!(rows[1].1, "add two");
    assert_eq!(c.flag(revision_id).await, 1);
}

/// Pushing to a tracked branch records the new revision's commits via the
/// post-receive scan path (`append_revision`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_driven_revision_records_commits() {
    let c = Ctx::start().await;
    let n = c.create_trail("scan").await;
    let (head, revision_id) = push_and_open(&c, n, &["add two"]).await;
    assert_eq!(c.commit_rows(revision_id).await.len(), 1);

    // A further push to the tracked branch appends a recorded revision.
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work2", &[("a.txt", "one\n")]).await;
    let url = c.s.git_url("alice", "proj", Some(&c.alice_full));
    git_ok(&work, &["fetch", "-q", &url, "feature/x:feature/x"]).await;
    git_ok(&work, &["checkout", "-q", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\nthree\n")], "add three").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let new_head = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    assert_ne!(new_head, head);
    let change_row =
        starforged_db::changes::open_branch_changes(c.s.core.db(), c.repo_id, "feature/x")
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
    wait_for_revisions(&c.s, change_row.id, 2).await;
    let revision = starforged_db::changes::latest_revision_of_change(c.s.core.db(), change_row.id)
        .await
        .unwrap()
        .unwrap();
    let rows = c.commit_rows(revision.id).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].0, new_head, "position 0 is the new head");
    assert_eq!(c.flag(revision.id).await, 1);
}

/// The 250-row cap holds: the newest 250 are kept, position 0 is the head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revision_commit_cap_holds() {
    let c = Ctx::start().await;
    let n = c.create_trail("cap").await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let url = c.s.git_url("alice", "proj", Some(&c.alice_full));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    for i in 0..260 {
        git_ok(
            &work,
            &["commit", "-q", "--allow-empty", "-m", &format!("bulk {i}")],
        )
        .await;
    }
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let head = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", n, "feature/x", "main")
        .await
        .unwrap();
    let change_row =
        starforged_db::changes::open_branch_changes(c.s.core.db(), c.repo_id, "feature/x")
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
    let revision = starforged_db::changes::latest_revision_of_change(c.s.core.db(), change_row.id)
        .await
        .unwrap()
        .unwrap();
    let rows = c.commit_rows(revision.id).await;
    assert_eq!(rows.len(), 250, "the cap holds");
    assert_eq!(rows[0].0, head, "position 0 is the head");
    assert!(
        rows.iter().all(|(_, subject, _)| !subject.is_empty()),
        "subjects recorded"
    );
    assert_eq!(c.flag(revision.id).await, 1);
}

/// The hourly maintenance pass backfills an unrecorded revision and sets the flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backfill_job_records_unrecorded_revision() {
    let c = Ctx::start().await;
    let n = c.create_trail("backfill").await;
    let (_, revision_id) = push_and_open(&c, n, &["add two"]).await;
    assert_eq!(c.commit_rows(revision_id).await.len(), 1);
    sqlx::query("DELETE FROM revision_commits WHERE revision_id = $1")
        .bind(revision_id)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    sqlx::query("UPDATE revisions SET commits_recorded = 0 WHERE id = $1")
        .bind(revision_id)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    assert_eq!(c.flag(revision_id).await, 0);

    c.s.core.enqueue(&Job::HourlyCleanup).await.unwrap();
    c.s.core.run_due_jobs().await.unwrap();
    // The hourly pass enqueues the backfill; the worker records it.
    c.s.core.run_due_jobs().await.unwrap();

    let rows = c.commit_rows(revision_id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1, "add two");
    assert_eq!(c.flag(revision_id).await, 1);
}

/// A session uploaded before the push resolves under the commit once the
/// change exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_link_resolves_upload_before_push() {
    let c = Ctx::start().await;
    let n = c.create_trail("early").await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let url = c.s.git_url("alice", "proj", Some(&c.alice_full));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();

    // The upload and claim land before the server ever sees the commit.
    c.upload(&c.upload_alice, ULID_A).await;
    c.claim(&c.upload_alice, ULID_A, &sha).await;

    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", n, "feature/x", "main")
        .await
        .unwrap();

    let (status, body) = c.sessions(Some(&c.alice_full), n).await;
    assert_eq!(status, 200, "{body}");
    let commits = body["commits"].as_array().unwrap();
    assert_eq!(commits.len(), 1, "{body}");
    assert_eq!(commits[0]["sha"], json!(sha));
    assert_eq!(commits[0]["subject"], json!("add two"));
    let sessions = commits[0]["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "{body}");
    assert_eq!(sessions[0]["ulid"], json!(ULID_A));
    assert_eq!(sessions[0]["confidence"], json!("exact"));
    assert_eq!(sessions[0]["agent"], json!("claude-code"));
    assert_eq!(body["linked"], json!([]));
    // Trail totals cover the one distinct session.
    assert_eq!(body["totals"]["input"], json!(10));
    assert_eq!(body["totals"]["total"], json!(150));
}

/// A session uploaded after the push resolves under the already-recorded commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_link_resolves_push_before_upload() {
    let c = Ctx::start().await;
    let n = c.create_trail("late").await;
    let (head, _) = push_and_open(&c, n, &["add two"]).await;

    c.upload(&c.upload_alice, ULID_A).await;
    c.claim(&c.upload_alice, ULID_A, &head).await;

    let (status, body) = c.sessions(Some(&c.alice_full), n).await;
    assert_eq!(status, 200, "{body}");
    let commits = body["commits"].as_array().unwrap();
    assert_eq!(commits.len(), 1, "{body}");
    assert_eq!(commits[0]["sessions"][0]["ulid"], json!(ULID_A));
    // The claim carries its start sequence through to the row.
    assert_eq!(commits[0]["sessions"][0]["seq_start"], json!(0));
}

/// Trailer-first rows (NULL session id) never surface; the upload backfills them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trailer_row_without_session_is_invisible() {
    let c = Ctx::start().await;
    let n = c.create_trail("trailer").await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let url = c.s.git_url("alice", "proj", Some(&c.alice_full));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(
        &work,
        &[("a.txt", b"one\ntwo\n")],
        &format!("add two\n\nStarforge-Session: {ULID_B}\n"),
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", n, "feature/x", "main")
        .await
        .unwrap();
    // Wait for the post-receive trailer scan to file its row.
    for _ in 0..200 {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM commit_links")
            .fetch_one(c.s.core.db().pool())
            .await
            .unwrap();
        if count == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, body) = c.sessions(Some(&c.alice_full), n).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["commits"], json!([]), "no session yet: {body}");

    c.upload(&c.upload_alice, ULID_B).await;
    let (status, body) = c.sessions(Some(&c.alice_full), n).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["commits"][0]["sessions"][0]["ulid"], json!(ULID_B));
    assert_eq!(
        body["commits"][0]["sessions"][0]["confidence"],
        json!("heuristic")
    );
}

/// Triage links explicitly: one timeline row, idempotent repeat, unlink works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_link_round_trip() {
    let c = Ctx::start().await;
    let n = c.create_trail("explicit").await;
    c.upload(&c.upload_alice, ULID_A).await;

    let (status, body) = c.link(&c.bob_triage, n, ULID_A).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["linked"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["linked"][0]["ulid"], json!(ULID_A));
    assert_eq!(body["linked"][0]["confidence"], json!("explicit"));
    assert_eq!(body["linked"][0]["uploader"], json!("alice"));

    let kinds = c.timeline_kinds(&c.alice_full, n).await;
    assert_eq!(
        kinds
            .iter()
            .filter(|k| *k == "trail.session_linked")
            .count(),
        1,
        "{kinds:?}"
    );

    // Idempotent repeat: 200, no new row.
    let (status, _) = c.link(&c.bob_triage, n, ULID_A).await;
    assert_eq!(status, 200);
    let kinds = c.timeline_kinds(&c.alice_full, n).await;
    assert_eq!(
        kinds
            .iter()
            .filter(|k| *k == "trail.session_linked")
            .count(),
        1,
        "{kinds:?}"
    );

    let (status, body) = c.unlink(&c.bob_triage, n, ULID_A).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["linked"], json!([]));
    let kinds = c.timeline_kinds(&c.alice_full, n).await;
    assert_eq!(
        kinds
            .iter()
            .filter(|k| *k == "trail.session_unlinked")
            .count(),
        1,
        "{kinds:?}"
    );

    // Unlinking again is a silent no-op.
    let (status, _) = c.unlink(&c.bob_triage, n, ULID_A).await;
    assert_eq!(status, 200);
    let kinds = c.timeline_kinds(&c.alice_full, n).await;
    assert_eq!(
        kinds
            .iter()
            .filter(|k| *k == "trail.session_unlinked")
            .count(),
        1,
        "{kinds:?}"
    );
}

/// The Trail author may link a session they uploaded; a read user may not
/// link someone else's session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_link_author_and_permission_rules() {
    let c = Ctx::start().await;
    let n = c.create_trail("perms").await;
    c.upload(&c.upload_alice, ULID_A).await;
    c.upload(&c.upload_alice, ULID_B).await;

    // The author links their own upload: allowed without triage.
    let (status, body) = c.link(&c.alice_full, n, ULID_A).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["linked"][0]["ulid"], json!(ULID_A));

    // A read user linking someone else's session is 403.
    let (status, _) = c.link(&c.carol_read, n, ULID_A).await;
    assert_eq!(status, 403);

    // Unknown ULIDs and other-repo sessions are 404, never 403.
    let (status, _) = c.link(&c.bob_triage, n, "01ARZ3NDEKTSV4RRFFQ69G5FF9").await;
    assert_eq!(status, 404);
}

/// Sessions from another repository cannot be linked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_link_rejects_foreign_repo_session() {
    let c = Ctx::start().await;
    let n = c.create_trail("foreign").await;
    c.s.repo(&c.alice, "other", Visibility::Private).await;
    let upload_other = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let put = client
        .put(c.s.url(&format!("/api/v1/repos/alice/other/sessions/{ULID_B}")))
        .bearer_auth(&upload_other)
        .json(&meta_body(ULID_B))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success());
    let (status, _) = c.link(&c.bob_triage, n, ULID_B).await;
    assert_eq!(status, 404);
}

/// The 51st explicit link is 422; an archived repository refuses links.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_link_cap_and_archive() {
    let c = Ctx::start().await;
    let n = c.create_trail("cap").await;
    for i in 0..50 {
        let ulid = format!("01ARZ3NDEKTSV4RRFFQ69G{i:04}");
        c.upload(&c.upload_alice, &ulid).await;
        let (status, _) = c.link(&c.bob_triage, n, &ulid).await;
        assert_eq!(status, 200, "link {i}");
    }
    c.upload(&c.upload_alice, ULID_A).await;
    let (status, _) = c.link(&c.bob_triage, n, ULID_A).await;
    assert_eq!(status, 422, "the 51st link is rejected");

    c.s.core
        .archive_repo(&c.alice, "alice", "proj")
        .await
        .unwrap();
    let (status, _) = c.link(&c.bob_triage, n, ULID_A).await;
    assert_eq!(status, 422, "archived repos refuse links");
    let (status, _) = c.unlink(&c.bob_triage, n, ULID_A).await;
    assert_eq!(status, 422, "archived repos refuse unlinks");
    // Reads still work on the archived repo.
    let (status, _) = c.sessions(Some(&c.alice_full), n).await;
    assert_eq!(status, 200);
}

/// A real link and unlink each deliver one `trail`/`updated` webhook.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_links_dispatch_webhooks() {
    use std::sync::{Arc, Mutex};
    let s = TestServer::start_with(|c| c.webhooks.allow_loopback = true).await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Triage)
        .await
        .unwrap();
    let rw = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
    let token = s.token(&alice, rw).await;
    let bob_token = s.token(&bob, &[Scope::RepoRead, Scope::TrailWrite]).await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();

    let hits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = hits.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |body: axum::body::Bytes| {
            let seen = seen.clone();
            async move {
                seen.lock()
                    .unwrap()
                    .push(serde_json::from_slice::<Value>(&body).expect("hook body is JSON"));
                (axum::http::StatusCode::OK, "ok".to_string())
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    let res = client
        .post(s.url("/api/v1/repos/alice/proj/hooks"))
        .bearer_auth(&token)
        .json(&json!({"url": format!("http://{addr}/hook"), "events": ["trail"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "create hook");
    let res = client
        .post(s.url("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&token)
        .json(&json!({"title": "t", "intent": "i"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let put = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_A}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success());
    s.core.run_due_jobs().await.unwrap();
    hits.lock().unwrap().clear();

    let url = s.url("/api/v1/repos/alice/proj/trails/1/sessions");
    let res = client
        .post(&url)
        .bearer_auth(&bob_token)
        .json(&json!({"session": ULID_A}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .delete(s.url(&format!(
            "/api/v1/repos/alice/proj/trails/1/sessions/{ULID_A}"
        )))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    s.core.run_due_jobs().await.unwrap();

    let bodies = hits.lock().unwrap().clone();
    assert_eq!(bodies.len(), 2, "{bodies:?}");
    assert_eq!(bodies[0]["event"], "trail");
    assert_eq!(bodies[0]["action"], "updated");
    assert_eq!(bodies[0]["cause"], "session_linked");
    assert_eq!(bodies[1]["cause"], "session_unlinked");
}

/// §6.4 on the sessions API and on `has_sessions`: on a public repo an
/// unpublished session is invisible to non-members; quarantine admits only
/// the uploader and repo admins; published sessions read anonymously.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_api_applies_section_64() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let _carol = s.user("carol").await;
    let dave = s.user("dave").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.core
        .set_collaborator(&alice, "alice", "open", "bob", Permission::Triage)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "open", "dave", Permission::Write)
        .await
        .unwrap();
    let full = s
        .token(
            &alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;
    let bob_token = s.token(&bob, &[Scope::RepoRead, Scope::TrailWrite]).await;
    let upload_dave = s.token(&dave, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let res = client
        .post(s.url("/api/v1/repos/alice/open/trails"))
        .bearer_auth(&full)
        .json(&json!({"title": "t", "intent": "i"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let url = s.git_url("alice", "open", Some(&full));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    s.core
        .create_branch_change(&alice, "alice", "open", 1, "feature/x", "main")
        .await
        .unwrap();

    // Dave (a repo writer, but not an admin) uploads and claims the commit.
    let put = client
        .put(s.url(&format!("/api/v1/repos/alice/open/sessions/{ULID_A}")))
        .bearer_auth(&upload_dave)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "{}", put.status());
    let claim = client
        .post(s.url(&format!("/api/v1/repos/alice/open/sessions/{ULID_A}/links")))
        .bearer_auth(&upload_dave)
        .json(&json!({"links": [{"sha": sha, "confidence": "exact"}]}))
        .send()
        .await
        .unwrap();
    assert!(claim.status().is_success());

    async fn get(
        client: &reqwest::Client,
        s: &TestServer,
        token: Option<&str>,
    ) -> (reqwest::StatusCode, Value) {
        let mut req = client.get(s.url("/api/v1/repos/alice/open/trails/1/sessions"));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.unwrap();
        let status = res.status();
        let body = res.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }
    async fn listed(
        client: &reqwest::Client,
        s: &TestServer,
        token: Option<&str>,
        q: &str,
    ) -> Vec<i64> {
        let mut req = client.get(s.url(&format!("/api/v1/repos/alice/open/trails{q}")));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.unwrap();
        assert_eq!(res.status(), 200, "{q}");
        let body: Value = res.json().await.unwrap();
        body["trails"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["number"].as_i64().unwrap())
            .collect()
    }

    // Unpublished: invisible to anonymous and stranger members, visible to members.
    let (status, body) = get(&client, &s, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["commits"], json!([]), "anon sees nothing: {body}");
    assert_eq!(
        listed(&client, &s, None, "?has_sessions=true").await,
        Vec::<i64>::new()
    );
    assert_eq!(
        listed(&client, &s, Some(&full), "?has_sessions=true").await,
        vec![1]
    );
    assert_eq!(
        listed(&client, &s, Some(&full), "?has_sessions=false").await,
        Vec::<i64>::new()
    );
    let (status, body) = get(&client, &s, Some(&full)).await;
    assert_eq!(status, 200);
    assert_eq!(body["commits"][0]["sessions"][0]["ulid"], json!(ULID_A));

    // Quarantined: only the uploader and repo admins.
    let session_id = starforged_db::sessions::session_by_ulid(
        s.core.db(),
        s.core
            .repo_for(Some(&alice), "alice", "open")
            .await
            .unwrap()
            .repo
            .id,
        ULID_A,
    )
    .await
    .unwrap()
    .unwrap()
    .id;
    starforged_db::sessions::set_quarantine(s.core.db(), session_id, "quarantined", "probe", "")
        .await
        .unwrap();
    let (status, body) = get(&client, &s, Some(&upload_dave)).await;
    assert_eq!(status, 403, "upload scope is not repo read: {body}");
    let dave_read = s.token(&dave, &[Scope::RepoRead]).await;
    let (status, body) = get(&client, &s, Some(&dave_read)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["commits"][0]["sessions"][0]["ulid"],
        json!(ULID_A),
        "uploader sees: {body}"
    );
    let (status, body) = get(&client, &s, Some(&full)).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["commits"][0]["sessions"][0]["ulid"],
        json!(ULID_A),
        "owner sees: {body}"
    );
    let (status, body) = get(&client, &s, Some(&bob_token)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["commits"],
        json!([]),
        "triage non-admin does not: {body}"
    );
    assert_eq!(
        listed(&client, &s, Some(&bob_token), "?has_sessions=true").await,
        Vec::<i64>::new()
    );

    // Published: anonymous readers see it.
    starforged_db::sessions::set_quarantine(s.core.db(), session_id, "none", "", "")
        .await
        .unwrap();
    starforged_db::sessions::set_visibility(s.core.db(), session_id, "published")
        .await
        .unwrap();
    let (status, body) = get(&client, &s, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["commits"][0]["sessions"][0]["ulid"],
        json!(ULID_A),
        "anon sees published: {body}"
    );
    assert_eq!(
        listed(&client, &s, None, "?has_sessions=true").await,
        vec![1]
    );
}

/// `has_sessions` composes with state/label filters and keyset paging;
/// anything but true/false is a 422.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn has_sessions_filter_composes() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    for title in ["linked", "plain", "other"] {
        c.create_trail(title).await;
    }
    push_and_open(&c, 1, &["add two"]).await;
    c.upload(&c.upload_alice, ULID_A).await;
    let (status, _) = c.link(&c.bob_triage, 1, ULID_A).await;
    assert_eq!(status, 200);
    // Label trail 1 so the composition has something to grip.
    let res = client
        .post(c.s.url("/api/v1/repos/alice/proj/trails/1/labels"))
        .bearer_auth(&c.alice_full)
        .json(&json!({"name": "bug"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    async fn numbers(client: &reqwest::Client, c: &Ctx, q: &str) -> Vec<i64> {
        let res = client
            .get(c.s.url(&format!("/api/v1/repos/alice/proj/trails{q}")))
            .bearer_auth(&c.alice_full)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "GET {q}");
        let body: Value = res.json().await.unwrap();
        body["trails"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["number"].as_i64().unwrap())
            .collect()
    }
    assert_eq!(numbers(&client, &c, "?has_sessions=true").await, vec![1]);
    assert_eq!(
        numbers(&client, &c, "?has_sessions=false").await,
        vec![2, 3]
    );
    assert_eq!(
        numbers(&client, &c, "?has_sessions=true&label=bug").await,
        vec![1]
    );
    assert_eq!(
        numbers(&client, &c, "?has_sessions=false&label=bug").await,
        Vec::<i64>::new()
    );
    assert_eq!(
        numbers(&client, &c, "?has_sessions=true&state=closed").await,
        Vec::<i64>::new()
    );
    assert_eq!(
        numbers(&client, &c, "?has_sessions=true&limit=1").await,
        vec![1]
    );
    assert_eq!(
        numbers(&client, &c, "?has_sessions=true&limit=1&after=1").await,
        Vec::<i64>::new()
    );

    let bad = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails?has_sessions=maybe"))
        .bearer_auth(&c.alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
}
