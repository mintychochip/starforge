//! D6: push-trailer commit links. Pushing a commit whose message carries a
//! `Starforge-Session: <ULID>` trailer files a link row (after the post-push
//! scan task runs); a later CLI claim merges into the same row. Trailer-first
//! rows store with a NULL session id until the upload arrives, and re-scans
//! are idempotent.
mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
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
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

/// `(sha, confidence, trailer_seen, claim_seen, session_id)` for every link filed under `ulid`.
async fn link_rows(
    core: &starforged_core::Core,
    repo_id: i64,
    ulid: &str,
) -> Vec<(String, String, i64, i64, Option<i64>)> {
    sqlx::query_as::<_, (String, String, i64, i64, Option<i64>)>(
        "SELECT sha, confidence, trailer_seen, claim_seen, session_id FROM commit_links \
         WHERE repo_id = $1 AND session_ulid = $2 ORDER BY sha",
    )
    .bind(repo_id)
    .bind(ulid)
    .fetch_all(core.db().pool())
    .await
    .unwrap()
}

async fn link_count(core: &starforged_core::Core) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM commit_links")
        .fetch_one(core.db().pool())
        .await
        .unwrap()
}

/// The post-push scan runs in a spawned task after the push response, so poll for the row.
async fn wait_for_link(core: &starforged_core::Core, repo_id: i64, ulid: &str, sha: &str) {
    for _ in 0..200 {
        if link_rows(core, repo_id, ulid)
            .await
            .iter()
            .any(|row| row.0 == sha)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("link row for {ulid} {sha} never appeared");
}

/// Polls until `ulid` has exactly `expected` link rows (the scan writes one row
/// per trailer-bearing commit, including non-tip commits).
async fn wait_for_link_count(
    core: &starforged_core::Core,
    repo_id: i64,
    ulid: &str,
    expected: usize,
) {
    for _ in 0..200 {
        if link_rows(core, repo_id, ulid).await.len() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "ulid {ulid} never reached {expected} link rows: {:?}",
        link_rows(core, repo_id, ulid).await
    );
}

/// Waits for a push's spawned post-push task to finish its scan. The task leaves no
/// completion handle, and a trailer-less push writes no link rows, so there is no direct
/// signal — but the same task enqueues `git_maintenance` immediately before scanning.
/// Callers drain the queue first (dedupe is per-repo, so a stale row would mask a fresh
/// enqueue); a fresh pending `git_maintenance` row then proves the task ran, and a link
/// count stable across consecutive polls proves the scan finished without writing.
/// Returns the settled link count. Panics with the jobs table on timeout.
async fn wait_for_post_push_scan(core: &starforged_core::Core) -> i64 {
    let mut enqueued = false;
    for _ in 0..100 {
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM jobs WHERE kind = 'git_maintenance' AND state IN ('queued', 'running')",
        )
        .fetch_one(core.db().pool())
        .await
        .unwrap();
        if pending > 0 {
            enqueued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if !enqueued {
        let rows: Vec<(i64, String, String)> =
            sqlx::query_as("SELECT id, kind, state FROM jobs ORDER BY id")
                .fetch_all(core.db().pool())
                .await
                .unwrap();
        panic!("post-push task never enqueued git_maintenance; jobs: {rows:?}");
    }
    let mut last = link_count(core).await;
    let mut stable = 0;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let now = link_count(core).await;
        if now == last {
            stable += 1;
            if stable >= 10 {
                return now;
            }
        } else {
            stable = 0;
            last = now;
        }
    }
    panic!("link count never settled; last count: {last}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_trailers_create_links_and_claims_merge() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    let client = reqwest::Client::new();

    // Session A is already uploaded when its commit lands.
    let put = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_A}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success());

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    let url = s.git_url("alice", "proj", Some(&write));

    // Push a commit whose message carries a trailer for the uploaded session.
    commit_files(
        &work,
        &[("feature.txt", b"feature\n")],
        &format!("implement feature\n\nStarforge-Session: {ULID_A}\n"),
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let sha_a = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();

    wait_for_link(&s.core, repo_id, ULID_A, &sha_a).await;
    let expected: Vec<(String, String, i64, i64, Option<i64>)> =
        vec![(sha_a.clone(), "heuristic".to_owned(), 1, 0, None)];
    assert_eq!(link_rows(&s.core, repo_id, ULID_A).await, expected);

    // A later CLI claim merges into the same row.
    let claim = client
        .post(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_A}/links")))
        .bearer_auth(&upload)
        .json(&json!({"links": [{"sha": sha_a, "confidence": "exact", "seq_start": 0, "seq_end": 5}]}))
        .send()
        .await
        .unwrap();
    assert!(claim.status().is_success());
    let session_id = starforged_db::sessions::session_by_ulid(s.core.db(), repo_id, ULID_A)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(
        link_rows(&s.core, repo_id, ULID_A).await,
        vec![(sha_a.clone(), "exact".to_owned(), 1, 1, Some(session_id))]
    );

    // A trailer for an unknown ULID stores with a NULL session id; the later
    // upload backfills it and the later claim merges into the same row.
    commit_files(
        &work,
        &[("other.txt", b"other\n")],
        &format!("more work\n\nStarforge-Session: {ULID_B}\n"),
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let sha_b = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    wait_for_link(&s.core, repo_id, ULID_B, &sha_b).await;
    assert_eq!(
        link_rows(&s.core, repo_id, ULID_B).await,
        vec![(sha_b.clone(), "heuristic".to_owned(), 1, 0, None)]
    );
    let put = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_B}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_B))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success());
    let session_b = starforged_db::sessions::session_by_ulid(s.core.db(), repo_id, ULID_B)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(
        link_rows(&s.core, repo_id, ULID_B).await,
        vec![(sha_b.clone(), "heuristic".to_owned(), 1, 0, Some(session_b))]
    );
    let claim = client
        .post(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_B}/links")))
        .bearer_auth(&upload)
        .json(&json!({"links": [{"sha": sha_b, "confidence": "exact"}]}))
        .send()
        .await
        .unwrap();
    assert!(claim.status().is_success());
    assert_eq!(
        link_rows(&s.core, repo_id, ULID_B).await,
        vec![(sha_b.clone(), "exact".to_owned(), 1, 1, Some(session_b))]
    );

    // A commit without trailers creates nothing. Drain the queue first so the post-push
    // task's fresh `git_maintenance` enqueue is observable (dedupe is per-repo).
    s.core.run_due_jobs().await.unwrap();
    let before = link_count(&s.core).await;
    commit_files(&work, &[("plain.txt", b"plain\n")], "plain commit\n").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    assert_eq!(wait_for_post_push_scan(&s.core).await, before);

    // Re-scanning the same commit is a no-op (no duplicate rows).
    let message = format!("implement feature\n\nStarforge-Session: {ULID_A}\n");
    s.core
        .record_trailer_links(repo_id, &[(sha_a.clone(), message)])
        .await
        .unwrap();
    assert_eq!(link_count(&s.core).await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_scans_non_tip_commits() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    let client = reqwest::Client::new();
    let put = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_A}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_A))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success());

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    let url = s.git_url("alice", "proj", Some(&write));

    // Three trailer-bearing commits in one push: the scan must record all three,
    // not just the new tip.
    for (file, subject) in [("a.txt", "first"), ("b.txt", "second"), ("c.txt", "third")] {
        commit_files(
            &work,
            &[(file, b"content\n".as_slice())],
            &format!("{subject}\n\nStarforge-Session: {ULID_A}\n"),
        )
        .await;
    }
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let mut pushed: Vec<String> = git_ok(&work, &["rev-list", "HEAD"])
        .await
        .lines()
        .map(str::to_owned)
        .collect();
    // The initial commit carries no trailer; the three pushed ones do.
    pushed.truncate(3);
    wait_for_link_count(&s.core, repo_id, ULID_A, 3).await;
    let mut got: Vec<String> = link_rows(&s.core, repo_id, ULID_A)
        .await
        .into_iter()
        .map(|row| row.0)
        .collect();
    got.sort();
    pushed.sort();
    assert_eq!(got, pushed);
    assert!(
        link_rows(&s.core, repo_id, ULID_A)
            .await
            .iter()
            .all(|row| row.1 == "heuristic" && row.2 == 1)
    );

    // A new branch push includes its non-tip commits too.
    git_ok(&work, &["checkout", "-qb", "feature"]).await;
    for (file, subject) in [("d.txt", "fourth"), ("e.txt", "fifth")] {
        commit_files(
            &work,
            &[(file, b"content\n".as_slice())],
            &format!("{subject}\n\nStarforge-Session: {ULID_A}\n"),
        )
        .await;
    }
    git_ok(&work, &["push", "-q", &url, "feature"]).await;
    wait_for_link_count(&s.core, repo_id, ULID_A, 5).await;

    // Pushing to main leaves the unchanged branch alone and duplicates nothing.
    git_ok(&work, &["checkout", "-q", "main"]).await;
    s.core.run_due_jobs().await.unwrap();
    let before = link_count(&s.core).await;
    commit_files(&work, &[("plain.txt", b"plain\n")], "plain commit\n").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    assert_eq!(wait_for_post_push_scan(&s.core).await, before);
    assert_eq!(link_count(&s.core).await, 5);
}
