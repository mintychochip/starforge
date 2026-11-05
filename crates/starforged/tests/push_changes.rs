//! M2b G3: pushing `refs/for/*` ingests agit changes + revisions + trail refs,
//! and the mergeability worker resolves clean/conflict. Real git over HTTP,
//! in-process server (follows `session_links.rs` conventions).
mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::*;
use serde_json::Value;
use starforged_core::accounts::User;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use tokio::time::sleep;

const SCAN_TIMEOUT: Duration = Duration::from_secs(20);

async fn writer_url(
    s: &TestServer,
    owner: &str,
    repo: &str,
    user: &User,
    scopes: &[Scope],
) -> String {
    let token = s.token(user, scopes).await;
    s.git_url(owner, repo, Some(&token))
}

async fn setup_repo(s: &TestServer, alice: &User, name: &str) -> (i64, String, PathBuf, PathBuf) {
    s.repo(alice, name, Visibility::Private).await;
    let repo_id = s
        .core
        .repo_for(Some(alice), "alice", name)
        .await
        .unwrap()
        .repo
        .id;
    let url = writer_url(s, "alice", name, alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let server = s.core.repo_path(repo_id);
    (repo_id, url, work, server)
}

fn git_dir_arg(server: &Path) -> String {
    format!("--git-dir={}", server.display())
}

/// `rev-parse` of `r` in the server repo, or `None` when the ref is absent.
async fn server_rev(work: &Path, server: &Path, r: &str) -> Option<String> {
    let gd = git_dir_arg(server);
    let out = git(work, &[&gd, "rev-parse", "--verify", r]).await;
    if out.status.success() {
        Some(String::from_utf8(out.stdout).unwrap().trim().to_owned())
    } else {
        None
    }
}

async fn server_rev_ok(work: &Path, server: &Path, r: &str) -> String {
    server_rev(work, server, r)
        .await
        .unwrap_or_else(|| panic!("expected server ref {r} to exist"))
}

/// All `refs/for/*` names left in the server repo (ingest must delete them).
async fn server_for_refs(work: &Path, server: &Path) -> Vec<String> {
    let gd = git_dir_arg(server);
    git_ok(
        work,
        &[&gd, "for-each-ref", "--format=%(refname)", "refs/for"],
    )
    .await
    .lines()
    .filter(|l| !l.trim().is_empty())
    .map(str::to_owned)
    .collect()
}

async fn wait_for_open_change(
    s: &TestServer,
    repo_id: i64,
    user_id: i64,
    base: &str,
    topic: &str,
) -> starforged_db::changes::ChangeRow {
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
        if let Some(change) = found {
            return change;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "timed out waiting for open change {base}/{topic}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_revisions(
    s: &TestServer,
    change_id: i64,
    expected: usize,
) -> Vec<starforged_db::changes::RevisionRow> {
    let start = Instant::now();
    loop {
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), change_id)
            .await
            .unwrap();
        if revs.len() == expected {
            return revs;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "timed out waiting for {expected} revisions (have {})",
            revs.len()
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_for_creates_trail_change_and_revision() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("feature.txt", b"feature\n")], "add feature").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main"]).await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let main_tip = server_rev_ok(&work, &server, "refs/heads/main").await;

    // The default topic is the pusher's handle; the trail takes the tip subject.
    let change = wait_for_open_change(&s, repo_id, alice.id, "main", "alice").await;
    assert_eq!(change.number, 1);
    assert_eq!(change.kind, "agit");
    assert_eq!(change.base_branch, "main");
    assert_eq!(change.topic, "alice");
    assert_eq!(change.state, "open");
    assert_eq!(change.creator_id, Some(alice.id));

    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, 1)
        .await
        .unwrap()
        .expect("trail 1 exists");
    assert_eq!(trail.id, change.trail_id);
    assert_eq!(trail.title, "add feature");

    let revs = wait_for_revisions(&s, change.id, 1).await;
    assert_eq!(revs[0].number, 1);
    assert_eq!(revs[0].head_sha, sha);
    assert_eq!(revs[0].base_sha, main_tip);
    assert_eq!(revs[0].pusher_id, Some(alice.id));
    assert_eq!(revs[0].mergeability, "unknown");
    assert_eq!(change.current_revision_id, Some(revs[0].id));

    // Trail refs resolve to the pushed SHA; the pseudo-ref is gone.
    assert_eq!(
        server_rev_ok(&work, &server, "refs/trails/1/changes/1/head").await,
        sha
    );
    assert_eq!(
        server_rev_ok(&work, &server, "refs/trails/1/changes/1/rev/1").await,
        sha
    );
    assert!(server_for_refs(&work, &server).await.is_empty());

    // The server-only namespaces stay out of fetch advertisements.
    let advertised = git_ok(&work, &["ls-remote", &url]).await;
    assert!(!advertised.contains("refs/for"), "{advertised}");
    assert!(!advertised.contains("refs/trails"), "{advertised}");
    assert!(advertised.contains("refs/heads/main"), "{advertised}");

    // Timeline audit: one change.open and one change.revision row.
    let timeline = starforged_db::trails::timeline_of_trail(s.core.db(), trail.id)
        .await
        .unwrap();
    let kinds: Vec<&str> = timeline.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"trail.open"), "{kinds:?}");
    assert!(kinds.contains(&"change.open"), "{kinds:?}");
    assert!(kinds.contains(&"change.revision"), "{kinds:?}");

    // Mergeability starts unknown; the worker resolves it to clean.
    assert_eq!(change.mergeability, "unknown");
    s.core.run_due_jobs().await.unwrap();
    let after = starforged_db::changes::change_by_trail_number(s.core.db(), trail.id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.mergeability, "clean");
    assert_eq!(after.conflict_paths, "[]");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_push_to_same_base_topic_creates_r2() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "first").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/feat"]).await;
    let first = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let change = wait_for_open_change(&s, repo_id, alice.id, "main", "feat").await;
    wait_for_revisions(&s, change.id, 1).await;

    commit_files(&work, &[("b.txt", b"b\n")], "second").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/feat"]).await;
    let second = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    assert_ne!(first, second);

    let revs = wait_for_revisions(&s, change.id, 2).await;
    assert_eq!(revs[1].number, 2);
    assert_eq!(revs[1].head_sha, second);
    // History is preserved: rev/1 still points at the first push.
    assert_eq!(
        server_rev_ok(&work, &server, "refs/trails/1/changes/1/rev/1").await,
        first
    );
    assert_eq!(
        server_rev_ok(&work, &server, "refs/trails/1/changes/1/rev/2").await,
        second
    );
    assert_eq!(
        server_rev_ok(&work, &server, "refs/trails/1/changes/1/head").await,
        second
    );
    assert!(server_for_refs(&work, &server).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_commit_to_two_topics_creates_two_changes() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, _server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "shared").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &url,
            "HEAD:refs/for/main/alpha",
            "HEAD:refs/for/main/beta",
        ],
    )
    .await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();

    let a = wait_for_open_change(&s, repo_id, alice.id, "main", "alpha").await;
    let b = wait_for_open_change(&s, repo_id, alice.id, "main", "beta").await;
    assert_ne!(a.id, b.id);
    assert_ne!(
        a.trail_id, b.trail_id,
        "unpinned topics get their own trails"
    );
    for change in [&a, &b] {
        let revs = wait_for_revisions(&s, change.id, 1).await;
        assert_eq!(revs[0].head_sha, sha);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_option_trail_pins_the_existing_trail() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, _server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "one").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/one"]).await;
    let first = wait_for_open_change(&s, repo_id, alice.id, "main", "one").await;
    wait_for_revisions(&s, first.id, 1).await;

    commit_files(&work, &[("b.txt", b"b\n")], "two").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            "-o",
            "trail=1",
            &url,
            "HEAD:refs/for/main/two",
        ],
    )
    .await;
    let second = wait_for_open_change(&s, repo_id, alice.id, "main", "two").await;
    assert_eq!(second.trail_id, first.trail_id);
    assert_eq!(second.number, 2);
    wait_for_revisions(&s, second.id, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_option_title_names_the_new_trail() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, _server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "some subject").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            "-o",
            "title=My feature",
            &url,
            "HEAD:refs/for/main/delta",
        ],
    )
    .await;
    let change = wait_for_open_change(&s, repo_id, alice.id, "main", "delta").await;
    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(change.trail_id, trail.id);
    assert_eq!(trail.title, "My feature");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn force_push_creates_a_new_revision_and_repush_is_a_noop() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, _server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "v1").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/feat"]).await;
    let change = wait_for_open_change(&s, repo_id, alice.id, "main", "feat").await;
    wait_for_revisions(&s, change.id, 1).await;

    // Amend into a new SHA and force-push: a new revision, not an overwrite.
    git_ok(&work, &["commit", "-q", "--amend", "-m", "v2"]).await;
    git_ok(
        &work,
        &["push", "-q", "-f", &url, "HEAD:refs/for/main/feat"],
    )
    .await;
    let amended = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let revs = wait_for_revisions(&s, change.id, 2).await;
    assert_eq!(revs[1].number, 2);
    assert_eq!(revs[1].head_sha, amended);

    // Re-pushing the identical SHA creates nothing further.
    s.core.run_due_jobs().await.unwrap();
    git_ok(
        &work,
        &["push", "-q", "-f", &url, "HEAD:refs/for/main/feat"],
    )
    .await;
    let start = Instant::now();
    loop {
        s.core.run_due_jobs().await.unwrap();
        let count = starforged_db::changes::revisions_of_change(s.core.db(), change.id)
            .await
            .unwrap()
            .len();
        assert_eq!(count, 2, "identical re-push must not create a revision");
        if start.elapsed() > Duration::from_secs(3) {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    // The same guard holds when calling the ingest directly with the tip SHA.
    let main_tip = server_rev_ok(&work, &s.core.repo_path(repo_id), "refs/heads/main").await;
    let dup = s
        .core
        .record_agit_push(
            repo_id,
            alice.id,
            &starforged_core::changes::IngestSidecar {
                base: "main".to_owned(),
                topic: "feat".to_owned(),
                trail: None,
                title: None,
            },
            &amended,
            &main_tip,
        )
        .await
        .unwrap();
    assert_eq!(dup, None);
    assert_eq!(
        starforged_db::changes::revisions_of_change(s.core.db(), change.id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mergeability_reports_conflict_paths_and_unrelated_histories() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, server) = setup_repo(&s, &alice, "proj").await;
    let main_tip0 = server_rev_ok(&work, &server, "refs/heads/main").await;

    // Base file both sides will edit.
    std::fs::write(work.join("f.txt"), b"v1\n").unwrap();
    git_ok(&work, &["add", "-A"]).await;
    git_ok(&work, &["commit", "-q", "-m", "base file"]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;

    // The proposed change edits the same line.
    std::fs::write(work.join("f.txt"), b"v2\n").unwrap();
    git_ok(&work, &["add", "-A"]).await;
    git_ok(&work, &["commit", "-q", "-m", "proposed"]).await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/feat"]).await;
    let change = wait_for_open_change(&s, repo_id, alice.id, "main", "feat").await;
    let _ = main_tip0;

    // Fast-forwardable over the base: clean.
    let start = Instant::now();
    let clean = loop {
        s.core.run_due_jobs().await.unwrap();
        let row = starforged_db::changes::change_by_trail_number(
            s.core.db(),
            change.trail_id,
            change.number,
        )
        .await
        .unwrap()
        .unwrap();
        if row.mergeability != "unknown" {
            break row;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "mergeability never resolved"
        );
        sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(clean.mergeability, "clean");
    assert_eq!(clean.conflict_paths, "[]");

    // Advance main on the same line: the change now conflicts. The proposed
    // commit stays reachable server-side (trail refs point at it) but must
    // leave local main's history, else it merges as an ancestor (clean).
    git_ok(&work, &["reset", "-q", "--hard", "HEAD~1"]).await;
    std::fs::write(work.join("f.txt"), b"v3\n").unwrap();
    git_ok(&work, &["add", "-A"]).await;
    git_ok(&work, &["commit", "-q", "-m", "main moves"]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;

    let start = Instant::now();
    let conflicted = loop {
        s.core.run_due_jobs().await.unwrap();
        let row = starforged_db::changes::change_by_trail_number(
            s.core.db(),
            change.trail_id,
            change.number,
        )
        .await
        .unwrap()
        .unwrap();
        if row.mergeability == "conflict" {
            break row;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "mergeability never turned to conflict (is {})",
            row.mergeability
        );
        sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(conflicted.conflict_paths, "[\"f.txt\"]");

    // An orphan history shares no merge-base: conflict flagged unrelated.
    git_ok(&work, &["checkout", "-q", "--orphan", "weird"]).await;
    git_ok(&work, &["rm", "-q", "-rf", "."]).await;
    std::fs::write(work.join("other.txt"), b"other\n").unwrap();
    git_ok(&work, &["add", "-A"]).await;
    git_ok(&work, &["commit", "-q", "-m", "unrelated"]).await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/weird"]).await;
    let odd = wait_for_open_change(&s, repo_id, alice.id, "main", "weird").await;

    let start = Instant::now();
    loop {
        s.core.run_due_jobs().await.unwrap();
        let row =
            starforged_db::changes::change_by_trail_number(s.core.db(), odd.trail_id, odd.number)
                .await
                .unwrap()
                .unwrap();
        if row.mergeability == "conflict" {
            break;
        }
        assert!(start.elapsed() < SCAN_TIMEOUT, "unrelated never resolved");
        sleep(Duration::from_millis(50)).await;
    }
    let timeline = starforged_db::trails::timeline_of_trail(s.core.db(), odd.trail_id)
        .await
        .unwrap();
    let merge_event = timeline
        .iter()
        .find(|e| e.kind == "change.mergeability")
        .expect("a mergeability timeline row");
    assert!(
        merge_event.payload.contains("unrelated"),
        "payload flags unrelated: {}",
        merge_event.payload
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_change_is_never_resurrected() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, _server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "first").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/feat"]).await;
    let first = wait_for_open_change(&s, repo_id, alice.id, "main", "feat").await;
    wait_for_revisions(&s, first.id, 1).await;

    starforged_db::changes::set_change_state(s.core.db(), first.id, "closed", starforged_db::now())
        .await
        .unwrap();

    // A new push on the same base/topic opens a fresh change; the closed one keeps one revision.
    commit_files(&work, &[("b.txt", b"b\n")], "second").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/feat"]).await;
    let start = Instant::now();
    let second = loop {
        s.core.run_due_jobs().await.unwrap();
        let open = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            alice.id,
            "main",
            "feat",
            None,
        )
        .await
        .unwrap();
        if let Some(row) = open
            && row.id != first.id
        {
            break row;
        }
        assert!(start.elapsed() < SCAN_TIMEOUT, "fresh change never opened");
        sleep(Duration::from_millis(50)).await;
    };
    assert_ne!(second.trail_id, first.trail_id);
    assert_eq!(second.number, 1, "fresh k on the new trail");
    wait_for_revisions(&s, second.id, 1).await;
    assert_eq!(
        starforged_db::changes::revisions_of_change(s.core.db(), first.id)
            .await
            .unwrap()
            .len(),
        1,
        "the closed change gains no revisions"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_head_move_creates_a_revision_and_base_move_recomputes() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, server) = setup_repo(&s, &alice, "proj").await;

    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit_files(&work, &[("feat.txt", b"f\n")], "feature work").await;
    git_ok(&work, &["push", "-q", &url, "feature"]).await;
    let feature_tip = server_rev_ok(&work, &server, "refs/heads/feature").await;
    let main_tip = server_rev_ok(&work, &server, "refs/heads/main").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;

    let view = s
        .core
        .create_trail(&alice, "alice", "proj", "Branch work", "")
        .await
        .unwrap();
    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, view.number)
        .await
        .unwrap()
        .unwrap();
    let now = starforged_db::now();
    let change = starforged_db::changes::insert_change(
        s.core.db(),
        trail.id,
        "branch",
        Some("feature"),
        "main",
        alice.id,
        now,
    )
    .await
    .unwrap();
    let rev = starforged_db::changes::insert_revision(
        s.core.db(),
        change.id,
        &feature_tip,
        &main_tip,
        Some(alice.id),
        now,
    )
    .await
    .unwrap();
    starforged_db::changes::set_current_revision(s.core.db(), change.id, rev.id, now)
        .await
        .unwrap();

    // Advancing the head branch records a new revision on the open change.
    git_ok(&work, &["checkout", "-q", "feature"]).await;
    commit_files(&work, &[("more.txt", b"m\n")], "more feature").await;
    git_ok(&work, &["push", "-q", &url, "feature"]).await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    let new_tip = git_ok(&work, &["rev-parse", "feature"])
        .await
        .trim()
        .to_owned();
    let revs = wait_for_revisions(&s, change.id, 2).await;
    assert_eq!(revs[1].number, 2);
    assert_eq!(revs[1].head_sha, new_tip);

    // Moving the base branch creates no revision but recomputes mergeability.
    commit_files(&work, &[("other.txt", b"o\n")], "main moves").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let start = Instant::now();
    loop {
        s.core.run_due_jobs().await.unwrap();
        let row =
            starforged_db::changes::change_by_trail_number(s.core.db(), trail.id, change.number)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            starforged_db::changes::revisions_of_change(s.core.db(), change.id)
                .await
                .unwrap()
                .len(),
            2,
            "base moves never create revisions"
        );
        if row.mergeability == "clean" {
            break;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "mergeability never resolved"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_push_to_refs_for_is_rejected() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (_repo_id, _url, work, _server) = setup_repo(&s, &alice, "proj").await;
    let anon = s.git_url("alice", "proj", None);
    commit_files(&work, &[("a.txt", b"a\n")], "anon attempt").await;
    let denied = git(&work, &["push", &anon, "HEAD:refs/for/main/x"]).await;
    assert!(!denied.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn members_mode_rejects_a_non_member_push() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    starforged_db::repos::set_refs_for_access(s.core.db(), repo_id, "members")
        .await
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    commit_files(&work, &[("a.txt", b"a\n")], "bob attempt").await;
    // Bob can see the public repo but is not a member and holds no write grant:
    // the RPC write gate rejects him before the hook policy is reached.
    let denied = git(&work, &["push", &bob_url, "HEAD:refs/for/main/x"]).await;
    assert!(!denied.status.success());
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(stderr.contains("403"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_user_refs_for_push_creates_change() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (repo_id, _url, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let read = s.token(&bob, &[Scope::RepoRead]).await;
    let bob_url = s.git_url("alice", "proj", Some(&read));

    // A read-only token on an anyone_with_read repo may propose via refs/for.
    commit_files(&work, &[("bob.txt", b"bob\n")], "bob proposal").await;
    git_ok(&work, &["push", "-q", &bob_url, "HEAD:refs/for/main"]).await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let change = wait_for_open_change(&s, repo_id, bob.id, "main", "bob").await;
    assert_eq!(change.kind, "agit");
    assert_eq!(change.number, 1);
    assert_eq!(change.creator_id, Some(bob.id));
    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trail.title, "bob proposal");
    let revs = wait_for_revisions(&s, change.id, 1).await;
    assert_eq!(revs[0].head_sha, sha);
    assert_eq!(
        server_rev_ok(&work, &server, "refs/trails/1/changes/1/head").await,
        sha
    );
    assert!(server_for_refs(&work, &server).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn members_mode_rejects_non_member_read_token() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    starforged_db::repos::set_refs_for_access(s.core.db(), repo_id, "members")
        .await
        .unwrap();
    let read = s.token(&bob, &[Scope::RepoRead]).await;

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    commit_files(&work, &[("a.txt", b"a\n")], "bob attempt").await;
    // Bob can read the public repo but is not a member: the RPC read tier
    // rejects him before the hook policy is reached.
    let denied = git(
        &work,
        &[
            "push",
            &s.git_url("alice", "proj", Some(&read)),
            "HEAD:refs/for/main/x",
        ],
    )
    .await;
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("403"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_token_branch_push_rejected_and_branch_unmoved() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (_repo_id, _url, work, _server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let read = s.token(&bob, &[Scope::RepoRead]).await;
    let bob_url = s.git_url("alice", "proj", Some(&read));

    // A reader may enter receive-pack (for refs/for), but the hook rejects
    // branch writes with a clear message and moves nothing.
    let tip_before = git_ok(&work, &["ls-remote", &bob_url, "refs/heads/main"]).await;
    commit_files(&work, &[("sneaky.txt", b"sneaky\n")], "sneaky").await;
    let denied = git(&work, &["push", &bob_url, "main"]).await;
    assert!(!denied.status.success());
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(stderr.contains("starforge:"), "{stderr}");
    assert!(stderr.contains("need write permission"), "{stderr}");
    let tip_after = git_ok(&work, &["ls-remote", &bob_url, "refs/heads/main"]).await;
    assert_eq!(tip_before, tip_after, "rejected push moved the branch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_trail_push_matches_by_id_not_number() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, _server) = setup_repo(&s, &alice, "proj").await;
    // Shift global trail ids: this other-repo trail takes id 2, so proj's
    // trail number 2 will have a different id.
    s.repo(&alice, "other", Visibility::Private).await;
    let _other = s
        .core
        .create_trail(&alice, "alice", "other", "Other", "")
        .await
        .unwrap();

    // Unpinned push creates proj trail number 1; a titled push creates
    // number 2 (global id 3, not 2).
    commit_files(&work, &[("a.txt", b"a\n")], "first").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/feat"]).await;
    wait_for_open_change(&s, repo_id, alice.id, "main", "feat").await;
    commit_files(&work, &[("b.txt", b"b\n")], "pin me").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            "-o",
            "title=Pinned",
            &url,
            "HEAD:refs/for/main/pin",
        ],
    )
    .await;
    let pinned = wait_for_open_change(&s, repo_id, alice.id, "main", "pin").await;
    wait_for_revisions(&s, pinned.id, 1).await;
    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trail.id, pinned.trail_id);
    assert_ne!(
        trail.id, trail.number,
        "test premise: trail id must differ from its number"
    );

    // A second `-o trail=2` push must update that same change (r=2), not
    // scope by the number-as-id (which names the other repo's trail) and
    // open a duplicate.
    commit_files(&work, &[("c.txt", b"c\n")], "pin again").await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(
        &work,
        &[
            "push",
            "-q",
            "-o",
            "trail=2",
            &url,
            "HEAD:refs/for/main/pin",
        ],
    )
    .await;
    let start = Instant::now();
    loop {
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), pinned.id)
            .await
            .unwrap();
        if revs.len() == 2 {
            assert_eq!(revs[1].head_sha, sha);
            break;
        }
        let changes = starforged_db::changes::changes_of_trail(s.core.db(), trail.id)
            .await
            .unwrap();
        assert_eq!(
            changes.len(),
            1,
            "pinned push opened a duplicate change instead of updating"
        );
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "pinned push never appended r=2"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_consumes_only_its_own_sidecar() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, server) = setup_repo(&s, &alice, "proj").await;
    let zero = "0".repeat(40);

    // Two foreign sidecars for the same refname with different nonces and
    // options: the scan must touch neither.
    for (nonce, title) in [
        ("aaaa1111bbbb2222", "Stolen A"),
        ("cccc3333dddd4444", "Stolen B"),
    ] {
        starforged_git::pushsidecar::write_sidecar(
            &server,
            nonce,
            "refs/for/main/victim",
            &starforged_git::pushsidecar::Sidecar {
                repo_id,
                user_id: Some(alice.id),
                base: "main".to_owned(),
                topic: "victim".to_owned(),
                trail: None,
                title: Some(title.to_owned()),
                refname: "refs/for/main/victim".to_owned(),
                old: zero.clone(),
                new: "f".repeat(40),
                nonce: nonce.to_owned(),
            },
        )
        .unwrap();
    }

    commit_files(&work, &[("v.txt", b"v\n")], "victim work").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/victim"]).await;
    let change = wait_for_open_change(&s, repo_id, alice.id, "main", "victim").await;
    wait_for_revisions(&s, change.id, 1).await;
    // Ingested without options: the trail takes the tip subject, and both
    // foreign sidecars are still on disk (the push's own nonce file was
    // consumed).
    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trail.title, "victim work");
    let left = starforged_git::pushsidecar::find_for_ref(&server, "refs/for/main/victim");
    assert_eq!(left.len(), 2, "a foreign sidecar was stolen: {left:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn base_branch_delete_recomputes_mergeability() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, server) = setup_repo(&s, &alice, "proj").await;

    // The base must not be the repo's current branch: git refuses to delete
    // HEAD's target, so the change tracks `develop` instead of `main`.
    git_ok(&work, &["checkout", "-q", "-b", "develop"]).await;
    git_ok(&work, &["push", "-q", &url, "develop"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit_files(&work, &[("feat.txt", b"f\n")], "feature work").await;
    git_ok(&work, &["push", "-q", &url, "feature"]).await;
    let feature_tip = server_rev_ok(&work, &server, "refs/heads/feature").await;
    let develop_tip = server_rev_ok(&work, &server, "refs/heads/develop").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;

    let view = s
        .core
        .create_trail(&alice, "alice", "proj", "Branch work", "")
        .await
        .unwrap();
    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, view.number)
        .await
        .unwrap()
        .unwrap();
    let now = starforged_db::now();
    let change = starforged_db::changes::insert_change(
        s.core.db(),
        trail.id,
        "branch",
        Some("feature"),
        "develop",
        alice.id,
        now,
    )
    .await
    .unwrap();
    let rev = starforged_db::changes::insert_revision(
        s.core.db(),
        change.id,
        &feature_tip,
        &develop_tip,
        Some(alice.id),
        now,
    )
    .await
    .unwrap();
    starforged_db::changes::set_current_revision(s.core.db(), change.id, rev.id, now)
        .await
        .unwrap();
    // Baseline: mergeability resolves clean while the base exists.
    s.core
        .enqueue(&starforged_core::jobs::Job::ChangeMergeability {
            change_id: change.id,
        })
        .await
        .unwrap();
    s.core.run_due_jobs().await.unwrap();
    let baseline =
        starforged_db::changes::change_by_trail_number(s.core.db(), trail.id, change.number)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(baseline.mergeability, "clean");

    // Deleting the base branch records no revision but recomputes
    // mergeability to conflict (missing base).
    git_ok(&work, &["push", "-q", &url, ":develop"]).await;
    let start = Instant::now();
    loop {
        s.core.run_due_jobs().await.unwrap();
        let row =
            starforged_db::changes::change_by_trail_number(s.core.db(), trail.id, change.number)
                .await
                .unwrap()
                .unwrap();
        if row.mergeability == "conflict" {
            break;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "base delete never recomputed (is {})",
            row.mergeability
        );
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        starforged_db::changes::revisions_of_change(s.core.db(), change.id)
            .await
            .unwrap()
            .len(),
        1,
        "a delete must not record a revision"
    );
}

/// D1: change heads stay hidden from advertisements but are fetchable by SHA
/// over both protocol versions; anonymous fetches on a private repo fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_change_head_by_sha() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (repo_id, url, work, _server) = setup_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("feature.txt", b"feature\n")], "add feature").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main"]).await;
    let change = wait_for_open_change(&s, repo_id, alice.id, "main", "alice").await;
    let revs = wait_for_revisions(&s, change.id, 1).await;
    assert_eq!(revs[0].head_sha.len(), 40);

    // The head SHA as the API reports it (fresh repo: the push opens trail 1).
    let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, 1)
        .await
        .unwrap()
        .expect("trail 1 exists");
    assert_eq!(trail.id, change.trail_id);
    let api_token = s.token(&alice, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();
    let res = client
        .get(s.url("/api/v1/repos/alice/proj/trails/1/changes/1"))
        .bearer_auth(&api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let head = body["selected"]["head_sha"].as_str().unwrap().to_owned();
    assert_eq!(head, revs[0].head_sha);

    // The server-only namespaces stay out of advertisements …
    let advertised = git_ok(&work, &["ls-remote", &url]).await;
    assert!(!advertised.contains("refs/trails"), "{advertised}");
    assert!(!advertised.contains("refs/for"), "{advertised}");

    // … but the head is fetchable by SHA over both protocol versions.
    let tmp = tempfile::tempdir().unwrap();
    let fresh = work_repo(tmp.path(), "fresh", &[("other.txt", "other\n")]).await;
    for version in ["0", "2"] {
        let out = git(
            &fresh,
            &[
                "-c",
                &format!("protocol.version={version}"),
                "fetch",
                "-q",
                &url,
                &head,
            ],
        )
        .await;
        assert!(
            out.status.success(),
            "protocol v{version} fetch of {head} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        git_ok(&fresh, &["cat-file", "-e", &head]).await;
    }

    // Anonymous fetches on a private repo are refused.
    let anon_url = s.git_url("alice", "proj", None);
    let out = git(
        &fresh,
        &["-c", "protocol.version=0", "fetch", &anon_url, &head],
    )
    .await;
    assert!(
        !out.status.success(),
        "anonymous fetch of a private change head must fail"
    );
}
