//! `sessions backfill-links` tests.
//!
//! Tempdir git repos (`git init`, local `user.email`/`user.name`) with commits
//! at controlled committer dates; temp spool seeded through the `Spool` seam.
//! No network. Commits carry real file changes so `git log --name-only`
//! reports the paths the backfill matches against.

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser as _;
use starforge_cli::cli::{Cli, SessionsCmd};
use starforge_cli::commands::sessions::backfill_links;
use starforge_cli::git::common_dir;
use starforge_cli::queue::{QueueOp, read_queue};
use starforge_cli::spool::{LinkConfidence, LinkSource, Spool};
use starforge_format::{CaptureInfo, RedactionSummary, RepoInfo, SessionMeta, Usage};
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git runs")
}

fn git_ok(repo: &Path, args: &[&str]) -> String {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Create `path` with `bytes`, stage it, and commit the change at committer
/// time `date` (RFC 3339). Returns the commit SHA.
fn commit_file(repo: &Path, path: &str, bytes: &str, date: &str, msg: &str) -> String {
    std::fs::write(repo.join(path), bytes).unwrap();
    git_ok(repo, &["add", path]);
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["commit", "-m", msg])
        .env("GIT_COMMITTER_DATE", date)
        .env("GIT_AUTHOR_DATE", date)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    git_ok(repo, &["rev-parse", "HEAD"]).trim().to_string()
}

fn init_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let repo = dir.path().to_path_buf();
    git_ok(&repo, &["init"]);
    git_ok(&repo, &["config", "user.email", "t@t.t"]);
    git_ok(&repo, &["config", "user.name", "t"]);
    (dir, repo)
}

fn open_spool(repo: &Path) -> Spool {
    Spool::open(&common_dir(repo).unwrap())
}

fn session_meta(ulid: &str, started: &str, ended: Option<&str>, files: &[&str]) -> SessionMeta {
    SessionMeta {
        format: starforge_format::session::FORMAT_TAG.to_string(),
        id: ulid.parse().unwrap(),
        agent: Default::default(),
        models: Vec::new(),
        title: None,
        started_at: started.to_string(),
        ended_at: ended.map(str::to_string),
        repo: RepoInfo::default(),
        parent_id: None,
        usage: Usage::default(),
        files_touched: files.iter().map(|s| s.to_string()).collect(),
        redaction: RedactionSummary::default(),
        capture: CaptureInfo::default(),
    }
}

fn seed(spool: &Spool, ulid: &str, meta: SessionMeta, last_event_at: Option<&str>) {
    spool.put_session(&meta).unwrap();
    if let Some(ts) = last_event_at {
        spool
            .write_cursor(
                "pi/test",
                ulid,
                starforge_capture::Cursor::start(),
                "/tmp/native.jsonl",
                Some(ts.to_string()),
                None,
            )
            .unwrap();
    }
}

const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB0";

/// Backfill links only commits inside the activity window that touch a
/// session file: a commit before `started_at` and one past the grace,
/// plus a commit inside the window touching an unrelated file, are ignored.
/// A session with no `ended_at` uses its cursor's `last_event_at`.
#[test]
fn backfill_links_matches_window_and_file_overlap_only() {
    let (_dir, repo) = init_repo();
    let spool = open_spool(&repo);

    let before = commit_file(&repo, "a.txt", "old", "2026-01-01T10:00:00Z", "before");
    let inside = commit_file(&repo, "a.txt", "new", "2026-01-01T12:15:00Z", "inside");
    let unrelated = commit_file(&repo, "other.txt", "x", "2026-01-01T12:20:00Z", "unrelated");
    let after = commit_file(&repo, "a.txt", "later", "2026-01-01T14:00:00Z", "after");
    let for_b = commit_file(&repo, "b.txt", "b", "2026-01-01T12:20:00Z", "for-b");

    seed(
        &spool,
        ULID_A,
        session_meta(
            ULID_A,
            "2026-01-01T12:00:00Z",
            Some("2026-01-01T12:30:00Z"),
            &["a.txt"],
        ),
        None,
    );
    seed(
        &spool,
        ULID_B,
        session_meta(ULID_B, "2026-01-01T11:00:00Z", None, &["b.txt"]),
        Some("2026-01-01T12:00:00Z"),
    );

    let (out, code) = backfill_links(&repo, None, false);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, "linked 2 pair(s)", "{out}");

    let links = spool.links().unwrap();
    let pairs: Vec<(&str, &str)> = links
        .iter()
        .map(|l| (l.ulid.as_str(), l.commit.as_str()))
        .collect();
    assert!(pairs.contains(&(ULID_A, inside.as_str())), "{pairs:?}");
    assert!(pairs.contains(&(ULID_B, for_b.as_str())), "{pairs:?}");
    for sha in [&before, &unrelated, &after] {
        assert!(
            !pairs.iter().any(|(_, c)| c == sha),
            "sha {sha} must not link: {pairs:?}"
        );
    }
}

#[test]
fn backfill_links_normalizes_worktree_absolute_paths() {
    let (_dir, repo) = init_repo();
    let spool = open_spool(&repo);

    let sha = commit_file(&repo, "c.txt", "c", "2026-01-01T12:15:00Z", "c");
    let abs = repo.join("c.txt").to_string_lossy().into_owned();

    seed(
        &spool,
        ULID_A,
        session_meta(
            ULID_A,
            "2026-01-01T12:00:00Z",
            Some("2026-01-01T12:30:00Z"),
            &[abs.as_str()],
        ),
        None,
    );
    // An absolute path outside every root is dropped: no link from it.
    let outside = "/definitely/not/under/the/repo/d.txt";
    seed(
        &spool,
        ULID_B,
        session_meta(
            ULID_B,
            "2026-01-01T12:00:00Z",
            Some("2026-01-01T12:30:00Z"),
            &[outside],
        ),
        None,
    );

    let (out, code) = backfill_links(&repo, None, false);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, "linked 1 pair(s)", "{out}");
    let links = spool.links().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ulid, ULID_A);
    assert_eq!(links[0].commit, sha);
}

#[test]
fn backfill_links_dry_run_writes_nothing_then_idempotent() {
    let (_dir, repo) = init_repo();
    let spool = open_spool(&repo);

    let sha = commit_file(&repo, "a.txt", "a", "2026-01-01T12:15:00Z", "a");
    seed(
        &spool,
        ULID_A,
        session_meta(
            ULID_A,
            "2026-01-01T12:00:00Z",
            Some("2026-01-01T12:30:00Z"),
            &["a.txt"],
        ),
        None,
    );

    let (out, code) = backfill_links(&repo, None, true);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains(&format!("{ULID_A}  {sha}  a.txt")),
        "dry-run line: {out}"
    );
    assert!(out.contains("would link 1 pair(s)"), "{out}");
    assert!(spool.links().unwrap().is_empty(), "dry-run writes no links");
    assert!(
        !read_queue(&spool)
            .unwrap()
            .iter()
            .any(|e| e.op == QueueOp::Links),
        "dry-run enqueues no upload"
    );

    let (out, code) = backfill_links(&repo, None, false);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, "linked 1 pair(s)", "{out}");
    let links = spool.links().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].source, LinkSource::CliClaim);
    assert_eq!(links[0].confidence, LinkConfidence::Exact);
    assert!(
        read_queue(&spool)
            .unwrap()
            .iter()
            .any(|e| e.op == QueueOp::Links && e.ulid == ULID_A),
        "a Links upload is queued"
    );

    let (out, code) = backfill_links(&repo, None, false);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, "linked 0 pair(s)", "{out}");
    assert_eq!(
        spool.links().unwrap().len(),
        1,
        "second run adds no duplicates"
    );
}

#[test]
fn backfill_links_since_excludes_older_commits() {
    let (_dir, repo) = init_repo();
    let spool = open_spool(&repo);

    let old = commit_file(&repo, "a.txt", "old", "2026-01-01T12:15:00Z", "old");
    let new_sha = commit_file(&repo, "a.txt", "new", "2026-02-01T12:15:00Z", "new");
    // Two sessions so each commit has its own window.
    seed(
        &spool,
        ULID_A,
        session_meta(
            ULID_A,
            "2026-01-01T12:00:00Z",
            Some("2026-01-01T12:30:00Z"),
            &["a.txt"],
        ),
        None,
    );
    seed(
        &spool,
        ULID_B,
        session_meta(
            ULID_B,
            "2026-02-01T12:00:00Z",
            Some("2026-02-01T12:30:00Z"),
            &["a.txt"],
        ),
        None,
    );

    let (out, code) = backfill_links(&repo, Some("2026-02-01"), false);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, "linked 1 pair(s)", "{out}");
    let links = spool.links().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].commit, new_sha);
    assert_ne!(links[0].commit, old);
    assert_eq!(links[0].ulid, ULID_B);
}

#[test]
fn backfill_links_rejects_bad_since() {
    let (_dir, repo) = init_repo();
    let (out, code) = backfill_links(&repo, Some("not-a-date"), false);
    assert_eq!(code, 1);
    assert!(out.starts_with("error:"), "{out}");
}

#[test]
fn backfill_links_arguments_parse() {
    let cli = Cli::try_parse_from([
        "starforge",
        "sessions",
        "backfill-links",
        "--since",
        "2026-01-01",
    ])
    .unwrap();
    assert!(
        matches!(
            &cli.cmd,
            starforge_cli::cli::Cmd::Sessions {
                cmd: SessionsCmd::BackfillLinks { since: Some(s) }
            } if s == "2026-01-01"
        ),
        "{:?}",
        cli.cmd
    );
    // `--dry-run` is global.
    let cli =
        Cli::try_parse_from(["starforge", "--dry-run", "sessions", "backfill-links"]).unwrap();
    assert!(cli.dry_run);
}
