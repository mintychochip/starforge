//! `starforge hook session-end`: Claude Code SessionEnd entry point.
//!
//! A temp git repo with its own `STARFORGE_HOME` runs `starforge enable`,
//! then a Claude fixture transcript at
//! `<home>/.claude/projects/<slug>/<id>.jsonl` whose `cwd` is the repo.
//! `starforge hook session-end` with the Claude payload on stdin must exit
//! `0`, leave the spool session marked ended, and queue a `complete` op
//! (no server is configured, so the upload pass only warns). Outside any
//! repo it still exits `0`. No network beyond process spawn, no real `$HOME`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

mod common;

use common::hermetic_command;

use starforge_cli::git::common_dir;
use starforge_cli::spool::Spool;
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str], home: &Path, path: &str) -> std::process::Output {
    hermetic_command("git", home)
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("PATH", path)
        .output()
        .expect("git runs")
}

fn git_ok(repo: &Path, args: &[&str], home: &Path, path: &str) -> String {
    let out = git(repo, args, home, path);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn init_repo(home: &Path, path: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init"], home, path);
    git_ok(&repo, &["config", "user.email", "t@t.t"], home, path);
    git_ok(&repo, &["config", "user.name", "t"], home, path);
    git_ok(&repo, &["config", "commit.gpgsign", "false"], home, path);
    git_ok(
        &repo,
        &["commit", "--allow-empty", "-m", "init"],
        home,
        path,
    );
    (dir, repo)
}

fn bin_path() -> String {
    let exe = env!("CARGO_BIN_EXE_starforge");
    let dir = Path::new(exe).parent().unwrap().to_path_buf();
    format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

fn starforge(
    repo: &Path,
    home: &Path,
    path: &str,
    args: &[&str],
    stdin_data: Option<&str>,
) -> std::process::Output {
    let mut cmd = hermetic_command("starforge", home);
    cmd.current_dir(repo)
        .args(args)
        .env("PATH", path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn().expect("starforge runs");
    if let Some(data) = stdin_data {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();
    }
    child.wait_with_output().expect("starforge exits")
}

fn claude_transcript(repo: &Path, session_id: &str) -> String {
    let cwd = repo.to_string_lossy();
    let lines = [
        format!(
            "{{\"cwd\":\"{cwd}\",\"sessionId\":\"{session_id}\",\"version\":\"1.2.3\",\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":[{{\"type\":\"text\",\"text\":\"hi\"}}]}},\"timestamp\":\"2026-11-04T12:00:00Z\"}}"
        ),
        format!(
            "{{\"cwd\":\"{cwd}\",\"sessionId\":\"{session_id}\",\"version\":\"1.2.3\",\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5\",\"content\":[{{\"type\":\"text\",\"text\":\"hello\"}}],\"usage\":{{\"input_tokens\":10,\"output_tokens\":5}}}},\"timestamp\":\"2026-11-04T12:00:05Z\"}}"
        ),
    ];
    lines.join("\n") + "\n"
}

#[test]
fn hook_session_end_marks_session_ended_and_queues_complete() {
    let home_dir = TempDir::new().unwrap();
    let home = home_dir.path().to_path_buf();
    let path = bin_path();
    let (_dir, repo) = init_repo(&home, &path);

    // The subcommand resolves and shows under the `hook` group.
    let help = starforge(&repo, &home, &path, &["--help"], None);
    assert!(help.status.success(), "help must exit 0");
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("hook"), "help must list hook:\n{help}");

    // Enable the repo (creates the spool layout) as a process.
    let enable = starforge(&repo, &home, &path, &["enable"], None);
    assert!(
        enable.status.success(),
        "enable failed: {}",
        String::from_utf8_lossy(&enable.stderr)
    );

    // Claude fixture transcript: <home>/.claude/projects/<slug>/<id>.jsonl.
    let session_id = "test-session-1";
    let store = home.join(".claude/projects/test-slug");
    std::fs::create_dir_all(&store).unwrap();
    let transcript = store.join(format!("{session_id}.jsonl"));
    std::fs::write(&transcript, claude_transcript(&repo, session_id)).unwrap();

    let payload = serde_json::json!({
        "session_id": session_id,
        "transcript_path": transcript.to_string_lossy(),
        "cwd": repo.to_string_lossy(),
        "hook_event_name": "SessionEnd",
        "reason": "exit",
    })
    .to_string();

    let out = starforge(
        &repo,
        &home,
        &path,
        &["hook", "session-end"],
        Some(&payload),
    );
    assert!(
        out.status.success(),
        "hook session-end must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The spool holds the session marked ended, with a queued `complete` op.
    // (No server is configured, so the best-effort upload only warns.)
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    let records = spool.cursor_records().unwrap();
    let ulid = records
        .values()
        .find_map(|r| (r.native_path == transcript.to_string_lossy()).then_some(r.ulid.clone()))
        .expect("ingest must spool the Claude session");
    let meta = spool.read_meta(&ulid).unwrap();
    assert!(meta.ended_at.is_some(), "session must be marked ended");
    let queued = starforge_cli::queue::read_queue(&spool).unwrap();
    assert!(
        queued
            .iter()
            .any(|e| e.op == starforge_cli::queue::QueueOp::Complete && e.ulid == ulid),
        "a complete op must be queued: {queued:?}"
    );
}

#[test]
fn hook_session_end_outside_repo_exits_0() {
    let home_dir = TempDir::new().unwrap();
    let home = home_dir.path().to_path_buf();
    let path = bin_path();
    let outside = TempDir::new().unwrap();

    let payload = serde_json::json!({
        "session_id": "nope",
        "transcript_path": "/nonexistent/nope.jsonl",
        "cwd": outside.path().to_string_lossy(),
        "hook_event_name": "SessionEnd",
        "reason": "other",
    })
    .to_string();

    let out = starforge(
        outside.path(),
        &home,
        &path,
        &["hook", "session-end"],
        Some(&payload),
    );
    assert!(
        out.status.success(),
        "outside a repo the hook must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The hook acts only on the repo containing the process's current
/// directory: a payload `cwd` pointing at another enabled repo must not
/// ingest that repo's sessions. A `cwd` inside the current repo works.
#[test]
fn hook_session_end_ignores_payload_cwd_outside_current_repo() {
    let home_dir = TempDir::new().unwrap();
    let home = home_dir.path().to_path_buf();
    let path = bin_path();
    let (_dir_a, repo_a) = init_repo(&home, &path);
    let (_dir_b, repo_b) = init_repo(&home, &path);

    for repo in [&repo_a, &repo_b] {
        let enable = starforge(repo, &home, &path, &["enable"], None);
        assert!(
            enable.status.success(),
            "enable failed: {}",
            String::from_utf8_lossy(&enable.stderr)
        );
    }

    // A Claude transcript whose cwd is repo_b.
    let session_id = "foreign-session";
    let store = home.join(".claude/projects/foreign-slug");
    std::fs::create_dir_all(&store).unwrap();
    let transcript = store.join(format!("{session_id}.jsonl"));
    std::fs::write(&transcript, claude_transcript(&repo_b, session_id)).unwrap();

    // Run from repo_a with a payload cwd pointing at repo_b.
    let payload = serde_json::json!({
        "session_id": session_id,
        "transcript_path": transcript.to_string_lossy(),
        "cwd": repo_b.to_string_lossy(),
        "hook_event_name": "SessionEnd",
        "reason": "exit",
    })
    .to_string();
    let out = starforge(
        &repo_a,
        &home,
        &path,
        &["hook", "session-end"],
        Some(&payload),
    );
    assert!(
        out.status.success(),
        "hook must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // repo_b's spool must have gained no cursor and no session from this call.
    let common_b = common_dir(&repo_b).unwrap();
    let spool_b = Spool::open(&common_b);
    let records_b = spool_b.cursor_records().unwrap();
    assert!(
        !records_b
            .values()
            .any(|r| r.native_path == transcript.to_string_lossy()),
        "foreign repo must not be ingested: {records_b:?}"
    );

    // And a payload cwd inside the current repo still works: run from
    // repo_b with its own cwd and the session is ingested there.
    let payload_b = serde_json::json!({
        "session_id": session_id,
        "transcript_path": transcript.to_string_lossy(),
        "cwd": repo_b.to_string_lossy(),
        "hook_event_name": "SessionEnd",
        "reason": "exit",
    })
    .to_string();
    let out = starforge(
        &repo_b,
        &home,
        &path,
        &["hook", "session-end"],
        Some(&payload_b),
    );
    assert!(
        out.status.success(),
        "hook must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records_b = spool_b.cursor_records().unwrap();
    assert!(
        records_b
            .values()
            .any(|r| r.native_path == transcript.to_string_lossy()),
        "cwd inside the current repo must ingest: {records_b:?}"
    );
}
