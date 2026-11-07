//! C5 hook tests (TDD RED first): install/remove with chaining, `enable`/
//! `disable`, and `prepare-commit-msg` trailer logic.
//!
//! Tempdir git repos (`git init`, local `user.email`/`user.name`); no network.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use common::hermetic_command;

use clap::Parser as _;
use starforge_cli::cli::Cli;
use starforge_cli::commands::hooks::{
    disable, enable, hook_post_commit, hook_pre_push, hook_prepare,
};
use starforge_cli::config::CliPaths;
use starforge_cli::git::common_dir;
use starforge_cli::hooks::{
    HOOKS, MANAGED_MARKER, SessionCandidate, append_trailers, dispatcher_body,
    existing_trailer_ulids, install_hook, remove_hook, select_links, trailer_line,
};
use starforge_cli::queue::{QueueOp, read_queue};
use starforge_cli::spool::{LinkConfidence, LinkSource, Spool};
use starforge_format::{
    CaptureInfo, DEFAULT_SEGMENT_CAP, Event, EventKind, RedactionSummary, RepoInfo, SessionMeta,
    ToolCall, ToolRef, Usage,
};
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

fn init_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let repo = dir.path().to_path_buf();
    git_ok(&repo, &["init"]);
    git_ok(&repo, &["config", "user.email", "t@t.t"]);
    git_ok(&repo, &["config", "user.name", "t"]);
    // Deterministic HEAD time so seeded event timestamps (2026-10-01) are
    // always after the previous commit.
    let out = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["commit", "--allow-empty", "-m", "init"])
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00+00:00")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00+00:00")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "init commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (dir, repo)
}
/// Isolated home for `enable`/`disable` (agent adapter hooks install under it).
fn test_paths() -> (TempDir, CliPaths) {
    let home = TempDir::new().unwrap();
    let paths = CliPaths::from_home(home.path().to_path_buf());
    (home, paths)
}
fn hooks_dir(repo: &Path) -> PathBuf {
    common_dir(repo).unwrap().join("hooks")
}

fn test_meta(ulid: &str, files: &[&str]) -> SessionMeta {
    SessionMeta {
        format: starforge_format::session::FORMAT_TAG.to_string(),
        id: ulid.parse().unwrap(),
        agent: Default::default(),
        models: Vec::new(),
        title: None,
        started_at: "2026-10-01T12:00:00Z".to_string(),
        ended_at: None,
        repo: RepoInfo::default(),
        parent_id: None,
        usage: Usage::default(),
        files_touched: files.iter().map(|s| s.to_string()).collect(),
        redaction: RedactionSummary::default(),
        capture: CaptureInfo::default(),
    }
}

/// Seed one session: `meta.json` (+ optional segment events) and a
/// `cursors.json` entry pointing at it.
fn seed_session(spool: &Spool, ulid: &str, files: &[&str], extra_events: &str) {
    spool.put_session(&test_meta(ulid, files)).unwrap();
    if !extra_events.is_empty() {
        spool
            .append_events(ulid, extra_events, DEFAULT_SEGMENT_CAP, &BTreeMap::new())
            .unwrap();
    }
    spool
        .write_cursor(
            "pi/test",
            ulid,
            starforge_capture::Cursor::start(),
            "/tmp/native.jsonl",
        )
        .unwrap();
}

fn tool_event(seq: u64, tool: &str, path: &str) -> String {
    let event = Event {
        v: 1,
        seq,
        ts: "2026-10-01T12:00:00Z".to_string(),
        kind: EventKind::ToolCall(ToolCall {
            tool: ToolRef {
                name: tool.to_string(),
                input: serde_json::json!({"path": path}),
            },
        }),
        extra: BTreeMap::new(),
    };
    serde_json::to_string(&event).unwrap()
}

/// `starforge` shim on PATH: the installed dispatcher calls `starforge`,
/// which here execs the freshly built test binary.
fn install_shim(dir: &Path) -> PathBuf {
    let shim_dir = dir.join("shim");
    std::fs::create_dir_all(&shim_dir).unwrap();
    let bin = env!("CARGO_BIN_EXE_starforge");
    let shim = shim_dir.join("starforge");
    std::fs::write(&shim, format!("#!/bin/sh\nexec \"{bin}\" \"$@\"\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    shim_dir
}

fn path_with(shim_dir: &Path) -> String {
    format!(
        "{}:{}",
        shim_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

// (a) enable installs three dispatchers with markers and prints them.

#[test]
fn enable_installs_three_marked_dispatchers_and_prints_them() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let (out, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0, "enable output: {out}");

    let dir = hooks_dir(&repo);
    for hook in HOOKS {
        let path = dir.join(hook);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains(MANAGED_MARKER),
            "{hook} dispatcher carries the marker"
        );
        assert!(
            body.contains("_hook-"),
            "{hook} dispatcher invokes a hidden _hook-* command"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert!(mode & 0o111 != 0, "{hook} dispatcher is executable");
        }
        assert!(
            out.lines()
                .any(|l| l.trim_end() == path.to_string_lossy() || l.contains(hook)),
            "enable prints {hook}; got:\n{out}"
        );
    }
}

// (b) pre-existing hook still runs; message gains exactly one trailer (exact).

#[test]
fn orig_hook_chains_and_exact_trailer_is_appended_on_real_commit() {
    let (_dir, repo) = init_repo();
    let (home, paths) = test_paths();
    let dir = hooks_dir(&repo);

    let orig = "#!/bin/sh\necho ORIG-LINE >> \"$1\"\n";
    let orig_path = dir.join("prepare-commit-msg");
    std::fs::write(&orig_path, orig).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&orig_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let (out, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0, "{out}");
    assert!(dir.join("prepare-commit-msg.starforge-orig").is_file());

    let ulid = "01J9KQXF1T3NP2R8A5B6C7D9E1";
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    seed_session(&spool, ulid, &["tracked.txt"], "");

    std::fs::write(repo.join("tracked.txt"), "hello\n").unwrap();
    git_ok(&repo, &["add", "tracked.txt"]);

    // PATH shim so the dispatcher reaches this build's binary.
    let shim_dir = install_shim(&repo);
    let status = hermetic_command("git", home.path())
        .arg("-C")
        .arg(&repo)
        .args(["commit", "-m", "add tracked"])
        .env("PATH", path_with(&shim_dir))
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    let body = git_ok(&repo, &["log", "-1", "--format=%B"]);
    assert!(body.contains("ORIG-LINE"), "orig hook ran; body:\n{body}");
    let trailers: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("Starforge-Session:"))
        .collect();
    assert_eq!(
        trailers,
        vec![format!("Starforge-Session: {ulid}").as_str()],
        "exactly one trailer; body:\n{body}"
    );

    let links = spool.links().unwrap();
    assert_eq!(links.len(), 1, "one link recorded: {links:?}");
    assert_eq!(links[0].ulid, ulid);
    assert_eq!(links[0].source, LinkSource::Trailer);
    assert_eq!(links[0].confidence, LinkConfidence::Exact);
    assert_eq!(
        links[0].commit,
        git_ok(&repo, &["rev-parse", "HEAD"]).trim(),
        "link points at the new commit"
    );
}

// (c) enable twice is idempotent.

#[test]
fn enable_twice_is_idempotent() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let (out1, code1) = enable(&repo, &paths, false);
    assert_eq!(code1, 0, "{out1}");
    let dir = hooks_dir(&repo);
    let before: Vec<(String, Vec<u8>)> = HOOKS
        .iter()
        .map(|h| (h.to_string(), std::fs::read(dir.join(h)).unwrap()))
        .collect();

    let (_out2, code2) = enable(&repo, &paths, false);
    assert_eq!(code2, 0);
    for (hook, bytes) in &before {
        assert_eq!(
            &std::fs::read(dir.join(hook)).unwrap(),
            bytes,
            "{hook} unchanged by second enable"
        );
    }
    assert!(
        !dir.join("prepare-commit-msg.starforge-orig.starforge-orig")
            .exists(),
        "no chained backup of a backup"
    );
}

// (d) disable restores byte-for-byte; second disable is a no-op.

#[test]
fn disable_restores_original_and_second_is_noop() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let dir = hooks_dir(&repo);
    let orig = "#!/bin/sh\necho ORIG-LINE >> \"$1\"\n";
    std::fs::write(dir.join("prepare-commit-msg"), orig).unwrap();

    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let (out, code) = disable(&repo, &paths, false);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        std::fs::read_to_string(dir.join("prepare-commit-msg")).unwrap(),
        orig,
        "original restored byte-for-byte"
    );
    for hook in HOOKS {
        assert!(
            !dir.join(format!("{hook}.starforge-orig")).exists(),
            "{hook} backup removed"
        );
    }

    let snapshot: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let (out2, code2) = disable(&repo, &paths, false);
    assert_eq!(code2, 0);
    assert!(out2.trim().is_empty(), "second disable prints nothing");
    let after: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(snapshot, after, "second disable changes nothing");
}

// (e) a session that touches nothing yields no trailer.

#[test]
fn untouched_session_yields_no_trailer() {
    let (_dir, repo) = init_repo();
    let (home, paths) = test_paths();
    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let ulid = "01J9KQXF1T3NP2R8A5B6C7D9E2";
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    seed_session(&spool, ulid, &[], "");

    std::fs::write(repo.join("other.txt"), "x\n").unwrap();
    git_ok(&repo, &["add", "other.txt"]);

    let msg = repo.join("COMMIT_MSG");
    std::fs::write(&msg, "subject\n").unwrap();
    let shim_dir = install_shim(&repo);
    let status = hermetic_command("sh", home.path())
        .arg(hooks_dir(&repo).join("prepare-commit-msg"))
        .arg(&msg)
        .current_dir(&repo)
        .env("PATH", path_with(&shim_dir))
        .output()
        .unwrap();
    assert!(status.status.success());
    let body = std::fs::read_to_string(&msg).unwrap();
    assert!(
        !body.contains("Starforge-Session:"),
        "no trailer for untouched session; body:\n{body}"
    );
}

// (f) hook failures never block the commit (warning on stderr).

#[test]
fn hook_failure_never_blocks_commit() {
    let (_dir, repo) = init_repo();
    let (home, paths) = test_paths();
    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let ulid = "01J9KQXF1T3NP2R8A5B6C7D9E3";
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    seed_session(&spool, ulid, &["tracked.txt"], "");

    // Replace the spool dir with a regular file: every spool write fails
    // regardless of uid, while the commit message file stays writable.
    std::fs::remove_dir_all(&spool.root).unwrap();
    std::fs::write(&spool.root, "not a dir").unwrap();

    std::fs::write(repo.join("tracked.txt"), "hello\n").unwrap();
    git_ok(&repo, &["add", "tracked.txt"]);

    let shim_dir = install_shim(&repo);
    let status = hermetic_command("git", home.path())
        .arg("-C")
        .arg(&repo)
        .args(["commit", "-m", "despite broken spool"])
        .env("PATH", path_with(&shim_dir))
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "commit must succeed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stderr = String::from_utf8_lossy(&status.stderr).to_string();
    assert!(
        stderr.to_lowercase().contains("warning"),
        "warning on stderr; got:\n{stderr}"
    );
}
// Heuristic (§7.2): a session WITH file-level data whose files do not overlap
// the staged files gets NO trailer.

#[test]
fn filed_session_without_overlap_gets_no_trailer() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let ulid = "01J9KQXF1T3NP2R8A5B6C7D9E4";
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let events = format!("{}\n", tool_event(0, "Edit", "/work/elsewhere.txt"));
    seed_session(&spool, ulid, &["elsewhere.txt"], &events);

    std::fs::write(repo.join("tracked.txt"), "hello\n").unwrap();
    git_ok(&repo, &["add", "tracked.txt"]);

    let msg = repo.join("COMMIT_MSG");
    std::fs::write(&msg, "subject\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg, &paths), 0);
    let body = std::fs::read_to_string(&msg).unwrap();
    assert!(
        !body.contains("Starforge-Session:"),
        "filed-but-unrelated session must not link; body:\n{body}"
    );

    assert_eq!(hook_post_commit(&repo, &paths), 0);
    assert!(spool.links().unwrap().is_empty(), "no link recorded");
}

// Heuristic (§7.2): a session with NO file-level data but activity since the
// last commit links with heuristic confidence.

#[test]
fn fileless_active_session_gets_heuristic_trailer() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let ulid = "01J9KQXF1T3NP2R8A5B6C7D9E6";
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    // Shell tool call: activity with no file paths.
    let events = format!("{}\n", tool_event(0, "Bash", "/work/nowhere.txt"));
    seed_session(&spool, ulid, &[], &events);

    std::fs::write(repo.join("tracked.txt"), "hello\n").unwrap();
    git_ok(&repo, &["add", "tracked.txt"]);

    let msg = repo.join("COMMIT_MSG");
    std::fs::write(&msg, "subject\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg, &paths), 0);
    let body = std::fs::read_to_string(&msg).unwrap();
    assert!(
        body.contains(&format!("Starforge-Session: {ulid}")),
        "heuristic trailer present; body:\n{body}"
    );

    assert_eq!(hook_post_commit(&repo, &paths), 0);
    let links = spool.links().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].confidence, LinkConfidence::Heuristic);
}

fn commit_with_msg(repo: &Path, msg: &Path, date: &str) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["commit", "--no-verify", "-F"])
        .arg(msg)
        .env("GIT_COMMITTER_DATE", date)
        .env("GIT_AUTHOR_DATE", date)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Real ingest (not a seeded spool): a fileless Pi session whose events are
// after the previous commit gets a heuristic trailer; with no new events it
// gets none; a new event after the next commit re-arms it.
#[test]
fn real_ingest_fileless_session_trailer_lifecycle() {
    let (_dir, repo) = init_repo();
    let (home, paths) = test_paths();
    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let cwd = repo.to_string_lossy().into_owned();
    let native = |ts: &str| {
        format!(
            "{{\"type\":\"session\",\"version\":3,\"id\":\"s1\",\"timestamp\":\"{ts}\",\"cwd\":\"{cwd}\",\"runtime\":{{\"version\":\"0.5.2\"}}}}\n{{\"type\":\"message\",\"id\":\"m1\",\"parentId\":null,\"timestamp\":\"{ts}\",\"runtime\":{{\"version\":\"0.5.2\"}},\"message\":{{\"role\":\"user\",\"content\":[{{\"type\":\"text\",\"text\":\"hi\"}}]}}}}\n"
        )
    };
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    let native_path = store.join("s.jsonl");
    // Events at 2026-06-01: after the init commit (2026-01-01), before
    // commit 1's committer date (2026-07-01).
    std::fs::write(&native_path, native("2026-06-01T12:00:00Z")).unwrap();

    let msg = repo.join("COMMIT_MSG");
    let spool = Spool::open(&common_dir(&repo).unwrap());

    // Commit 1: exactly one heuristic trailer.
    std::fs::write(repo.join("tracked.txt"), "one\n").unwrap();
    git_ok(&repo, &["add", "tracked.txt"]);
    std::fs::write(&msg, "subject\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg, &paths), 0);
    let body = std::fs::read_to_string(&msg).unwrap();
    assert_eq!(
        body.lines()
            .filter(|l| l.starts_with("Starforge-Session:"))
            .count(),
        1,
        "commit 1 trailer; body:\n{body}"
    );
    commit_with_msg(&repo, &msg, "2026-07-01T00:00:00+00:00");
    assert_eq!(hook_post_commit(&repo, &paths), 0);
    let links = spool.links().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].confidence, LinkConfidence::Heuristic);

    // Commit 2: no new events → no trailer.
    std::fs::write(repo.join("tracked.txt"), "two\n").unwrap();
    git_ok(&repo, &["add", "tracked.txt"]);
    std::fs::write(&msg, "subject\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg, &paths), 0);
    let body = std::fs::read_to_string(&msg).unwrap();
    assert!(
        !body.contains("Starforge-Session:"),
        "commit 2 must have no trailer; body:\n{body}"
    );
    commit_with_msg(&repo, &msg, "2026-08-01T00:00:00+00:00");
    assert_eq!(hook_post_commit(&repo, &paths), 0);
    assert_eq!(spool.links().unwrap().len(), 1);

    // Append an event after commit 2's date, then commit 3: trailer back.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&native_path)
        .unwrap()
        .write_all(native("2026-09-01T12:00:00Z").as_bytes())
        .unwrap();
    std::fs::write(repo.join("tracked.txt"), "three\n").unwrap();
    git_ok(&repo, &["add", "tracked.txt"]);
    std::fs::write(&msg, "subject\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg, &paths), 0);
    let body = std::fs::read_to_string(&msg).unwrap();
    assert_eq!(
        body.lines()
            .filter(|l| l.starts_with("Starforge-Session:"))
            .count(),
        1,
        "commit 3 trailer; body:\n{body}"
    );
    commit_with_msg(&repo, &msg, "2026-10-01T00:00:00+00:00");
    assert_eq!(hook_post_commit(&repo, &paths), 0);
    assert_eq!(spool.links().unwrap().len(), 2);
}

// pre-push enqueues uploads for sessions with unwritten segments.

#[test]
fn pre_push_enqueues_unwritten_segments_and_always_succeeds() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let ulid = "01J9KQXF1T3NP2R8A5B6C7D9E5";
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let events = format!("{}\n", tool_event(0, "Write", "new.txt"));
    seed_session(&spool, ulid, &["new.txt"], &events);

    assert_eq!(hook_pre_push(&repo, &paths), 0);
    let queue = read_queue(&spool).unwrap();
    assert!(
        queue
            .iter()
            .any(|e| e.op == QueueOp::Segment && e.ulid == ulid && e.segment == Some(0)),
        "segment 0 enqueued: {queue:?}"
    );

    // Second pre-push does not duplicate entries.
    assert_eq!(hook_pre_push(&repo, &paths), 0);
    let queue2 = read_queue(&spool).unwrap();
    assert_eq!(queue, queue2, "no duplicate queue entries");
}

/// The remote URL enqueued by `pre-push` is sanitized: embedded
/// credentials never reach the queue.
#[test]
fn pre_push_enqueues_sanitized_remote_url() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let (_, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);
    git_ok(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://user:token@example.com/o/r.git",
        ],
    );

    let ulid = "01J9KQXF1T3NP2R8A5B6C7D9E5";
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let events = format!("{}\n", tool_event(0, "Write", "new.txt"));
    seed_session(&spool, ulid, &["new.txt"], &events);

    assert_eq!(hook_pre_push(&repo, &paths), 0);
    let queue = read_queue(&spool).unwrap();
    let entry = queue
        .iter()
        .find(|e| e.op == QueueOp::Segment && e.ulid == ulid)
        .expect("segment enqueued");
    assert_eq!(entry.repo, "https://example.com/o/r.git");
    assert!(
        !format!("{:?}", queue).contains("token"),
        "no credentials in queue"
    );
}

// Pure trailer + selection helpers.

#[test]
fn trailer_helpers_dedupe_and_keep_order() {
    assert_eq!(trailer_line("ABC"), "Starforge-Session: ABC");
    assert_eq!(
        append_trailers("subject\n", &["U1".to_string(), "U2".to_string()]),
        "subject\nStarforge-Session: U1\nStarforge-Session: U2\n"
    );
    // Never duplicate a ULID already in the message.
    assert_eq!(
        append_trailers(
            "subject\nStarforge-Session: U1\n",
            &["U1".to_string(), "U2".to_string()]
        ),
        "subject\nStarforge-Session: U1\nStarforge-Session: U2\n"
    );
    assert_eq!(
        existing_trailer_ulids("a\nStarforge-Session: U9\n"),
        vec!["U9".to_string()]
    );
}

#[test]
fn select_links_exact_beats_heuristic_and_inactive_is_skipped() {
    let staged = vec!["src/main.rs".to_string()];
    let candidates = vec![
        SessionCandidate {
            ulid: "U-HEU-FILED".to_string(),
            files_touched: vec!["other.txt".to_string()],
            active: true,
        },
        SessionCandidate {
            ulid: "U-EXACT".to_string(),
            files_touched: vec!["src/main.rs".to_string()],
            active: true,
        },
        SessionCandidate {
            ulid: "U-HEU-FREE".to_string(),
            files_touched: Vec::new(),
            active: true,
        },
        SessionCandidate {
            ulid: "U-IDLE".to_string(),
            files_touched: Vec::new(),
            active: false,
        },
    ];
    let links = select_links(&staged, &candidates);
    // Filed-but-unrelated sessions get nothing; fileless-but-active ones get
    // the heuristic trailer. Stable order: sorted by ULID.
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].ulid, "U-EXACT");
    assert_eq!(links[0].confidence, LinkConfidence::Exact);
    assert_eq!(links[1].ulid, "U-HEU-FREE");
    assert_eq!(links[1].confidence, LinkConfidence::Heuristic);
}

#[test]
fn dispatcher_body_runs_orig_then_hidden_hook() {
    for hook in ["prepare-commit-msg", "post-commit", "pre-push"] {
        let body = dispatcher_body(hook);
        assert!(body.contains(MANAGED_MARKER), "{hook} has marker");
        assert!(body.contains(".starforge-orig"), "{hook} chains orig");
        assert!(
            body.contains(&format!("_hook-{hook}")),
            "{hook} calls hidden command"
        );
    }
    let prepare = dispatcher_body("prepare-commit-msg");
    let pre_push = dispatcher_body("pre-push");
    let post_commit = dispatcher_body("post-commit");
    assert!(
        prepare.contains("ORIG_STATUS") || prepare.contains("orig"),
        "prepare propagates the orig hook's exit status"
    );
    assert!(
        pre_push.contains("ORIG_STATUS") && pre_push.trim_end().ends_with("exit $ORIG_STATUS"),
        "pre-push propagates the orig hook's exit status: {pre_push:?}"
    );
    assert!(
        post_commit.trim_end().ends_with("exit 0") && !post_commit.contains("ORIG_STATUS"),
        "post-commit always exits 0: {post_commit:?}"
    );
}

#[test]
fn install_and_remove_round_trip_unit() {
    let dir = TempDir::new().unwrap();
    for hook in HOOKS {
        let written = install_hook(dir.path(), hook).unwrap();
        assert_eq!(written, dir.path().join("hooks").join(*hook));
        // Second install keeps the dispatcher byte-identical.
        let before = std::fs::read(&written).unwrap();
        install_hook(dir.path(), hook).unwrap();
        assert_eq!(std::fs::read(&written).unwrap(), before);
    }
    for hook in HOOKS {
        let changed = remove_hook(dir.path(), hook).unwrap();
        assert!(
            changed.iter().any(|p| p.ends_with(hook)),
            "remove reports {hook}: {changed:?}"
        );
        assert!(!dir.path().join("hooks").join(*hook).exists());
    }
    // Removing again changes nothing.
    for hook in HOOKS {
        assert!(remove_hook(dir.path(), hook).unwrap().is_empty());
    }
}

// I2: the pre-push dispatcher propagates a failing orig hook's exit status
// (the starforge step itself always exits 0 and never changes it).

#[test]
fn pre_push_dispatcher_propagates_orig_exit_status() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let common = common_dir(&repo).unwrap();
    let hooks_dir = common.join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();

    // Failing orig hook (executable bit only matters on unix).
    let orig = hooks_dir.join("pre-push.starforge-orig");
    std::fs::write(&orig, "#!/bin/sh\nexit 3\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&orig, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let dispatcher = install_hook(&common, "pre-push").unwrap();

    let shim_dir = install_shim(&repo);
    let run = |orig_present: bool| {
        if !orig_present {
            std::fs::remove_file(&orig).ok();
        }
        hermetic_command("sh", &paths.home)
            .arg(&dispatcher)
            .current_dir(&repo)
            .env("PATH", path_with(&shim_dir))
            .output()
            .expect("dispatcher runs")
    };
    #[cfg(unix)]
    assert_eq!(
        run(true).status.code(),
        Some(3),
        "failing orig pre-push hook fails the push"
    );
    assert_eq!(run(false).status.code(), Some(0), "no orig hook exits 0");
}

// Drift guard: every hook command `enable` installs must parse with the
// real CLI, so a renamed subcommand fails here instead of in users' shells.
#[test]
fn installed_hook_commands_parse_with_real_cli() {
    let (_dir, repo) = init_repo();
    let (_home, paths) = test_paths();
    let (_out, code) = enable(&repo, &paths, false);
    assert_eq!(code, 0);

    let mut commands: Vec<String> = Vec::new();

    // Claude SessionEnd hook commands from <home>/.claude/settings.json.
    let settings_path = paths.home.join(".claude").join("settings.json");
    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
    if let Some(hooks_obj) = settings.get("hooks").and_then(|v| v.as_object()) {
        for groups in hooks_obj.values() {
            for group in groups.as_array().into_iter().flatten() {
                for entry in group
                    .get("hooks")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                {
                    if let Some(cmd) = entry.get("command").and_then(|v| v.as_str()) {
                        commands.push(cmd.to_string());
                    }
                }
            }
        }
    }

    // Git dispatcher `starforge ...` lines (shell args like "$1" -> MSG).
    let dir = hooks_dir(&repo);
    for hook in HOOKS {
        let body = std::fs::read_to_string(dir.join(hook)).unwrap();
        for line in body.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("starforge ") {
                let rest = rest.replace("\"$1\"", "MSG").replace("$1", "MSG");
                commands.push(format!("starforge {rest}"));
            }
        }
    }

    assert!(
        commands.len() >= 4,
        "expected at least 4 installed hook commands, got {}: {commands:?}",
        commands.len()
    );
    for command in &commands {
        let argv: Vec<&str> = command.split_whitespace().collect();
        assert!(
            !argv.is_empty() && argv[0] == "starforge",
            "hook command must start with starforge: {command}"
        );
        assert!(
            Cli::try_parse_from(argv).is_ok(),
            "installed hook command must parse with the real CLI: {command}"
        );
    }
}
