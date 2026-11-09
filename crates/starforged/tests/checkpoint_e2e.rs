//! End-to-end checkpoint flow: hooks create a checkpoint, `starforge sync`
//! pushes the ref and metadata with a `session:upload` token, and a fresh
//! clone rewinds to it.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;
use serde_json::{Value, json};
use starforge_cli::spool::Spool;
use starforge_format::SessionMeta;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

/// The workspace `starforge` binary, building it once when a targeted test
/// run did not build the CLI package.
fn starforge_bin() -> PathBuf {
    // Always run the incremental build: nextest builds test targets, not this
    // binary, so a stale `starforge` would silently exercise old code.
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "starforge-cli", "--bin", "starforge"])
        .status()
        .expect("cargo runs");
    assert!(status.success(), "building starforge failed");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut path = std::env::current_exe().unwrap();
            path.pop(); // deps
            path.pop(); // debug
            path
        });
    target.join("starforge")
}

fn run_cli(bin: &Path, cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin);
    cmd.current_dir(cwd).args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME");
    cmd.output().expect("starforge runs")
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checkpoint_hooks_sync_and_rewind_end_to_end() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s
        .token(&alice, &[Scope::RepoRead, Scope::SessionUpload])
        .await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;

    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let bin = starforge_bin();
    let path_env = format!(
        "{}:{}",
        bin.parent().unwrap().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let envs = [
        ("PATH", path_env.as_str()),
        ("STARFORGE_HOME", home.to_str().unwrap()),
        ("HOME", home.to_str().unwrap()),
        ("STARFORGE_TOKEN", upload.as_str()),
    ];

    // Point the CLI at the server and install the real hooks.
    git_ok(&work, &["config", "user.name", "Test"]).await;
    git_ok(&work, &["config", "user.email", "test@example.com"]).await;
    git_ok(&work, &["config", "starforge.server", &s.base]).await;
    git_ok(&work, &["config", "starforge.repo", "alice/proj"]).await;
    git_ok(
        &work,
        &["remote", "add", "origin", &s.git_url("alice", "proj", None)],
    )
    .await;
    let enabled = run_cli(&bin, &work, &["enable"], &envs);
    assert_ok(&enabled, "starforge enable");

    // Seed the spool with a session that touched a.txt. The prepare hook
    // links it to the staged file and writes the trailer.
    let common = starforge_cli::git::common_dir(&work).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let meta: SessionMeta = serde_json::from_value(json!({
        "format": "starforge.session/v1",
        "id": ULID,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": [],
        "title": "e2e checkpoint",
        "started_at": "2026-11-08T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": ["a.txt"],
        "redaction": {"fingerprint": "fp-e2e", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true}
    }))
    .unwrap();
    spool.put_session(&meta).unwrap();

    // The installed prepare/post-commit hooks run through the real binary.
    std::fs::write(work.join("a.txt"), "two\n").unwrap();
    git_ok(&work, &["add", "a.txt"]).await;
    let commit = Command::new("git")
        .arg("-C")
        .arg(&work)
        .args(["commit", "-m", "change a"])
        .envs(envs.iter().copied())
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_ok(&commit, "git commit with installed hooks");
    let message = git_ok(&work, &["log", "-1", "--format=%B"]).await;
    assert!(
        message.contains(&format!("Starforge-Session: {ULID}")),
        "prepare hook wrote the trailer: {message}"
    );
    let checkpoints = spool.read_checkpoints(ULID).unwrap();
    assert_eq!(checkpoints.len(), 1, "post-commit created one checkpoint");
    assert_eq!(checkpoints[0].source, "commit");

    // Sync uploads the session metadata, the checkpoint ref, and its row.
    let synced = run_cli(&bin, &work, &["sync"], &envs);
    assert_ok(&synced, "starforge sync");

    let client = reqwest::Client::new();
    let list: Value = client
        .get(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/checkpoints"
        )))
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["n"], 1);
    assert_eq!(list[0]["label"], "change a");
    let checkpoint_commit = list[0]["commit"].as_str().unwrap().to_owned();

    // The checkpoint commit is not a user commit: the push scan must not
    // record a trailer link from the session to it.
    for _ in 0..20 {
        let links: Value = client
            .get(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}/links")))
            .bearer_auth(&upload)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            !links.to_string().contains(&checkpoint_commit),
            "checkpoint commit must not be a session link: {links}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // A later commit makes the clone differ from the checkpoint.
    std::fs::write(work.join("a.txt"), "three\n").unwrap();
    git_ok(&work, &["add", "a.txt"]).await;
    // `--no-verify` does not skip prepare-commit-msg; disable hooks for this
    // commit so the test does not re-run capture/checkpoint work.
    git_ok(
        &work,
        &["-c", "core.hooksPath=/dev/null", "commit", "-m", "second"],
    )
    .await;
    let write_url = s.git_url("alice", "proj", Some(&write));
    git_ok(&work, &["push", "--no-verify", "-q", &write_url, "main"]).await;

    // A fresh clone starts at "three"; rewind restores the checkpoint tree.
    let clone = tmp.path().join("clone");
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "proj", Some(&write)),
            clone.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(clone.join("a.txt")).unwrap(),
        "three\n"
    );
    let rewound = run_cli(&bin, &clone, &["rewind", ULID, "--checkpoint", "1"], &envs);
    assert_ok(&rewound, "starforge rewind");
    assert_eq!(
        std::fs::read_to_string(clone.join("a.txt")).unwrap(),
        "two\n"
    );
    let stdout = String::from_utf8_lossy(&rewound.stdout);
    assert!(stdout.contains("restored checkpoint 1"), "{stdout}");

    // The server ref and the local checkpoint agree.
    let ref_sha = git_ok(
        &clone,
        &["rev-parse", &format!("refs/starforge/checkpoints/{ULID}/1")],
    )
    .await
    .trim()
    .to_owned();
    assert_eq!(ref_sha, checkpoint_commit);
}
