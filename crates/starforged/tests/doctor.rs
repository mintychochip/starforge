//! `starforged doctor` integration tests (plan M5b task O3).
//!
//! Each test builds a real data directory with the `init` and `migrate`
//! CLI commands plus a user, a repository, and a Trail created through
//! the library, drops the in-process `Core` (so the search-index writer
//! is released), injects one fault, and runs the `doctor` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use starforged::admin::open_core;
use starforged::config::Config;
use starforged_core::accounts::CreateUser;
use starforged_core::permission::Visibility;
use starforged_core::repos::CreateRepo;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_starforged"))
}

struct Fixture {
    _tmp: tempfile::TempDir,
    config_path: PathBuf,
    config: Config,
    repo_id: i64,
    repo_path: PathBuf,
}

async fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("starforged.toml");
    let data_dir = tmp.path().join("data");
    let out = bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "init",
            "--data-dir",
            data_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let config = Config::load(&config_path).unwrap();
    let core = open_core(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
        .await
        .unwrap();
    let alice = core
        .create_user(CreateUser {
            handle: "alice".into(),
            password: Some("correct horse battery".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let repo = core
        .create_repo(
            &alice,
            &alice.handle,
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility: Visibility::Public,
                readme: false,
            },
        )
        .await
        .unwrap();
    core.create_trail(
        &alice,
        &alice.handle,
        &repo.name,
        "First trail",
        "Intent text",
    )
    .await
    .unwrap();
    // Run the queued IndexTrail job so the index matches the database.
    core.run_due_jobs().await.unwrap();
    let repo_path = core.repo_path(repo.id);
    let repo_id = repo.id;
    drop(core);
    Fixture {
        _tmp: tmp,
        config_path,
        config,
        repo_id,
        repo_path,
    }
}

fn doctor(fixture: &Fixture, fix: bool) -> Output {
    let mut cmd = bin();
    cmd.args(["--config", fixture.config_path.to_str().unwrap(), "doctor"]);
    if fix {
        cmd.arg("--fix");
    }
    cmd.output().unwrap()
}

fn doctor_with_path(fixture: &Fixture, path: &str) -> Output {
    bin()
        .args(["--config", fixture.config_path.to_str().unwrap(), "doctor"])
        .env("PATH", path)
        .output()
        .unwrap()
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn hook_path(fixture: &Fixture) -> PathBuf {
    fixture.repo_path.join("hooks").join("pre-receive")
}

fn blob_file(fixture: &Fixture, hash: &str) -> PathBuf {
    let shard = &hash[..2];
    fixture.config.blob_dir().join(shard).join(hash)
}

fn backdate(path: &Path, secs_ago: u64) {
    let when = std::time::UNIX_EPOCH
        + std::time::Duration::from_secs(starforged_db::now().max(0) as u64 - secs_ago);
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(when).unwrap();
}

#[tokio::test]
async fn healthy_data_dir_exits_zero() {
    let fixture = fixture().await;
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    for line in [
        "[OK] git version:",
        "[OK] ssh client:",
        "[OK] pg_dump:",
        "[OK] data directory permissions:",
        "[OK] repository hooks:",
        "[OK] stray repository directories:",
        "[OK] repository locks:",
        "[OK] orphan blobs:",
        "[OK] search index:",
        "[OK] migrations:",
    ] {
        assert!(text.contains(line), "missing {line} in:\n{text}");
    }
}

#[tokio::test]
async fn deleted_hook_fails() {
    let fixture = fixture().await;
    std::fs::remove_file(hook_path(&fixture)).unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("[FAIL] repository hooks:"), "{text}");
    assert!(
        text.contains(&format!(
            "repo {} is missing hooks/pre-receive",
            fixture.repo_id
        )),
        "{text}"
    );
}

#[tokio::test]
async fn missing_repo_directory_fails() {
    let fixture = fixture().await;
    std::fs::remove_dir_all(&fixture.repo_path).unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("[FAIL] repository hooks:"), "{text}");
    assert!(text.contains("missing its directory"), "{text}");
}

#[tokio::test]
async fn stray_repository_directory_warns() {
    let fixture = fixture().await;
    // Repo id 123 lives in shard 23; no such row exists.
    let stray = fixture.config.repos_dir().join("23").join("123.git");
    std::fs::create_dir_all(&stray).unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(
        text.contains("[WARN] stray repository directories:"),
        "{text}"
    );
    assert!(text.contains("123.git"), "{text}");
}

#[tokio::test]
async fn orphan_blob_file_warns() {
    let fixture = fixture().await;
    let hash = "ab".repeat(32);
    let path = blob_file(&fixture, &hash);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"orphan").unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("[WARN] orphan blobs:"), "{text}");
    assert!(text.contains("orphaned blob file"), "{text}");
}

#[tokio::test]
async fn old_zero_ref_blob_row_warns() {
    let fixture = fixture().await;
    let db = starforged_db::Db::connect(&fixture.config.database_url())
        .await
        .unwrap();
    let hash = "cd".repeat(32);
    let old = starforged_db::now() - 48 * 3600;
    sqlx::query(
        "INSERT INTO blobs (hash, size, refcount, backend_key, created_at) \
         VALUES ($1, $2, 0, $3, $4)",
    )
    .bind(&hash)
    .bind(4_i64)
    .bind(format!("blobs/{hash}"))
    .bind(old)
    .execute(db.pool())
    .await
    .unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("[WARN] orphan blobs:"), "{text}");
    assert!(text.contains("zero-ref"), "{text}");
}

#[cfg(unix)]
#[tokio::test]
async fn world_writable_data_dir_warns() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = fixture().await;
    std::fs::set_permissions(
        &fixture.config.storage.data_dir,
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(
        text.contains("[WARN] data directory permissions:") && text.contains("world-writable"),
        "{text}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn loose_config_permissions_warn() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = fixture().await;
    std::fs::set_permissions(&fixture.config_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(
        text.contains("[WARN] data directory permissions:"),
        "{text}"
    );
    assert!(text.contains("0600"), "{text}");
}

#[tokio::test]
async fn removed_index_warns() {
    let fixture = fixture().await;
    std::fs::remove_dir_all(fixture.config.index_dir()).unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("[WARN] search index:"), "{text}");
    assert!(text.contains("index rebuild"), "{text}");
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_blob_shard_is_not_followed_by_fix() {
    let fixture = fixture().await;
    // An outside directory holding an old file, reachable only through a
    // symlinked blob shard.
    let outside = fixture._tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let victim = outside.join("ffdeadbeef");
    std::fs::write(&victim, b"do not delete").unwrap();
    backdate(&victim, 2 * 3600);
    std::fs::create_dir_all(fixture.config.blob_dir()).unwrap();
    let shard = fixture.config.blob_dir().join("ff");
    std::os::unix::fs::symlink(&outside, &shard).unwrap();

    let _out = doctor(&fixture, true);
    assert!(
        victim.exists(),
        "--fix must not delete through a symlinked shard"
    );
    // And the plain (non-fix) run must not report it as an orphan either.
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert!(text.contains("[OK] orphan blobs:"), "{text}");
}

#[tokio::test]
async fn corrupt_index_is_not_mutated_by_doctor() {
    let fixture = fixture().await;
    // Replace the healthy index with garbage bytes, then snapshot the
    // directory; doctor and doctor --fix must leave it byte-identical.
    let index_dir = fixture.config.index_dir();
    std::fs::remove_dir_all(&index_dir).unwrap();
    std::fs::create_dir_all(&index_dir).unwrap();
    std::fs::write(index_dir.join("meta.json"), b"not a real index").unwrap();
    std::fs::write(index_dir.join("garbage.bin"), b"\x00\x01\x02").unwrap();

    let snapshot = || -> Vec<(PathBuf, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut stack = vec![index_dir.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    entries.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        entries.sort();
        entries
    };
    let before = snapshot();

    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("[WARN] search index:"), "{text}");
    assert!(text.contains("index rebuild"), "{text}");
    assert_eq!(snapshot(), before, "doctor mutated the index directory");

    let out = doctor(&fixture, true);
    assert!(out.status.code().is_some(), "doctor --fix did not run");
    assert_eq!(
        snapshot(),
        before,
        "doctor --fix mutated the index directory"
    );
}

#[tokio::test]
async fn old_git_fails() {
    let fixture = fixture().await;
    // A `git` shim that reports an ancient version; doctor only runs
    // `git --version`, so the shim is enough.
    let shim = fixture._tmp.path().join("shim");
    std::fs::create_dir_all(&shim).unwrap();
    let git = shim.join("git");
    std::fs::write(&git, "#!/bin/sh\necho 'git version 2.30.0'\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", shim.display(), std::env::var("PATH").unwrap());
    let out = doctor_with_path(&fixture, &path);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("[FAIL] git version:"), "{text}");
    assert!(text.contains("2.30"), "{text}");
}

#[tokio::test]
async fn fix_reinstalls_hook_and_removes_orphan_file() {
    let fixture = fixture().await;
    // Fault 1: the hook is gone.
    std::fs::remove_file(hook_path(&fixture)).unwrap();
    // Fault 2: an old orphaned blob file (backdated past the 1h fix age).
    let orphan_hash = "ef".repeat(32);
    let orphan = blob_file(&fixture, &orphan_hash);
    std::fs::create_dir_all(orphan.parent().unwrap()).unwrap();
    std::fs::write(&orphan, b"orphan").unwrap();
    backdate(&orphan, 2 * 3600);
    // A fresh zero-ref blob row + file: --fix must leave rows untouched.
    let kept_hash = "12".repeat(32);
    let kept = blob_file(&fixture, &kept_hash);
    std::fs::create_dir_all(kept.parent().unwrap()).unwrap();
    std::fs::write(&kept, b"kept").unwrap();
    let db = starforged_db::Db::connect(&fixture.config.database_url())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO blobs (hash, size, refcount, backend_key, created_at) \
         VALUES ($1, $2, 0, $3, $4)",
    )
    .bind(&kept_hash)
    .bind(4_i64)
    .bind(format!("blobs/{kept_hash}"))
    .bind(starforged_db::now())
    .execute(db.pool())
    .await
    .unwrap();
    db.pool().close().await;

    let out = doctor(&fixture, true);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("[OK] repository hooks:"), "{text}");
    assert!(text.contains("[OK] orphan blobs:"), "{text}");

    // The hook is back with the expected content.
    let hook = std::fs::read_to_string(hook_path(&fixture)).unwrap();
    assert!(
        starforged_git::init::is_expected_hook(&hook, "pre-receive"),
        "{hook}"
    );
    // The old orphan file is gone; the fresh blob row and its file survive.
    assert!(!orphan.exists());
    assert!(kept.exists(), "fix must not delete referenced blob files");
    let db = starforged_db::Db::connect(&fixture.config.database_url())
        .await
        .unwrap();
    let row: Option<String> = sqlx::query_scalar("SELECT hash FROM blobs WHERE hash = $1")
        .bind(&kept_hash)
        .fetch_optional(db.pool())
        .await
        .unwrap();
    assert_eq!(row.as_deref(), Some(kept_hash.as_str()));
}

/// A repository lock held by another process (a writer or backup in
/// flight) warns; doctor itself stays read-only and exits 2.
#[tokio::test]
async fn held_repository_lock_warns() {
    let fixture = fixture().await;
    let _held = starforged_core::repolock::RepoLock::exclusive(&fixture.repo_path).unwrap();
    let out = doctor(&fixture, false);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("[WARN] repository locks:"), "{text}");
}
