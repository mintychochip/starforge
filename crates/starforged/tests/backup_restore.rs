//! `starforged backup` integration tests (plan M5b task O1; restore is
//! task O2 and lands in this file later).
//!
//! Locks and consistency are pinned here together with the backup
//! contents: a backup holds each repository's exclusive lock, repository
//! writers (receive-pack, merges, imports, mirror fetches, maintenance,
//! purge) hold it shared, and the blob GC holds the blob-GC lock
//! exclusive while a backup holds it shared.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::time::Duration;

use common::pg_shims::install_pg_shims;
use starforged::admin::open_core;
use starforged::config::Config;
use starforged_core::accounts::CreateUser;
use starforged_core::jobs::Job;
use starforged_core::permission::Visibility;
use starforged_core::repolock::{BlobGcLock, RepoLock};
use starforged_core::repos::CreateRepo;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_starforged"))
}

struct Fixture {
    _tmp: tempfile::TempDir,
    config_path: PathBuf,
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
                readme: true,
            },
        )
        .await
        .unwrap();
    // One blob, so the backup has something to copy and count.
    let blob = core
        .config()
        .blob_store
        .put(b"starforge backup test blob")
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO blobs (hash, size, refcount, backend_key, created_at) \
         VALUES ($1, $2, 1, $3, $4)",
    )
    .bind(&blob.hash)
    .bind(blob.size as i64)
    .bind(&blob.key)
    .bind(starforged_db::now())
    .execute(core.db().pool())
    .await
    .unwrap();
    let repo_path = core.repo_path(repo.id);
    let repo_id = repo.id;
    drop(core);
    Fixture {
        _tmp: tmp,
        config_path,
        repo_id,
        repo_path,
    }
}

fn backup(fixture: &Fixture, target: &Path, extra: &[&str]) -> Output {
    let mut cmd = bin();
    cmd.args(["--config", fixture.config_path.to_str().unwrap(), "backup"]);
    cmd.arg(target.to_str().unwrap());
    cmd.args(extra);
    cmd.output().unwrap()
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `git fsck` must accept a copied repository.
fn assert_fsck_clean(repo: &Path) {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .arg("fsck")
        .arg("--strict")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git fsck failed for {}: {}\n{}",
        repo.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn backup_contains_manifest_database_repos_blobs_and_config() {
    let fixture = fixture().await;
    let target = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &target, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(target.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["format_version"].as_u64(), Some(1));
    assert_eq!(manifest["engine"].as_str(), Some("sqlite"));
    assert!(manifest["starforged_version"].is_string());
    assert!(manifest["created_at"].is_number());
    assert!(manifest["latest_migration"].is_number());
    assert_eq!(manifest["repositories"].as_u64(), Some(1));
    assert_eq!(manifest["blobs"].as_u64(), Some(1));

    // The database snapshot is a real, queryable SQLite database.
    let db_path = target.join("database").join("starforge.db");
    let db = starforged_db::Db::connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
        .await
        .unwrap();
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(users, 1);

    let copied = target
        .join("repos")
        .join(format!("{:02}", fixture.repo_id.rem_euclid(100)))
        .join(format!("{}.git", fixture.repo_id));
    assert!(
        copied.is_dir(),
        "repository was not copied: {}",
        combined(&out)
    );
    assert_fsck_clean(&copied);

    assert_eq!(count_files(&target.join("blobs")), 1, "blob was not copied");
    assert!(target.join("config").join("starforged.toml").is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&target), 0o700, "backup dir mode");
        assert_eq!(
            mode(&target.join("config").join("starforged.toml")),
            0o600,
            "config file mode"
        );
    }
}

fn count_files(dir: &Path) -> usize {
    let mut count = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                count += 1;
            }
        }
    }
    count
}

#[tokio::test]
async fn backup_refuses_a_non_empty_target() {
    let fixture = fixture().await;
    let target = fixture._tmp.path().join("backup");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep.txt"), b"not empty").unwrap();
    let out = backup(&fixture, &target, &[]);
    assert!(
        !out.status.success(),
        "backup into a non-empty dir succeeded"
    );
    assert!(
        combined(&out).contains("not empty"),
        "unexpected error: {}",
        combined(&out)
    );
    assert!(
        target.join("keep.txt").exists(),
        "the refusal must not touch the existing contents"
    );
}

#[tokio::test]
async fn backup_no_config_omits_the_config_copy() {
    let fixture = fixture().await;
    let target = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &target, &["--no-config"]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));
    assert!(
        !target.join("config").exists(),
        "the config copy must be omitted with --no-config"
    );
    assert!(target.join("manifest.json").is_file());
}

/// While a writer holds the repository's shared lock, the backup's
/// exclusive acquisition blocks; once the writer finishes, the backup
/// copies the post-write state and `git fsck` accepts it.
#[tokio::test]
async fn backup_waits_for_a_writer_and_copies_a_consistent_repository() {
    let fixture = fixture().await;
    let target = fixture._tmp.path().join("backup");

    // A writer in flight: the shared lock, exactly as receive-pack holds it.
    let writer = RepoLock::shared(&fixture.repo_path).unwrap();
    // Its write: a new branch ref inside the repository.
    let head = Command::new("git")
        .arg("--git-dir")
        .arg(&fixture.repo_path)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .unwrap();
    assert!(head.status.success());
    let head = String::from_utf8(head.stdout).unwrap();
    let head = head.trim();
    let write = Command::new("git")
        .arg("--git-dir")
        .arg(&fixture.repo_path)
        .arg("update-ref")
        .arg("refs/heads/topic")
        .arg(head)
        .output()
        .unwrap();
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );

    let (tx, rx) = mpsc::channel();
    let config_path = fixture.config_path.clone();
    let target_thread = target.clone();
    let backup_thread = std::thread::spawn(move || {
        let out = bin()
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "backup",
                target_thread.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let _ = tx.send(out.status.success());
    });

    // The backup must still be waiting for the exclusive lock.
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "the backup finished while a writer held the shared lock"
    );
    drop(writer);
    assert!(
        rx.recv_timeout(Duration::from_secs(60)).unwrap(),
        "the backup did not finish after the writer released the lock"
    );
    backup_thread.join().unwrap();

    let copied = target
        .join("repos")
        .join(format!("{:02}", fixture.repo_id.rem_euclid(100)))
        .join(format!("{}.git", fixture.repo_id));
    assert_fsck_clean(&copied);
    // The copy contains the post-write state: the branch the writer made.
    let topic = Command::new("git")
        .arg("--git-dir")
        .arg(&copied)
        .arg("rev-parse")
        .arg("--verify")
        .arg("refs/heads/topic")
        .output()
        .unwrap();
    assert!(
        topic.status.success(),
        "copied repository lacks the writer's branch: {}",
        String::from_utf8_lossy(&topic.stderr)
    );
}

/// The blob GC takes the blob-GC lock exclusive, so while a backup holds
/// it shared the sweep waits — and the blobs the snapshot references
/// survive until the backup is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blob_gc_waits_for_the_backups_shared_lock() {
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
    assert!(out.status.success());
    let config = Config::load(&config_path).unwrap();
    let core = open_core(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
        .await
        .unwrap();
    let blob = core
        .config()
        .blob_store
        .put(b"zero-ref blob that must survive the backup")
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO blobs (hash, size, refcount, backend_key, created_at) \
         VALUES ($1, $2, 0, $3, $4)",
    )
    .bind(&blob.hash)
    .bind(blob.size as i64)
    .bind(&blob.key)
    .bind(starforged_db::now())
    .execute(core.db().pool())
    .await
    .unwrap();
    let blob_file = config.blob_dir().join(&blob.hash[..2]).join(&blob.hash);
    assert!(blob_file.is_file());

    // A backup in flight holds the GC lock shared.
    let backup_guard = BlobGcLock::shared(&config.blob_dir()).unwrap();
    core.enqueue(&Job::HourlyCleanup).await.unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let worker = core.clone();
    tokio::spawn(async move {
        let _ = worker.run_due_jobs().await;
        let _ = tx.send(());
    });

    // The GC sweep must not run while the backup holds the shared lock.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut rx)
            .await
            .is_err(),
        "the blob GC ran while a backup held the GC lock shared"
    );
    assert!(
        blob_file.is_file(),
        "the blob was deleted under a running backup"
    );
    drop(backup_guard);
    tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .expect("the GC did not finish after the backup released the lock")
        .unwrap();
    assert!(
        !blob_file.exists(),
        "the zero-ref blob should be swept once the GC lock is free"
    );
}

/// A real push over HTTP racing a real backup: the copied repository is
/// either the pre-push or the post-push state, never a torn one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_during_a_http_push_contains_pre_or_post_state() {
    use common::*;
    let server = TestServer::start().await;
    let alice = server.user("alice").await;
    server.repo(&alice, "proj", Visibility::Public).await;
    let token = server
        .token(&alice, &[starforged_core::tokens::Scope::RepoWrite])
        .await;

    // The config file the backup CLI reads: the test server's own settings.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("starforged.toml");
    let config = Config {
        server: starforged::config::ServerConfig {
            http_addr: "127.0.0.1:3000".into(),
            base_url: server.base.clone(),
        },
        database: starforged::config::DatabaseConfig {
            url: server.db_url().to_owned(),
            auto_migrate: true,
        },
        storage: starforged::config::StorageConfig {
            data_dir: server.data.path().to_path_buf(),
            index_dir: PathBuf::from("index"),
        },
        security: starforged::config::SecurityConfig {
            secret_key: "0".repeat(64),
        },
        mail: starforged::config::MailConfig::default(),
        registration: starforged::config::RegistrationConfig::default(),
        sessions: starforged::config::SessionsConfig::default(),
        webhooks: starforged::config::WebhooksConfig::default(),
        git: starforged::config::GitConfig::default(),
        remotes: starforged::config::RemotesConfig::default(),
        github: starforged::config::GithubConfig::default(),
        oidc: starforged::config::OidcConfig::default(),
        limits: starforged::config::LimitsConfig::default(),
        ssh: starforged::config::SshConfig::default(),
        log: starforged::config::LogConfig::default(),
        metrics: starforged::config::MetricsConfig::default(),
    };
    std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

    let work_tmp = tempfile::tempdir().unwrap();
    let work = work_repo(work_tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &server.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
    let pre = git_ok(&work, &["rev-parse", "main"]).await;
    let pre = pre.trim().to_owned();

    // A second, larger push racing the backup.
    commit_files(&work, &[("data/blob.bin", &noise(8 * 1024 * 1024))], "big").await;
    let post = git_ok(&work, &["rev-parse", "main"]).await;
    let post = post.trim().to_owned();

    let target = tmp.path().join("backup");
    let backup_config = config_path.clone();
    let backup_target = target.clone();
    // On Postgres the backup shells out to pg_dump: run it through the
    // container shims (skip when no test container is available).
    let shims = if server.db_url().starts_with("postgres") {
        match install_pg_shims() {
            Some(shims) => Some(shims),
            None => return,
        }
    } else {
        None
    };
    let path_env = shims.as_ref().map(|shims| shims.prepended_path());
    let (tx, rx) = mpsc::channel();
    let backup_thread = std::thread::spawn(move || {
        let mut cmd = bin();
        cmd.args([
            "--config",
            backup_config.to_str().unwrap(),
            "backup",
            backup_target.to_str().unwrap(),
        ]);
        if let Some(path) = &path_env {
            cmd.env("PATH", path);
        }
        let out = cmd.output().unwrap();
        let _ = tx.send(out);
    });
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &server.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
    let out = rx.recv_timeout(Duration::from_secs(120)).unwrap();
    backup_thread.join().unwrap();
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    let repos = target.join("repos");
    let copied = std::fs::read_dir(&repos)
        .and_then(|shards| {
            let shard = shards.flatten().next().unwrap().path();
            std::fs::read_dir(shard).map(|mut entries| entries.next().unwrap().unwrap().path())
        })
        .unwrap();
    assert_fsck_clean(&copied);
    let copied_main = Command::new("git")
        .arg("--git-dir")
        .arg(&copied)
        .arg("rev-parse")
        .arg("main")
        .output()
        .unwrap();
    let copied_main = String::from_utf8(copied_main.stdout).unwrap();
    let copied_main = copied_main.trim();
    assert!(
        copied_main == pre || copied_main == post,
        "copied HEAD {copied_main} is neither the pre-push {pre} nor the post-push {post} state"
    );
}

/// Postgres: the backup writes `starforged.pgdump` through the container
/// shims. Skips (with a printed reason) when no test Postgres/container
/// engine is present — never silently.
#[tokio::test]
async fn postgres_backup_writes_a_pgdump_through_the_shims() {
    if std::env::var("STARFORGE_TEST_PG_URL").is_err() {
        println!("SKIP: STARFORGE_TEST_PG_URL is not set; Postgres backup test skipped");
        return;
    }
    let Some(shims) = install_pg_shims() else {
        return;
    };
    let test_db = starforged_db::testing::TestDb::new().await;

    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("starforged.toml");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config_text = format!(
        "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"http://127.0.0.1:3000\"\n\
         [database]\nurl = \"{}\"\n\
         [storage]\ndata_dir = \"{}\"\n\
         [security]\nsecret_key = \"{}\"\n",
        test_db.url,
        data_dir.display(),
        "0".repeat(64)
    );
    std::fs::write(&config_path, &config_text).unwrap();
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
                readme: true,
            },
        )
        .await
        .unwrap();
    let repo_id = repo.id;
    drop(core);

    let target = tmp.path().join("backup");
    let out = bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "backup",
            target.to_str().unwrap(),
        ])
        .env("PATH", shims.prepended_path())
        .output()
        .unwrap();
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    let pgdump = target.join("database").join("starforge.pgdump");
    let bytes = std::fs::read(&pgdump).unwrap();
    assert!(
        bytes.starts_with(b"PGD"),
        "starforge.pgdump is not a pg_dump custom-format archive ({} bytes)",
        bytes.len()
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(target.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["engine"].as_str(), Some("postgres"));
    assert_eq!(manifest["repositories"].as_u64(), Some(1));
    let copied = target
        .join("repos")
        .join(format!("{:02}", repo_id.rem_euclid(100)))
        .join(format!("{}.git", repo_id));
    assert!(copied.is_dir());
    assert_fsck_clean(&copied);
}
