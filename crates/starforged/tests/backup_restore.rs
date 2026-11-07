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

/// An existing empty target is accepted but tightened to `0700` (D3): the
/// backup holds `secret_key`.
#[cfg(unix)]
#[tokio::test]
async fn backup_sets_0700_on_a_preexisting_empty_target() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = fixture().await;
    let target = fixture._tmp.path().join("backup");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = backup(&fixture, &target, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o700,
        "a pre-existing empty target must be tightened to 0700"
    );
}

/// A symlink under a repository directory makes the backup fail (matching
/// restore's `check_tree`): the error names the path and no manifest is
/// written, so a backup never reports success unless restore accepts it.
#[cfg(unix)]
#[tokio::test]
async fn backup_refuses_a_symlink_under_a_repository() {
    let fixture = fixture().await;
    let link = fixture.repo_path.join("sneaky-link");
    std::os::unix::fs::symlink("HEAD", &link).unwrap();
    let target = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &target, &[]);
    assert!(!out.status.success(), "backup over a symlink succeeded");
    let text = combined(&out);
    assert!(
        text.contains("sneaky-link"),
        "the error must name the offending path: {text}"
    );
    assert!(
        !target.join("manifest.json").exists(),
        "a refused backup must not write a manifest"
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
        sandbox: starforged_core::sandboxes::SandboxConfig::default(),
        ci: starforged_core::ci_usage::CiConfig::default(),
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

/// Runs `starforged restore <backup>` with the plan's interface:
/// `--config` names the target config, `--data-dir` the target data
/// directory (required when `--config` is absent).
fn restore_cmd(
    backup: &Path,
    config: Option<&Path>,
    data_dir: Option<&Path>,
    path_env: Option<&str>,
) -> Output {
    let mut cmd = bin();
    cmd.arg("restore").arg(backup);
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }
    if let Some(data_dir) = data_dir {
        cmd.arg("--data-dir").arg(data_dir);
    }
    if let Some(path) = path_env {
        cmd.env("PATH", path);
    }
    cmd.output().unwrap()
}

/// A minimal SQLite target config for restore: `database.url` empty
/// (SQLite at `<data_dir>/starforge.db`) and the given `secret_key`
/// (the same key the backup was taken under, so sealed secrets open).
fn write_sqlite_config(path: &Path, data_dir: &Path, secret_key: &str) {
    let text = format!(
        "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"http://127.0.0.1:3000\"\n\
         [storage]\ndata_dir = \"{}\"\n\
         [security]\nsecret_key = \"{secret_key}\"\n",
        data_dir.display()
    );
    std::fs::write(path, text).unwrap();
}

/// A webhook receiver: captures every delivery's signature header and
/// exact body, and answers 200. The restored server delivers to it
/// after a push, proving its sealed webhook secret still opens under
/// the restored `secret_key` (only the secret holder can sign).
type HookHits = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

async fn spawn_hook_sink() -> (String, HookHits) {
    let hits: HookHits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let inner = hits.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let inner = inner.clone();
                async move {
                    let signature = headers
                        .get("x-starforge-signature-256")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    inner.lock().unwrap().push((signature, body.to_vec()));
                    (axum::http::StatusCode::OK, "ok".to_string())
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    (format!("http://{addr}/hook"), hits)
}

/// The SQLite round trip: a populated server (repository with a push,
/// a Trail, an org, a webhook, a sealed mirror credential, and a
/// completed session with blobs) is backed up, restored into a fresh
/// data dir, and served again — clone, session viewer, Trail page,
/// login with the same password, and both sealed secrets all work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_restore_round_trip_serves_the_same_instance() {
    use common::*;
    use serde_json::json;
    use starforged_core::orgs::NewOrgInput;
    use starforged_core::tokens::Scope;

    const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    let s = TestServer::start().await;
    // SQLite-specific: under STARFORGE_TEST_PG_URL the TestServer runs
    // on Postgres and the backup would need pg_dump. The Postgres
    // round trip has its own test below.
    if s.db_url().starts_with("postgres") {
        println!("SKIP: SQLite restore round trip skipped on Postgres");
        return;
    }
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;

    let work_tmp = tempfile::tempdir().unwrap();
    let work = work_repo(work_tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;

    let trail = s
        .core
        .create_trail(&alice, "alice", "proj", "Restore trail", "body text")
        .await
        .unwrap();
    assert_eq!(trail.number, 1);
    s.core
        .create_org(
            &alice,
            NewOrgInput {
                handle: "acme".into(),
                display_name: "Acme".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    let (hook_url, hook_hits) = spawn_hook_sink().await;
    let (_hook, webhook_secret) = s
        .core
        .create_webhook(&alice, "alice", "proj", &hook_url, &["push".to_owned()])
        .await
        .unwrap();
    // A mirror credential sealed under the server `secret_key`.
    let key_bytes: [u8; 32] = hex::decode("0".repeat(64)).unwrap().try_into().unwrap();
    let sealed_mirror =
        starforged_core::crypto::CredentialBox::new(&key_bytes).seal(b"mirror-password");
    starforged_db::remotes::insert(
        s.core.db(),
        &starforged_db::remotes::NewRemote {
            repo_id: repo.id,
            role: "pull",
            url: "https://example.test/upstream.git",
            auth: "https",
            username: "mirror-user",
            sealed_secret: Some(&sealed_mirror),
            ssh_public_key: None,
            created_by: alice.id,
        },
    )
    .await
    .unwrap();

    // A completed session with one blob segment, through the API.
    let client = reqwest::Client::new();
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let meta = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}")))
        .bearer_auth(&upload)
        .json(&json!({
            "format": "starforge.session/v1",
            "id": ULID,
            "agent": {"name": "claude-code", "version": "1.0"},
            "models": ["opus"],
            "title": "restore session",
            "started_at": "2026-11-04T00:00:00Z",
            "ended_at": null,
            "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "parent_id": null,
            "usage": {"input": 1, "output": 2, "cache_read": 3, "cache_write": 4, "reasoning": 5},
            "files_touched": ["README.md"],
            "redaction": {"fingerprint": "fp", "counts": {}},
            "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
        }))
        .send()
        .await
        .unwrap();
    assert!(meta.status().is_success(), "{}", meta.status());
    let jsonl = "{\"v\":1,\"seq\":0,\"ts\":\"2026-11-04T00:00:00Z\",\"kind\":\"user_message\",\"text\":\"hello restore\"}\n";
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    let segment = client
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/segments/0"
        )))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(segment.status(), 200);
    let complete = client
        .post(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/complete"
        )))
        .bearer_auth(&upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(complete.status(), 200);

    // Back up through the CLI, using a config file naming this server.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("starforged.toml");
    let config_text = format!(
        "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"{}\"\n\
         [database]\nurl = \"{}\"\n\
         [storage]\ndata_dir = \"{}\"\n\
         [security]\nsecret_key = \"{}\"\n",
        s.base,
        s.db_url(),
        s.data.path().display(),
        "0".repeat(64)
    );
    std::fs::write(&config_path, &config_text).unwrap();
    let backup_dir = tmp.path().join("backup");
    let out = bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "backup",
            backup_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    // Restore into a fresh data dir under a fresh target config.
    let fresh_data = tmp.path().join("restored-data");
    let target_config = tmp.path().join("restored.toml");
    write_sqlite_config(&target_config, &fresh_data, &"0".repeat(64));
    let out = restore_cmd(&backup_dir, Some(&target_config), None, None);
    assert!(out.status.success(), "restore failed: {}", combined(&out));
    assert!(
        fresh_data.join("starforge.db").is_file(),
        "the database file was not restored"
    );

    // The restore enqueued exactly one search-index rebuild, and the
    // restored database holds the same schema state.
    let restored_db = starforged_db::Db::connect(&format!(
        "sqlite://{}?mode=rwc",
        fresh_data.join("starforge.db").display()
    ))
    .await
    .unwrap();
    let rebuilds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'rebuild_index' AND state = 'queued'",
    )
    .fetch_one(restored_db.pool())
    .await
    .unwrap();
    assert_eq!(rebuilds, 1, "restore must enqueue one index rebuild");

    // Serve the restored instance and exercise it end to end.
    let restored = TestServer::start_with(|config| {
        config.storage.data_dir = fresh_data.clone();
        config.database.url = String::new();
        // The delivery SSRF gate denies loopback unless the test-only
        // config flag is set; the in-process receiver needs it.
        config.webhooks.allow_loopback = true;
    })
    .await;

    // git clone works against the restored repositories.
    let clone_tmp = tempfile::tempdir().unwrap();
    git_ok(
        clone_tmp.path(),
        &[
            "clone",
            "-q",
            &restored.git_url("alice", "proj", None),
            "clone",
        ],
    )
    .await;
    let readme = std::fs::read_to_string(clone_tmp.path().join("clone").join("README.md")).unwrap();
    assert_eq!(readme, "# proj\n");

    // Login works with the same password.
    let (browser, _csrf) = restored.login("alice").await;
    let dashboard = get_text(&browser, &restored.url("/")).await;
    assert!(dashboard.contains("Sign out"), "{dashboard}");

    // The session viewer renders (its events come from the blobs).
    // The session is unpublished on a public repo, so it is viewed as
    // its owner (anonymous viewers 404 by the §6.4 read rule).
    let session_page = get_text(
        &browser,
        &restored.url(&format!("/alice/proj/sessions/{ULID}")),
    )
    .await;
    assert!(session_page.contains("restore session"), "{session_page}");
    assert!(session_page.contains("hello restore"), "{session_page}");

    // The Trail page renders.
    let viewer = restored.browser();
    let trail_page = get_text(&viewer, &restored.url("/alice/proj/trails/1")).await;
    assert!(trail_page.contains("Restore trail"), "{trail_page}");

    // The org survived.
    let org_page = get_text(&viewer, &restored.url("/acme")).await;
    assert!(org_page.contains("Acme"), "{org_page}");

    // The sealed webhook secret opens under the restored secret_key:
    // a push to the restored server is delivered signed with it. The
    // secret is never stored in clear (the row still holds `v1:` AEAD).
    let hooks = starforged_db::checks::webhooks_of_repo(restored.core.db(), repo.id)
        .await
        .unwrap();
    assert_eq!(hooks.len(), 1);
    assert!(hooks[0].secret_encrypted.starts_with("v1:"));
    assert_ne!(hooks[0].secret_encrypted, webhook_secret);
    commit_files(&work, &[("second.txt", b"second\n")], "second commit").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &restored.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
    restored.core.run_due_jobs().await.unwrap();
    let first = hook_hits.lock().unwrap().first().cloned();
    let (signature, body) =
        first.expect("no webhook delivery after the push to the restored server");
    assert_eq!(
        signature,
        format!(
            "sha256={}",
            starforged_core::webhooks::hmac_sha256_hex(&webhook_secret, &body)
        ),
        "delivery must be signed with the restored webhook secret"
    );

    // The sealed mirror credential opens too.
    let remote = starforged_db::remotes::by_repo_role(restored.core.db(), repo.id, "pull")
        .await
        .unwrap()
        .unwrap();
    let opened = starforged_core::crypto::CredentialBox::new(&key_bytes)
        .open(remote.sealed_secret.as_deref().unwrap())
        .unwrap();
    assert_eq!(opened, b"mirror-password");
}

/// Restore refuses a non-empty target data directory and leaves its
/// contents untouched.
#[tokio::test]
async fn restore_refuses_a_non_empty_data_dir() {
    let fixture = fixture().await;
    let backup_dir = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &backup_dir, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    let fresh_data = fixture._tmp.path().join("restored-data");
    std::fs::create_dir_all(&fresh_data).unwrap();
    std::fs::write(fresh_data.join("keep.txt"), b"not empty").unwrap();
    let target_config = fixture._tmp.path().join("restored.toml");
    write_sqlite_config(&target_config, &fresh_data, &"0".repeat(64));

    let out = restore_cmd(&backup_dir, Some(&target_config), None, None);
    assert!(
        !out.status.success(),
        "restore into a non-empty data dir succeeded"
    );
    assert!(
        combined(&out).contains("not empty"),
        "unexpected error: {}",
        combined(&out)
    );
    assert_eq!(
        std::fs::read(fresh_data.join("keep.txt")).unwrap(),
        b"not empty",
        "the refusal must not touch the existing contents"
    );
}

/// Restore refuses a manifest whose schema is newer than the binary
/// knows, before writing anything.
#[tokio::test]
async fn restore_refuses_a_newer_schema_manifest() {
    let fixture = fixture().await;
    let backup_dir = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &backup_dir, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    let manifest_path = backup_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["latest_migration"] = serde_json::json!(999_999);
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let fresh_data = fixture._tmp.path().join("restored-data");
    let target_config = fixture._tmp.path().join("restored.toml");
    write_sqlite_config(&target_config, &fresh_data, &"0".repeat(64));
    let out = restore_cmd(&backup_dir, Some(&target_config), None, None);
    assert!(
        !out.status.success(),
        "restore of a newer-schema backup succeeded"
    );
    assert!(
        combined(&out).contains("newer"),
        "unexpected error: {}",
        combined(&out)
    );
    assert!(
        !fresh_data.join("starforge.db").exists(),
        "the refusal must happen before the database is written"
    );
}

/// Restore refuses a manifest format version this binary does not
/// understand.
#[tokio::test]
async fn restore_refuses_an_unknown_format_version() {
    let fixture = fixture().await;
    let backup_dir = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &backup_dir, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    let manifest_path = backup_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["format_version"] = serde_json::json!(99);
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let fresh_data = fixture._tmp.path().join("restored-data");
    let target_config = fixture._tmp.path().join("restored.toml");
    write_sqlite_config(&target_config, &fresh_data, &"0".repeat(64));
    let out = restore_cmd(&backup_dir, Some(&target_config), None, None);
    assert!(
        !out.status.success(),
        "restore of a format-version-99 backup succeeded"
    );
    assert!(
        combined(&out).contains("format version"),
        "unexpected error: {}",
        combined(&out)
    );
}

/// Without `--config`, restore uses the backup's config copy with
/// `storage.data_dir` from `--data-dir`, and writes the adjusted
/// config into the restored data directory (`0600`).
#[tokio::test]
async fn restore_without_config_uses_the_backup_config() {
    let fixture = fixture().await;
    let backup_dir = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &backup_dir, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    let fresh_data = fixture._tmp.path().join("restored-data");
    let out = restore_cmd(&backup_dir, None, Some(&fresh_data), None);
    assert!(out.status.success(), "restore failed: {}", combined(&out));

    let written = fresh_data.join("starforged.toml");
    assert!(written.is_file(), "the adjusted config was not written");
    let text = std::fs::read_to_string(&written).unwrap();
    assert!(
        text.contains(&fresh_data.display().to_string()),
        "the written config must name the new data dir:\n{text}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&written).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "written config mode");
    }

    let db = starforged_db::Db::connect(&format!(
        "sqlite://{}?mode=rwc",
        fresh_data.join("starforge.db").display()
    ))
    .await
    .unwrap();
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(users, 1, "the restored database lost its rows");
    let rebuilds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'rebuild_index' AND state = 'queued'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(rebuilds, 1, "restore must enqueue one index rebuild");
}

/// Postgres round trip through the container shims: backup, restore
/// into a fresh (empty) database, and the restored instance's rows
/// are intact. A second restore into the now-populated database is
/// refused. Skips (with a printed reason) when no test
/// Postgres/container engine is present — never silently.
#[tokio::test]
async fn postgres_restore_round_trip_through_the_shims() {
    if std::env::var("STARFORGE_TEST_PG_URL").is_err() {
        println!("SKIP: STARFORGE_TEST_PG_URL is not set; Postgres restore test skipped");
        return;
    }
    let Some(shims) = install_pg_shims() else {
        return;
    };

    let source_db = starforged_db::testing::TestDb::new().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("starforged.toml");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config_text = format!(
        "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"http://127.0.0.1:3000\"\n\
         [database]\nurl = \"{}\"\n\
         [storage]\ndata_dir = \"{}\"\n\
         [security]\nsecret_key = \"{}\"\n",
        source_db.url,
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

    let backup_dir = tmp.path().join("backup");
    let out = bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "backup",
            backup_dir.to_str().unwrap(),
        ])
        .env("PATH", shims.prepended_path())
        .output()
        .unwrap();
    assert!(out.status.success(), "backup failed: {}", combined(&out));

    // Restore into a fresh, empty Postgres database (created but never
    // migrated: `TestDb::new` would hand back a populated one, which
    // restore rightfully refuses).
    let target_db_url = starforged_db::testing::create_empty_pg_database().await;
    let fresh_data = tmp.path().join("restored-data");
    let target_config = tmp.path().join("restored.toml");
    let target_text = format!(
        "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"http://127.0.0.1:3000\"\n\
         [database]\nurl = \"{}\"\n\
         [storage]\ndata_dir = \"{}\"\n\
         [security]\nsecret_key = \"{}\"\n",
        target_db_url,
        fresh_data.display(),
        "0".repeat(64)
    );
    std::fs::write(&target_config, &target_text).unwrap();
    let out = restore_cmd(
        &backup_dir,
        Some(&target_config),
        None,
        Some(&shims.prepended_path()),
    );
    assert!(out.status.success(), "restore failed: {}", combined(&out));

    // The restored database holds the same rows, and one index
    // rebuild is queued.
    let restored_db = starforged_db::Db::connect(&target_db_url).await.unwrap();
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(restored_db.pool())
        .await
        .unwrap();
    assert_eq!(users, 1);
    let repos: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repos")
        .fetch_one(restored_db.pool())
        .await
        .unwrap();
    assert_eq!(repos, 1);
    let rebuilds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'rebuild_index' AND state = 'queued'",
    )
    .fetch_one(restored_db.pool())
    .await
    .unwrap();
    assert_eq!(rebuilds, 1, "restore must enqueue one index rebuild");

    let copied = fresh_data
        .join("repos")
        .join(format!("{:02}", repo_id.rem_euclid(100)))
        .join(format!("{}.git", repo_id));
    assert!(copied.is_dir());
    assert_fsck_clean(&copied);

    // Restoring into the populated source database is refused.
    let fresh_data2 = tmp.path().join("restored-data-2");
    let target_config2 = tmp.path().join("restored2.toml");
    let target_text2 = format!(
        "[server]\nhttp_addr = \"127.0.0.1:3000\"\nbase_url = \"http://127.0.0.1:3000\"\n\
         [database]\nurl = \"{}\"\n\
         [storage]\ndata_dir = \"{}\"\n\
         [security]\nsecret_key = \"{}\"\n",
        source_db.url,
        fresh_data2.display(),
        "0".repeat(64)
    );
    std::fs::write(&target_config2, &target_text2).unwrap();
    let out = restore_cmd(
        &backup_dir,
        Some(&target_config2),
        None,
        Some(&shims.prepended_path()),
    );
    assert!(
        !out.status.success(),
        "restore into a populated Postgres database succeeded"
    );
    assert!(
        combined(&out).contains("tables"),
        "unexpected error: {}",
        combined(&out)
    );
}

/// An incomplete backup (no `blobs/`) is refused before any write:
/// the target data dir is never created.
#[tokio::test]
async fn restore_refuses_a_backup_missing_blobs_and_leaves_the_target_untouched() {
    let fixture = fixture().await;
    let backup_dir = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &backup_dir, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));
    std::fs::remove_dir_all(backup_dir.join("blobs")).unwrap();

    let fresh_data = fixture._tmp.path().join("restored-data");
    let target_config = fixture._tmp.path().join("restored.toml");
    write_sqlite_config(&target_config, &fresh_data, &"0".repeat(64));
    let out = restore_cmd(&backup_dir, Some(&target_config), None, None);
    assert!(
        !out.status.success(),
        "restore of an incomplete backup succeeded"
    );
    assert!(
        combined(&out).contains("blobs"),
        "unexpected error: {}",
        combined(&out)
    );
    assert!(
        !fresh_data.exists(),
        "the refusal must happen before the data dir is created"
    );
}

/// A planted symlink in the backup (here: a repository hook pointing
/// outside the backup) is refused before any write, so a hostile
/// backup cannot plant files outside the restored data dir.
#[cfg(unix)]
#[tokio::test]
async fn restore_refuses_a_planted_symlink_before_any_write() {
    let fixture = fixture().await;
    let backup_dir = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &backup_dir, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));
    let copied = backup_dir
        .join("repos")
        .join(format!("{:02}", fixture.repo_id.rem_euclid(100)))
        .join(format!("{}.git", fixture.repo_id));
    let hook = copied.join("hooks").join("pre-receive");
    let _ = std::fs::remove_file(&hook);
    std::os::unix::fs::symlink("/bin/true", &hook).unwrap();

    let fresh_data = fixture._tmp.path().join("restored-data");
    let target_config = fixture._tmp.path().join("restored.toml");
    write_sqlite_config(&target_config, &fresh_data, &"0".repeat(64));
    let out = restore_cmd(&backup_dir, Some(&target_config), None, None);
    assert!(
        !out.status.success(),
        "restore of a backup with a planted symlink succeeded"
    );
    assert!(
        combined(&out).contains("symlink"),
        "unexpected error: {}",
        combined(&out)
    );
    assert!(
        !fresh_data.exists(),
        "the refusal must happen before the data dir is created"
    );
}

/// A manifest whose counts do not match the snapshot's contents is
/// refused before any write.
#[tokio::test]
async fn restore_refuses_a_manifest_count_mismatch() {
    let fixture = fixture().await;
    let backup_dir = fixture._tmp.path().join("backup");
    let out = backup(&fixture, &backup_dir, &[]);
    assert!(out.status.success(), "backup failed: {}", combined(&out));
    let manifest_path = backup_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["blobs"] = serde_json::json!(99);
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let fresh_data = fixture._tmp.path().join("restored-data");
    let target_config = fixture._tmp.path().join("restored.toml");
    write_sqlite_config(&target_config, &fresh_data, &"0".repeat(64));
    let out = restore_cmd(&backup_dir, Some(&target_config), None, None);
    assert!(
        !out.status.success(),
        "restore of a count-mismatched backup succeeded"
    );
    assert!(
        combined(&out).contains("manifest counts"),
        "unexpected error: {}",
        combined(&out)
    );
    assert!(
        !fresh_data.exists(),
        "the refusal must happen before the data dir is created"
    );
}
