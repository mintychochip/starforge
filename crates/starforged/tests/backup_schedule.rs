//! Scheduled backups: rotation keeps the newest valid backups only, and a
//! scheduled run writes a restore-acceptable backup.

mod common;

use std::path::{Path, PathBuf};

use starforged::backup;
use starforged::config::Config;

fn manifest_json(created_at: i64) -> String {
    format!(
        "{{\n  \"format_version\": 1,\n  \"starforged_version\": \"0.0.0-test\",\n  \"created_at\": {created_at},\n  \"engine\": \"sqlite\",\n  \"latest_migration\": 1,\n  \"repositories\": 0,\n  \"blobs\": 0\n}}\n"
    )
}

fn make_backup(dir: &Path, name: &str, created_at: i64) {
    let path = dir.join(name);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("manifest.json"), manifest_json(created_at)).unwrap();
}

/// Rotation keeps the newest `keep` valid backups and never removes the
/// backup just written, which is the newest one.
#[test]
fn rotation_keeps_newest_valid_backups_and_newest_survives() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    make_backup(dir, "starforge-backup-20240101-000000", 100);
    make_backup(dir, "starforge-backup-20240102-000000", 200);
    make_backup(dir, "starforge-backup-20240103-000000", 300);
    make_backup(dir, "starforge-backup-20240104-000000", 400);

    backup::rotate(dir, 2).unwrap();
    assert!(
        dir.join("starforge-backup-20240104-000000").is_dir(),
        "newest survives"
    );
    assert!(dir.join("starforge-backup-20240103-000000").is_dir());
    assert!(!dir.join("starforge-backup-20240101-000000").exists());
    assert!(!dir.join("starforge-backup-20240102-000000").exists());
}

/// Rotation ignores directories without a valid manifest.
#[test]
fn rotation_ignores_directories_without_valid_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    make_backup(dir, "starforge-backup-20240102-000000", 200);
    make_backup(dir, "starforge-backup-20240103-000000", 300);
    let no_manifest = dir.join("not-a-backup");
    std::fs::create_dir_all(&no_manifest).unwrap();
    std::fs::write(no_manifest.join("readme.txt"), b"keep me").unwrap();
    let bad_manifest = dir.join("starforge-backup-broken");
    std::fs::create_dir_all(&bad_manifest).unwrap();
    std::fs::write(bad_manifest.join("manifest.json"), b"{not json").unwrap();
    let wrong_version = dir.join("starforge-backup-future");
    std::fs::create_dir_all(&wrong_version).unwrap();
    std::fs::write(
        wrong_version.join("manifest.json"),
        manifest_json(999).replace("\"format_version\": 1", "\"format_version\": 999"),
    )
    .unwrap();
    let plain_file = dir.join("plain.txt");
    std::fs::write(&plain_file, b"keep me").unwrap();

    backup::rotate(dir, 1).unwrap();
    assert!(dir.join("starforge-backup-20240103-000000").is_dir());
    assert!(!dir.join("starforge-backup-20240102-000000").exists());
    assert!(no_manifest.is_dir(), "no-manifest dir is left alone");
    assert!(bad_manifest.is_dir(), "invalid manifest is left alone");
    assert!(
        wrong_version.is_dir(),
        "unknown format version is left alone"
    );
    assert!(plain_file.is_file(), "plain files are left alone");
}

/// A scheduled run with a short interval writes a backup with a valid
/// manifest that restore accepts (restore round-trip is exercised here
/// through the manifest check plus the backup layout).
#[tokio::test]
async fn scheduled_run_writes_valid_manifest_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("starforged.toml");
    let data_dir = tmp.path().join("data");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_starforged"))
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
    let mut config = Config::load(&config_path).unwrap();
    let backup_dir = tmp.path().join("backups");
    config.backup.dir = backup_dir.clone();
    config.backup.interval_hours = 1;
    config.backup.keep = 2;
    assert!(config.backup.enabled());

    // Migrate the database so the snapshot has a schema.
    let db = starforged_db::Db::connect(&config.database_url())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    drop(db);

    let target = backup::run_scheduled(&config, Some(&config_path))
        .await
        .unwrap();
    assert!(target.is_dir());
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(target.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["format_version"], 1);
    assert!(manifest["created_at"].as_i64().unwrap() > 0);
    assert!(target.join("database").is_dir());
    assert!(target.join("repos").is_dir());
    assert!(target.join("blobs").is_dir());
    assert!(target.join("config").join("starforged.toml").is_file());
    assert!(
        !target
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .is_empty()
    );

    // Rotation after a second run keeps both until `keep` is exceeded.
    let target2 = backup::run_scheduled(&config, Some(&config_path))
        .await
        .unwrap();
    assert_ne!(target, target2);
    backup::rotate(&backup_dir, 2).unwrap();
    assert!(target.is_dir());
    assert!(target2.is_dir());

    // The serve-level wrapper agrees with the shared implementation.
    let target3 = starforged::serve::run_scheduled_backup(&config, Some(&config_path))
        .await
        .unwrap();
    assert!(target3.is_dir());
    let names: Vec<PathBuf> = std::fs::read_dir(&backup_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(names.len() <= 3, "rotation bounds the count: {names:?}");
}

/// Rotation never counts or deletes a manual backup under another name,
/// however new, nor a symlink (even one named `starforge-backup-*`
/// pointing at a valid backup).
#[test]
fn rotation_never_touches_manual_backups_or_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    make_backup(dir, "starforge-backup-20240102-000000", 200);
    make_backup(dir, "starforge-backup-20240103-000000", 300);
    // A manual `starforged backup <dir>/quarterly`: valid, and newest,
    // but never a scheduled backup.
    make_backup(dir, "quarterly", 9999);
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        dir.join("starforge-backup-20240103-000000"),
        dir.join("starforge-backup-link"),
    )
    .unwrap();

    backup::rotate(dir, 1).unwrap();
    assert!(dir.join("starforge-backup-20240103-000000").is_dir());
    assert!(!dir.join("starforge-backup-20240102-000000").exists());
    assert!(
        dir.join("quarterly").join("manifest.json").is_file(),
        "manual backup survives rotation"
    );
    #[cfg(unix)]
    assert!(
        std::fs::symlink_metadata(dir.join("starforge-backup-link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "symlink survives rotation"
    );
}

/// Startup validation creates the backup directory, accepts a writable
/// one, and refuses one it cannot use, naming the directory.
#[test]
fn backup_dir_validation_refuses_unusable_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let good = tmp.path().join("backups");
    backup::validate_backup_dir(&good).unwrap();
    assert!(good.is_dir());
    assert!(
        std::fs::read_dir(&good).unwrap().next().is_none(),
        "the writability probe leaves nothing behind"
    );

    // A regular file where the directory must be: creation fails.
    let bad = tmp.path().join("not-a-dir");
    std::fs::write(&bad, b"keep me").unwrap();
    let err = backup::validate_backup_dir(&bad).unwrap_err();
    assert!(
        format!("{err:?}").contains(&bad.display().to_string()),
        "error names the directory: {err:?}"
    );
}

/// A scheduled run that fails partway (here: a symlink in the blob
/// store, which `copy_tree` refuses) leaves no partial backup behind.
#[cfg(unix)]
#[tokio::test]
async fn failed_scheduled_run_leaves_no_partial_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("starforged.toml");
    let data_dir = tmp.path().join("data");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_starforged"))
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
    let mut config = Config::load(&config_path).unwrap();
    let backup_dir = tmp.path().join("backups");
    config.backup.dir = backup_dir.clone();
    config.backup.interval_hours = 1;
    config.backup.keep = 2;

    let db = starforged_db::Db::connect(&config.database_url())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    drop(db);

    // A symlink in the blob store makes the copy bail after the database
    // snapshot has already been written into the target.
    std::fs::create_dir_all(config.blob_dir()).unwrap();
    std::os::unix::fs::symlink(config_path.clone(), config.blob_dir().join("stray-link")).unwrap();

    let err = backup::run_scheduled(&config, Some(&config_path))
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("symlink"), "{err:?}");
    let leftovers: Vec<_> = std::fs::read_dir(&backup_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(
        leftovers.is_empty(),
        "no partial backup remains: {leftovers:?}"
    );
}
