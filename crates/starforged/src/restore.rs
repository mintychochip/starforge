//! `starforged restore <dir>`: restore a backup snapshot (plan M5b O2,
//! spec §12) into the data directory and database named by the target
//! config.
//!
//! The manifest is validated before anything is written: the format
//! version must be one this binary understands, the engine must match
//! the target database, and the snapshot's schema must not be newer
//! than this binary knows. Restore refuses a non-empty data directory
//! and, on Postgres, a database that already has tables. The database
//! snapshot is then restored (SQLite file copy, Postgres through
//! `pg_restore` from `PATH`, decision D4), repositories and blobs are
//! copied with their modes, migrations run (an older snapshot is
//! brought up to date), and a search-index rebuild is enqueued (the
//! backup deliberately skips the index; it is rebuildable).
//!
//! The target config comes from `--config`; without it, the backup's
//! own config copy is used with `storage.data_dir` taken from
//! `--data-dir`, and the adjusted config is written to
//! `<data_dir>/starforged.toml` (`0600`, like the backup's copy).

use std::path::Path;
use std::process::Command as ShellCommand;

use anyhow::{Context, bail};
use serde::Deserialize;
use starforged_db::{Backend, Db};

use crate::admin::open_core;
use crate::backup::{self, MANIFEST_FORMAT_VERSION};
use crate::config::Config;

#[derive(Deserialize)]
struct Manifest {
    format_version: u32,
    engine: String,
    latest_migration: Option<i64>,
    repositories: u64,
    blobs: u64,
}

/// Restores `backup_dir` into the target named by `config_path` (or the
/// backup's config with `data_dir`) and prints a one-line summary.
pub async fn run(
    backup_dir: &Path,
    config_path: Option<&Path>,
    data_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let manifest = read_manifest(backup_dir)?;
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        bail!(
            "backup manifest format version {} is not understood by this binary (it understands {})",
            manifest.format_version,
            MANIFEST_FORMAT_VERSION
        );
    }
    let manifest_backend = match manifest.engine.as_str() {
        "sqlite" => Backend::Sqlite,
        "postgres" => Backend::Postgres,
        engine => bail!("backup manifest names an unknown database engine {engine:?}"),
    };

    let (config, from_backup_config) = resolve_config(backup_dir, config_path, data_dir)?;
    let target_backend = config_backend(&config)
        .context("determining the target database engine from the config")?;
    if target_backend != manifest_backend {
        bail!(
            "backup engine {} does not match the target database engine {}",
            manifest.engine,
            match target_backend {
                Backend::Sqlite => "sqlite",
                Backend::Postgres => "postgres",
            }
        );
    }

    let data_dir = config.storage.data_dir.clone();
    prepare_target(&data_dir)?;

    // A probe connection: for Postgres it is the target itself (to
    // refuse a populated database); for SQLite an in-memory database,
    // so the schema check below creates no file in the target.
    let probe = match target_backend {
        Backend::Sqlite => Db::connect("sqlite::memory:")
            .await
            .context("probing the SQLite schema version")?,
        Backend::Postgres => {
            let db = Db::connect(&config.database_url())
                .await
                .context("connecting to the target Postgres database")?;
            let tables = starforged_db::doctor::table_count(&db)
                .await
                .context("checking the target Postgres database")?;
            if tables > 0 {
                bail!(
                    "target Postgres database already has {tables} tables; refusing to restore over it"
                );
            }
            db
        }
    };
    if let Some(latest) = manifest.latest_migration
        && latest > probe.known_migration()
    {
        bail!(
            "backup was taken at schema migration {latest}, which is newer than this binary knows ({})",
            probe.known_migration()
        );
    }
    drop(probe);

    // Database snapshot.
    match target_backend {
        Backend::Sqlite => {
            let src = backup_dir.join("database").join("starforge.db");
            if !src.is_file() {
                bail!("backup database snapshot {} is missing", src.display());
            }
            let dest = data_dir.join("starforge.db");
            std::fs::copy(&src, &dest)
                .with_context(|| format!("copying {} to {}", src.display(), dest.display()))?;
            backup::set_mode(&dest, 0o600)?;
        }
        Backend::Postgres => {
            let src = backup_dir.join("database").join("starforge.pgdump");
            if !src.is_file() {
                bail!("backup database snapshot {} is missing", src.display());
            }
            pg_restore(&config.database.url, &src)
                .context("restoring the Postgres snapshot (pg_restore)")?;
        }
    }

    // Repositories and blobs, with modes.
    let repos_src = backup_dir.join("repos");
    if !repos_src.is_dir() {
        bail!("backup is missing its repos/ directory");
    }
    backup::copy_tree(&repos_src, &config.repos_dir(), None)?;
    backup::set_mode(&config.repos_dir(), 0o700)?;
    let blobs_src = backup_dir.join("blobs");
    if !blobs_src.is_dir() {
        bail!("backup is missing its blobs/ directory");
    }
    backup::copy_tree(&blobs_src, &config.blob_dir(), None)?;
    backup::set_mode(&config.blob_dir(), 0o700)?;

    // The adjusted backup config, when one was used, is written into
    // the restored data directory for the restored instance to run.
    if from_backup_config {
        let text = toml::to_string_pretty(&config).context("serializing the restored config")?;
        backup::write_file(&data_dir.join("starforged.toml"), text.as_bytes(), 0o600)?;
    }

    // Migrations bring an older snapshot up to date; the index rebuild
    // is enqueued (the backup skipped the index deliberately).
    let db = Db::connect(&config.database_url())
        .await
        .context("connecting to the restored database")?;
    db.migrate()
        .await
        .context("migrating the restored database")?;
    drop(db);
    let core = open_core(&config, std::env::current_exe()?)
        .await
        .context("opening the restored database")?;
    core.enqueue(&starforged_core::jobs::Job::RebuildIndex)
        .await
        .context("enqueueing the search index rebuild")?;

    println!(
        "restored {} repositories and {} blobs from {} (engine {})",
        manifest.repositories,
        manifest.blobs,
        backup_dir.display(),
        manifest.engine
    );
    Ok(())
}

/// Reads and parses `<backup_dir>/manifest.json`.
fn read_manifest(backup_dir: &Path) -> anyhow::Result<Manifest> {
    let path = backup_dir.join("manifest.json");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading backup manifest {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("parsing backup manifest {}", path.display()))
}

/// Resolves the target config: `--config` when given, otherwise the
/// backup's config copy with `storage.data_dir` from `--data-dir`.
/// Returns the config and whether it came from the backup.
fn resolve_config(
    backup_dir: &Path,
    config_path: Option<&Path>,
    data_dir: Option<&Path>,
) -> anyhow::Result<(Config, bool)> {
    match config_path {
        Some(path) => {
            let mut config =
                Config::load(path).with_context(|| format!("loading {}", path.display()))?;
            if let Some(data_dir) = data_dir {
                config.storage.data_dir = data_dir.to_path_buf();
            }
            Ok((config, false))
        }
        None => {
            let backup_config = backup_dir.join("config").join("starforged.toml");
            if !backup_config.is_file() {
                bail!(
                    "backup has no config copy (it was taken with --no-config); \
                     pass --config <path> naming the target config"
                );
            }
            let Some(data_dir) = data_dir else {
                bail!("restore without --config needs --data-dir naming the target data directory");
            };
            let mut config = Config::load(&backup_config)
                .with_context(|| format!("loading backup config {}", backup_config.display()))?;
            config.storage.data_dir = data_dir.to_path_buf();
            Ok((config, true))
        }
    }
}

/// The database engine the target config names: an empty
/// `database.url` (or a `sqlite:` URL) is SQLite, `postgres:` is
/// Postgres.
fn config_backend(config: &Config) -> anyhow::Result<Backend> {
    let url = config.database.url.trim();
    if url.is_empty() || url.starts_with("sqlite:") {
        Ok(Backend::Sqlite)
    } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
        Ok(Backend::Postgres)
    } else {
        bail!("unsupported database url (expected sqlite: or postgres:)")
    }
}

/// Refuses a non-empty data directory; creates an absent one (and
/// tightens an existing empty one) `0700`.
fn prepare_target(data_dir: &Path) -> anyhow::Result<()> {
    if data_dir.exists() {
        if !data_dir.is_dir() {
            bail!("data directory {} is not a directory", data_dir.display());
        }
        let mut entries = std::fs::read_dir(data_dir)
            .with_context(|| format!("reading {}", data_dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "data directory {} is not empty; refusing to restore over it",
                data_dir.display()
            );
        }
        backup::set_mode(data_dir, 0o700)?;
    } else {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating {}", data_dir.display()))?;
        backup::set_mode(data_dir, 0o700)?;
    }
    Ok(())
}

/// `pg_restore --no-owner --dbname <url> <file>` (decision D4): the
/// password travels through `PGPASSWORD` in the child environment,
/// never argv, and a missing `pg_restore` fails naming the requirement.
fn pg_restore(url: &str, file: &Path) -> anyhow::Result<()> {
    let (restore_url, password) = backup::split_pg_password(url);
    let mut command = ShellCommand::new("pg_restore");
    command
        .arg("--no-owner")
        .arg("--dbname")
        .arg(&restore_url)
        .arg(file);
    if let Some(password) = &password {
        command.env("PGPASSWORD", password);
    }
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("pg_restore exited with {status}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
            "pg_restore is required for Postgres restores but was not found in PATH; \
             install the PostgreSQL client tools (postgresql-client) and retry"
        ),
        Err(err) => Err(err).context("running pg_restore"),
    }
}
