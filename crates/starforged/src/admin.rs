//! Administrative commands that act on the database directly, without a running server.

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use starforged_core::accounts::{CreateUser, User};
use starforged_core::{Core, CoreConfig, tokens};
use starforged_db::Db;

use crate::config::Config;

/// Connects to the configured database (migrating it when `database.auto_migrate` is on) and builds `Core`.
pub async fn open_core(config: &Config, hook_exe: PathBuf) -> anyhow::Result<Core> {
    let db = Db::connect(&config.database_url())
        .await
        .context("connecting to the database")?;
    if config.database.auto_migrate {
        db.migrate().await.context("migrating the database")?;
    }
    Ok(Core::new(
        db,
        CoreConfig {
            repos_dir: config.repos_dir(),
            tmp_dir: config.tmp_dir(),
            blob_dir: config.blob_dir(),
            max_segment_bytes: config.sessions.max_segment_bytes,
            max_repo_bytes: config.sessions.max_repo_bytes,
            max_user_bytes: config.sessions.max_user_bytes,
            max_hourly_bytes: config.sessions.max_hourly_bytes,
            blob_store: Arc::new(starforged_blob::FsBlobStore::new(config.blob_dir())),
            hook_exe,
            base_url: config.server.base_url.clone(),
            mailer: config.mailer()?,
            registration: config.registration_settings()?,
        },
    ))
}

pub async fn migrate(config: &Config) -> anyhow::Result<()> {
    let db = Db::connect(&config.database_url())
        .await
        .context("connecting to the database")?;
    db.migrate().await.context("migrating the database")?;
    Ok(())
}

pub struct NewUserArgs {
    pub handle: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub admin: bool,
    pub password_stdin: bool,
}

pub async fn create_user(config: &Config, args: NewUserArgs) -> anyhow::Result<User> {
    let password = if args.password_stdin {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading the password from stdin")?;
        Some(text.trim_end_matches(['\r', '\n']).to_owned())
    } else {
        None
    };
    let core = open_core(config, std::env::current_exe()?).await?;
    let user = core
        .create_user(CreateUser {
            handle: args.handle,
            display_name: args.display_name.unwrap_or_default(),
            email: args.email,
            email_verified: true,
            password,
            is_admin: args.admin,
        })
        .await?;
    Ok(user)
}

pub async fn create_token(
    config: &Config,
    handle: &str,
    name: &str,
    scopes: &str,
    expires_days: u32,
) -> anyhow::Result<String> {
    let core = open_core(config, std::env::current_exe()?).await?;
    let user = core
        .user_by_handle(handle)
        .await?
        .with_context(|| format!("no user named '{handle}'"))?;
    let scopes = tokens::parse_scopes(scopes)?;
    Ok(core
        .create_token(&user, name, &scopes, expires_days)
        .await?
        .secret)
}

/// `starforged admin mail test`: sends one message directly, bypassing the job queue.
pub async fn mail_test(config: &Config, to: &str) -> anyhow::Result<()> {
    let mailer = config
        .mailer()?
        .context("mail.url is empty; configure [mail] in starforged.toml first")?;
    let email = starforged_core::mail::test_email(to, &config.server.base_url)?;
    mailer.send(&email).await?;
    Ok(())
}
