//! `starforged init`: writes a fresh `starforged.toml` and data directory.

use std::path::Path;

use anyhow::{Context, bail};

use crate::config::{
    Config, DatabaseConfig, MailConfig, RegistrationConfig, SecurityConfig, ServerConfig,
    SessionsConfig, StorageConfig,
};

pub struct InitOptions<'a> {
    pub config_path: &'a Path,
    pub data_dir: &'a Path,
    pub base_url: &'a str,
    pub http_addr: &'a str,
}

pub fn run(opts: &InitOptions<'_>) -> anyhow::Result<Config> {
    if opts.config_path.exists() {
        bail!(
            "{} already exists; refusing to overwrite it",
            opts.config_path.display()
        );
    }
    for sub in ["repos", "tmp", "run"] {
        let dir = opts.data_dir.join(sub);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let data_dir = std::fs::canonicalize(opts.data_dir)?;
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|e| anyhow::anyhow!("reading OS randomness: {e}"))?;
    let config = Config {
        server: ServerConfig {
            http_addr: opts.http_addr.to_owned(),
            base_url: opts.base_url.trim_end_matches('/').to_owned(),
        },
        database: DatabaseConfig::default(),
        storage: StorageConfig { data_dir },
        security: SecurityConfig {
            secret_key: hex::encode(key),
        },
        mail: MailConfig::default(),
        registration: RegistrationConfig::default(),
        sessions: SessionsConfig::default(),
    };
    config.validate()?;
    write_private(opts.config_path, &toml::to_string_pretty(&config)?)?;
    Ok(config)
}

#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    std::fs::write(path, text).with_context(|| format!("creating {}", path.display()))
}
