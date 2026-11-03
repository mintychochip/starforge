//! `starforged.toml`: loading, `STARFORGE__SECTION__KEY` environment overrides, and derived paths (spec §12).

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Socket address the HTTP server binds, e.g. `127.0.0.1:3000`.
    pub http_addr: String,
    /// Public URL of the server without a trailing slash, e.g. `https://forge.example.com`.
    pub base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Empty means SQLite at `<data_dir>/starforge.db`.
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_true")]
    pub auto_migrate: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            url: String::new(),
            auto_migrate: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// 64 hex characters (32 bytes). Losing it logs everyone out (spec §12).
    pub secret_key: String,
}

impl Config {
    /// Reads `path`, applies environment overrides, and validates.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.apply_env(std::env::vars())?;
        config.validate()?;
        Ok(config)
    }

    /// Applies `STARFORGE__<SECTION>__<KEY>` overrides; other variables are ignored.
    pub fn apply_env(
        &mut self,
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> anyhow::Result<()> {
        for (key, value) in vars {
            let Some(rest) = key.strip_prefix("STARFORGE__") else {
                continue;
            };
            match rest.to_ascii_lowercase().as_str() {
                "server__http_addr" => self.server.http_addr = value,
                "server__base_url" => self.server.base_url = value,
                "database__url" => self.database.url = value,
                "database__auto_migrate" => self.database.auto_migrate = parse_bool(&key, &value)?,
                "storage__data_dir" => self.storage.data_dir = PathBuf::from(value),
                "security__secret_key" => self.security.secret_key = value,
                _ => bail!("unknown configuration override {key}"),
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let key = &self.security.secret_key;
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("security.secret_key must be 64 hex characters");
        }
        if self.server.base_url.ends_with('/') {
            bail!("server.base_url must not end with '/'");
        }
        Ok(())
    }

    pub fn database_url(&self) -> String {
        if self.database.url.is_empty() {
            format!(
                "sqlite://{}?mode=rwc",
                self.storage.data_dir.join("starforge.db").display()
            )
        } else {
            self.database.url.clone()
        }
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.storage.data_dir.join("repos")
    }

    /// Cookies carry `Secure` when the public URL is HTTPS.
    pub fn secure_cookies(&self) -> bool {
        self.server.base_url.starts_with("https://")
    }
}

fn parse_bool(key: &str, value: &str) -> anyhow::Result<bool> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => bail!("{key} must be true or false"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            server: ServerConfig {
                http_addr: "127.0.0.1:3000".into(),
                base_url: "http://127.0.0.1:3000".into(),
            },
            database: DatabaseConfig::default(),
            storage: StorageConfig {
                data_dir: PathBuf::from("/srv/starforge"),
            },
            security: SecurityConfig {
                secret_key: "ab".repeat(32),
            },
        }
    }

    #[test]
    fn env_overrides_apply_and_ignore_other_variables() {
        let mut config = sample();
        config
            .apply_env([
                (
                    "STARFORGE__SERVER__HTTP_ADDR".to_owned(),
                    "0.0.0.0:80".to_owned(),
                ),
                (
                    "STARFORGE__DATABASE__URL".to_owned(),
                    "postgres://db/starforge".to_owned(),
                ),
                (
                    "STARFORGE__DATABASE__AUTO_MIGRATE".to_owned(),
                    "false".to_owned(),
                ),
                (
                    "STARFORGE_CONFIG".to_owned(),
                    "/etc/starforged.toml".to_owned(),
                ),
                ("HOME".to_owned(), "/root".to_owned()),
            ])
            .unwrap();
        assert_eq!(config.server.http_addr, "0.0.0.0:80");
        assert_eq!(config.database.url, "postgres://db/starforge");
        assert!(!config.database.auto_migrate);
    }

    #[test]
    fn unknown_overrides_are_rejected() {
        let err = sample()
            .apply_env([("STARFORGE__SERVER__PORT".to_owned(), "1".to_owned())])
            .unwrap_err();
        assert!(err.to_string().contains("STARFORGE__SERVER__PORT"));
    }

    #[test]
    fn empty_database_url_means_sqlite_in_the_data_dir() {
        assert_eq!(
            sample().database_url(),
            "sqlite:///srv/starforge/starforge.db?mode=rwc"
        );
        assert_eq!(sample().repos_dir(), PathBuf::from("/srv/starforge/repos"));
    }

    #[test]
    fn validation_checks_secret_key_and_base_url() {
        assert!(sample().validate().is_ok());
        let mut short_key = sample();
        short_key.security.secret_key = "abc".into();
        assert!(short_key.validate().is_err());
        let mut slash = sample();
        slash.server.base_url = "http://x/".into();
        assert!(slash.validate().is_err());
        let mut https = sample();
        https.server.base_url = "https://forge.example.com".into();
        assert!(https.secure_cookies());
        assert!(!sample().secure_cookies());
    }
}
