//! `CliPaths` — the ONLY module in this crate allowed to read env/home.

use std::path::PathBuf;

/// Resolved filesystem locations for the CLI.
///
/// `resolve()` is the sole function in the crate that touches the environment.
/// Every other function takes paths as parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliPaths {
    /// `$STARFORGE_HOME`, else `$HOME` / `%USERPROFILE%`, else a temp-dir fallback.
    pub home: PathBuf,
    /// `<home>/.config/starforge`.
    pub config_dir: PathBuf,
    /// `<config_dir>/credentials.toml`.
    pub credential_file: PathBuf,
}

impl CliPaths {
    /// Build paths from an explicit home directory (tests + all non-root construction).
    pub fn from_home(home: PathBuf) -> Self {
        let config_dir = home.join(".config").join("starforge");
        let credential_file = config_dir.join("credentials.toml");
        Self {
            home,
            config_dir,
            credential_file,
        }
    }

    /// Resolve paths from an injected env lookup (tests use this; no globals touched).
    pub fn resolve_with(lookup: impl Fn(&str) -> Option<String>) -> Self {
        if let Some(home) = lookup("STARFORGE_HOME")
            && !home.is_empty()
        {
            return Self::from_home(PathBuf::from(home));
        }
        let home = lookup("HOME")
            .or_else(|| lookup("USERPROFILE"))
            .filter(|h| !h.is_empty());
        match home {
            Some(home) => Self::from_home(PathBuf::from(home)),
            None => Self::from_home(std::env::temp_dir().join("starforge")),
        }
    }

    /// Resolve paths from the environment. Never fails: falls back to a temp dir
    /// when neither `STARFORGE_HOME` nor `HOME`/`USERPROFILE` is set.
    pub fn resolve() -> Self {
        Self::resolve_with(|key| std::env::var(key).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_paths_from_home_shapes() {
        let p = CliPaths::from_home(PathBuf::from("/tmp/h"));
        assert_eq!(
            p.credential_file,
            PathBuf::from("/tmp/h/.config/starforge/credentials.toml")
        );
    }

    #[test]
    fn cli_paths_override_wins() {
        let lookup = |key: &str| match key {
            "STARFORGE_HOME" => Some(String::from("/tmp/override")),
            "HOME" => Some(String::from("/tmp/home")),
            _ => None,
        };
        let p = CliPaths::resolve_with(lookup);
        assert_eq!(p.home, PathBuf::from("/tmp/override"));
        assert_eq!(
            p.config_dir,
            PathBuf::from("/tmp/override/.config/starforge")
        );
    }

    #[test]
    fn cli_paths_resolve_never_fails_without_home_vars() {
        // Pure check: an empty environment must not panic and must still
        // produce a non-empty home (temp-dir fallback). No globals touched.
        let paths = CliPaths::resolve_with(|_| None);
        assert!(!paths.home.as_os_str().is_empty());
        assert_eq!(
            paths.credential_file,
            paths.config_dir.join("credentials.toml")
        );
    }
}
