//! `CliPaths` — the ONLY module in this crate allowed to read env/home.
//!
//! Agent store-dir env overrides (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
//! `XDG_DATA_HOME`, `XDG_CONFIG_HOME`) are captured here, in
//! [`CliPaths::agent_dirs`], and nowhere else.

use std::path::PathBuf;

/// Agent store-dir env overrides captured by [`CliPaths::resolve_with`].
///
/// Each field is the corresponding env var's value, or `None` when the var
/// is unset/empty or when `STARFORGE_HOME` is set (hermetic test/CI mode).
/// [`CliPaths::from_home`] leaves all of them `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentDirOverrides {
    /// `$CLAUDE_CONFIG_DIR`.
    pub claude_config_dir: Option<PathBuf>,
    /// `$CODEX_HOME`.
    pub codex_home: Option<PathBuf>,
    /// `$XDG_DATA_HOME`.
    pub xdg_data_home: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<PathBuf>,
}

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
    /// Agent store-dir env overrides (see [`AgentDirOverrides`]).
    pub agent_dirs: AgentDirOverrides,
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
            agent_dirs: AgentDirOverrides::default(),
        }
    }

    /// Resolve paths from an injected env lookup (tests use this; no globals touched).
    ///
    /// When `STARFORGE_HOME` is set and non-empty, agent-dir overrides are
    /// all `None` (the hermetic test and CI mode). Otherwise the four
    /// agent-dir variables are captured, treating empty as unset.
    pub fn resolve_with(lookup: impl Fn(&str) -> Option<String>) -> Self {
        if let Some(home) = lookup("STARFORGE_HOME")
            && !home.is_empty()
        {
            return Self::from_home(PathBuf::from(home));
        }
        let dir = |key: &str| lookup(key).filter(|v| !v.is_empty()).map(PathBuf::from);
        let agent_dirs = AgentDirOverrides {
            claude_config_dir: dir("CLAUDE_CONFIG_DIR"),
            codex_home: dir("CODEX_HOME"),
            xdg_data_home: dir("XDG_DATA_HOME"),
            xdg_config_home: dir("XDG_CONFIG_HOME"),
        };
        let home = lookup("HOME")
            .or_else(|| lookup("USERPROFILE"))
            .filter(|h| !h.is_empty());
        let mut paths = match home {
            Some(home) => Self::from_home(PathBuf::from(home)),
            None => Self::from_home(std::env::temp_dir().join("starforge")),
        };
        paths.agent_dirs = agent_dirs;
        paths
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

    #[test]
    fn cli_paths_resolve_with_captures_agent_dirs_without_starforge_home() {
        let lookup = |key: &str| match key {
            "HOME" => Some(String::from("/tmp/home")),
            "CLAUDE_CONFIG_DIR" => Some(String::from("/c")),
            "CODEX_HOME" => Some(String::from("/x")),
            "XDG_DATA_HOME" => Some(String::from("/xd")),
            "XDG_CONFIG_HOME" => Some(String::from("/xc")),
            _ => None,
        };
        let p = CliPaths::resolve_with(lookup);
        assert_eq!(p.agent_dirs.claude_config_dir, Some(PathBuf::from("/c")));
        assert_eq!(p.agent_dirs.codex_home, Some(PathBuf::from("/x")));
        assert_eq!(p.agent_dirs.xdg_data_home, Some(PathBuf::from("/xd")));
        assert_eq!(p.agent_dirs.xdg_config_home, Some(PathBuf::from("/xc")));
    }

    #[test]
    fn cli_paths_resolve_with_starforge_home_captures_no_agent_dirs() {
        let lookup = |key: &str| match key {
            "STARFORGE_HOME" => Some(String::from("/tmp/override")),
            "CLAUDE_CONFIG_DIR" => Some(String::from("/c")),
            "CODEX_HOME" => Some(String::from("/x")),
            "XDG_DATA_HOME" => Some(String::from("/xd")),
            "XDG_CONFIG_HOME" => Some(String::from("/xc")),
            _ => None,
        };
        let p = CliPaths::resolve_with(lookup);
        assert_eq!(p.agent_dirs, AgentDirOverrides::default());
    }

    #[test]
    fn cli_paths_from_home_has_no_agent_dirs() {
        let p = CliPaths::from_home(PathBuf::from("/tmp/h"));
        assert_eq!(p.agent_dirs, AgentDirOverrides::default());
    }
}
