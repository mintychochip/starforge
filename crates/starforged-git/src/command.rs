//! Running `git` with a hermetic environment.

use std::ffi::{OsStr, OsString};
use std::process::Stdio;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git {command} failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error("running git: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Gix(String),
    #[error("unsupported git ({0}); starforged needs git 2.38 or newer")]
    TooOld(String),
}

/// A `git` command isolated from system and user configuration, with prompts disabled and
/// stdin closed. Callers that stream data replace stdin/stdout/stderr.
pub fn git() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    cmd
}

/// Runs git and returns stdout; a non-zero exit becomes [`GitError::Failed`] with stderr.
pub async fn run<I, S>(args: I) -> Result<Vec<u8>, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<OsString> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();
    let out = git().args(&args).output().await?;
    if !out.status.success() {
        return Err(GitError::Failed {
            command: args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" "),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    Ok(out.stdout)
}

/// Parses `git version 2.53.0` (and vendor suffixes) into `(major, minor)`.
pub fn parse_version(output: &str) -> Option<(u32, u32)> {
    let version = output.trim().strip_prefix("git version ")?;
    let mut numbers = version.split(|c: char| !c.is_ascii_digit());
    Some((numbers.next()?.parse().ok()?, numbers.next()?.parse().ok()?))
}

/// Fails unless the installed git is 2.38+ (`merge-tree --write-tree`, spec §5.5).
pub async fn check_version() -> Result<(u32, u32), GitError> {
    let text = String::from_utf8_lossy(&run(["version"]).await?).into_owned();
    match parse_version(&text) {
        Some(version) if version >= (2, 38) => Ok(version),
        _ => Err(GitError::TooOld(text.trim().to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_versions() {
        assert_eq!(parse_version("git version 2.53.0\n"), Some((2, 53)));
        assert_eq!(
            parse_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        assert_eq!(parse_version("git version 2.38.0.windows.1"), Some((2, 38)));
        assert_eq!(parse_version("hg version 6.0"), None);
    }

    #[tokio::test]
    async fn installed_git_is_new_enough() {
        assert!(check_version().await.unwrap() >= (2, 38));
    }

    #[tokio::test]
    async fn failures_carry_stderr() {
        let err = run([
            "--git-dir",
            "/nonexistent/starforge-test",
            "rev-parse",
            "HEAD",
        ])
        .await
        .unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }));
        assert!(err.to_string().contains("not a git repository"), "{err}");
    }
}
