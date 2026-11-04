//! `git` config/remote readers (C3).
//!
//! Every function shells out to the system `git` binary (no git2 dep) and
//! takes the repo path explicitly: this module never reads the environment.
//! Callers pass `cwd` (or any repo working dir / git dir); `git -C` resolves
//! it, so bare repos work too.

use std::path::Path;
use std::process::Command;

/// git invocation failures.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// `git` could not be started.
    #[error("cannot run git: {0}")]
    Spawn(String),
    /// `git` exited non-zero for a command where that is always an error.
    #[error("git failed: {0}")]
    Failed(String),
    /// Output was not valid UTF-8.
    #[error("git output was not UTF-8: {0}")]
    Utf8(String),
}

fn git_output(repo: &Path, args: &[&str]) -> Result<std::process::Output, GitError> {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))
}

fn stdout_utf8(output: std::process::Output, what: &str) -> Result<String, GitError> {
    String::from_utf8(output.stdout).map_err(|err| GitError::Utf8(format!("{what}: {err}")))
}

/// `git rev-parse --git-common-dir`: the shared git dir (worktrees resolve to
/// the main repo). Relative output is joined onto `repo`.
pub fn common_dir(repo: &Path) -> Result<std::path::PathBuf, GitError> {
    let output = git_output(repo, &["rev-parse", "--git-common-dir"])?;
    if !output.status.success() {
        return Err(GitError::Failed(format!(
            "git rev-parse --git-common-dir failed in {}",
            repo.display()
        )));
    }
    let dir = stdout_utf8(output, "git-common-dir")?;
    let dir = dir.trim();
    let path = Path::new(dir);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    })
}

/// `git config --get <key>`: `Ok(None)` when the key is unset (exit status 1),
/// `Err` only when git itself fails.
pub fn config_get(repo: &Path, key: &str) -> Result<Option<String>, GitError> {
    let output = git_output(repo, &["config", "--get", key])?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = stdout_utf8(output, "git config")?;
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

/// All remotes as `(name, url)` pairs in `.git/config` order, via
/// `git config --get-regexp '^remote\..*\.url$'`. Empty when the repo has no
/// remotes (exit status 1), never an error for that case.
pub fn remotes(repo: &Path) -> Result<Vec<(String, String)>, GitError> {
    let output = git_output(repo, &["config", "--get-regexp", r"^remote\..*\.url$"])?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let raw = stdout_utf8(output, "git remotes")?;
    let mut out = Vec::new();
    for line in raw.lines() {
        // Format: `remote.<name>.url <url>` (url may contain spaces).
        let Some((key, url)) = line.split_once(' ') else {
            continue;
        };
        let name = key
            .strip_prefix("remote.")
            .and_then(|rest| rest.strip_suffix(".url"));
        if let Some(name) = name
            && !name.is_empty()
            && !url.is_empty()
        {
            out.push((name.to_string(), url.to_string()));
        }
    }
    Ok(out)
}

/// Preferred remote by name: explicit `configured` name wins when it names a
/// known remote, else `starforge` → `origin` → `upstream` → first remote.
/// (`starforge.server` is a server URL, not a remote name, and is handled by
/// [`crate::discovery`] before this is consulted; `configured` here is an
/// optional remote-name override for future callers.)
pub fn pick_remote(
    remotes: &[(String, String)],
    configured: Option<&str>,
) -> Option<(String, String)> {
    if let Some(want) = configured
        && let Some(hit) = remotes.iter().find(|(name, _)| name == want)
    {
        return Some(hit.clone());
    }
    for preferred in ["starforge", "origin", "upstream"] {
        if let Some(hit) = remotes.iter().find(|(name, _)| name == preferred) {
            return Some(hit.clone());
        }
    }
    remotes.first().cloned()
}
