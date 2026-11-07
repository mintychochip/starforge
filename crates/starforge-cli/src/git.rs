//! `git` config/remote readers (C3).
//!
//! Every function shells out to the system `git` binary (no git2 dep) and
//! takes the repo path explicitly: this module never reads the environment.
//! Callers pass `cwd` (or any repo working dir / git dir); `git -C` resolves
//! it, so bare repos work too.

use std::ffi::OsString;
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

/// `git diff --cached --name-only`: repo-relative paths with staged changes.
/// Empty when nothing is staged; never fails on an unborn HEAD (exit status
/// is still success with empty output for `--cached` against no HEAD? no:
/// git handles it, and any real failure is an `Err`).
pub fn staged_files(repo: &Path) -> Result<Vec<String>, GitError> {
    let output = git_output(repo, &["diff", "--cached", "--name-only", "--no-renames"])?;
    if !output.status.success() {
        return Err(GitError::Failed(format!(
            "git diff --cached --name-only failed in {}",
            repo.display()
        )));
    }
    Ok(stdout_utf8(output, "staged files")?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// `git rev-parse HEAD`: the current commit SHA.
pub fn head_commit(repo: &Path) -> Result<String, GitError> {
    let output = git_output(repo, &["rev-parse", "HEAD"])?;
    if !output.status.success() {
        return Err(GitError::Failed(format!(
            "git rev-parse HEAD failed in {}",
            repo.display()
        )));
    }
    Ok(stdout_utf8(output, "HEAD")?.trim().to_string())
}

/// `git log -1 --format=%ct HEAD`: HEAD's committer time as unix seconds,
/// or `None` when there is no HEAD (first commit / unborn branch).
pub fn head_commit_time(repo: &Path) -> Result<Option<i64>, GitError> {
    let output = git_output(repo, &["log", "-1", "--format=%ct", "HEAD"])?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = stdout_utf8(output, "HEAD time")?;
    Ok(text.trim().parse::<i64>().ok())
}
/// `git rev-parse --show-toplevel`: the working-tree root of `repo` (a
/// linked worktree resolves to its own root).
pub fn toplevel(repo: &Path) -> Result<std::path::PathBuf, GitError> {
    let output = git_output(repo, &["rev-parse", "--show-toplevel"])?;
    if !output.status.success() {
        return Err(GitError::Failed(format!(
            "git rev-parse --show-toplevel failed in {}",
            repo.display()
        )));
    }
    let text = stdout_utf8(output, "toplevel")?;
    Ok(std::path::PathBuf::from(text.trim()))
}

/// `git worktree list --porcelain`: the working-tree root of every worktree
/// (the main worktree plus any linked ones), in list order.
pub fn worktrees(repo: &Path) -> Result<Vec<std::path::PathBuf>, GitError> {
    let output = git_output(repo, &["worktree", "list", "--porcelain"])?;
    if !output.status.success() {
        return Err(GitError::Failed(format!(
            "git worktree list failed in {}",
            repo.display()
        )));
    }
    let text = stdout_utf8(output, "worktree list")?;
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            out.push(std::path::PathBuf::from(path.trim()));
        }
    }
    Ok(out)
}

/// One commit reachable from `HEAD`: its SHA, committer time (unix seconds),
/// and the repo-relative paths it changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRecord {
    pub sha: String,
    pub time: i64,
    pub files: Vec<String>,
}

/// `git log --format=<RS>%H %ct --name-only HEAD`: every commit reachable
/// from `HEAD`, newest first. The `%x1e` record separator delimits commits
/// so a changed path can never be mistaken for a header. An unborn HEAD
/// (no commits yet) yields an empty vec, never an error.
pub fn commit_log(repo: &Path) -> Result<Vec<CommitRecord>, GitError> {
    let output = git_output(repo, &["log", "--format=%x1e%H %ct", "--name-only", "HEAD"])?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let text = stdout_utf8(output, "git log")?;
    let mut out = Vec::new();
    for chunk in text.split('\u{001e}') {
        if chunk.trim().is_empty() {
            continue;
        }
        let mut lines = chunk.lines();
        let Some(header) = lines.next() else {
            continue;
        };
        let mut iter = header.split_whitespace();
        let (Some(sha), Some(time)) = (iter.next(), iter.next()) else {
            continue;
        };
        let Ok(time) = time.parse::<i64>() else {
            continue;
        };
        let files: Vec<String> = lines
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        out.push(CommitRecord {
            sha: sha.to_string(),
            time,
            files,
        });
    }
    Ok(out)
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

/// J4 (`trail push`/`trail checkout`) git helpers: argv arrays only, and every
/// fn takes `env`, applied with `Command::envs`, so trail commands run git
/// with `TrailCtx.git_env` (empty in production, hermetic in tests). `push`
/// and `fetch` inherit stdin and stderr so credential prompts, progress, and
/// `remote:` lines reach the user; the rest capture output. The CLI never
/// hands its API token to git: authentication is the user's remote config.
fn git_with(repo: &Path, env: &[(OsString, OsString)], args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args).envs(env.iter().cloned());
    cmd
}

/// `git symbolic-ref --quiet --short HEAD`: the current branch, or `None`
/// when HEAD is detached (exit status 1 with no output).
pub fn current_branch(
    repo: &Path,
    env: &[(OsString, OsString)],
) -> Result<Option<String>, GitError> {
    let output = git_with(repo, env, &["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if output.status.success() {
        let name = stdout_utf8(output, "current branch")?;
        let name = name.trim();
        return Ok(if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        });
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    Err(GitError::Failed(format!(
        "git symbolic-ref HEAD failed in {}",
        repo.display()
    )))
}

/// `git rev-parse HEAD`: the current commit SHA.
pub fn head_sha(repo: &Path, env: &[(OsString, OsString)]) -> Result<String, GitError> {
    let output = git_with(repo, env, &["rev-parse", "HEAD"])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if !output.status.success() {
        return Err(status_failed(&output, "git rev-parse HEAD", repo));
    }
    Ok(stdout_utf8(output, "HEAD")?.trim().to_string())
}

/// `git ls-remote --symref <remote> HEAD`: the remote's default branch, or
/// `None` when the remote advertises no `HEAD` symref.
pub fn remote_default_branch(
    repo: &Path,
    remote: &str,
    env: &[(OsString, OsString)],
) -> Result<Option<String>, GitError> {
    let output = git_with(repo, env, &["ls-remote", "--symref", remote, "HEAD"])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if !output.status.success() {
        return Err(status_failed(&output, "git ls-remote --symref", repo));
    }
    let stdout = stdout_utf8(output, "ls-remote")?;
    for line in stdout.lines() {
        if let Some((lhs, rhs)) = line.split_once('\t')
            && rhs.trim() == "HEAD"
            && let Some(target) = lhs.strip_prefix("ref: ")
            && let Some(branch) = target.strip_prefix("refs/heads/")
            && !branch.is_empty()
        {
            return Ok(Some(branch.to_string()));
        }
    }
    Ok(None)
}

/// `git push <remote> <refspec>` with `-o <opt>` per push option. Stdin and
/// stderr are inherited; a non-zero exit is always an error.
pub fn push_refspec(
    repo: &Path,
    remote: &str,
    refspec: &str,
    push_options: &[String],
    env: &[(OsString, OsString)],
) -> Result<(), GitError> {
    let mut cmd = git_with(repo, env, &["push", remote, refspec]);
    for opt in push_options {
        cmd.arg("-o").arg(opt);
    }
    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(GitError::Failed("git push failed".to_string()))
    }
}

/// `git fetch --no-tags <remote> <sha>`: fetch a change head by SHA (the
/// server sets `uploadpack.allowTipSHA1InWant`, so tip SHAs are fetchable
/// even though trail refs stay hidden). Stdin and stderr are inherited.
pub fn fetch_object(
    repo: &Path,
    remote: &str,
    sha: &str,
    env: &[(OsString, OsString)],
) -> Result<(), GitError> {
    let status = git_with(repo, env, &["fetch", "--no-tags", remote, sha])
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(GitError::Failed("git fetch failed".to_string()))
    }
}

/// `git rev-parse --verify --quiet refs/heads/<branch>`: the branch tip, or
/// `None` when the branch does not exist (exit status 1 with no output).
pub fn branch_tip(
    repo: &Path,
    branch: &str,
    env: &[(OsString, OsString)],
) -> Result<Option<String>, GitError> {
    let output = git_with(
        repo,
        env,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
    )
    .output()
    .map_err(|err| GitError::Spawn(err.to_string()))?;
    if output.status.success() {
        let tip = stdout_utf8(output, "branch tip")?;
        let tip = tip.trim();
        return Ok(if tip.is_empty() {
            None
        } else {
            Some(tip.to_string())
        });
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    Err(status_failed(&output, "git rev-parse --verify", repo))
}

/// `git merge-base --is-ancestor <ancestor> <descendant>`.
pub fn is_ancestor(
    repo: &Path,
    ancestor: &str,
    descendant: &str,
    env: &[(OsString, OsString)],
) -> Result<bool, GitError> {
    let output = git_with(
        repo,
        env,
        &["merge-base", "--is-ancestor", ancestor, descendant],
    )
    .output()
    .map_err(|err| GitError::Spawn(err.to_string()))?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    Err(status_failed(&output, "git merge-base --is-ancestor", repo))
}

/// `git check-ref-format --branch <name>`: whether git accepts the name as a
/// branch name. A repo probe runs first so a broken injected env surfaces as
/// an error (`check-ref-format` itself never touches the repo).
pub fn valid_branch_name(
    repo: &Path,
    name: &str,
    env: &[(OsString, OsString)],
) -> Result<bool, GitError> {
    let probe = git_with(repo, env, &["rev-parse", "--git-dir"])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if !probe.status.success() {
        return Err(status_failed(&probe, "git rev-parse --git-dir", repo));
    }
    let output = git_with(repo, env, &["check-ref-format", "--branch", name])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    Ok(output.status.success())
}

/// `git switch --create <branch> <sha>`.
pub fn switch_create(
    repo: &Path,
    branch: &str,
    sha: &str,
    env: &[(OsString, OsString)],
) -> Result<(), GitError> {
    let output = git_with(repo, env, &["switch", "--create", branch, sha])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(status_failed(&output, "git switch --create", repo))
    }
}

/// `git switch <branch>`.
pub fn switch_to(repo: &Path, branch: &str, env: &[(OsString, OsString)]) -> Result<(), GitError> {
    let output = git_with(repo, env, &["switch", branch])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(status_failed(&output, "git switch", repo))
    }
}

/// `git merge --ff-only <sha>`.
pub fn merge_ff_only(repo: &Path, sha: &str, env: &[(OsString, OsString)]) -> Result<(), GitError> {
    let output = git_with(repo, env, &["merge", "--ff-only", sha])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(status_failed(&output, "git merge --ff-only", repo))
    }
}

/// `git switch --detach <sha>`.
pub fn switch_detach(repo: &Path, sha: &str, env: &[(OsString, OsString)]) -> Result<(), GitError> {
    let output = git_with(repo, env, &["switch", "--detach", sha])
        .output()
        .map_err(|err| GitError::Spawn(err.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(status_failed(&output, "git switch --detach", repo))
    }
}

/// Failure detail: the command, the repo, and git's stderr first line when
/// there is one.
fn status_failed(output: &std::process::Output, what: &str, repo: &Path) -> GitError {
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    if detail.is_empty() {
        GitError::Failed(format!("{what} failed in {}", repo.display()))
    } else {
        GitError::Failed(format!("{what} failed in {}: {detail}", repo.display()))
    }
}

#[cfg(test)]
mod sync_tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// Hermetic env for git subprocesses: no system/global config, no
    /// prompts, a scratch HOME, and an identity so `commit` works without
    /// developer config. `set_var` is forbidden workspace-wide, so every
    /// value travels through the injected `env`.
    fn hermetic(home: &Path) -> Vec<(OsString, OsString)> {
        [
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_ASKPASS", "/bin/false"),
        ]
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .chain([(OsString::from("HOME"), home.as_os_str().to_os_string())])
        .chain(
            [
                ("GIT_AUTHOR_NAME", "Test"),
                ("GIT_AUTHOR_EMAIL", "test@example.com"),
                ("GIT_COMMITTER_NAME", "Test"),
                ("GIT_COMMITTER_EMAIL", "test@example.com"),
            ]
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        )
        .collect()
    }

    fn run(repo: &Path, env: &[(OsString, OsString)], args: &[&str]) {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .envs(env.iter().cloned())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Scratch home plus a repo with one commit on `main`.
    fn setup() -> (tempfile::TempDir, PathBuf, Vec<(OsString, OsString)>) {
        let tmp = tempfile::tempdir().unwrap();
        let env = hermetic(tmp.path());
        let repo = tmp.path().join("work");
        run(tmp.path(), &env, &["init", "-q", "-b", "main", "work"]);
        std::fs::write(repo.join("README.md"), "# proj\n").unwrap();
        run(&repo, &env, &["add", "-A"]);
        run(&repo, &env, &["commit", "-q", "-m", "initial commit"]);
        (tmp, repo, env)
    }

    #[test]
    fn current_branch_on_branch_and_detached() {
        let (_tmp, repo, env) = setup();
        assert_eq!(
            current_branch(&repo, &env).unwrap(),
            Some("main".to_string())
        );
        run(&repo, &env, &["switch", "-q", "--detach", "HEAD"]);
        assert_eq!(current_branch(&repo, &env).unwrap(), None);
    }

    #[test]
    fn head_sha_and_branch_tip_round_trip() {
        let (_tmp, repo, env) = setup();
        let sha = head_sha(&repo, &env).unwrap();
        assert_eq!(sha.len(), 40);
        assert_eq!(branch_tip(&repo, "main", &env).unwrap(), Some(sha));
        assert_eq!(branch_tip(&repo, "nope", &env).unwrap(), None);
    }

    #[test]
    fn remote_default_branch_reads_bare_head() {
        let (_tmp, repo, env) = setup();
        let remote = repo.parent().unwrap().join("bare.git");
        run(
            repo.parent().unwrap(),
            &env,
            &["init", "-q", "--bare", "bare.git"],
        );
        run(&remote, &env, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        run(
            &repo,
            &env,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        // An empty repo advertises no symref; push `main` first.
        run(&repo, &env, &["push", "-q", "origin", "main"]);
        assert_eq!(
            remote_default_branch(&repo, "origin", &env).unwrap(),
            Some("main".to_string())
        );
    }

    #[test]
    fn switch_and_merge_cover_branch_lifecycle() {
        let (_tmp, repo, env) = setup();
        let sha = head_sha(&repo, &env).unwrap();
        switch_create(&repo, "trail/1/1", &sha, &env).unwrap();
        assert_eq!(
            branch_tip(&repo, "trail/1/1", &env).unwrap(),
            Some(sha.clone())
        );
        switch_to(&repo, "trail/1/1", &env).unwrap();
        assert_eq!(
            current_branch(&repo, &env).unwrap(),
            Some("trail/1/1".to_string())
        );
        std::fs::write(repo.join("more"), "x").unwrap();
        run(&repo, &env, &["add", "-A"]);
        run(&repo, &env, &["commit", "-q", "-m", "second"]);
        let next = head_sha(&repo, &env).unwrap();
        switch_to(&repo, "main", &env).unwrap();
        assert!(is_ancestor(&repo, &sha, &next, &env).unwrap());
        assert!(!is_ancestor(&repo, &next, &sha, &env).unwrap());
        merge_ff_only(&repo, &next, &env).unwrap();
        assert_eq!(head_sha(&repo, &env).unwrap(), next);
        switch_detach(&repo, &sha, &env).unwrap();
        assert_eq!(current_branch(&repo, &env).unwrap(), None);
        assert_eq!(head_sha(&repo, &env).unwrap(), sha);
    }

    #[test]
    fn valid_branch_name_accepts_and_rejects() {
        let (_tmp, repo, env) = setup();
        assert!(valid_branch_name(&repo, "trail/1/1", &env).unwrap());
        assert!(!valid_branch_name(&repo, "bad..name", &env).unwrap());
    }

    #[test]
    fn push_and_fetch_use_plain_git() {
        let (_tmp, repo, env) = setup();
        let remote = repo.parent().unwrap().join("bare.git");
        run(
            repo.parent().unwrap(),
            &env,
            &["init", "-q", "--bare", "bare.git"],
        );
        run(
            &repo,
            &env,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        let sha = head_sha(&repo, &env).unwrap();
        push_refspec(&repo, "origin", "HEAD:refs/for/main", &[], &env).unwrap();
        fetch_object(&repo, "origin", &sha, &env).unwrap();
    }

    /// Every new git fn applies the injected env: a wrong `GIT_DIR` fails.
    #[test]
    fn every_fn_honors_injected_env() {
        let (_tmp, repo, env) = setup();
        let mut bad = env.clone();
        bad.push((
            OsString::from("GIT_DIR"),
            OsString::from("/nonexistent-starforge-git-dir"),
        ));
        assert!(current_branch(&repo, &bad).is_err());
        assert!(head_sha(&repo, &bad).is_err());
        assert!(remote_default_branch(&repo, "origin", &bad).is_err());
        assert!(branch_tip(&repo, "main", &bad).is_err());
        assert!(is_ancestor(&repo, "a", "b", &bad).is_err());
        assert!(valid_branch_name(&repo, "trail/1/1", &bad).is_err());
        assert!(switch_create(&repo, "b", "s", &bad).is_err());
        assert!(switch_to(&repo, "b", &bad).is_err());
        assert!(merge_ff_only(&repo, "s", &bad).is_err());
        assert!(switch_detach(&repo, "s", &bad).is_err());
        assert!(push_refspec(&repo, "origin", "HEAD:refs/for/main", &[], &bad).is_err());
        assert!(fetch_object(&repo, "origin", "abc", &bad).is_err());
    }
}
