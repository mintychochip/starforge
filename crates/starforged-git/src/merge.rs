//! Merge-path probes (spec §8.4): `git merge-tree --write-tree` dry-runs a
//! merge with no worktree, and `git merge-base --is-ancestor` answers whether
//! a fast-forward is possible. Argv-only (validated SHAs, never a shell
//! string), hermetic env via [`command::git`], bounded by
//! [`MERGE_TREE_TIMEOUT`] / [`IS_ANCESTOR_TIMEOUT`]; on expiry the dropped
//! child is killed (`kill_on_drop`).
//!
//! Output contract (verified against real git): stdout's first line is the
//! resulting tree object id; with `--name-only` the conflicting paths follow,
//! one per line, up to the first blank line (informational `Auto-merging` /
//! `CONFLICT` messages come after it). Exit status `0` means the merge is
//! clean; anything else reports the conflicting paths.

use std::path::Path;
use std::time::Duration;

use crate::command::{GitError, git};
use crate::refpolicy;

/// How long one merge-tree probe may run; the worker treats a timeout as a
/// failed job attempt (retried), never as a verdict.
pub const MERGE_TREE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the fast-forward ancestry probe may run: the merge path's 60 s
/// budget (the same as `write::WRITE_TIMEOUT`).
pub const IS_ANCESTOR_TIMEOUT: Duration = Duration::from_secs(60);
/// Cap on reported conflict paths; the serialized payload is capped separately
/// by the caller.
pub const MAX_CONFLICT_PATHS: usize = 100;

/// The outcome of one merge-tree probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeTreeOutcome {
    /// True when git exited `0`: `head` merges cleanly into `base`.
    pub clean: bool,
    /// The resulting tree object id (first stdout line), when parseable.
    pub tree: Option<String>,
    /// Conflicting paths (`--name-only`), capped at [`MAX_CONFLICT_PATHS`].
    /// Empty both when clean and when git reported no parseable paths.
    pub paths: Vec<String>,
}

/// Dry-runs merging `head` into `base` (both full object ids) and reports the
/// outcome. Real git errors (missing repo, bad objects, timeouts) are `Err`;
/// only a completed probe with a non-zero status is a conflict.
pub async fn merge_tree(repo: &Path, base: &str, head: &str) -> Result<MergeTreeOutcome, GitError> {
    if !refpolicy::is_oid(base) || !refpolicy::is_oid(head) {
        return Err(GitError::Failed {
            command: "merge-tree --write-tree".to_owned(),
            stderr: "merge-tree needs full object ids".to_owned(),
        });
    }
    let mut cmd = git();
    cmd.arg("-C")
        .arg(repo)
        .arg("merge-tree")
        .arg("--write-tree")
        .arg("--name-only")
        .arg(base)
        .arg(head);
    let out = tokio::time::timeout(MERGE_TREE_TIMEOUT, cmd.output())
        .await
        .map_err(|_| GitError::Failed {
            command: "merge-tree --write-tree".to_owned(),
            stderr: "merge-tree timed out".to_owned(),
        })??;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (tree, mut paths) = parse_merge_tree(&stdout);
    paths.truncate(MAX_CONFLICT_PATHS);
    Ok(MergeTreeOutcome {
        clean: out.status.success(),
        tree,
        paths,
    })
}

/// Dry-runs merging `head` into `base` with an explicit merge base (the
/// rebase/cherry-pick probe): `git merge-tree --write-tree
/// --merge-base=<merge_base> <base> <head>`. All three must be full object
/// ids. Same output contract as [`merge_tree`].
pub async fn merge_tree_with_base(
    repo: &Path,
    base: &str,
    head: &str,
    merge_base: &str,
) -> Result<MergeTreeOutcome, GitError> {
    if !refpolicy::is_oid(base) || !refpolicy::is_oid(head) || !refpolicy::is_oid(merge_base) {
        return Err(GitError::Failed {
            command: "merge-tree --write-tree".to_owned(),
            stderr: "merge-tree needs full object ids".to_owned(),
        });
    }
    let mut cmd = git();
    cmd.arg("-C")
        .arg(repo)
        .arg("merge-tree")
        .arg("--write-tree")
        .arg("--name-only")
        .arg(format!("--merge-base={merge_base}"))
        .arg(base)
        .arg(head);
    let out = tokio::time::timeout(MERGE_TREE_TIMEOUT, cmd.output())
        .await
        .map_err(|_| GitError::Failed {
            command: "merge-tree --write-tree".to_owned(),
            stderr: "merge-tree timed out".to_owned(),
        })??;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (tree, mut paths) = parse_merge_tree(&stdout);
    paths.truncate(MAX_CONFLICT_PATHS);
    Ok(MergeTreeOutcome {
        clean: out.status.success(),
        tree,
        paths,
    })
}

/// Why a rebase could not produce a new head.
#[derive(Debug)]
pub enum RebaseError {
    /// A git command failed (missing objects, timeout, bad input).
    Git(GitError),
    /// The range contains a merge commit; rebase requires a linear history.
    NonLinear { commit: String, parents: usize },
    /// The range is longer than the caller's cap.
    TooMany { total: usize, max: usize },
    /// Replaying `commit` onto the new parent conflicted.
    Conflict { commit: String, paths: Vec<String> },
}

/// The result of a successful rebase: the new head commit and how many
/// commits were replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseOutcome {
    pub head: String,
    pub commits: usize,
}

/// Replays every commit in `merge_base..head` onto `base`, oldest first,
/// preserving each commit's author (name, email, time) and message, with
/// `committer` as the committer. Each replayed commit gets `trail_stamp`
/// appended as a `Starforge-Trail` trailer when absent. Refuses merge
/// commits and conflicts; the caller maps [`RebaseError`] to its own error
/// type. No ref moves here.
pub async fn rebase_onto(
    repo: &Path,
    base: &str,
    head: &str,
    merge_base: &str,
    committer: crate::write::Identity<'_>,
    trail_stamp: &str,
    max_commits: usize,
) -> Result<RebaseOutcome, RebaseError> {
    if !refpolicy::is_oid(base) || !refpolicy::is_oid(head) || !refpolicy::is_oid(merge_base) {
        return Err(RebaseError::Git(GitError::Failed {
            command: "rebase".to_owned(),
            stderr: "rebase needs full object ids".to_owned(),
        }));
    }
    let repo_path = repo.to_path_buf();
    let (from, to) = (merge_base.to_owned(), head.to_owned());
    let (mut commits, total) = tokio::task::spawn_blocking(move || {
        crate::read::range_log(&repo_path, &from, &to, max_commits)
    })
    .await
    .map_err(|e| {
        RebaseError::Git(GitError::Failed {
            command: "rebase".to_owned(),
            stderr: e.to_string(),
        })
    })?
    .map_err(RebaseError::Git)?;
    if total > max_commits {
        return Err(RebaseError::TooMany {
            total,
            max: max_commits,
        });
    }
    commits.reverse();
    let mut new_parent = base.to_owned();
    let mut replayed = 0_usize;
    for commit in commits {
        if commit.parents.len() != 1 {
            return Err(RebaseError::NonLinear {
                commit: commit.id,
                parents: commit.parents.len(),
            });
        }
        let original_parent = commit.parents[0].clone();
        let probe = merge_tree_with_base(repo, &new_parent, &commit.id, &original_parent)
            .await
            .map_err(RebaseError::Git)?;
        if !probe.clean {
            return Err(RebaseError::Conflict {
                commit: commit.id,
                paths: probe.paths,
            });
        }
        let tree = probe.tree.ok_or_else(|| {
            RebaseError::Git(GitError::Failed {
                command: "merge-tree --write-tree".to_owned(),
                stderr: "merge-tree reported clean with no tree".to_owned(),
            })
        })?;
        let message = append_trail_trailer(&commit.message, trail_stamp);
        let author = crate::write::Identity {
            name: &commit.author_name,
            email: &commit.author_email,
            time: commit.author_time,
        };
        let new_commit =
            crate::write::commit_tree_as(repo, &tree, &[&new_parent], &message, author, committer)
                .await
                .map_err(RebaseError::Git)?;
        new_parent = new_commit;
        replayed += 1;
    }
    Ok(RebaseOutcome {
        head: new_parent,
        commits: replayed,
    })
}

/// Appends `Starforge-Trail: <stamp>` to a commit message unless it already
/// carries that trailer.
fn append_trail_trailer(message: &str, stamp: &str) -> String {
    if message.contains("Starforge-Trail:") {
        return message.to_owned();
    }
    let mut out = message.trim_end().to_owned();
    out.push_str("\n\nStarforge-Trail: ");
    out.push_str(stamp);
    out.push('\n');
    out
}

/// True when `ancestor` is reachable from `head` (`merge-base --is-ancestor`:
/// exit `0` is true, `1` is false). Both must be full object ids. Any other
/// outcome — bad repo, missing object, an unexpected exit, or running past
/// [`IS_ANCESTOR_TIMEOUT`] (the child is killed) — is `Err`, never a verdict.
pub async fn is_ancestor(repo: &Path, ancestor: &str, head: &str) -> Result<bool, GitError> {
    if !refpolicy::is_oid(ancestor) || !refpolicy::is_oid(head) {
        return Err(GitError::Failed {
            command: "merge-base --is-ancestor".to_owned(),
            stderr: "merge-base needs full object ids".to_owned(),
        });
    }
    let mut cmd = git();
    cmd.arg("-C")
        .arg(repo)
        .arg("merge-base")
        .arg("--is-ancestor")
        .arg(ancestor)
        .arg(head);
    let out = tokio::time::timeout(IS_ANCESTOR_TIMEOUT, cmd.output())
        .await
        .map_err(|_| GitError::Failed {
            command: "merge-base --is-ancestor".to_owned(),
            stderr: "merge-base --is-ancestor timed out".to_owned(),
        })??;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Failed {
            command: "merge-base --is-ancestor".to_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        }),
    }
}

/// Sync `merge-base --is-ancestor` that inherits the process environment.
/// The hook runs inside receive-pack with the quarantined objects visible
/// through `GIT_OBJECT_DIRECTORY` / `GIT_ALTERNATE_OBJECT_DIRECTORIES`; the
/// hermetic [`git`] builder strips exactly those variables, so hook
/// ancestry checks must use this instead. Exit `0` is true, `1` is false;
/// anything else (missing objects, timeouts) is `Err`, never a verdict.
/// The probe is bounded by [`IS_ANCESTOR_TIMEOUT`] (same as the hermetic
/// probe; a timeout kills the child and is `Err`, so the caller's
/// error-means-not-an-ancestor policy fails closed) and pins the git
/// config (`GIT_CONFIG_NOSYSTEM`/`GLOBAL`/`TERMINAL_PROMPT`) like
/// [`crate::command::git`], while deliberately keeping the quarantine
/// object env.
pub fn is_ancestor_inherit_env(repo: &Path, ancestor: &str, head: &str) -> Result<bool, GitError> {
    if !refpolicy::is_oid(ancestor) || !refpolicy::is_oid(head) {
        return Err(GitError::Failed {
            command: "merge-base --is-ancestor".to_owned(),
            stderr: "merge-base needs full object ids".to_owned(),
        });
    }
    use std::io::Read as _;
    use std::process::Stdio;
    let mut child = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("merge-base")
        .arg("--is-ancestor")
        .arg(ancestor)
        .arg(head)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GitError::Io)?;
    let deadline = std::time::Instant::now() + IS_ANCESTOR_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(GitError::Io)? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(GitError::Failed {
                command: "merge-base --is-ancestor".to_owned(),
                stderr: "merge-base --is-ancestor timed out".to_owned(),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_end(&mut stderr);
    }
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Failed {
            command: "merge-base --is-ancestor".to_owned(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
        }),
    }
}

/// Splits merge-tree `--name-only` stdout into its tree line and conflict
/// paths: the paths run from the second line to the first blank line.
fn parse_merge_tree(stdout: &str) -> (Option<String>, Vec<String>) {
    let mut lines = stdout.lines();
    let tree = lines
        .next()
        .map(str::trim)
        .filter(|line| refpolicy::is_oid(line))
        .map(str::to_owned);
    let mut paths = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        paths.push(line.to_owned());
    }
    (tree, paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(clean: bool) -> &'static str {
        if clean {
            "31ed18425b8f64f9c15e12f5708a6992e65872d8\n"
        } else {
            "84bc6e906266a9e7c63f4b6a6e98053fca3047fa\n\
             f.txt\n\
             \n\
             Auto-merging f.txt\n\
             CONFLICT (content): Merge conflict in f.txt\n"
        }
    }

    #[test]
    fn parses_clean_output() {
        let (tree, paths) = parse_merge_tree(sample(true));
        assert_eq!(
            tree.as_deref(),
            Some("31ed18425b8f64f9c15e12f5708a6992e65872d8")
        );
        assert!(paths.is_empty());
    }

    #[test]
    fn parses_conflict_paths_before_the_blank_line() {
        let (tree, paths) = parse_merge_tree(sample(false));
        assert!(tree.is_some());
        assert_eq!(paths, vec!["f.txt".to_owned()]);
    }

    #[test]
    fn rejects_non_oid_inputs_without_running_git() {
        let repo = Path::new("/nonexistent");
        let err = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(merge_tree(repo, "main", "HEAD"));
        assert!(matches!(err, Err(GitError::Failed { .. })));
    }
}
