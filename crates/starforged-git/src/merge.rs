//! Mergeability probing (spec §8.4): `git merge-tree --write-tree` dry-runs a
//! merge with no worktree. Argv-only (validated SHAs, never a shell string),
//! hermetic env via [`command::git`], bounded by [`MERGE_TREE_TIMEOUT`].
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
