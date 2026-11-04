//! Changing hosted repositories with git plumbing.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;

use crate::command::{GitError, git, run};

/// Points the bare repository's `HEAD` at `refs/heads/<branch>`, so new clones check that branch out.
/// git refuses names that are not valid ref names.
pub async fn set_head(repo: &Path, branch: &str) -> Result<(), GitError> {
    let target = format!("refs/heads/{branch}");
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("symbolic-ref"),
        OsStr::new("HEAD"),
        OsStr::new(&target),
    ])
    .await?;
    Ok(())
}

/// Who a commit written by the server is by. `time` is unix seconds.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub time: i64,
}

/// Writes the first commit of `branch`: `files` (a name without `/`, and the content) at the root of the
/// tree, with `author` as author and committer. Fails without changing any ref when `branch` already exists.
/// Returns the commit id.
pub async fn initial_commit(
    repo: &Path,
    branch: &str,
    files: &[(&str, &[u8])],
    author: Identity<'_>,
    message: &str,
) -> Result<String, GitError> {
    let mut tree = String::new();
    for (name, content) in files {
        let blob = plumbing(repo, &["hash-object", "-w", "--stdin"], Some(content), &[]).await?;
        tree.push_str(&format!("100644 blob {blob}\t{name}\n"));
    }
    let tree_id = plumbing(repo, &["mktree"], Some(tree.as_bytes()), &[]).await?;
    let date = format!("@{} +0000", author.time);
    let env = [
        ("GIT_AUTHOR_NAME", author.name),
        ("GIT_AUTHOR_EMAIL", author.email),
        ("GIT_AUTHOR_DATE", date.as_str()),
        ("GIT_COMMITTER_NAME", author.name),
        ("GIT_COMMITTER_EMAIL", author.email),
        ("GIT_COMMITTER_DATE", date.as_str()),
    ];
    let commit = plumbing(repo, &["commit-tree", &tree_id, "-m", message], None, &env).await?;
    // The empty old value makes `update-ref` refuse to overwrite an existing branch.
    let target = format!("refs/heads/{branch}");
    plumbing(repo, &["update-ref", &target, &commit, ""], None, &[]).await?;
    Ok(commit)
}

/// Runs `git --git-dir <repo> <args>` with optional stdin and extra environment; returns trimmed stdout.
async fn plumbing(
    repo: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    env: &[(&str, &str)],
) -> Result<String, GitError> {
    let mut command = git();
    command
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;
    if let Some(input) = stdin
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(input).await?;
        // `pipe` drops here, closing git's stdin.
    }
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command: args.first().copied().unwrap_or_default().to_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_head_moves_the_symbolic_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        set_head(&repo, "feature/x").await.unwrap();
        assert_eq!(
            std::fs::read_to_string(repo.join("HEAD")).unwrap(),
            "ref: refs/heads/feature/x\n"
        );
        assert!(set_head(&repo, "bad..name").await.is_err());
        assert_eq!(
            std::fs::read_to_string(repo.join("HEAD")).unwrap(),
            "ref: refs/heads/feature/x\n"
        );
    }

    #[tokio::test]
    async fn initial_commit_writes_the_first_commit_once() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        let author = Identity {
            name: "Alice Doe",
            email: "alice@example.com",
            time: 1_700_000_000,
        };
        let id = initial_commit(
            &repo,
            "main",
            &[("README.md", b"# proj\n")],
            author,
            "Initial commit",
        )
        .await
        .unwrap();
        let log = crate::read::log(&repo, &id, 0, 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            (
                log[0].summary.as_str(),
                log[0].author_name.as_str(),
                log[0].author_email.as_str(),
                log[0].author_time
            ),
            (
                "Initial commit",
                "Alice Doe",
                "alice@example.com",
                1_700_000_000
            )
        );
        assert_eq!(
            crate::read::blob_bytes(&repo, &id, "README.md")
                .unwrap()
                .unwrap(),
            b"# proj\n"
        );
        assert_eq!(crate::read::branches(&repo).unwrap(), vec!["main"]);
        let again =
            initial_commit(&repo, "main", &[("README.md", b"other\n")], author, "Again").await;
        assert!(again.is_err(), "an existing branch is never overwritten");
        assert_eq!(
            crate::read::resolve(&repo, "main")
                .unwrap()
                .unwrap()
                .commit_id,
            id
        );
    }
}
