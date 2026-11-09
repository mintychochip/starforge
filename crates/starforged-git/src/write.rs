//! Changing hosted repositories with git plumbing.

use std::ffi::{OsStr, OsString};
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

/// How long one server-side write (`commit-tree`, `rev-parse`, `update-ref`)
/// may take; the caller sees a failed write, never a hang.
pub const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Builds a commit object without touching any ref: `commit-tree <tree>
/// (-p <parent>)* -m <msg>` with `author` as author and committer (argv-only;
/// `tree` and every parent must pass [`crate::refpolicy::is_oid`]). Returns
/// the new commit id.
pub async fn commit_tree(
    repo: &Path,
    tree: &str,
    parents: &[&str],
    message: &str,
    author: Identity<'_>,
) -> Result<String, GitError> {
    commit_tree_as(repo, tree, parents, message, author, author).await
}

/// Builds a commit object with distinct author and committer identities. The
/// rebase path preserves the original author (name, email, time) while the
/// server is the committer. Argv-only; `tree` and every parent must pass
/// [`crate::refpolicy::is_oid`]. Returns the new commit id.
pub async fn commit_tree_as(
    repo: &Path,
    tree: &str,
    parents: &[&str],
    message: &str,
    author: Identity<'_>,
    committer: Identity<'_>,
) -> Result<String, GitError> {
    if !crate::refpolicy::is_oid(tree) || !parents.iter().all(|p| crate::refpolicy::is_oid(p)) {
        return Err(GitError::Failed {
            command: "commit-tree".to_owned(),
            stderr: "commit-tree needs full object ids".to_owned(),
        });
    }
    let author_date = format!("@{} +0000", author.time);
    let committer_date = format!("@{} +0000", committer.time);
    let env = [
        ("GIT_AUTHOR_NAME", author.name),
        ("GIT_AUTHOR_EMAIL", author.email),
        ("GIT_AUTHOR_DATE", author_date.as_str()),
        ("GIT_COMMITTER_NAME", committer.name),
        ("GIT_COMMITTER_EMAIL", committer.email),
        ("GIT_COMMITTER_DATE", committer_date.as_str()),
    ];
    let mut args: Vec<&str> = vec!["commit-tree", tree];
    for parent in parents {
        args.push("-p");
        args.push(parent);
    }
    args.push("-m");
    args.push(message);
    let fut = plumbing(repo, &args, None, &env);
    tokio::time::timeout(WRITE_TIMEOUT, fut)
        .await
        .map_err(|_| GitError::Failed {
            command: "commit-tree".to_owned(),
            stderr: "commit-tree timed out".to_owned(),
        })?
}

/// Object id a `refs/starforge/checkpoints/*` ref points at (`rev-parse
/// --verify <name>`). Argv-only; any other namespace is refused, so caller
/// input cannot reach another ref.
pub async fn rev_parse_ref(repo: &Path, name: &str) -> Result<String, GitError> {
    if !name.starts_with("refs/starforge/checkpoints/") {
        return Err(GitError::Failed {
            command: "rev-parse".to_owned(),
            stderr: format!("refusing to resolve non-checkpoint ref {name:?}"),
        });
    }
    let args = ["rev-parse", "--verify", name];
    let fut = plumbing(repo, &args, None, &[]);
    tokio::time::timeout(WRITE_TIMEOUT, fut)
        .await
        .map_err(|_| GitError::Failed {
            command: "rev-parse".to_owned(),
            stderr: "rev-parse timed out".to_owned(),
        })?
}

/// Tree object id of commit `sha` (`rev-parse <sha>^{tree}`, argv-only; `sha`
/// must pass [`crate::refpolicy::is_oid`], so the `^{tree}` suffix cannot be
/// attacker-controlled).
pub async fn rev_parse_tree(repo: &Path, sha: &str) -> Result<String, GitError> {
    if !crate::refpolicy::is_oid(sha) {
        return Err(GitError::Failed {
            command: "rev-parse".to_owned(),
            stderr: "rev-parse needs a full object id".to_owned(),
        });
    }
    let spec = format!("{sha}^{{tree}}");
    let args = ["rev-parse", spec.as_str()];
    let fut = plumbing(repo, &args, None, &[]);
    tokio::time::timeout(WRITE_TIMEOUT, fut)
        .await
        .map_err(|_| GitError::Failed {
            command: "rev-parse".to_owned(),
            stderr: "rev-parse timed out".to_owned(),
        })?
}

/// Compare-and-swaps `refs/heads/<branch>` from `old` to `new` (`update-ref
/// <name> <new> <old>`, argv-only). `Ok(true)` when the ref moved; `Ok(false)`
/// when the ref moved under us — git reports `… is at <actual> but expected
/// <old>` (verified against real git), which is a retryable race, never a
/// hard error. Any other failure (bad name, missing ref, timeout) is `Err`.
/// Only `refs/heads/` refs move here; trail refs go through [`set_ref`].
pub async fn update_ref_cas(
    repo: &Path,
    name: &str,
    new: &str,
    old: &str,
) -> Result<bool, GitError> {
    if !name.starts_with("refs/heads/") {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: format!("refusing to CAS non-branch ref {name:?}"),
        });
    }
    if !crate::refpolicy::is_oid(new) || !crate::refpolicy::is_oid(old) {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: "update-ref needs full object ids".to_owned(),
        });
    }
    let args = ["update-ref", name, new, old];
    let fut = plumbing(repo, &args, None, &[]);
    match tokio::time::timeout(WRITE_TIMEOUT, fut).await {
        Err(_) => Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: "update-ref timed out".to_owned(),
        }),
        Ok(Ok(_)) => Ok(true),
        Ok(Err(GitError::Failed { command, stderr })) if is_cas_mismatch(&stderr) => {
            let _ = command;
            Ok(false)
        }
        Ok(Err(other)) => Err(other),
    }
}

/// True when git refused an `update-ref` because the ref moved: `… is at
/// <actual> but expected <old>`.
fn is_cas_mismatch(stderr: &str) -> bool {
    stderr.contains("but expected")
}

/// Points a server-only `refs/trails/*` ref at `sha`. Argv-only (`update-ref`
/// takes no rev spec); the name must stay inside `refs/trails/` and the sha
/// must pass [`crate::refpolicy::is_oid`], so client input can never escape
/// into another namespace or inject flags.
pub async fn set_ref(repo: &Path, name: &str, sha: &str) -> Result<(), GitError> {
    if !name.starts_with("refs/trails/") || crate::refpolicy::parse_for_ref(name).is_some() {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: format!("refusing to set non-trails ref {name:?}"),
        });
    }
    if !crate::refpolicy::is_oid(sha) {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: format!("refusing to set {name:?} to non-oid {sha:?}"),
        });
    }
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("update-ref"),
        OsStr::new(name),
        OsStr::new(sha),
    ])
    .await?;
    Ok(())
}

/// Deletes a pseudo-ref after the scan ingests it: `refs/for/*` (physically
/// created by receive-pack, never stored) or `refs/trails/*`. Argv-only; any
/// other namespace is refused without touching git.
pub async fn delete_ref(repo: &Path, name: &str) -> Result<(), GitError> {
    let deletable =
        crate::refpolicy::parse_for_ref(name).is_some() || name.starts_with("refs/trails/");
    if !deletable {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: format!("refusing to delete non-pseudo ref {name:?}"),
        });
    }
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("update-ref"),
        OsStr::new("-d"),
        OsStr::new(name),
    ])
    .await?;
    Ok(())
}

/// Creates a lightweight tag `refs/tags/<name>` pointing at `commit_id`.
/// Argv-only (`update-ref <ref> <commit> ""`): the empty old value makes git
/// refuse to overwrite a tag that already exists. The name must be a valid
/// tag name and `commit_id` must pass [`crate::refpolicy::is_oid`], so
/// caller input can never inject flags or escape the tags namespace.
pub async fn create_tag(repo: &Path, name: &str, commit_id: &str) -> Result<(), GitError> {
    if !valid_tag_name(name) {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: format!("refusing to create invalid tag {name:?}"),
        });
    }
    if !crate::refpolicy::is_oid(commit_id) {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: format!("refusing to point tag {name:?} at non-oid {commit_id:?}"),
        });
    }
    let target = format!("refs/tags/{name}");
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("update-ref"),
        OsStr::new(&target),
        OsStr::new(commit_id),
        OsStr::new(""),
    ])
    .await?;
    Ok(())
}

/// True for a tag name `git check-ref-format` accepts under `refs/tags/`:
/// non-empty, no control chars, spaces, or `~^:?*[\`, no `..` or `@{`, no
/// leading/trailing `/`, no `//`, no component starting with `.` or ending
/// with `.lock`, and not ending in `.`.
fn valid_tag_name(name: &str) -> bool {
    if name.is_empty()
        || name == "@"
        || name.starts_with('/')
        || name.ends_with('/')
        || name.ends_with('.')
        || name.contains("..")
        || name.contains("@{")
        || name.contains("//")
    {
        return false;
    }
    if name.bytes().any(|b| {
        b < 0x20 || b == 0x7f || matches!(b, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
    }) {
        return false;
    }
    name.split('/')
        .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

/// True for a branch name `git check-ref-format` accepts under
/// `refs/heads/`: the tag rules plus no leading `-` (which git would read as
/// an option).
fn valid_branch_name(name: &str) -> bool {
    !name.starts_with('-') && valid_tag_name(name)
}

/// Fetches one source branch into a temporary import ref in `repo` and
/// returns its tip. `source` is a local bare-repository path (both sides are
/// Starforge repositories). The refspec is built here from a validated branch
/// name; `temp_ref` must stay inside `refs/starforge/import/`. The caller
/// deletes the temporary ref after the change's trail refs point at the tip.
pub async fn fetch_branch(
    repo: &Path,
    source: &Path,
    branch: &str,
    temp_ref: &str,
) -> Result<String, GitError> {
    if !valid_branch_name(branch) {
        return Err(GitError::Failed {
            command: "fetch".to_owned(),
            stderr: format!("refusing to fetch invalid branch {branch:?}"),
        });
    }
    if !temp_ref.starts_with("refs/starforge/import/") {
        return Err(GitError::Failed {
            command: "fetch".to_owned(),
            stderr: format!("refusing to fetch into non-import ref {temp_ref:?}"),
        });
    }
    let refspec = format!("+refs/heads/{branch}:{temp_ref}");
    let args: Vec<OsString> = vec![
        "--git-dir".into(),
        repo.as_os_str().to_owned(),
        "fetch".into(),
        "--no-tags".into(),
        "--".into(),
        source.as_os_str().to_owned(),
        refspec.into(),
    ];
    let fut = run(args);
    tokio::time::timeout(WRITE_TIMEOUT, fut)
        .await
        .map_err(|_| GitError::Failed {
            command: "fetch".to_owned(),
            stderr: "fetch timed out".to_owned(),
        })??;
    plumbing(repo, &["rev-parse", temp_ref], None, &[]).await
}

/// Deletes a temporary `refs/starforge/import/*` ref after a cross-repository
/// change has recorded its head. Argv-only; any other namespace is refused.
pub async fn delete_import_ref(repo: &Path, name: &str) -> Result<(), GitError> {
    if !name.starts_with("refs/starforge/import/") {
        return Err(GitError::Failed {
            command: "update-ref".to_owned(),
            stderr: format!("refusing to delete non-import ref {name:?}"),
        });
    }
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("update-ref"),
        OsStr::new("-d"),
        OsStr::new(name),
    ])
    .await?;
    Ok(())
}

/// True when `sha` names a commit object present in `repo` (`cat-file -e
/// <sha>^{commit}`). A malformed id is `false`, never a git call.
pub async fn object_exists(repo: &Path, sha: &str) -> Result<bool, GitError> {
    if !crate::refpolicy::is_oid(sha) {
        return Ok(false);
    }
    let spec = format!("{sha}^{{commit}}");
    let mut cmd = git();
    cmd.arg("--git-dir")
        .arg(repo)
        .args(["cat-file", "-e", &spec]);
    let out = cmd.output().await?;
    Ok(out.status.success())
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

    #[tokio::test]
    async fn pseudo_refs_set_and_delete_inside_their_namespaces() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        let sha = initial_commit(
            &repo,
            "main",
            &[("README.md", b"# proj\n")],
            Identity {
                name: "A",
                email: "a@x",
                time: 1,
            },
            "Init",
        )
        .await
        .unwrap();
        set_ref(&repo, "refs/trails/1/changes/1/head", &sha)
            .await
            .unwrap();
        delete_ref(&repo, "refs/trails/1/changes/1/head")
            .await
            .unwrap();
        delete_ref(&repo, "refs/trails/1/changes/1/head")
            .await
            .unwrap();
        // Validation happens before git runs: no repo needed for these.
        assert!(set_ref(&repo, "refs/heads/main", &sha).await.is_err());
        assert!(set_ref(&repo, "refs/for/main/t", &sha).await.is_err());
        assert!(
            set_ref(&repo, "refs/trails/1/changes/1/head", "xyz")
                .await
                .is_err()
        );
        assert!(
            set_ref(&repo, "refs/trails/x", &"0".repeat(40))
                .await
                .is_err()
        );
        assert!(delete_ref(&repo, "refs/heads/main").await.is_err());
        assert!(delete_ref(&repo, "refs/tags/v1").await.is_err());
        delete_ref(&repo, "refs/trails/1/changes/1/head")
            .await
            .unwrap();
        delete_ref(&repo, "refs/for/main/t").await.unwrap();
    }
}
