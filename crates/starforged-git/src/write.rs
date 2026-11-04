//! Changing hosted repositories with git plumbing.

use std::ffi::OsStr;
use std::path::Path;

use crate::command::{GitError, run};

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
}
