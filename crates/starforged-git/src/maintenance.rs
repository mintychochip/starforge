//! Housekeeping for hosted repositories.

use std::ffi::OsStr;
use std::path::Path;

use crate::command::{GitError, run};

/// `git maintenance run --auto`: packs loose objects and refs when git's thresholds say it is worth it.
pub async fn run_auto(repo: &Path) -> Result<(), GitError> {
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("maintenance"),
        OsStr::new("run"),
        OsStr::new("--auto"),
    ])
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[tokio::test]
    async fn runs_on_bare_repositories_and_fails_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        super::run_auto(&repo).await.unwrap();
        assert!(
            super::run_auto(&tmp.path().join("missing.git"))
                .await
                .is_err()
        );
    }
}
