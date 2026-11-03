//! Repository content for viewers who passed a permission check (they hold a `RepoAccess`).

use starforged_git::GitError;
use starforged_git::diff::CommitDiff;
use starforged_git::read::{self, CommitInfo, Resolved, TreeEntry};

use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// Largest file the web UI renders inline.
pub const MAX_INLINE_BLOB_BYTES: usize = 1024 * 1024;

async fn blocking<T, F>(f: F) -> CoreResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, GitError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?
        .map_err(CoreError::from)
}

impl Core {
    pub async fn branches(&self, access: &RepoAccess) -> CoreResult<Vec<String>> {
        let repo = self.repo_path(access.repo.id);
        blocking(move || read::branches(&repo)).await
    }

    /// Resolves a `<ref>/<path>` URL suffix; `NotFound` when no branch, tag, or commit matches.
    pub async fn resolve(&self, access: &RepoAccess, rest: &str) -> CoreResult<Resolved> {
        let repo = self.repo_path(access.repo.id);
        let rest = rest.to_owned();
        blocking(move || read::resolve(&repo, &rest))
            .await?
            .ok_or(CoreError::NotFound)
    }

    pub async fn tree(
        &self,
        access: &RepoAccess,
        commit_id: &str,
        dir: &str,
    ) -> CoreResult<Vec<TreeEntry>> {
        let repo = self.repo_path(access.repo.id);
        let (commit_id, dir) = (commit_id.to_owned(), dir.to_owned());
        blocking(move || read::tree(&repo, &commit_id, &dir))
            .await?
            .ok_or(CoreError::NotFound)
    }

    pub async fn blob(
        &self,
        access: &RepoAccess,
        commit_id: &str,
        file: &str,
    ) -> CoreResult<Vec<u8>> {
        let repo = self.repo_path(access.repo.id);
        let (commit_id, file) = (commit_id.to_owned(), file.to_owned());
        blocking(move || read::blob_bytes(&repo, &commit_id, &file))
            .await?
            .ok_or(CoreError::NotFound)
    }

    pub async fn log(
        &self,
        access: &RepoAccess,
        commit_id: &str,
        skip: usize,
        limit: usize,
    ) -> CoreResult<Vec<CommitInfo>> {
        let repo = self.repo_path(access.repo.id);
        let commit_id = commit_id.to_owned();
        blocking(move || read::log(&repo, &commit_id, skip, limit)).await
    }

    pub async fn commit(&self, access: &RepoAccess, id: &str) -> CoreResult<CommitInfo> {
        let repo = self.repo_path(access.repo.id);
        let id = id.to_owned();
        blocking(move || read::commit(&repo, &id))
            .await?
            .ok_or(CoreError::NotFound)
    }
}

/// Diff lines rendered per commit before truncating.
pub const MAX_DIFF_LINES: usize = 10_000;

impl Core {
    /// The diff of commit `commit_id` against its first parent.
    pub async fn diff(&self, access: &RepoAccess, commit_id: &str) -> CoreResult<CommitDiff> {
        let repo = self.repo_path(access.repo.id);
        Ok(starforged_git::diff::commit_diff(&repo, commit_id, MAX_DIFF_LINES).await?)
    }
}
