//! Repository content for viewers who passed a permission check (they hold a `RepoAccess`).

use starforged_git::GitError;
use starforged_git::diff::CommitDiff;
use starforged_git::read::{self, BranchInfo, CommitInfo, Resolved, TagInfo, TreeEntry};

use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// Largest file the web UI renders inline.
pub const MAX_INLINE_BLOB_BYTES: usize = 1024 * 1024;

/// A file's identity and size, with content only when it fits inline.
pub struct FileBlob {
    /// Full lowercase hex object id of the blob, for [`Core::blob_stream`].
    pub id: String,
    /// Size of the blob's content in bytes.
    pub size: u64,
    /// The content when `size <= MAX_INLINE_BLOB_BYTES as u64`; otherwise `None`.
    pub bytes: Option<Vec<u8>>,
}

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

    /// Branches with their tip commits, the newest tip first.
    pub async fn branch_list(&self, access: &RepoAccess) -> CoreResult<Vec<BranchInfo>> {
        let repo = self.repo_path(access.repo.id);
        blocking(move || read::branch_list(&repo)).await
    }

    /// Tags with their commits, the newest first.
    pub async fn tag_list(&self, access: &RepoAccess) -> CoreResult<Vec<TagInfo>> {
        let repo = self.repo_path(access.repo.id);
        blocking(move || read::tag_list(&repo)).await
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

    /// Identity, size, and (for small files) content of `file` in `commit_id`.
    /// Files larger than [`MAX_INLINE_BLOB_BYTES`] are never read into memory:
    /// `bytes` is `None` and the caller streams them with [`Core::blob_stream`].
    pub async fn blob(
        &self,
        access: &RepoAccess,
        commit_id: &str,
        file: &str,
    ) -> CoreResult<FileBlob> {
        let repo = self.repo_path(access.repo.id);
        let (commit_id, file) = (commit_id.to_owned(), file.to_owned());
        let probe = (repo.clone(), commit_id.clone(), file.clone());
        let meta = blocking(move || read::blob_ref(&probe.0, &probe.1, &probe.2))
            .await?
            .ok_or(CoreError::NotFound)?;
        let bytes = if meta.size <= MAX_INLINE_BLOB_BYTES as u64 {
            Some(
                blocking(move || read::blob_bytes(&repo, &commit_id, &file))
                    .await?
                    .ok_or(CoreError::NotFound)?,
            )
        } else {
            None
        };
        Ok(FileBlob {
            id: meta.id,
            size: meta.size,
            bytes,
        })
    }

    /// Streams the blob with object id `id` (from [`FileBlob::id`]) without
    /// loading it into memory.
    pub async fn blob_stream(
        &self,
        access: &RepoAccess,
        id: &str,
    ) -> CoreResult<tokio::process::ChildStdout> {
        read::stream_blob(&self.repo_path(access.repo.id), id).map_err(CoreError::from)
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

    /// Up to `limit` commits reachable from `commit_id` that touched `path`,
    /// newest first, after skipping `skip` matches; renames are not followed.
    pub async fn log_path(
        &self,
        access: &RepoAccess,
        commit_id: &str,
        path: &str,
        skip: usize,
        limit: usize,
    ) -> CoreResult<Vec<CommitInfo>> {
        let repo = self.repo_path(access.repo.id);
        let commit_id = commit_id.to_owned();
        let path = path.to_owned();
        blocking(move || read::log_path(&repo, &commit_id, &path, skip, limit)).await
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

/// Largest `git show` output the commit page reads before truncating the diff.
pub const MAX_DIFF_BYTES: usize = 4 * 1024 * 1024;

impl Core {
    /// The diff of commit `commit_id` against its first parent.
    pub async fn diff(&self, access: &RepoAccess, commit_id: &str) -> CoreResult<CommitDiff> {
        let repo = self.repo_path(access.repo.id);
        Ok(
            starforged_git::diff::commit_diff(&repo, commit_id, MAX_DIFF_LINES, MAX_DIFF_BYTES)
                .await?,
        )
    }
}

/// Most commits a comparison lists; the rest are counted.
pub const MAX_COMPARE_COMMITS: usize = 250;

/// What `head` adds to `base` (forge-basics design §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    pub base: Resolved,
    pub head: Resolved,
    /// `None` when the refs share no history; `commits` and `diff` are then empty.
    pub merge_base: Option<String>,
    /// Newest first; at most [`MAX_COMPARE_COMMITS`].
    pub commits: Vec<CommitInfo>,
    /// Every commit reachable from `head` but not from `base`, listed or not.
    pub total_commits: usize,
    /// From the merge base to `head`, within [`MAX_DIFF_LINES`] and [`MAX_DIFF_BYTES`].
    pub diff: CommitDiff,
}

impl Core {
    /// Compares two refs (branch, tag, or full commit id) of one repository. Both are resolved to object ids
    /// before git runs; a name that is not exactly a ref is `NotFound`.
    pub async fn compare(
        &self,
        access: &RepoAccess,
        base: &str,
        head: &str,
    ) -> CoreResult<Comparison> {
        let base = self.resolve_exact(access, base).await?;
        let head = self.resolve_exact(access, head).await?;
        let repo = self.repo_path(access.repo.id);
        let (probe, a, b) = (repo.clone(), base.commit_id.clone(), head.commit_id.clone());
        let Some(merge_base) = blocking(move || read::merge_base(&probe, &a, &b)).await? else {
            return Ok(Comparison {
                base,
                head,
                merge_base: None,
                commits: Vec::new(),
                total_commits: 0,
                diff: CommitDiff {
                    files: Vec::new(),
                    truncated: false,
                },
            });
        };
        let (probe, a, b) = (repo.clone(), base.commit_id.clone(), head.commit_id.clone());
        let (commits, total_commits) =
            blocking(move || read::range_log(&probe, &a, &b, MAX_COMPARE_COMMITS)).await?;
        let diff = starforged_git::diff::range_diff(
            &repo,
            &merge_base,
            &head.commit_id,
            MAX_DIFF_LINES,
            MAX_DIFF_BYTES,
        )
        .await?;
        Ok(Comparison {
            base,
            head,
            merge_base: Some(merge_base),
            commits,
            total_commits,
            diff,
        })
    }

    /// A branch, tag, or commit id with nothing after it.
    async fn resolve_exact(&self, access: &RepoAccess, name: &str) -> CoreResult<Resolved> {
        let resolved = self.resolve(access, name).await?;
        if resolved.path.is_empty() {
            Ok(resolved)
        } else {
            Err(CoreError::NotFound)
        }
    }
}
