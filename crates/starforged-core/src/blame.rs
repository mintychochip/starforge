//! Blame enriched with readable session links (M1e E4).
//!
//! [`Core::blame_with_sessions`] resolves `rev` through the same
//! [`Core::resolve`] path the tree/blob pages use, refuses files the blob
//! page would not render inline, and attaches to each blamed commit the
//! linked sessions the viewer may read — via the same per-row
//! [`can_read_session`](crate::read::can_read_session) filter as
//! [`Core::readable_links_for_commit`]. Unreadable links are omitted
//! entirely, never leaked as locked chips.

use std::collections::HashMap;

use starforged_db::sessions::{CommitLinkRow, SessionRow};
use starforged_git::blame::{self, BlameError};
use starforged_git::read;

use crate::accounts::User;
use crate::content::MAX_INLINE_BLOB_BYTES;
use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// One blamed run with the sessions its commit links to.
#[derive(Debug, Clone)]
pub struct BlameBlockView {
    pub sha: String,
    pub author: String,
    pub author_time: i64,
    /// First line of the commit summary.
    pub summary: String,
    /// 1-based number of the run's first line in the file.
    pub start: usize,
    pub lines: Vec<String>,
    /// Linked sessions the viewer may read, oldest first.
    pub sessions: Vec<(CommitLinkRow, SessionRow)>,
}

/// A blamed file: the resolved revision plus its runs in file order.
#[derive(Debug, Clone)]
pub struct BlameView {
    pub ref_name: String,
    pub commit_id: String,
    pub path: String,
    /// Set when the file cannot be blamed (binary or too large for inline
    /// display); `blocks` is empty and the page shows this instead.
    pub unavailable: Option<String>,
    pub blocks: Vec<BlameBlockView>,
}

/// A path is blameable only when the blob page could render it: no traversal,
/// no absolute paths, never empty.
fn valid_path(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && !path.split('/').any(|s| s == "..")
}

async fn blocking<T, F>(f: F) -> CoreResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, BlameError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?
        .map_err(|e| match e {
            BlameError::NotFound => CoreError::NotFound,
            BlameError::Unavailable => CoreError::NotFound,
            BlameError::Git(git) => CoreError::from(git),
        })
}

impl Core {
    /// Blames `path` at `rev` (branch, tag, or commit id; `None` or empty
    /// means the default branch) and enriches each run with the linked
    /// sessions `viewer` may read.
    ///
    /// Unknown revs, missing files, and traversal/absolute paths answer
    /// [`CoreError::NotFound`]. Binary and oversized files answer a view with
    /// `unavailable` set instead of failing.
    pub async fn blame_with_sessions(
        &self,
        access: &RepoAccess,
        viewer: Option<&User>,
        rev: Option<&str>,
        path: &str,
    ) -> CoreResult<BlameView> {
        if !valid_path(path) {
            return Err(CoreError::NotFound);
        }
        let repo = self.repo_path(access.repo.id);
        let rev = rev.filter(|r| !r.is_empty()).map(str::to_owned);
        let default_branch = access.repo.default_branch.clone();
        let path_owned = path.to_owned();
        let resolved = tokio::task::spawn_blocking(move || {
            let rev = rev.as_deref().unwrap_or(&default_branch);
            // `resolve` needs `<ref>/<path>`; unknown revs resolve to `None`.
            read::resolve(&repo, &format!("{rev}/{path_owned}"))
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?
        .map_err(CoreError::from)?
        .ok_or(CoreError::NotFound)?;
        if resolved.path != path {
            return Err(CoreError::NotFound);
        }

        let base = BlameView {
            ref_name: resolved.ref_name.clone(),
            commit_id: resolved.commit_id.clone(),
            path: path.to_owned(),
            unavailable: None,
            blocks: Vec::new(),
        };
        // The same inline gate as the blob page: oversized files never reach
        // memory, and binary files have no lines worth attributing.
        let repo = self.repo_path(access.repo.id);
        let (commit_id, file) = (resolved.commit_id.clone(), resolved.path.clone());
        let probe = tokio::task::spawn_blocking(move || read::blob_ref(&repo, &commit_id, &file))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?
            .map_err(CoreError::from)?
            .ok_or(CoreError::NotFound)?;
        if probe.size > MAX_INLINE_BLOB_BYTES as u64 {
            return Ok(BlameView {
                unavailable: Some("Blame is unavailable for large files.".into()),
                ..base
            });
        }
        let repo = self.repo_path(access.repo.id);
        let (commit_id, file) = (resolved.commit_id.clone(), resolved.path.clone());
        let bytes = tokio::task::spawn_blocking(move || read::blob_bytes(&repo, &commit_id, &file))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?
            .map_err(CoreError::from)?
            .ok_or(CoreError::NotFound)?;
        if matches!(read::classify(bytes), read::Blob::Binary) {
            return Ok(BlameView {
                unavailable: Some("Blame is unavailable for binary files.".into()),
                ..base
            });
        }

        let repo = self.repo_path(access.repo.id);
        let (commit_id, file) = (resolved.commit_id.clone(), resolved.path.clone());
        let runs = blocking(move || blame::blame(&repo, &commit_id, &file)).await?;

        // One batched link lookup for every distinct sha (E3's batch fn, one
        // query total), then the same per-row read filter as the commit panel.
        let shas: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            let mut ordered = Vec::new();
            for run in &runs {
                if seen.insert(run.sha.clone()) {
                    ordered.push(run.sha.clone());
                }
            }
            ordered
        };
        let links = starforged_db::sessions::links_for_shas(self.db(), access.repo.id, &shas)
            .await
            .map_err(CoreError::from)?;
        let readable = self.filter_readable_links(access, viewer, links).await?;
        let mut by_sha: HashMap<String, Vec<(CommitLinkRow, SessionRow)>> = HashMap::new();
        for (link, session) in readable {
            by_sha
                .entry(link.sha.clone())
                .or_default()
                .push((link, session));
        }

        Ok(BlameView {
            blocks: runs
                .into_iter()
                .map(|run| BlameBlockView {
                    sessions: by_sha.remove(&run.sha).unwrap_or_default(),
                    sha: run.sha,
                    author: run.author,
                    author_time: run.author_time,
                    summary: run.summary,
                    start: run.start,
                    lines: run.lines,
                })
                .collect(),
            ..base
        })
    }
}
