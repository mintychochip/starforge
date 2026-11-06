//! The GitHub-import status view (M4c G3): the fields the API and the
//! web settings page render. Carries no token material — only
//! `has_token` says whether a sealed token is still stored.
//!
//! This lives apart from [`super::importer`] so the read path never
//! depends on the importer's internals, and the row-to-view conversion
//! keeps `starforged-db` types out of the API/web crates.

use starforged_db::github_imports as db_imports;

use crate::{Core, CoreResult};

/// What the API and web page show for a repository's GitHub import:
/// never a secret, only progress, counts, and the scrubbed error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubImportView {
    pub id: i64,
    pub repo_id: i64,
    pub source: String,
    pub state: String,
    pub cursor_kind: String,
    pub cursor_page: i64,
    pub cursor_number: Option<i64>,
    pub issues_count: i64,
    pub pulls_count: i64,
    pub comments_count: i64,
    pub reviews_count: i64,
    pub review_comments_count: i64,
    /// Dropped assignees, `;`-joined (the importer's storage shape);
    /// renderers split on `;`.
    pub dropped_assignees: String,
    pub has_token: bool,
    pub error: Option<String>,
    pub failures: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<&db_imports::GithubImportRow> for GithubImportView {
    fn from(row: &db_imports::GithubImportRow) -> GithubImportView {
        GithubImportView {
            id: row.id,
            repo_id: row.repo_id,
            source: row.source.clone(),
            state: row.state.clone(),
            cursor_kind: row.cursor_kind.clone(),
            cursor_page: row.cursor_page,
            cursor_number: row.cursor_number,
            issues_count: row.issues_count,
            pulls_count: row.pulls_count,
            comments_count: row.comments_count,
            reviews_count: row.reviews_count,
            review_comments_count: row.review_comments_count,
            dropped_assignees: row.dropped_assignees.clone(),
            has_token: row.token_sealed.is_some(),
            error: row.error.clone(),
            failures: row.failures,
            started_at: row.started_at,
            finished_at: row.finished_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl Core {
    /// The GitHub-import record for `owner/repo`, for readers: `None`
    /// when no import has run. Non-readers get `NotFound` (via
    /// `repo_for`), so the record's existence stays undiscoverable.
    pub async fn github_import_for(
        &self,
        user: Option<&crate::accounts::User>,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Option<GithubImportView>> {
        let access = self.repo_for(user, owner, repo).await?;
        let row = db_imports::import_of_repo(self.db(), access.repo.id).await?;
        Ok(row.as_ref().map(GithubImportView::from))
    }
}
