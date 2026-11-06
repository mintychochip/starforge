use starforged_db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("not found")]
    NotFound,
    #[error("permission denied")]
    Forbidden,
    #[error("authentication required")]
    Unauthenticated,
    #[error("rate limited")]
    RateLimited,
    #[error("the email address is not verified")]
    EmailUnverified,
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("git: {0}")]
    Git(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(DbError),
}

impl From<DbError> for CoreError {
    fn from(e: DbError) -> CoreError {
        // A repo-scoped write that loses an FK race with its parent's
        // deletion (org/account/repo gone) is a 404, not a 500: the parent
        // row the caller just authorized against no longer exists.
        if e.is_foreign_key_violation() {
            CoreError::NotFound
        } else {
            CoreError::Db(e)
        }
    }
}

impl From<starforged_git::GitError> for CoreError {
    fn from(e: starforged_git::GitError) -> CoreError {
        CoreError::Git(e.to_string())
    }
}
pub type CoreResult<T> = Result<T, CoreError>;
