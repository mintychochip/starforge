use starforged_db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("not found")]
    NotFound,
    #[error("permission denied")]
    Forbidden,
    #[error("authentication required")]
    Unauthenticated,
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("git: {0}")]
    Git(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<starforged_git::GitError> for CoreError {
    fn from(e: starforged_git::GitError) -> CoreError {
        CoreError::Git(e.to_string())
    }
}
pub type CoreResult<T> = Result<T, CoreError>;
