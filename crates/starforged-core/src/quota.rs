//! Upload quotas (spec §7.7): per-repository and per-uploader storage caps plus a
//! per-uploader rolling-hour volume cap, all enforced from `segments` sums.
//!
//! Per-token request rate limiting lives in [`crate::limits`] (M5a), keyed by
//! token id in memory; the API layer consults it on every request.

use starforged_db::sessions as db_sessions;

use crate::{Core, CoreError, CoreResult};

/// Rejects the upload when `incoming_bytes` would push the repository or the
/// uploader past their stored totals (`sum(segments.byte_size)`).
pub async fn check_storage_quotas(
    core: &Core,
    user_id: i64,
    repo_id: i64,
    incoming_bytes: u64,
) -> CoreResult<()> {
    let incoming = i64::try_from(incoming_bytes).unwrap_or(i64::MAX);
    let repo_used = db_sessions::repo_storage_bytes(core.db(), repo_id).await?;
    if repo_used.saturating_add(incoming) > core.config().max_repo_bytes as i64 {
        return Err(CoreError::Invalid(format!(
            "repository storage quota exceeded ({} of {} bytes used)",
            repo_used,
            core.config().max_repo_bytes
        )));
    }
    let user_used = db_sessions::user_storage_bytes(core.db(), user_id).await?;
    if user_used.saturating_add(incoming) > core.config().max_user_bytes as i64 {
        return Err(CoreError::Invalid(format!(
            "uploader storage quota exceeded ({} of {} bytes used)",
            user_used,
            core.config().max_user_bytes
        )));
    }
    Ok(())
}

/// Rejects the upload when `incoming_bytes` would push the uploader past the
/// rolling-hour volume cap (segments with `uploaded_at` in the last hour).
pub async fn check_hourly_volume(core: &Core, user_id: i64, incoming_bytes: u64) -> CoreResult<()> {
    let incoming = i64::try_from(incoming_bytes).unwrap_or(i64::MAX);
    let since = starforged_db::now().saturating_sub(3600);
    let used = db_sessions::user_volume_since(core.db(), user_id, since).await?;
    if used.saturating_add(incoming) > core.config().max_hourly_bytes as i64 {
        return Err(CoreError::Invalid(format!(
            "hourly upload volume quota exceeded ({} of {} bytes used)",
            used,
            core.config().max_hourly_bytes
        )));
    }
    Ok(())
}

/// Per-token request rate limiting is enforced by the API layer via
/// [`crate::limits`] on every request; this hook stays `Ok` for the segment
/// upload path, whose requests already counted at the API layer.
pub fn check_rate_limit() -> CoreResult<()> {
    Ok(())
}
