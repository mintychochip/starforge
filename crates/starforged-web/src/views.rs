//! View models shared by templates.

use starforged_core::repos::Repo;
use starforged_core::sessions::WebSession;

/// What the page header needs: the signed-in handle and the CSRF token for its sign-out form.
pub struct NavUser {
    pub handle: String,
    pub csrf: String,
}

impl NavUser {
    pub fn from_session(session: &WebSession) -> NavUser {
        NavUser {
            handle: session.user.handle.clone(),
            csrf: session.csrf_token.clone(),
        }
    }
}

pub fn nav(session: Option<&WebSession>) -> Option<NavUser> {
    session.map(NavUser::from_session)
}

pub struct RepoItem {
    pub owner: String,
    pub name: String,
    pub visibility: &'static str,
    pub description: String,
}

impl From<Repo> for RepoItem {
    fn from(repo: Repo) -> RepoItem {
        RepoItem {
            owner: repo.owner,
            name: repo.name,
            visibility: repo.visibility.as_str(),
            description: repo.description,
        }
    }
}

/// Formats unix seconds as `2026-11-03 12:00 UTC`.
pub fn format_time(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(time::macros::format_description!(
                "[year]-[month]-[day] [hour]:[minute] UTC"
            ))
            .ok()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_time_in_utc() {
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13 UTC");
    }
}
