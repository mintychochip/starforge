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

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

/// Characters percent-encoded inside a single URL path segment.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\');

/// Percent-encodes each `/`-separated segment of `path`, dropping empty segments.
pub fn encode_path(path: &str) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| utf8_percent_encode(s, SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// `/{owner}/{repo}/{kind}/{ref}[/{path}]`, every ref and path segment encoded.
pub fn content_href(owner: &str, repo: &str, kind: &str, ref_name: &str, path: &str) -> String {
    let mut href = format!("/{owner}/{repo}/{kind}/{}", encode_path(ref_name));
    let encoded = encode_path(path);
    if !encoded.is_empty() {
        href.push('/');
        href.push_str(&encoded);
    }
    href
}

pub struct Crumb {
    pub name: String,
    pub href: String,
}

/// One tree link per directory level of `dir`.
pub fn crumbs(owner: &str, repo: &str, ref_name: &str, dir: &str) -> Vec<Crumb> {
    let mut out = Vec::new();
    let mut prefix = String::new();
    for segment in dir.split('/').filter(|s| !s.is_empty()) {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(segment);
        out.push(Crumb {
            name: segment.to_owned(),
            href: content_href(owner, repo, "tree", ref_name, &prefix),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_time_in_utc() {
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13 UTC");
    }

    #[test]
    fn content_hrefs_encode_each_segment() {
        assert_eq!(
            content_href("alice", "proj", "blob", "feature/x", "docs/a b.txt"),
            "/alice/proj/blob/feature/x/docs/a%20b.txt"
        );
        assert_eq!(
            content_href("alice", "proj", "tree", "main", ""),
            "/alice/proj/tree/main"
        );
        assert_eq!(encode_path("a#b/c?d"), "a%23b/c%3Fd");
        let hrefs: Vec<String> = crumbs("alice", "proj", "main", "src/bin")
            .into_iter()
            .map(|c| c.href)
            .collect();
        assert_eq!(
            hrefs,
            vec!["/alice/proj/tree/main/src", "/alice/proj/tree/main/src/bin"]
        );
    }
}
