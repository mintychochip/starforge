//! View models shared by templates.

use starforged_core::permission::Permission;
use starforged_core::repos::{Repo, RepoAccess};
use starforged_core::sessions::WebSession;

/// Content-Security-Policy for pages rendered from attacker-influenced
/// content (session viewer, session download, blame with session chips). A
/// superset of the site default: `default-src` tightened to `'none'` with
/// same-origin `img-src`/`style-src`/`script-src`, keeping the site-wide
/// `frame-ancestors`, `base-uri`, and `form-action` directives (the viewer
/// has POST forms). There are no inline scripts at all (this codebase has
/// no CSP-nonce mechanism because no page needs one). Handlers set this
/// header themselves so it wins over the `security_headers` middleware
/// default (`or_insert` keeps ours).
pub const STRICT_CSP: &str = "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

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

/// The header of every repository page (`repo_head.html`): owner and name, badges, description, and tabs.
pub struct RepoHead {
    pub owner: String,
    pub name: String,
    pub description: String,
    pub visibility: &'static str,
    /// The repository is archived: read-only, pushes refused.
    pub archived: bool,
    /// The highlighted tab: `code`, `commits`, `branches`, `tags`, or `settings`; any other value highlights none.
    pub tab: &'static str,
    /// The Commits tab: the history of the ref being viewed, or `/{owner}/{repo}/commits`.
    pub commits_href: String,
    /// Maintainers and admins see the Settings tab.
    pub can_maintain: bool,
    /// Admins also see the admin-only settings.
    pub can_admin: bool,
}

impl RepoHead {
    /// `ref_name` is the branch, tag, or commit the page shows, when it shows one.
    pub fn new(access: &RepoAccess, tab: &'static str, ref_name: Option<&str>) -> RepoHead {
        let repo = &access.repo;
        let commits_href = match ref_name {
            Some(name) => format!(
                "/{}/{}/commits/{}",
                repo.owner,
                repo.name,
                encode_path(name)
            ),
            None => format!("/{}/{}/commits", repo.owner, repo.name),
        };
        RepoHead {
            owner: repo.owner.clone(),
            name: repo.name.clone(),
            description: repo.description.clone(),
            visibility: repo.visibility.as_str(),
            archived: repo.archived_at.is_some(),
            tab,
            commits_href,
            can_maintain: access.permission >= Permission::Maintain,
            can_admin: access.permission >= Permission::Admin,
        }
    }
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

/// How long ago `then` was, seen at `now` (unix seconds): "just now", "5 minutes ago", "1 day ago", …
/// Times in the future read "just now".
pub fn format_age(now: i64, then: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    let secs = (now - then).max(0);
    let (count, unit) = if secs < MINUTE {
        return "just now".to_owned();
    } else if secs < HOUR {
        (secs / MINUTE, "minute")
    } else if secs < DAY {
        (secs / HOUR, "hour")
    } else if secs < 30 * DAY {
        (secs / DAY, "day")
    } else if secs < 365 * DAY {
        (secs / (30 * DAY), "month")
    } else {
        (secs / (365 * DAY), "year")
    };
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural} ago")
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

use starforged_git::diff::{FileDiff, FileStatus, LineKind};
use starforged_git::read::CommitInfo;

/// One commit in a list (`commits.html`, `compare.html`).
pub struct CommitRow {
    pub id: String,
    pub short_id: String,
    pub summary: String,
    pub author: String,
    pub when: String,
    /// Readable linked sessions (commits list badge; always 0 on compare).
    pub session_count: usize,
}

impl From<CommitInfo> for CommitRow {
    fn from(commit: CommitInfo) -> CommitRow {
        let short_id = commit.short_id().to_owned();
        CommitRow {
            id: commit.id,
            short_id,
            summary: commit.summary,
            author: commit.author_name,
            when: format_time(commit.author_time),
            session_count: 0,
        }
    }
}

/// One linked session in the commit Sessions panel (`sessions_panel.html`)
/// and the commits-list count badge (`commits.html`).
pub struct SessionChip {
    /// Session ULID (only ever populated for sessions the viewer may read).
    pub ulid: String,
    /// `agent_name agent_version`, e.g. `pi 2.1`.
    pub agent: String,
    pub started: String,
    /// Link confidence: `exact` or `heuristic`.
    pub confidence: String,
    /// Link provenance: `trailer` or `cli_claim`.
    pub source: String,
    /// Viewer URL, with `#turn-<seq_start>` when the claim carries a range.
    pub href: String,
}

impl SessionChip {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: &str,
        repo: &str,
        ulid: &str,
        agent_name: &str,
        agent_version: &str,
        started_at: i64,
        confidence: &str,
        source: &str,
        seq_start: Option<i64>,
    ) -> SessionChip {
        let mut href = format!("/{owner}/{repo}/sessions/{ulid}");
        if let Some(seq) = seq_start {
            href.push_str(&format!("#turn-{seq}"));
        }
        SessionChip {
            ulid: ulid.to_owned(),
            agent: format!("{agent_name} {agent_version}"),
            started: format_time(started_at),
            confidence: confidence.to_owned(),
            source: source.to_owned(),
            href,
        }
    }
}

/// One blamed line: its 1-based file number and escaped text.
pub struct BlameLine {
    pub n: usize,
    pub text: String,
}

/// One contiguous blamed run on the current page: attribution, session
/// chips, and the page's slice of its lines.
pub struct BlameLineGroup {
    pub sha: String,
    pub short: String,
    pub author: String,
    pub when: String,
    pub summary: String,
    pub commit_href: String,
    /// The run started on an earlier page; the header marks the continuation.
    pub continuation: bool,
    pub sessions: Vec<SessionChip>,
    pub lines: Vec<BlameLine>,
}

pub struct LineView {
    pub class: &'static str,
    pub old: String,
    pub new: String,
    pub text: String,
}

pub struct HunkView {
    pub header: String,
    pub lines: Vec<LineView>,
}

pub struct FileView {
    pub status: &'static str,
    pub path: String,
    pub binary: bool,
    pub hunks: Vec<HunkView>,
}

/// Diff files as `diff_files.html` renders them.
pub fn file_views(files: Vec<FileDiff>) -> Vec<FileView> {
    files
        .into_iter()
        .map(|file| FileView {
            status: match file.status {
                FileStatus::Added => "added",
                FileStatus::Deleted => "deleted",
                FileStatus::Modified => "modified",
                FileStatus::Renamed => "renamed",
            },
            path: match (file.status, &file.old_path) {
                (FileStatus::Renamed, Some(old)) => format!("{old} → {}", file.display_path()),
                _ => file.display_path().to_owned(),
            },
            binary: file.binary,
            hunks: file
                .hunks
                .into_iter()
                .map(|hunk| HunkView {
                    header: hunk.header,
                    lines: hunk
                        .lines
                        .into_iter()
                        .map(|line| LineView {
                            class: match line.kind {
                                LineKind::Context => "ctx",
                                LineKind::Added => "add",
                                LineKind::Removed => "del",
                                LineKind::NoNewline => "nonl",
                            },
                            old: line.old_line.map(|n| n.to_string()).unwrap_or_default(),
                            new: line.new_line.map(|n| n.to_string()).unwrap_or_default(),
                            text: line.text,
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect()
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
    #[test]
    fn ages_read_naturally() {
        let now = 1_700_000_000;
        let cases = [
            (now, "just now"),
            (now - 59, "just now"),
            (now - 60, "1 minute ago"),
            (now - 5 * 60, "5 minutes ago"),
            (now - 3_600, "1 hour ago"),
            (now - 2 * 86_400, "2 days ago"),
            (now - 45 * 86_400, "1 month ago"),
            (now - 800 * 86_400, "2 years ago"),
            (now + 30, "just now"),
        ];
        for (then, expected) in cases {
            assert_eq!(format_age(now, then), expected, "{then}");
        }
    }
}
