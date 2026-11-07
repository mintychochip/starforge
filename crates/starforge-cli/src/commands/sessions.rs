//! `sessions` subcommands: read-only views plus explicit link management.
//!
//! `list`/`show` resolve ULID prefixes (unambiguous prefix wins; ambiguous or
//! unknown prefixes are errors listing the candidates). `link` records an
//! explicit (`cli_claim`/`exact`) link for the session plus a `Links` queue
//! entry and advances the session's link watermark; `unlink` removes matching
//! `links.jsonl` lines. `--dry-run` prints what would happen and writes
//! nothing.

use std::path::Path;

use crate::git::{common_dir, head_commit};
use crate::queue::{QueueEntry, QueueOp, enqueue};
use crate::spool::{LinkConfidence, LinkEntry, LinkSource, Spool};

/// Resolve `prefix` to a full spooled ULID: exact match wins, else the single
/// prefix match, else an error naming the candidates (or "unknown session").
pub fn resolve_prefix(spool: &Spool, prefix: &str) -> Result<String, String> {
    let mut ulids = Vec::new();
    match std::fs::read_dir(spool.root.join("sessions")) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if entry.path().is_dir()
                    && let Some(name) = entry.file_name().to_str()
                {
                    ulids.push(name.to_string());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("cannot list sessions: {err}")),
    }
    ulids.sort();
    if ulids.iter().any(|u| u == prefix) {
        return Ok(prefix.to_string());
    }
    let hits: Vec<&str> = ulids
        .iter()
        .map(String::as_str)
        .filter(|u| u.starts_with(prefix))
        .collect();
    match hits.as_slice() {
        [] => Err(format!("unknown session `{prefix}`")),
        [one] => Ok((*one).to_string()),
        many => Err(format!(
            "ambiguous session prefix `{prefix}`: {}",
            many.join(", ")
        )),
    }
}

/// One table row for `list`.
struct SessionRow {
    ulid: String,
    agent: String,
    title: String,
    events: u64,
    segments: u64,
    uploaded: u64,
    /// Local blobs pruned (`spool prune`): the transcript lives on the server.
    pruned: bool,
}

fn agent_name(name: &starforge_format::AgentName) -> &'static str {
    match name {
        starforge_format::AgentName::ClaudeCode => "claude-code",
        starforge_format::AgentName::Codex => "codex",
        starforge_format::AgentName::Pi => "pi",
        starforge_format::AgentName::Opencode => "opencode",
        starforge_format::AgentName::Gemini => "gemini",
    }
}

fn row_for(spool: &Spool, ulid: &str) -> Option<SessionRow> {
    let meta = spool.read_meta(ulid).ok()?;
    let mut events = 0u64;
    let mut segments = 0u64;
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".jsonl.zst") {
                continue;
            }
            segments += 1;
            let bytes = std::fs::read(entry.path()).ok()?;
            let text = starforge_format::decompress(&bytes).ok()?;
            let text = String::from_utf8(text).ok()?;
            events += text.lines().filter(|l| !l.trim().is_empty()).count() as u64;
        }
    }
    let uploaded = spool
        .read_upload(ulid)
        .map(|s| s.uploaded_segments.len() as u64)
        .unwrap_or(0);
    let title: String = meta
        .title
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Some(SessionRow {
        ulid: ulid.to_string(),
        agent: agent_name(&meta.agent.name).to_string(),
        title: title.chars().take(40).collect(),
        events,
        segments,
        uploaded,
        pruned: spool.is_pruned(ulid),
    })
}

/// List spooled sessions as a table (`ULID agent title events segments
/// uploaded`), one row per line with a header. Empty spool prints
/// `(no sessions)`.
pub fn list(repo: &Path, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    if dry_run {
        return (
            format!("would list sessions in {}", spool.root.display()),
            0,
        );
    }
    let mut ulids = Vec::new();
    match std::fs::read_dir(spool.root.join("sessions")) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if entry.path().is_dir()
                    && let Some(name) = entry.file_name().to_str()
                {
                    ulids.push(name.to_string());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return (format!("error: cannot read sessions: {err}"), 1),
    }
    ulids.sort();
    if ulids.is_empty() {
        return ("(no sessions)".to_string(), 0);
    }
    let mut out = String::from("ULID AGENT TITLE EVENTS SEGMENTS UPLOADED");
    for ulid in &ulids {
        match row_for(&spool, ulid) {
            Some(row) => out.push_str(&format!(
                "\n{} {} {} {} {} {}",
                row.ulid,
                row.agent,
                row.title,
                row.events,
                if row.pruned {
                    "pruned".to_string()
                } else {
                    row.segments.to_string()
                },
                row.uploaded
            )),
            None => out.push_str(&format!("\n{ulid} ? ? 0 0 0")),
        }
    }
    (out, 0)
}

/// Print a session's `meta.json` (pretty) plus its `links.jsonl` entries.
pub fn show(repo: &Path, ulid_prefix: &str, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    if dry_run {
        return (
            format!(
                "would show session {ulid_prefix} in {}",
                spool.root.display()
            ),
            0,
        );
    }
    let ulid = match resolve_prefix(&spool, ulid_prefix) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let meta = match spool.read_meta(&ulid) {
        Ok(meta) => meta,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let links: Vec<LinkEntry> = spool
        .links()
        .map(|all| all.into_iter().filter(|l| l.ulid == ulid).collect())
        .unwrap_or_default();
    let mut out = serde_json::to_string_pretty(&meta).expect("SessionMeta serializes");
    out.push_str(&format!(
        "\nlinks: {}",
        serde_json::to_string(&links).expect("links serialize")
    ));
    if spool.is_pruned(&ulid) {
        out.push_str(
            "\ncontent: pruned locally; the transcript lives on the server (view it at the session URL)",
        );
    }
    (out, 0)
}

/// Event `seq` range covered by `ulid`'s segments: `(min, max + 1)`, or
/// `(0, 0)` when the session has no parseable events.
fn session_seq_range(spool: &Spool, ulid: &str) -> (u64, u64) {
    let mut min: Option<u64> = None;
    let mut max: Option<u64> = None;
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return (0, 0),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".jsonl.zst") {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let Ok(raw) = starforge_format::decompress(&bytes) else {
            continue;
        };
        let Ok(text) = String::from_utf8(raw) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(event) = starforge_format::parse_event(line) else {
                continue;
            };
            min = Some(min.map_or(event.seq, |m: u64| m.min(event.seq)));
            max = Some(max.map_or(event.seq, |m: u64| m.max(event.seq)));
        }
    }
    match (min, max) {
        (Some(lo), Some(hi)) => (lo, hi + 1),
        _ => (0, 0),
    }
}

/// Record an explicit link (`cli_claim`/`exact`) for the session, enqueue a
/// `Links` upload, and advance the session's link watermark so heuristic
/// linking does not immediately re-link the same events.
pub fn link(repo: &Path, ulid_prefix: &str, commit: Option<&str>, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    let owned;
    // Resolve the prefix before the dry-run return so a typo'd ULID fails
    // the same way in both modes (still writing nothing here).
    let ulid = match resolve_prefix(&spool, ulid_prefix) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let commit: String = match commit {
        Some(c) => c.to_string(),
        None => {
            owned = match head_commit(repo) {
                Ok(sha) => sha,
                Err(err) => return (format!("error: {err}"), 1),
            };
            owned.trim().to_string()
        }
    };
    if dry_run {
        return (
            format!("would link session {ulid_prefix} to commit {commit}"),
            0,
        );
    }
    if let Err(err) = record_claim(&spool, &ulid, &commit) {
        return (format!("error: {err}"), 1);
    }
    (format!("linked {ulid} to {commit}"), 0)
}

/// Record one (`cli_claim`/`exact`) link for an already-resolved `ulid`:
/// a `links.jsonl` entry, a `Links` queue entry, and the link watermark.
/// Shared by `sessions link` and `sessions backfill-links` so both claim
/// through the identical path.
fn record_claim(spool: &Spool, ulid: &str, commit: &str) -> Result<(), String> {
    let (seq_start, seq_end) = session_seq_range(spool, ulid);
    spool
        .record_link(&LinkEntry {
            ulid: ulid.to_string(),
            commit: commit.to_string(),
            source: LinkSource::CliClaim,
            confidence: LinkConfidence::Exact,
            seq_start,
            seq_end,
        })
        .map_err(|err| format!("cannot record link: {err}"))?;
    enqueue(
        spool,
        QueueEntry {
            op: QueueOp::Links,
            ulid: ulid.to_string(),
            repo: String::new(),
            segment: None,
            attempts: 0,
            not_before: "1970-01-01T00:00:00Z".to_string(),
        },
    )
    .map_err(|err| format!("cannot enqueue links upload: {err}"))?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    spool
        .write_link_watermark(
            ulid,
            &crate::spool::LinkWatermark {
                last_linked_seq: seq_end,
                last_linked_at: now,
            },
        )
        .map_err(|err| format!("cannot write link watermark: {err}"))?;
    tracing::debug!("sessions link: {ulid} -> {commit} (seq {seq_start}..{seq_end})");
    Ok(())
}

/// Grace period after a session's last activity during which a commit
/// touching one of its files still counts as its work.
const BACKFILL_GRACE_SECS: i64 = 30 * 60;

/// Parse an RFC 3339 timestamp to unix seconds; `None` if unparseable.
fn ts_unix(ts: &str) -> Option<i64> {
    time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

/// Parse `--since <YYYY-MM-DD>` to the unix seconds of that day's UTC
/// midnight; `None` if the value is not a valid calendar date.
fn since_unix(date: &str) -> Option<i64> {
    ts_unix(&format!("{date}T00:00:00Z"))
}

/// Normalize one recorded `files_touched` path to a repo-relative path: an
/// absolute path is stripped of the longest matching worktree root (the
/// working-tree root, or any linked-worktree root); relative paths stay
/// as-is. Returns `None` for absolute paths outside every root and for
/// empty paths.
fn normalize_touch(path: &str, roots: &[std::path::PathBuf]) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let p = std::path::Path::new(trimmed);
    if p.is_absolute() {
        let (_, rel) = roots
            .iter()
            .filter_map(|root| p.strip_prefix(root).ok().map(|rel| (root, rel)))
            .max_by_key(|(root, _)| root.components().count())?;
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.is_empty() {
            return None;
        }
        Some(rel.trim_start_matches('/').to_string())
    } else {
        Some(
            trimmed
                .replace('\\', "/")
                .trim_start_matches("./")
                .to_string(),
        )
    }
}

/// Every spooled session ULID in sorted order (invalid names skipped).
fn spooled_ulids(spool: &Spool) -> Vec<String> {
    let mut ulids = Vec::new();
    if let Ok(entries) = std::fs::read_dir(spool.root.join("sessions")) {
        for entry in entries.flatten() {
            if entry.path().is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.parse::<ulid::Ulid>().is_ok())
            {
                ulids.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    ulids.sort();
    ulids
}

fn activity_window(
    meta: &starforge_format::SessionMeta,
    last_event: Option<i64>,
) -> Option<(i64, i64)> {
    let start = ts_unix(&meta.started_at)?;
    let last = meta
        .ended_at
        .as_deref()
        .and_then(ts_unix)
        .or(last_event)
        .unwrap_or(start);
    Some((start, last))
}

/// Backfill commit links for historical sessions that carry none: for every
/// spooled session with non-empty `files_touched`, link every commit
/// reachable from `HEAD` whose committer time falls inside
/// `[started_at, last_activity + 30 minutes]` AND whose changed paths
/// include a normalized `files_touched` path. `last_activity` is `ended_at`,
/// else the cursor `last_event_at`, else `started_at`. `--since <YYYY-MM-DD>`
/// considers only commits on or after that day's UTC midnight. Pairs
/// already linked locally are skipped, so a second run records nothing new.
///
/// `--dry-run` prints `ulid  sha  matched-path` lines plus the count and
/// writes nothing; a real run records each pair via [`record_claim`] (the
/// same claim path as `sessions link`, so the next `sync` uploads it) and
/// prints the count.
pub fn backfill_links(repo: &Path, since: Option<&str>, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    let since = match since {
        None => None,
        Some(date) => match since_unix(date) {
            Some(unix) => Some(unix),
            None => {
                return (
                    format!("error: invalid --since date `{date}` (want YYYY-MM-DD)"),
                    1,
                );
            }
        },
    };
    let roots = match repo_roots(repo) {
        Ok(roots) => roots,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let commits = match crate::git::commit_log(repo) {
        Ok(commits) => commits,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let commits: Vec<crate::git::CommitRecord> = commits
        .into_iter()
        .filter(|c| since.is_none_or(|since| c.time >= since))
        .collect();
    let linked: std::collections::HashSet<(String, String)> = match spool.links() {
        Ok(all) => all.into_iter().map(|l| (l.ulid, l.commit)).collect(),
        Err(err) => return (format!("error: {err}"), 1),
    };
    // Newest cursor last_event_at per session ULID.
    let last_event: std::collections::HashMap<String, i64> = match spool.cursor_records() {
        Ok(records) => records
            .values()
            .filter_map(|rec| {
                rec.last_event_at
                    .as_deref()
                    .and_then(ts_unix)
                    .map(|unix| (rec.ulid.clone(), unix))
            })
            .fold(std::collections::HashMap::new(), |mut map, (ulid, unix)| {
                map.entry(ulid)
                    .and_modify(|cur| *cur = (*cur).max(unix))
                    .or_insert(unix);
                map
            }),
        Err(_) => std::collections::HashMap::new(),
    };
    // (ulid, sha, matched-path) for every new matching pair.
    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for ulid in spooled_ulids(&spool) {
        let meta = match spool.read_meta(&ulid) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if meta.files_touched.is_empty() {
            continue;
        }
        let Some((start, last)) = activity_window(&meta, last_event.get(&ulid).copied()) else {
            continue;
        };
        let touches: std::collections::HashSet<String> = meta
            .files_touched
            .iter()
            .filter_map(|p| normalize_touch(p, &roots))
            .collect();
        if touches.is_empty() {
            continue;
        }
        for commit in &commits {
            if commit.time < start || commit.time > last + BACKFILL_GRACE_SECS {
                continue;
            }
            if linked.contains(&(ulid.clone(), commit.sha.clone())) {
                continue;
            }
            if let Some(matched) = commit.files.iter().filter(|f| touches.contains(*f)).min() {
                pairs.push((ulid.clone(), commit.sha.clone(), matched.clone()));
            }
        }
    }
    pairs.sort();
    pairs.dedup();
    if dry_run {
        let mut out: Vec<String> = pairs
            .iter()
            .map(|(ulid, sha, path)| format!("{ulid}  {sha}  {path}"))
            .collect();
        out.push(format!("would link {} pair(s)", pairs.len()));
        (out.join("\n"), 0)
    } else {
        for (ulid, sha, _) in &pairs {
            if let Err(err) = record_claim(&spool, ulid, sha) {
                return (format!("error: {err}"), 1);
            }
        }
        (format!("linked {} pair(s)", pairs.len()), 0)
    }
}

/// Every working-tree root stripped from absolute `files_touched` paths:
/// the `repo` root plus every root from `git worktree list`.
fn repo_roots(repo: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    match crate::git::toplevel(repo) {
        Ok(top) => {
            set.insert(top);
        }
        Err(err) => return Err(err.to_string()),
    }
    match crate::git::worktrees(repo) {
        Ok(list) => {
            for root in list {
                set.insert(root);
            }
        }
        Err(err) => return Err(err.to_string()),
    }
    Ok(set.into_iter().collect())
}

/// Remove `links.jsonl` lines matching (`ulid`, `commit`), rewriting the file
/// atomically. Errors when nothing matched.
pub fn unlink(repo: &Path, ulid_prefix: &str, commit: &str, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let spool = Spool::open(&common);
    // Resolve the prefix before the dry-run return so a typo'd ULID fails
    // the same way in both modes (still writing nothing here).
    let ulid = match resolve_prefix(&spool, ulid_prefix) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if dry_run {
        return (
            format!("would unlink session {ulid_prefix} from commit {commit}"),
            0,
        );
    }
    let all = match spool.links() {
        Ok(all) => all,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let kept: Vec<&LinkEntry> = all
        .iter()
        .filter(|l| !(l.ulid == ulid && l.commit == commit))
        .collect();
    if kept.len() == all.len() {
        return (format!("error: no link from {ulid} to {commit}"), 1);
    }
    let removed = all.len() - kept.len();
    let mut text = String::new();
    for link in kept {
        text.push_str(&serde_json::to_string(link).expect("LinkEntry serializes"));
        text.push('\n');
    }
    if let Err(err) = crate::spool::atomic_write(&spool.root.join("links.jsonl"), text.as_bytes()) {
        return (format!("error: cannot rewrite links: {err}"), 1);
    }
    tracing::debug!("sessions unlink: removed {removed} link(s) for {ulid}");
    (format!("unlinked {ulid} from {commit}"), 0)
}
