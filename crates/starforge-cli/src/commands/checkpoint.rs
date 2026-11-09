//! `checkpoint`, `rewind`, and `resume` commands (local spool + git).

use std::path::Path;

use crate::git;
use crate::spool::{CheckpointEntry, Spool};

fn open_spool(repo: &Path) -> Result<Spool, String> {
    let common = git::common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    Ok(spool)
}

fn resolve_session(spool: &Spool, session: Option<&str>) -> Result<String, String> {
    match session {
        Some(ulid) => {
            spool
                .read_meta(ulid)
                .map_err(|err| format!("unknown session `{ulid}`: {err}"))?;
            Ok(ulid.to_owned())
        }
        None => latest_session(spool).ok_or_else(|| {
            "no session in this repository's spool; pass --session <ulid>".to_owned()
        }),
    }
}

fn latest_session(spool: &Spool) -> Option<String> {
    let mut best: Option<(String, String)> = None;
    for ulid in spool.session_ulids().ok()? {
        let Ok(meta) = spool.read_meta(&ulid) else {
            continue;
        };
        let key = meta
            .ended_at
            .clone()
            .unwrap_or_else(|| meta.started_at.clone());
        if best.as_ref().is_none_or(|(_, best_key)| key > *best_key) {
            best = Some((ulid, key));
        }
    }
    best.map(|(ulid, _)| ulid)
}

/// `checkpoint create`: snapshots the working tree for a session.
pub fn create(repo: &Path, session: Option<&str>, label: &str, force: bool) -> (String, u8) {
    let spool = match open_spool(repo) {
        Ok(spool) => spool,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let ulid = match resolve_session(&spool, session) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    match crate::checkpoints::create(repo, &spool, &ulid, label, "manual", force) {
        Ok(entry) => (
            format!(
                "checkpoint {} for {} at {} ({})",
                entry.n,
                ulid,
                &entry.commit[..entry.commit.len().min(10)],
                entry.label
            ),
            0,
        ),
        Err(err) => (format!("error: {err}"), 1),
    }
}

/// `checkpoint list`: local checkpoints for one session.
pub fn list(repo: &Path, session: Option<&str>) -> (String, u8) {
    let spool = match open_spool(repo) {
        Ok(spool) => spool,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let ulid = match resolve_session(&spool, session) {
        Ok(ulid) => ulid,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let entries = match spool.read_checkpoints(&ulid) {
        Ok(entries) => entries,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if entries.is_empty() {
        return (format!("no checkpoints for {ulid}"), 0);
    }
    let mut out = String::new();
    for entry in entries {
        out.push_str(&format!(
            "{} {} {} {} {}{}\n",
            entry.n,
            &entry.commit[..entry.commit.len().min(10)],
            entry.source,
            entry.label,
            if entry.uploaded { "uploaded" } else { "local" },
            entry
                .parent
                .as_deref()
                .map(|parent| format!(" parent {}", &parent[..parent.len().min(10)]))
                .unwrap_or_default()
        ));
    }
    (out.trim_end().to_owned(), 0)
}

/// Loads checkpoint `n`, fetching its ref from the first remote when the
/// local spool has no entry and the ref is absent.
fn load_checkpoint(
    repo: &Path,
    spool: &Spool,
    ulid: &str,
    n: u64,
) -> Result<CheckpointEntry, String> {
    if let Some(entry) = spool
        .read_checkpoints(ulid)
        .map_err(|err| err.to_string())?
        .into_iter()
        .find(|entry| entry.n == n)
    {
        return Ok(entry);
    }
    let ref_name = format!("refs/starforge/checkpoints/{ulid}/{n}");
    if git::rev_parse(repo, &ref_name).is_err() {
        let remotes = git::remotes(repo).map_err(|err| err.to_string())?;
        let (_, url) = remotes
            .into_iter()
            .next()
            .ok_or_else(|| "no git remote to fetch the checkpoint from".to_owned())?;
        git::fetch_checkpoint(repo, &url, ulid, n).map_err(|err| err.to_string())?;
    }
    let commit = git::rev_parse(repo, &ref_name).map_err(|err| err.to_string())?;
    let tree = git::rev_parse_tree(repo, &commit).map_err(|err| err.to_string())?;
    let entry = CheckpointEntry {
        n,
        commit,
        tree,
        parent: None,
        label: String::new(),
        source: "manual".to_owned(),
        created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        uploaded: true,
    };
    spool
        .record_checkpoint(ulid, entry.clone())
        .map_err(|err| err.to_string())?;
    Ok(entry)
}

/// `rewind`: restores the working tree to checkpoint `n`.
pub fn rewind(repo: &Path, session: &str, n: u64, force: bool) -> (String, u8) {
    let spool = match open_spool(repo) {
        Ok(spool) => spool,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let entry = match load_checkpoint(repo, &spool, session, n) {
        Ok(entry) => entry,
        Err(err) => return (format!("error: {err}"), 1),
    };
    match crate::checkpoints::rewind(repo, &spool, session, entry.n, force) {
        Ok(entry) => (
            format!(
                "restored checkpoint {} ({}) for {}",
                entry.n,
                &entry.commit[..entry.commit.len().min(10)],
                session
            ),
            0,
        ),
        Err(err) => (format!("error: {err}"), 1),
    }
}

/// `resume`: rewinds and writes `.starforge/resume.md`.
pub fn resume(
    repo: &Path,
    session: &str,
    n: u64,
    force: bool,
    agent: Option<&str>,
) -> (String, u8) {
    let spool = match open_spool(repo) {
        Ok(spool) => spool,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let entry = match load_checkpoint(repo, &spool, session, n) {
        Ok(entry) => entry,
        Err(err) => return (format!("error: {err}"), 1),
    };
    match crate::checkpoints::resume(repo, &spool, session, entry.n, force) {
        Ok((entry, path)) => {
            let agent = agent.unwrap_or("your agent");
            (
                format!(
                    "restored checkpoint {} ({}) for {}\nresume context: {}\nstart {} in {}",
                    entry.n,
                    &entry.commit[..entry.commit.len().min(10)],
                    session,
                    path.display(),
                    agent,
                    repo.display()
                ),
                0,
            )
        }
        Err(err) => (format!("error: {err}"), 1),
    }
}
