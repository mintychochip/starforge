//! `enable`/`disable` + hidden `_hook-*` handlers (C5/C7).
//!
//! `enable` installs the three POSIX `sh` dispatchers (see [`crate::hooks`])
//! and prints every file it changes, one path per line. `disable` removes
//! only marker-bearing dispatchers and restores `.starforge-orig` backups.
//!
//! Agent adapter hooks (C7): `enable` also calls every `starforge_capture`
//! adapter's `install_hooks` (and `disable` their `remove_hooks`), printing
//! every touched path. The [`Roots`](starforge_capture::Roots) mapping is:
//!
//! - `config_dir = <home>/.config` (each adapter appends its own subdir:
//!   `claude-code/`, `pi/`),
//! - `data_dir = <home>` (each adapter resolves its own store subpaths),
//! - `worktree = <repo root>` (adapters keep sessions whose workdir is inside).
//!
//! A non-existent agent store is not an error: adapters decide via `detect`
//! what to do, and the no-hook-surface adapters (codex, gemini, opencode)
//! report no paths in either direction.
//!
//! The `prepare-commit-msg` handler appends one `Starforge-Session: <ULID>`
//! trailer per linked session (never rewriting existing trailers) and
//! records the pending selection for `post-commit`, which turns it into
//! `links.jsonl` entries plus a per-session `link-watermark.json` (so a
//! session with no new events since its last link is inactive and gains no
//! further heuristic trailers). `pre-push` enqueues segment uploads for
//! sessions with unwritten segments and then runs one best-effort sync pass
//! (no retries); every failure stays queued with a `warning:` on stderr.
//! The starforge hook steps never fail the git operation (every starforge
//! error becomes a `warning:` with exit `0`), but the dispatcher propagates
//! a failing user hook's exit status, so a failing `.starforge-orig`
//! pre-push hook still blocks the push.
//!
//! Accepted limitations (documented, not fixed in M1c): the pending-trailer
//! sidecar is a single shared `pending-trailer.json` (concurrent commits in
//! one repo can race); `core.hooksPath` is ignored (hooks install into the
//! common dir's `hooks/`); the installed dispatchers resolve the `starforge`
//! binary via `PATH`.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::git::{common_dir, head_commit, remotes, staged_files};
use crate::hooks::{
    HOOKS, PendingLink, SessionCandidate, append_trailers, existing_trailer_ulids, install_hook,
    remove_hook, select_links,
};
use crate::queue::{QueueEntry, QueueOp, enqueue, read_queue};
use crate::spool::{LinkConfidence, LinkEntry, LinkSource, Spool};
use time::format_description::well_known::Rfc3339;

/// Sidecar the prepare handler leaves for post-commit:
/// `<spool>/pending-trailer.json`.
fn pending_path(spool: &Spool) -> PathBuf {
    spool.root.join("pending-trailer.json")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingRecord {
    ulid: String,
    confidence: LinkConfidence,
    seq_start: u64,
    seq_end: u64,
}

/// Roots for the capture adapters: agent hook files live under
/// `<home>/.config` (adapters append `claude-code/`, `pi/`, …), native
/// stores resolve under `<home>`, and discovery is scoped to the repo root.
pub fn adapter_roots(paths: &crate::config::CliPaths, repo: &Path) -> starforge_capture::Roots {
    starforge_capture::Roots {
        config_dir: paths.home.join(".config"),
        data_dir: paths.home.clone(),
        worktree: repo.to_path_buf(),
    }
}

/// Every capture adapter, in stable order.
fn all_adapters() -> Vec<Box<dyn DynAdapter>> {
    vec![
        Box::new(starforge_capture::agents::ClaudeAdapter),
        Box::new(starforge_capture::agents::CodexAdapter),
        Box::new(starforge_capture::agents::PiAdapter),
        Box::new(starforge_capture::agents::OpencodeAdapter),
        Box::new(starforge_capture::agents::GeminiAdapter),
    ]
}

/// Object-safe slice of [`Adapter`](starforge_capture::Adapter) used for
/// hook wiring (discovery/reading stay on the concrete types).
trait DynAdapter {
    fn id(&self) -> &'static str;
    fn install_hooks(&self, roots: &starforge_capture::Roots) -> std::io::Result<Vec<PathBuf>>;
    fn remove_hooks(&self, roots: &starforge_capture::Roots) -> std::io::Result<Vec<PathBuf>>;
}

macro_rules! dyn_adapter {
    ($t:ty, $name:literal) => {
        impl DynAdapter for $t {
            fn id(&self) -> &'static str {
                $name
            }
            fn install_hooks(
                &self,
                roots: &starforge_capture::Roots,
            ) -> std::io::Result<Vec<PathBuf>> {
                <Self as starforge_capture::Adapter>::install_hooks(self, roots)
            }
            fn remove_hooks(
                &self,
                roots: &starforge_capture::Roots,
            ) -> std::io::Result<Vec<PathBuf>> {
                <Self as starforge_capture::Adapter>::remove_hooks(self, roots)
            }
        }
    };
}

dyn_adapter!(starforge_capture::agents::ClaudeAdapter, "claude-code");
dyn_adapter!(starforge_capture::agents::CodexAdapter, "codex");
dyn_adapter!(starforge_capture::agents::PiAdapter, "pi");
dyn_adapter!(starforge_capture::agents::OpencodeAdapter, "opencode");
dyn_adapter!(starforge_capture::agents::GeminiAdapter, "gemini");

/// Install all three dispatchers (+ spool layout) and every agent adapter's
/// hooks. Returns the human-readable output (one changed path per line) and
/// the exit code.
pub fn enable(repo: &Path, paths: &crate::config::CliPaths, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if dry_run {
        let mut lines = Vec::new();
        for hook in HOOKS {
            lines.push(format!(
                "would install {}",
                common.join("hooks").join(hook).display()
            ));
        }
        lines.push(format!(
            "would install agent hooks for claude-code, codex, pi, opencode, gemini under {}",
            paths.home.join(".config").display()
        ));
        return (lines.join("\n"), 0);
    }
    let spool = Spool::open(&common);
    let mut created = Vec::new();
    for name in ["cursors.json", "links.jsonl", "queue.jsonl"] {
        if !spool.root.join(name).exists() {
            created.push(spool.root.join(name));
        }
    }
    if let Err(err) = spool.ensure_layout() {
        return (format!("error: cannot set up spool: {err}"), 1);
    }
    let mut changed: Vec<String> = created.iter().map(|p| p.display().to_string()).collect();
    for hook in HOOKS {
        let backup = common.join("hooks").join(format!("{hook}.starforge-orig"));
        let had_backup = backup.exists();
        match install_hook(&common, hook) {
            Ok(path) => {
                changed.push(path.display().to_string());
                if !had_backup && backup.exists() {
                    changed.push(backup.display().to_string());
                }
            }
            Err(err) => return (format!("error: cannot install {hook}: {err}"), 1),
        }
    }
    let roots = adapter_roots(paths, repo);
    for adapter in all_adapters() {
        match adapter.install_hooks(&roots) {
            Ok(written) => {
                tracing::debug!(
                    "enable: {} installed {} hook file(s)",
                    adapter.id(),
                    written.len()
                );
                for path in written {
                    changed.push(path.display().to_string());
                }
            }
            Err(err) => {
                tracing::warn!("enable: {} hooks skipped: {err}", adapter.id());
            }
        }
    }
    tracing::debug!(
        "enable: {} path(s) changed in {}",
        changed.len(),
        repo.display()
    );
    (changed.join("\n"), 0)
}

/// Remove installed dispatchers and restore originals, plus every agent
/// adapter's hooks. Returns the human-readable output (one changed path per
/// line; empty when nothing changed) and the exit code (always `0` once the
/// repo resolves).
pub fn disable(repo: &Path, paths: &crate::config::CliPaths, dry_run: bool) -> (String, u8) {
    let common = match common_dir(repo) {
        Ok(common) => common,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if dry_run {
        let mut lines = Vec::new();
        for hook in HOOKS {
            lines.push(format!(
                "would remove {}",
                common.join("hooks").join(hook).display()
            ));
        }
        lines.push(format!(
            "would remove agent hooks for claude-code, codex, pi, opencode, gemini under {}",
            paths.home.join(".config").display()
        ));
        return (lines.join("\n"), 0);
    }
    let mut changed = Vec::new();
    for hook in HOOKS {
        match remove_hook(&common, hook) {
            Ok(paths) => changed.extend(paths.into_iter().map(|p| p.display().to_string())),
            Err(err) => return (format!("error: cannot remove {hook}: {err}"), 1),
        }
    }
    let roots = adapter_roots(paths, repo);
    for adapter in all_adapters() {
        match adapter.remove_hooks(&roots) {
            Ok(removed) => {
                tracing::debug!(
                    "disable: {} removed {} hook file(s)",
                    adapter.id(),
                    removed.len()
                );
                for path in removed {
                    changed.push(path.display().to_string());
                }
            }
            Err(err) => {
                tracing::warn!("disable: {} hooks skipped: {err}", adapter.id());
            }
        }
    }
    tracing::debug!(
        "disable: {} path(s) changed in {}",
        changed.len(),
        repo.display()
    );
    (changed.join("\n"), 0)
}

/// Hidden `_hook-prepare-commit-msg`: ingest, then append trailers. Always `0`.
pub fn hook_prepare(repo: &Path, msg_file: &Path, paths: &crate::config::CliPaths) -> u8 {
    if let Err(err) = prepare_inner(repo, msg_file, paths) {
        eprintln!("warning: starforge prepare-commit-msg skipped: {err}");
    }
    0
}

/// Hidden `_hook-post-commit`: ingest, then record trailer links. Always `0`.
pub fn hook_post_commit(repo: &Path, paths: &crate::config::CliPaths) -> u8 {
    if let Err(err) = post_commit_inner(repo, paths) {
        eprintln!("warning: starforge post-commit skipped: {err}");
    }
    0
}

/// Hidden `_hook-pre-push`: ingest + enqueue uploads. Always `0`.
///
/// Sync (enqueue-only) entry point kept for contexts without a runtime; the
/// installed hook runs [`hook_pre_push_full`], which additionally attempts a
/// bounded best-effort upload after enqueueing.
pub fn hook_pre_push(repo: &Path, paths: &crate::config::CliPaths) -> u8 {
    if let Err(err) = pre_push_inner(repo) {
        eprintln!("warning: starforge pre-push skipped: {err}");
    }
    if let Err(err) = run_ingest(repo, paths) {
        eprintln!("warning: starforge pre-push ingest skipped: {err}");
    }
    0
}

/// Full `_hook-pre-push` body (C7 carry-in 3): enqueue, then attempt the
/// queued uploads without blocking the push.
///
/// Best-effort budget is one pass with no retries
/// ([`sync_best_effort`](crate::commands::sync::sync_best_effort) caps the
/// whole attempt at 10 s and swallows every failure). Server resolution,
/// token, and upload failures all degrade to a `warning:` on stderr; the
/// return is always `0` so a push never fails because of session upload.
/// Entries that did not make it stay queued for the next `sync`.
pub async fn hook_pre_push_full(
    repo: &Path,
    paths: &crate::config::CliPaths,
    token_lookup: impl Fn(&str) -> Option<String>,
) -> u8 {
    // Same enqueue + ingest as the sync body, then one best-effort pass.
    let _ = hook_pre_push(repo, paths);
    if let Err(err) = pre_push_best_effort(repo, paths, token_lookup).await {
        eprintln!("warning: starforge pre-push upload skipped: {err}");
    }
    0
}

/// Run capture ingest for `repo` (GAP A): discover → read → redact → spool.
/// Warnings name the failure; the return is the ingest stats.
fn run_ingest(
    repo: &Path,
    paths: &crate::config::CliPaths,
) -> Result<crate::ingest::IngestStats, String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    let roots = adapter_roots(paths, repo);
    let now = time::OffsetDateTime::now_utc();
    let stats = crate::ingest::ingest(&spool, &roots, repo, now)
        .map_err(|err| format!("ingest failed: {err}"))?;
    tracing::debug!(
        "ingest: {} session(s), {} new event(s), {} new segment(s), {} queued",
        stats.sessions,
        stats.new_events,
        stats.new_segments,
        stats.enqueued
    );
    Ok(stats)
}

/// One best-effort upload pass over the entries [`pre_push_inner`] just
/// enqueued. `Ok` in both the uploaded and the skipped case; `Err` only when
/// the pass could not even start (no server, no token).
async fn pre_push_best_effort(
    repo: &Path,
    paths: &crate::config::CliPaths,
    token_lookup: impl Fn(&str) -> Option<String>,
) -> Result<(), String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    let (server, owner_repo, _chosen) = crate::commands::status::resolve_server(repo, paths)
        .await
        .map_err(|err| err.to_string())?;
    let host = crate::cli::sync_host_key(&server.api_url)
        .ok_or_else(|| format!("cannot parse server api_url {:?}", server.api_url))?;
    let token =
        crate::auth::resolve_token(paths, &host, token_lookup).map_err(|err| err.to_string())?;
    let now = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| format!("cannot format time: {err}"))?;
    let sleeper = crate::queue::TokioSleeper;
    crate::commands::sync::sync_best_effort(
        &spool,
        &server,
        &owner_repo,
        token.token(),
        &sleeper,
        &now,
    )
    .await;
    Ok(())
}

/// One candidate plus the event `seq` range the link will cover.
struct CandidateData {
    candidate: SessionCandidate,
    seq_start: u64,
    seq_end: u64,
}

fn prepare_inner(
    repo: &Path,
    msg_file: &Path,
    paths: &crate::config::CliPaths,
) -> Result<(), String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    // Ingest first so trailer selection sees fresh `files_touched`; an ingest
    // failure warns but never blocks the commit.
    if let Err(err) = run_ingest(repo, paths) {
        eprintln!("warning: starforge ingest skipped: {err}");
    }
    let staged = staged_files(repo).map_err(|err| err.to_string())?;
    let data = collect_candidates(&spool)?;
    let candidates: Vec<SessionCandidate> = data.iter().map(|d| d.candidate.clone()).collect();
    let links = select_links(&staged, &candidates);
    let msg = std::fs::read_to_string(msg_file)
        .map_err(|err| format!("cannot read {}: {err}", msg_file.display()))?;
    let have = existing_trailer_ulids(&msg);
    let fresh: Vec<&PendingLink> = links
        .iter()
        .filter(|link| !have.iter().any(|u| u == &link.ulid))
        .collect();
    if fresh.is_empty() {
        return Ok(());
    }
    let ulids: Vec<String> = fresh.iter().map(|link| link.ulid.clone()).collect();
    std::fs::write(msg_file, append_trailers(&msg, &ulids))
        .map_err(|err| format!("cannot write {}: {err}", msg_file.display()))?;
    let by_ulid: BTreeMap<&str, &CandidateData> = data
        .iter()
        .map(|d| (d.candidate.ulid.as_str(), d))
        .collect();
    let pending: Vec<PendingRecord> = fresh
        .iter()
        .map(|link| {
            let seq = by_ulid.get(link.ulid.as_str());
            PendingRecord {
                ulid: link.ulid.clone(),
                confidence: link.confidence,
                seq_start: seq.map(|d| d.seq_start).unwrap_or(0),
                seq_end: seq.map(|d| d.seq_end).unwrap_or(0),
            }
        })
        .collect();
    let bytes = serde_json::to_vec_pretty(&pending)
        .map_err(|err| format!("cannot encode pending: {err}"))?;
    crate::spool::atomic_write(&pending_path(&spool), &bytes)
        .map_err(|err| format!("cannot write pending links: {err}"))?;
    Ok(())
}

fn post_commit_inner(repo: &Path, paths: &crate::config::CliPaths) -> Result<(), String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    if let Err(err) = run_ingest(repo, paths) {
        eprintln!("warning: starforge ingest skipped: {err}");
    }
    let bytes = match std::fs::read(pending_path(&spool)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("cannot read pending links: {err}")),
    };
    let pending: Vec<PendingRecord> = serde_json::from_slice(&bytes)
        .map_err(|err| format!("cannot parse pending links: {err}"))?;
    if pending.is_empty() {
        std::fs::remove_file(pending_path(&spool)).ok();
        return Ok(());
    }
    let commit = head_commit(repo).map_err(|err| err.to_string())?;
    let now = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| format!("cannot format time: {err}"))?;
    for record in &pending {
        spool
            .record_link(&LinkEntry {
                ulid: record.ulid.clone(),
                commit: commit.clone(),
                source: LinkSource::Trailer,
                confidence: record.confidence,
                seq_start: record.seq_start,
                seq_end: record.seq_end,
            })
            .map_err(|err| format!("cannot record link: {err}"))?;
        spool
            .write_link_watermark(
                &record.ulid,
                &crate::spool::LinkWatermark {
                    last_linked_seq: record.seq_end,
                    last_linked_at: now.clone(),
                },
            )
            .map_err(|err| format!("cannot write link watermark: {err}"))?;
    }
    std::fs::remove_file(pending_path(&spool)).ok();
    Ok(())
}
fn pre_push_inner(repo: &Path) -> Result<(), String> {
    let common = common_dir(repo).map_err(|err| err.to_string())?;
    let spool = Spool::open(&common);
    spool
        .ensure_layout()
        .map_err(|err| format!("cannot set up spool: {err}"))?;
    let repo_url = remotes(repo)
        .map(|list| {
            list.into_iter()
                .next()
                .map(|(_, url)| url)
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let now = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| format!("cannot format time: {err}"))?;
    let queued = read_queue(&spool).map_err(|err| err.to_string())?;
    let sessions = spool.root.join("sessions");
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("cannot list sessions: {err}")),
    };
    for entry in entries {
        let entry = entry.map_err(|err| format!("cannot list sessions: {err}"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.parse::<ulid::Ulid>().is_err() {
            continue;
        };
        if !entry.path().is_dir() {
            continue;
        }
        let segments = segment_numbers(&spool, &name);
        if segments.is_empty() {
            continue;
        }
        let uploaded = spool
            .read_upload(&name)
            .map(|state| state.uploaded_segments)
            .unwrap_or_default();
        for n in segments {
            if uploaded.contains_key(&n) {
                continue;
            }
            let dup = queued
                .iter()
                .any(|e| e.op == QueueOp::Segment && e.ulid == name && e.segment == Some(n));
            if dup {
                continue;
            }
            enqueue(
                &spool,
                QueueEntry {
                    op: QueueOp::Segment,
                    ulid: name.clone(),
                    repo: repo_url.clone(),
                    segment: Some(n),
                    attempts: 0,
                    not_before: now.clone(),
                },
            )
            .map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

/// Sorted segment numbers present for `ulid` (`segments/<n>.jsonl.zst`).
fn segment_numbers(spool: &Spool, ulid: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let dir = spool.root.join("sessions").join(ulid).join("segments");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(n) = name
            .strip_suffix(".jsonl.zst")
            .and_then(|s| s.parse::<u64>().ok())
        {
            out.push(n);
        }
    }
    out.sort_unstable();
    out
}

/// Gather one [`SessionCandidate`] per spooled session plus the `seq` range
/// a link would cover.
///
/// Files come from `meta.json`'s `files_touched` plus tool-call (`edit` /
/// `write` / `patch`) input paths and `file_change` event paths scanned out
/// of the session's segment blobs. Only events at or past the stored spool
/// cursor (`cursors.json`, defaulting to `0`) count as new; their `seq`
/// range becomes the link's `[seq_start, seq_end)`. A session is `active`
/// when it has new events or any recorded file touches.
fn collect_candidates(spool: &Spool) -> Result<Vec<CandidateData>, String> {
    let cursors = stored_cursors(spool)?;
    let sessions = spool.root.join("sessions");
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("cannot list sessions: {err}")),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("cannot list sessions: {err}"))?;
        let Some(ulid) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if ulid.parse::<ulid::Ulid>().is_err() || !entry.path().is_dir() {
            continue;
        }
        let meta_path = entry.path().join("meta.json");
        let meta_bytes = match std::fs::read(&meta_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("cannot read {}: {err}", meta_path.display())),
        };
        let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
            .map_err(|err| format!("cannot parse {}: {err}", meta_path.display()))?;
        let mut files: Vec<String> = meta
            .get("files_touched")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        // The link watermark is the link's `seq_end`: only events at or past
        // it are new since the last link. A session that was already linked
        // and has no newer events is inactive, so heuristic linking fires
        // once per batch of activity instead of on every commit.
        let watermark = spool
            .read_link_watermark(&ulid)
            .map_err(|err| format!("cannot read link watermark for {ulid}: {err}"))?
            .map(|w| w.last_linked_seq)
            .unwrap_or(0);
        let floor = cursors.get(&ulid).copied().unwrap_or(0).max(watermark);
        let mut new_seqs: Vec<u64> = Vec::new();
        let mut all_seqs: Vec<u64> = Vec::new();
        for n in segment_numbers(spool, &ulid) {
            let path = spool
                .root
                .join("sessions")
                .join(&ulid)
                .join("segments")
                .join(format!("{n}.jsonl.zst"));
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let text = match starforge_format::decompress(&bytes) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            let Ok(text) = String::from_utf8(text) else {
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
                all_seqs.push(event.seq);
                if event.seq >= floor {
                    new_seqs.push(event.seq);
                }
                files.extend(event_files(&event));
            }
        }
        files.sort();
        files.dedup();
        // `files_touched` alone only counts for never-linked sessions: once a
        // session has a watermark, only newer events reactivate it.
        let active = !new_seqs.is_empty() || (watermark == 0 && !files.is_empty());
        let (seq_start, seq_end) = match (new_seqs.iter().min(), new_seqs.iter().max()) {
            (Some(&lo), Some(&hi)) => (lo, hi + 1),
            _ => match (all_seqs.iter().min(), all_seqs.iter().max()) {
                (Some(&lo), Some(&hi)) => (lo, hi + 1),
                _ => (0, 0),
            },
        };
        out.push(CandidateData {
            candidate: SessionCandidate {
                ulid,
                files_touched: files,
                active,
            },
            seq_start,
            seq_end,
        });
    }
    Ok(out)
}

/// `ulid -> cursor.events` floor from `cursors.json` (missing file = empty).
fn stored_cursors(spool: &Spool) -> Result<BTreeMap<String, u64>, String> {
    let bytes = match std::fs::read(spool.root.join("cursors.json")) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(format!("cannot read cursors: {err}")),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| format!("cannot parse cursors: {err}"))?;
    let mut out = BTreeMap::new();
    if let Some(sessions) = value.get("sessions").and_then(|v| v.as_object()) {
        for record in sessions.values() {
            let (Some(ulid), Some(events)) = (
                record.get("ulid").and_then(|v| v.as_str()),
                record
                    .get("cursor")
                    .and_then(|c| c.get("events"))
                    .and_then(|v| v.as_u64()),
            ) else {
                continue;
            };
            out.insert(ulid.to_string(), events);
        }
    }
    Ok(out)
}

/// File paths carried by one event: `file_change` paths plus `edit` /
/// `write` / `patch` tool-call input paths.
fn event_files(event: &starforge_format::Event) -> Vec<String> {
    use starforge_format::EventKind;
    match &event.kind {
        EventKind::FileChange(change) => vec![change.path.clone()],
        EventKind::ToolCall(call) => tool_input_paths(&call.tool.name, &call.tool.input),
        _ => Vec::new(),
    }
}

fn tool_input_paths(name: &str, input: &serde_json::Value) -> Vec<String> {
    match name.to_lowercase().as_str() {
        "edit" | "write" | "patch" => {}
        _ => return Vec::new(),
    }
    let Some(obj) = input.as_object() else {
        return Vec::new();
    };
    ["path", "file", "file_path", "filename", "filepath"]
        .into_iter()
        .filter_map(|key| obj.get(key).and_then(|v| v.as_str()).map(str::to_string))
        .collect()
}
