//! Post-push ingest scan (shared by smart HTTP and SSH): session trailers,
//! accepted `refs/for` tips, and branch-head moves. Both transports snapshot
//! refs before spawning `receive-pack`, then call [`Core::scan_push_changes`]
//! after a successful push — so SSH pushes trigger the identical scan as HTTP.
//! Failures only warn: a push never fails because of the scan.

use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use starforged_git::{command, pushsidecar, read, refpolicy, write};

use crate::Core;
use crate::accounts::User;
use crate::changes::{IngestSidecar, RefUpdate};

/// Upper bound on commits read per push for the trailer scan: a push can only
/// add so many commits, and the scan must stay bounded. This is a *commit* cap
/// over the union of every changed ref's new commits, not a ref cap.
const MAX_SCAN_COMMITS: usize = 1_000;

/// Upper bound on pre-push ref tips passed as `rev-list --not` exclusions for a
/// brand-new ref. Past this many refs the exclusion list could bust `ARG_MAX`,
/// so the scan falls back to the new tip alone (with a warning).
const MAX_EXCLUSIONS: usize = 10_000;

/// Refname → tip sha snapshot of `repo`; `None` when the snapshot itself fails (the
/// scan is skipped rather than treating the whole repository as new).
async fn list_refs(repo: &Path) -> Option<BTreeMap<String, String>> {
    match command::run([
        OsStr::new("-C"),
        repo.as_os_str(),
        OsStr::new("for-each-ref"),
        OsStr::new("--format=%(refname)%00%(objectname)"),
    ])
    .await
    {
        Ok(out) => {
            let mut refs = BTreeMap::new();
            for line in String::from_utf8_lossy(&out).lines() {
                let (name, sha) = line.split_once('\0').unwrap_or(("", ""));
                if !name.is_empty() && !sha.trim().is_empty() {
                    refs.insert(name.to_owned(), sha.trim().to_owned());
                }
            }
            Some(refs)
        }
        Err(err) => {
            tracing::warn!(%err, "trailer scan: ref snapshot failed");
            None
        }
    }
}

/// One ref to scan: `(refname, old tip or `None` when the ref is new, new tip)`,
/// in sorted refname order. Deleted refs and unchanged tips contribute nothing.
fn changed_refs(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<(String, Option<String>, String)> {
    let mut changes = Vec::new();
    for (name, new) in after {
        match before.get(name) {
            Some(old) if old == new => {}
            old => changes.push((name.clone(), old.cloned(), new.clone())),
        }
    }
    changes
}

/// Commits to scan: for each changed ref, `rev-list new --not old` (moved tip) or
/// `rev-list new --not <pre-push tips>` (brand-new ref; an empty pre-push snapshot
/// means the full history). Unioned across refs in sorted order, deduplicated, and
/// capped at [`MAX_SCAN_COMMITS`] total; hitting the cap warns with the cap and the
/// ref it cut off at. Per-ref failures warn and are skipped.
async fn new_commits(
    repo: &Path,
    before: &BTreeMap<String, String>,
    changes: &[(String, Option<String>, String)],
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    // The ref whose enumeration the commit cap cut off, if any — warned once below.
    let mut truncated: Option<&str> = None;
    for (name, old, new) in changes {
        if out.len() >= MAX_SCAN_COMMITS {
            truncated = Some(name.as_str());
            break;
        }
        let mut args: Vec<OsString> = vec![
            OsString::from("-C"),
            OsString::from(repo),
            OsString::from("rev-list"),
            OsString::from(new),
            OsString::from("--not"),
        ];
        match old {
            Some(old) => args.push(OsString::from(old)),
            None if before.is_empty() => {
                args.pop();
            }
            None if before.len() <= MAX_EXCLUSIONS => {
                args.extend(before.values().map(OsString::from));
            }
            None => {
                tracing::warn!(%name, tips = before.len(), "trailer scan: too many tips to exclude; scanning the tip alone");
                if seen.insert(new.clone()) {
                    out.push(new.clone());
                }
                continue;
            }
        }
        match command::run(args).await {
            Ok(bytes) => {
                for line in String::from_utf8_lossy(&bytes).lines() {
                    if out.len() >= MAX_SCAN_COMMITS {
                        truncated = Some(name.as_str());
                        break;
                    }
                    let sha = line.trim();
                    if !sha.is_empty() && seen.insert(sha.to_owned()) {
                        out.push(sha.to_owned());
                    }
                }
            }
            Err(err) => tracing::warn!(%name, %err, "trailer scan: rev-list failed"),
        }
        if truncated.is_some() {
            break;
        }
    }
    if let Some(refname) = truncated {
        tracing::warn!(
            %refname,
            cap = MAX_SCAN_COMMITS,
            enumerated = out.len(),
            "trailer scan: commit cap cut the scan; trailers past the cap were not scanned"
        );
    }
    out
}

impl Core {
    /// Snapshots every ref tip before a push runs; `None` on failure disables
    /// the scan for that push. Transports take this before spawning their
    /// `receive-pack` and pass it to [`Core::scan_push_changes`] on success.
    pub async fn snapshot_refs(&self, repo: &Path) -> Option<BTreeMap<String, String>> {
        list_refs(repo).await
    }

    /// Post-push ingest for one successful receive-pack: session trailers, accepted
    /// `refs/for` tips (agit changes + revisions + trail refs), and branch-head
    /// moves. The `before` snapshot was taken before the push ran; `pusher` is the
    /// authenticated user and `nonce` keys this push's pre-receive sidecars.
    /// Failures only warn: a push never fails because of the scan.
    pub async fn scan_push_changes(
        &self,
        repo_id: i64,
        repo: PathBuf,
        pusher: Option<User>,
        nonce: Option<String>,
        before: Option<BTreeMap<String, String>>,
    ) {
        let Some(before) = before else { return };
        // D1: the whole scan holds the per-repo ingest lock — `refs/for`
        // ingest, branch moves, and push events serialize with racing pushes.
        let ingest = self.repo_ingest_lock(repo_id).await;
        let Some(after) = list_refs(&repo).await else {
            return;
        };
        // Orphaned sidecars (a scan that never ran) must not accumulate.
        pushsidecar::reap(&repo, pushsidecar::MAX_AGE_SECS);
        let changes = changed_refs(&before, &after);
        // Deleted branches and tags never appear in `changed_refs` (it only
        // walks `after` — see its unit test); collect them separately so base
        // deletions still recompute mergeability.
        let deletes: Vec<(&str, &str)> = before
            .iter()
            .filter(|(name, _)| {
                (name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
                    && !after.contains_key(*name)
            })
            .map(|(name, old)| (name.as_str(), old.as_str()))
            .collect();
        if changes.is_empty() && deletes.is_empty() {
            return;
        }
        if !changes.is_empty() {
            scan_push_trailers(self, repo_id, &repo, &before, &changes).await;
            ingest_for_refs(
                self,
                repo_id,
                &repo,
                pusher.as_ref(),
                nonce.as_deref(),
                &after,
                &changes,
            )
            .await;
        }
        // Branch moves ingest each branch's CURRENT tip under the lock, never
        // the push line's `new` (stale when scans race); a missing branch is
        // skipped, while a delete still runs so base deletions recompute.
        // Non-heads never reach `record_branch_move` (it strips the prefix).
        let mut moves: Vec<(String, Option<String>, String)> = changes.clone();
        moves.extend(
            deletes
                .iter()
                .map(|(name, old)| ((*name).to_owned(), Some((*old).to_owned()), "0".repeat(40))),
        );
        self.ingest_branch_moves(&ingest, repo_id, pusher.as_ref().map(|u| u.id), &moves)
            .await;
        // Push fan-out runs AFTER branch moves and `refs/for` ingest: one
        // `push` event per heads/tags create, update, and delete, so a
        // delivered `push` event implies the push's revisions exist.
        // `record_push` skips `refs/for/*` and `refs/trails/*` itself; the zero
        // oid marks creates (`old`) and deletes (`new`).
        let mut push_updates: Vec<RefUpdate> = changes
            .iter()
            .map(|(name, old, new)| RefUpdate {
                name: name.clone(),
                old: old.clone().unwrap_or_else(|| "0".repeat(40)),
                new: new.clone(),
            })
            .collect();
        push_updates.extend(deletes.iter().map(|(name, old)| RefUpdate {
            name: (*name).to_owned(),
            old: (*old).to_owned(),
            new: "0".repeat(40),
        }));
        self.record_push(repo_id, pusher.as_ref(), &push_updates)
            .await;
    }
}

/// Ingests every new `refs/for/*` tip: change + revision + trail refs via
/// [`Core::record_agit_push`]. The consumed pseudo-ref (the hook accepted it
/// so receive-pack stored it; it is never kept) is deleted first, so every
/// row the scan's readers can observe implies the cleanup already happened.
/// The head ingested is the current tip from `after`, never a stale sidecar
/// address; the sidecar only supplies base/topic/options and is consumed
/// (deleted) either way.
async fn ingest_for_refs(
    core: &Core,
    repo_id: i64,
    repo: &Path,
    pusher: Option<&User>,
    nonce: Option<&str>,
    after: &BTreeMap<String, String>,
    changes: &[(String, Option<String>, String)],
) {
    let mut branches: Option<Vec<String>> = None;
    for (name, _old, new) in changes {
        if !name.starts_with("refs/for/") {
            continue;
        }
        if refpolicy::is_zero_oid(new) {
            continue;
        }
        if refpolicy::parse_for_ref(name).is_none() {
            tracing::warn!(
                repo_id,
                refname = name,
                "push scan: ignoring malformed refs/for ref"
            );
            continue;
        }
        let sidecar = load_sidecar(repo, nonce, name);
        let (user_id, sc) = match sidecar {
            Some(sidecar) => (
                sidecar.user_id,
                IngestSidecar {
                    base: sidecar.base,
                    topic: sidecar.topic,
                    trail: sidecar.trail,
                    title: sidecar.title,
                },
            ),
            None => {
                // No sidecar for this push's nonce: skip the options (never
                // borrow another push's file) and ingest optionless.
                tracing::warn!(
                    repo_id,
                    refname = name,
                    "push scan: no sidecar for this push; ingesting without options"
                );
                let Some(pusher) = pusher else {
                    tracing::warn!(
                        repo_id,
                        refname = name,
                        "push scan: no sidecar and no pusher; skipping"
                    );
                    continue;
                };
                if branches.is_none() {
                    let repo_path = repo.to_path_buf();
                    branches = tokio::task::spawn_blocking(move || {
                        read::branches(&repo_path).unwrap_or_default()
                    })
                    .await
                    .ok();
                }
                let remainder = name.strip_prefix("refs/for/").unwrap_or_default();
                let default = refpolicy::default_topic(&pusher.handle);
                match refpolicy::split_for(remainder, branches.as_deref().unwrap_or(&[]), &default)
                {
                    Ok((base, topic)) => (
                        Some(pusher.id),
                        IngestSidecar {
                            base,
                            topic,
                            trail: None,
                            title: None,
                        },
                    ),
                    Err(err) => {
                        tracing::warn!(repo_id, refname = name, error = %err, "push scan: cannot resolve refs/for target; skipping");
                        continue;
                    }
                }
            }
        };
        let Some(user_id) = user_id else {
            tracing::warn!(
                repo_id,
                refname = name,
                "push scan: sidecar has no user; skipping"
            );
            continue;
        };
        // Delete the consumed pseudo-ref BEFORE ingesting: the hook accepted
        // it so receive-pack stored it, and it is never kept. Deleting first
        // means every row the scan's readers can observe implies the cleanup
        // already happened (readers poll rows, never refs). A failed ingest
        // still warns loudly; re-pushing recreates the ref and its sidecar.
        if let Err(err) = write::delete_ref(repo, name).await {
            tracing::warn!(repo_id, refname = name, error = %err, "push scan: the refs/for pseudo-ref survived; it will be retried on the next push");
        }
        let base_tip = after
            .get(&format!("refs/heads/{}", sc.base))
            .cloned()
            .unwrap_or_else(|| new.clone());
        if let Err(err) = core
            .record_agit_push(repo_id, user_id, &sc, new, &base_tip)
            .await
        {
            tracing::warn!(repo_id, refname = name, error = %err, "push scan: refs/for ingest failed");
        }
    }
}

/// The sidecar for this push's `(nonce, refname)` pair, consumed exactly once.
/// Strictly the RPC-generated file: a missing file means the options are
/// skipped (the caller falls back to optionless addressing), never borrowed
/// from another push's sidecar for the same refname.
fn load_sidecar(repo: &Path, nonce: Option<&str>, refname: &str) -> Option<pushsidecar::Sidecar> {
    let nonce = nonce.filter(|nonce| pushsidecar::valid_nonce(nonce))?;
    let path = repo
        .join(pushsidecar::DIR_NAME)
        .join(pushsidecar::sidecar_name(nonce, refname));
    pushsidecar::consume_sidecar(&path).ok()
}

/// Scans commit trailers in the whole pushed range (not just the new tips), so
/// multi-commit pushes and new branches scan fully. Failures only warn: a push
/// never fails because of links.
async fn scan_push_trailers(
    core: &Core,
    repo_id: i64,
    repo: &Path,
    before: &BTreeMap<String, String>,
    changes: &[(String, Option<String>, String)],
) {
    let shas = new_commits(repo, before, changes).await;
    if shas.is_empty() {
        return;
    }
    let repo = repo.to_path_buf();
    let messages = tokio::task::spawn_blocking(move || {
        let mut out = Vec::with_capacity(shas.len());
        for sha in &shas {
            match read::commit(&repo, sha) {
                Ok(Some(info)) => out.push((sha.clone(), info.message.clone())),
                Ok(None) => tracing::warn!(%sha, "trailer scan: pushed commit not found"),
                Err(err) => tracing::warn!(%sha, %err, "trailer scan: commit read failed"),
            }
        }
        out
    })
    .await;
    let messages = match messages {
        Ok(messages) => messages,
        Err(err) => {
            tracing::warn!(%err, "trailer scan: commit read task failed");
            return;
        }
    };
    if messages.is_empty() {
        return;
    }
    if let Err(err) = core.record_trailer_links(repo_id, &messages).await {
        tracing::warn!(repo_id, %err, "trailer scan: storing links failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_refs_reports_updates_and_new_refs_in_order() {
        let before: BTreeMap<String, String> = [
            ("refs/heads/aaa".to_owned(), "tip-a".to_owned()),
            ("refs/heads/gone".to_owned(), "tip-g".to_owned()),
            ("refs/heads/main".to_owned(), "tip-1".to_owned()),
        ]
        .into_iter()
        .collect();
        let after: BTreeMap<String, String> = [
            ("refs/heads/aaa".to_owned(), "tip-a".to_owned()),
            ("refs/heads/feature".to_owned(), "tip-f".to_owned()),
            ("refs/heads/main".to_owned(), "tip-2".to_owned()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            changed_refs(&before, &after),
            vec![
                ("refs/heads/feature".to_owned(), None, "tip-f".to_owned()),
                (
                    "refs/heads/main".to_owned(),
                    Some("tip-1".to_owned()),
                    "tip-2".to_owned()
                ),
            ],
            "new and moved refs scan; unchanged and deleted refs add nothing"
        );
        assert!(changed_refs(&before, &before).is_empty());
    }
}
