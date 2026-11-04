//! Server-side re-scan, quarantine, and the admin quarantine queue (spec §7.7).
//!
//! Every accepted segment is scanned with
//! `built_in.merge(repo_rules).merge(site_rules)` — the operator's site rules
//! merge last, so they win scalar settings over the repo, which in turn wins
//! over the CLI-redaction built-ins. A high-confidence hit (per
//! `starforge-redact`'s high-confidence detector set: private keys, cloud
//! credentials, known tokens, and repo literals) quarantines the session;
//! quarantine is a state, never a rejection, so the segment is still stored.
//! Low-confidence hits only merge into the session's `redaction_counts`.

use std::collections::BTreeMap;

use serde::Serialize;
use starforge_redact::{Compiled, RuleSet, redact_text};
use starforged_db::sessions as db_sessions;

use crate::accounts::User;
use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// What the quarantine queue and the release endpoint return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub ulid: String,
    pub lifecycle: String,
    pub quarantine: String,
    pub reason: String,
    pub detail: String,
}

impl From<db_sessions::SessionRow> for SessionView {
    fn from(row: db_sessions::SessionRow) -> SessionView {
        SessionView {
            ulid: row.ulid,
            lifecycle: row.lifecycle,
            quarantine: row.quarantine,
            reason: row.quarantine_reason,
            detail: row.quarantine_detail,
        }
    }
}

/// Verdict of [`Core::rescan_session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    Clean,
    Quarantined { reason: String, detail: String },
}

/// The first high-confidence hit in one segment's JSONL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanHit {
    pub reason: String,
    /// `segment {n} line {k}` (1-based line within the segment).
    pub detail: String,
}

/// Scrubbed metadata strings plus the first high-confidence hit, if any.
/// `remote_urls` is scanned for the verdict and the counts but has no
/// session column, so only the other fields are returned for storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaScan {
    pub title: String,
    pub agent_version: String,
    pub branch: String,
    pub models: Vec<String>,
    pub files_touched: Vec<String>,
    pub counts: BTreeMap<String, u64>,
    pub first_hit: Option<ScanHit>,
}

/// Scans one metadata string value: returns the redacted text, accumulating
/// counts and recording the first high-confidence hit (in rule-priority
/// order, mirroring [`scan_segment_text`]).
fn scan_meta_value(
    compiled: &Compiled,
    high_confidence: &[&str],
    value: &str,
    detail: &str,
    counts: &mut BTreeMap<String, u64>,
    first_hit: &mut Option<ScanHit>,
) -> String {
    let (redacted, value_counts) = redact_text(compiled, value);
    for (id, n) in &value_counts {
        *counts.entry(id.clone()).or_insert(0) += n;
    }
    if first_hit.is_none()
        && let Some(reason) = high_confidence
            .iter()
            .find(|id| value_counts.contains_key(**id))
    {
        *first_hit = Some(ScanHit {
            reason: (*reason).to_owned(),
            detail: detail.to_owned(),
        });
    }
    redacted
}

/// String at `path` in session metadata (`None` when absent or not a string).
fn meta_str_at<'m>(meta: &'m serde_json::Value, path: &[&str]) -> Option<&'m str> {
    let mut value = meta;
    for key in path {
        value = value.get(*key)?;
    }
    value.as_str()
}

/// String elements of the array at `path` (`[]` when absent or not an array).
fn meta_list_at<'m>(meta: &'m serde_json::Value, path: &[&str]) -> Vec<&'m str> {
    let mut value = meta;
    for key in path {
        match value.get(*key) {
            Some(next) => value = next,
            None => return Vec::new(),
        }
    }
    match value.as_array() {
        Some(items) => items.iter().filter_map(serde_json::Value::as_str).collect(),
        None => Vec::new(),
    }
}

/// Scans the viewer-rendered session metadata strings with the same compiled
/// rule set as the segment path: `title`, each `models` / `files_touched` /
/// `repo.remote_urls` element, `repo.branch`, and `agent.version`. Values
/// come back redacted (store those, never the raw meta); a high-confidence
/// hit carries `meta.<field>` (or `meta.<field>[<i>]` for list items) as its
/// detail. Fields are scanned in that order, so the first hit wins.
/// Already-redacted values (`[redacted:<id>]`) match nothing and contribute
/// no counts, so re-scanning them never double-counts.
pub fn scan_session_meta(compiled: &Compiled, meta: &serde_json::Value) -> MetaScan {
    let ids = compiled.rule_ids();
    let mut high_confidence: Vec<&str> = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        if compiled.is_high_confidence(index) == Some(true) && !high_confidence.contains(id) {
            high_confidence.push(id);
        }
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut first_hit: Option<ScanHit> = None;
    let title = scan_meta_value(
        compiled,
        &high_confidence,
        meta_str_at(meta, &["title"]).unwrap_or(""),
        "meta.title",
        &mut counts,
        &mut first_hit,
    );
    let mut models = Vec::new();
    for (i, item) in meta_list_at(meta, &["models"]).into_iter().enumerate() {
        models.push(scan_meta_value(
            compiled,
            &high_confidence,
            item,
            &format!("meta.models[{i}]"),
            &mut counts,
            &mut first_hit,
        ));
    }
    let mut files_touched = Vec::new();
    for (i, item) in meta_list_at(meta, &["files_touched"])
        .into_iter()
        .enumerate()
    {
        files_touched.push(scan_meta_value(
            compiled,
            &high_confidence,
            item,
            &format!("meta.files_touched[{i}]"),
            &mut counts,
            &mut first_hit,
        ));
    }
    for (i, item) in meta_list_at(meta, &["repo", "remote_urls"])
        .into_iter()
        .enumerate()
    {
        scan_meta_value(
            compiled,
            &high_confidence,
            item,
            &format!("meta.repo.remote_urls[{i}]"),
            &mut counts,
            &mut first_hit,
        );
    }
    let branch = scan_meta_value(
        compiled,
        &high_confidence,
        meta_str_at(meta, &["repo", "branch"]).unwrap_or(""),
        "meta.repo.branch",
        &mut counts,
        &mut first_hit,
    );
    let agent_version = scan_meta_value(
        compiled,
        &high_confidence,
        meta_str_at(meta, &["agent", "version"]).unwrap_or(""),
        "meta.agent.version",
        &mut counts,
        &mut first_hit,
    );
    MetaScan {
        title,
        agent_version,
        branch,
        models,
        files_touched,
        counts,
        first_hit,
    }
}

/// Counts plus the first high-confidence hit for one segment's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    pub counts: BTreeMap<String, u64>,
    pub first_hit: Option<ScanHit>,
}

/// Compiles the effective server rule set: CLI-redaction built-ins, then the
/// repo's `.starforge/redact.toml`, then the operator's site rules. Detector
/// lists concatenate (a repo can only add detections); scalar settings
/// (`[pii]`, `[entropy]`) resolve to the last layer that sets them, so the
/// site can retune — or restore — what a repo weakened. Empty layers are
/// skipped; malformed TOML is an error, never a silent fallback.
pub fn compile_scan_rules(
    repo_rules: &str,
    site_rules: Option<&str>,
) -> Result<Compiled, starforge_redact::RuleError> {
    let mut rules = RuleSet::built_in();
    if !repo_rules.trim().is_empty() {
        rules = rules.merge(&RuleSet::parse_toml(repo_rules)?);
    }
    if let Some(site) = site_rules
        && !site.trim().is_empty()
    {
        rules = rules.merge(&RuleSet::parse_toml(site)?);
    }
    rules.compile()
}

/// Scans one segment's decompressed JSONL line by line. Counts accumulate
/// across lines; the first line whose counts include a high-confidence
/// detector id (in rule-priority order) wins the attribution.
pub fn scan_segment_text(compiled: &Compiled, text: &str, seg_n: i64) -> ScanOutcome {
    let ids = compiled.rule_ids();
    let mut high_confidence: Vec<&str> = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        if compiled.is_high_confidence(index) == Some(true) && !high_confidence.contains(id) {
            high_confidence.push(id);
        }
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut first_hit = None;
    for (k, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (_, line_counts) = redact_text(compiled, line);
        for (id, n) in &line_counts {
            *counts.entry(id.clone()).or_insert(0) += n;
        }
        if first_hit.is_none()
            && let Some(reason) = high_confidence
                .iter()
                .find(|id| line_counts.contains_key(**id))
        {
            first_hit = Some(ScanHit {
                reason: (*reason).to_owned(),
                detail: format!("segment {seg_n} line {}", k + 1),
            });
        }
    }
    ScanOutcome { counts, first_hit }
}

impl Core {
    /// The effective server rule set for `repo_id` (built-ins + repo + site).
    /// Malformed TOML answers `Invalid` (422): a misconfigured layer must be
    /// visible, never silently ignored.
    pub async fn scan_rules_for(&self, repo_id: i64) -> CoreResult<Compiled> {
        let repo_rules = starforged_db::repos::redact_rules(self.db(), repo_id).await?;
        compile_scan_rules(&repo_rules, self.config().site_redact_rules.as_deref())
            .map_err(|e| CoreError::Invalid(format!("invalid redact rules: {e}")))
    }

    /// Re-scans every stored segment of `session_id` with the effective rule
    /// set. The first high-confidence hit quarantines the session (reason +
    /// location) and audits `session.quarantine`, unless the session is
    /// already quarantined — the stored verdict stands, so a reviewed release
    /// is not re-armed by old segments. Runs synchronously: segments are
    /// small and the verdict must be settled before upload responses return.
    pub async fn rescan_session(&self, session_id: i64) -> CoreResult<QuarantineOutcome> {
        let session = db_sessions::session_by_id(self.db(), session_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if session.quarantine == "quarantined" {
            return Ok(QuarantineOutcome::Quarantined {
                reason: session.quarantine_reason,
                detail: session.quarantine_detail,
            });
        }
        let compiled = self.scan_rules_for(session.repo_id).await?;
        for seg in db_sessions::segments_of(self.db(), session.id).await? {
            let bytes = self
                .config()
                .blob_store
                .get_by_hash(&seg.blob_hash)
                .await
                .map_err(|e| CoreError::Internal(format!("reading segment blob: {e}")))?;
            let text = crate::ingest::decompress_segment_text(self.config(), &bytes)?;
            let outcome = scan_segment_text(&compiled, &text, seg.n);
            if let Some(hit) = &outcome.first_hit {
                self.apply_quarantine_hit(None, &session, hit).await?;
                return Ok(QuarantineOutcome::Quarantined {
                    reason: hit.reason.clone(),
                    detail: hit.detail.clone(),
                });
            }
        }
        Ok(QuarantineOutcome::Clean)
    }

    /// Sessions of the repository awaiting quarantine review, oldest first.
    pub async fn list_quarantined(&self, access: &RepoAccess) -> CoreResult<Vec<SessionView>> {
        Ok(db_sessions::quarantined_of_repo(self.db(), access.repo.id)
            .await?
            .into_iter()
            .map(SessionView::from)
            .collect())
    }

    /// Releases a quarantined session back to review; anything else is `Invalid`.
    pub async fn release_session(
        &self,
        actor: &User,
        access: &RepoAccess,
        ulid: &str,
    ) -> CoreResult<SessionView> {
        let session = db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        if session.quarantine != "quarantined" {
            return Err(CoreError::Invalid("session is not quarantined".into()));
        }
        db_sessions::set_quarantine(
            self.db(),
            session.id,
            "released",
            &session.quarantine_reason,
            &session.quarantine_detail,
        )
        .await?;
        self.audit(
            Some(actor.id),
            "session.quarantine.released",
            &format!("session:{ulid}"),
            "",
        )
        .await?;
        db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .map(SessionView::from)
            .ok_or_else(|| CoreError::Internal("session vanished during release".into()))
    }

    /// Deletes the session row, its segment rows, and every commit link filed
    /// under its ULID (the removal itself is [`Core::remove_session_rows`],
    /// shared with the user-facing delete path). Audits `session.purged`.
    pub async fn purge_session(
        &self,
        actor: &User,
        access: &RepoAccess,
        ulid: &str,
    ) -> CoreResult<()> {
        let session = db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.remove_session_rows(Some(actor.id), access, &session, "session.purged")
            .await
    }

    /// The admin rescan route's thin wrapper around [`Core::rescan_session`]:
    /// no new verdict logic. Looks the session up by ULID under the
    /// handler-proved `Admin` access, re-runs the rule scan (idempotent: an
    /// already-quarantined session keeps its stored verdict), and audits
    /// `session.rescan`.
    pub async fn admin_rescan_session(
        &self,
        actor: &User,
        access: &RepoAccess,
        ulid: &str,
    ) -> CoreResult<QuarantineOutcome> {
        let session = db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        let outcome = self.rescan_session(session.id).await?;
        self.audit(
            Some(actor.id),
            "session.rescan",
            &format!("session:{ulid}"),
            "",
        )
        .await?;
        Ok(outcome)
    }

    /// Merges one segment's server-found counts into the session's
    /// `redaction_counts` (additive; the client's fingerprint column is never
    /// rewritten). Unparseable existing counts restart from the server's.
    pub(crate) async fn merge_scan_counts(
        &self,
        session: &db_sessions::SessionRow,
        extra: &BTreeMap<String, u64>,
    ) -> CoreResult<()> {
        if extra.is_empty() {
            return Ok(());
        }
        let mut merged: BTreeMap<String, u64> =
            serde_json::from_str(&session.redaction_counts).unwrap_or_default();
        for (id, n) in extra {
            *merged.entry(id.clone()).or_insert(0) += n;
        }
        let counts = serde_json::to_string(&merged)
            .map_err(|e| CoreError::Internal(format!("encoding redaction counts: {e}")))?;
        db_sessions::set_redaction_counts(self.db(), session.id, &counts).await?;
        Ok(())
    }

    /// Records a quarantine hit unless the session is already quarantined
    /// (first hit wins). Returns whether the flag moved.
    pub(crate) async fn apply_quarantine_hit(
        &self,
        actor_id: Option<i64>,
        session: &db_sessions::SessionRow,
        hit: &ScanHit,
    ) -> CoreResult<bool> {
        let fresh = db_sessions::session_by_ulid(self.db(), session.repo_id, &session.ulid)
            .await?
            .ok_or_else(|| CoreError::Internal("session vanished during re-scan".into()))?;
        if fresh.quarantine == "quarantined" {
            return Ok(false);
        }
        db_sessions::set_quarantine(self.db(), fresh.id, "quarantined", &hit.reason, &hit.detail)
            .await?;
        self.audit(
            actor_id,
            "session.quarantine",
            &format!("session:{}", session.ulid),
            &format!("{} at {}", hit.reason, hit.detail),
        )
        .await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 36-byte all-unique alphanumeric token: Shannon entropy is log2(36) ≈
    /// 5.2 bits/char, above the 4.5 default and invisible at min_len 64.
    const ENTROPY_TOKEN: &str = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ";

    fn line_with(token: &str) -> String {
        format!(
            r#"{{"v":1,"seq":0,"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"token {token} here"}}"#
        )
    }

    #[test]
    fn site_rules_override_repo_weakening() {
        let repo = "[entropy]\nmin_len = 64\n";
        let site = "[entropy]\nmin_len = 20\n";
        let weakened = compile_scan_rules(repo, None).unwrap();
        let weakened_counts = scan_segment_text(&weakened, &line_with(ENTROPY_TOKEN), 0).counts;
        assert!(
            !weakened_counts.contains_key("high-entropy"),
            "{weakened_counts:?}"
        );
        let restored = compile_scan_rules(repo, Some(site)).unwrap();
        let restored_counts = scan_segment_text(&restored, &line_with(ENTROPY_TOKEN), 0).counts;
        assert_eq!(restored_counts.get("high-entropy"), Some(&1));
    }

    #[test]
    fn empty_layers_mean_built_ins_only() {
        let rules = compile_scan_rules("", None).unwrap();
        let outcome = scan_segment_text(&rules, &line_with("alice@example.com"), 0);
        assert_eq!(outcome.first_hit, None);
        assert!(outcome.counts.is_empty(), "{:?}", outcome.counts);
    }

    #[test]
    fn malformed_toml_is_an_error_not_a_fallback() {
        assert!(compile_scan_rules("[entropy\nmin_len = ", None).is_err());
        assert!(compile_scan_rules("", Some("[[pattern]]\nregex = \"([\"")).is_err());
    }

    #[test]
    fn first_high_confidence_hit_wins_with_location() {
        let rules = compile_scan_rules("", None).unwrap();
        let pem = "k -----BEGIN PRIVATE KEY-----\\nMIIEvA==\\n-----END PRIVATE KEY-----";
        let text = [line_with("clean"), line_with(pem)].join("\n");
        let outcome = scan_segment_text(&rules, &text, 3);
        assert_eq!(
            outcome.first_hit,
            Some(ScanHit {
                reason: "private-key".to_owned(),
                detail: "segment 3 line 2".to_owned(),
            })
        );
    }

    #[test]
    fn repo_literal_is_high_confidence() {
        let rules =
            compile_scan_rules("[entropy]\nliterals = [\"REPO-MARKER-42\"]\n", None).unwrap();
        let outcome = scan_segment_text(&rules, &line_with("deploy REPO-MARKER-42"), 0);
        assert_eq!(
            outcome.first_hit.as_ref().map(|h| h.reason.as_str()),
            Some("literal")
        );
        assert_eq!(outcome.counts.get("literal"), Some(&1));
    }

    #[test]
    fn meta_scan_reports_files_touched_hit_with_redacted_value() {
        let rules = compile_scan_rules("", None).unwrap();
        let meta = serde_json::json!({
            "title": "test session",
            "models": ["opus"],
            "files_touched": ["src/file with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 inside.rs"],
            "repo": {"branch": "feature/widget", "remote_urls": []},
            "agent": {"name": "claude-code", "version": "1.0"},
        });
        let scan = scan_session_meta(&rules, &meta);
        assert_eq!(
            scan.first_hit,
            Some(ScanHit {
                reason: "known-token".to_owned(),
                detail: "meta.files_touched[0]".to_owned(),
            })
        );
        assert!(scan.files_touched[0].contains("[redacted:known-token]"));
    }
}
