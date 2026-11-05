//! Merge-gate evaluation (spec §6.2, M2c H3): per-rule pass/fail over
//! approvals, request-changes, required contexts, branch freshness,
//! resolved threads, and session evidence.
//!
//! Matching is fail-closed AND: every rule whose pattern matches the
//! change's base branch must pass; zero matching rules pass. A `NULL` or
//! empty pattern matches all branches.
//!
//! Glob note: patterns are matched by the small in-task matcher
//! [`pattern_matches`] (`*` matches any run, `?` matches one character,
//! everything else is literal). No workspace pattern dependency exists, so a
//! 20-line matcher beats a new crate dependency here.
//!
//! Reads only: evaluation touches the database and git, never writes.

use serde::{Deserialize, Serialize};
use starforged_db::{changes as db_changes, checks as db_checks, sessions as db_sessions};
use starforged_git::read;

use crate::accounts::User;
use crate::permission::Permission;
use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// Outcome of one matching gate rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// The rule's pattern, or `"all branches"` when it matches everything.
    pub rule: String,
    pub passed: bool,
    /// Human reason: `"needs 1 more approval"`, `"missing session 01ARZ…"`,
    /// `"head is behind base 'main'"`, or `"all required gates pass"`.
    pub reason: String,
}

/// Outcome of evaluating every matching gate rule (AND semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub passed: bool,
    pub results: Vec<GateResult>,
}

/// Minimal glob: `*` matches any (possibly empty) run, `?` matches exactly
/// one character, everything else matches literally. Case-sensitive.
pub fn pattern_matches(pattern: Option<&str>, branch: &str) -> bool {
    let pat = match pattern {
        None | Some("") => return true,
        Some(p) => p,
    };
    glob_match(pat.as_bytes(), branch.as_bytes())
}

fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut px, mut tx) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while tx < text.len() {
        if px < pat.len() && (pat[px] == b'?' || pat[px] == text[tx]) {
            px += 1;
            tx += 1;
        } else if px < pat.len() && pat[px] == b'*' {
            star = Some(px);
            mark = tx;
            px += 1;
        } else if let Some(s) = star {
            px = s + 1;
            mark += 1;
            tx = mark;
        } else {
            return false;
        }
    }
    while px < pat.len() && pat[px] == b'*' {
        px += 1;
    }
    px == pat.len()
}

fn parse_strings(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

fn rule_label(pattern: &Option<String>) -> String {
    match pattern {
        Some(p) if !p.is_empty() => p.clone(),
        _ => "all branches".to_owned(),
    }
}

fn short(sha: &str) -> String {
    sha.chars().take(7).collect()
}

/// Bound on the `merge_base..head` walk for session evidence: more commits
/// than this fails the gate instead of scanning longer. Fail-closed: a gate
/// that can be defeated by pushing a long history is a security hole.
const MAX_EVIDENCE_COMMITS: usize = 1024;
/// Bound on `Starforge-Session` trailers read from one commit message.
const MAX_EVIDENCE_TRAILERS_PER_COMMIT: usize = 64;

/// `Starforge-Session` trailer ULIDs carried by one commit message.
pub(crate) fn session_trailers(message: &str) -> Vec<String> {
    message
        .lines()
        .filter_map(|line| line.strip_prefix("Starforge-Session:"))
        .filter_map(|value| value.split_whitespace().next().map(str::to_owned))
        .filter(|token| !token.is_empty())
        .collect()
}

impl Core {
    /// Evaluates every gate rule matching the change's base branch (AND;
    /// zero matching rules pass). `viewer` needs read visibility
    /// (`NotFound` otherwise — the same convention as [`Core::get_change`]).
    /// Reads only: no timeline rows, no writes.
    pub async fn evaluate_gates(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
    ) -> CoreResult<GateReport> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let trail = starforged_db::trails::trail_by_number(self.db(), access.repo.id, trail_n)
            .await?
            .ok_or(CoreError::NotFound)?;
        let change = db_changes::change_by_trail_number(self.db(), trail.id, k)
            .await?
            .ok_or(CoreError::NotFound)?;
        let rules = db_checks::gate_rules_for(self.db(), access.repo.id).await?;
        let matching: Vec<_> = rules
            .iter()
            .filter(|r| pattern_matches(r.pattern.as_deref(), &change.base_branch))
            .collect();
        if matching.is_empty() {
            return Ok(GateReport {
                passed: true,
                results: Vec::new(),
            });
        }
        let current_id = match change.current_revision_id {
            Some(id) => id,
            None => {
                return Ok(GateReport {
                    passed: false,
                    results: vec![GateResult {
                        rule: "change".to_owned(),
                        passed: false,
                        reason: "change has no revisions yet".to_owned(),
                    }],
                });
            }
        };
        let current = db_changes::revision_by_id(self.db(), current_id)
            .await?
            .ok_or_else(|| CoreError::Internal("change has no current revision".into()))?;
        let mut results = Vec::new();
        let mut all_pass = true;
        for rule in matching {
            let result = self.evaluate_rule(&access, &change, &current, rule).await?;
            all_pass &= result.passed;
            results.push(result);
        }
        Ok(GateReport {
            passed: all_pass,
            results,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn evaluate_rule(
        &self,
        access: &RepoAccess,
        change: &db_changes::ChangeRow,
        current: &db_changes::RevisionRow,
        rule: &db_checks::GateRuleRow,
    ) -> CoreResult<GateResult> {
        let mut failures: Vec<String> = Vec::new();

        // Counting scope: one voice per author. Only authors who currently
        // hold at least Write ever count. For each such author, only their
        // latest decisive review (highest id with verdict `approve` or
        // `request_changes`, in any state) speaks: `comment` reviews are
        // neutral and never change an author's state. A latest review that
        // is not `submitted` (dismissed explicitly or by `dismiss_on_push`)
        // contributes nothing — including an older `request_changes` it
        // supersedes, which a push never clears on its own. A submitted
        // `approve` counts one approval, from the current revision only
        // when this rule has `dismiss_on_push`; a submitted
        // `request_changes` makes the author a requester, from any revision.
        let current_only = rule.dismiss_on_push != 0;
        let reviews = db_changes::reviews_of_change(self.db(), change.id).await?;
        // Latest decisive review per author. `reviews_of_change` returns
        // id order, so walking backwards takes the highest id first.
        let mut latest: Vec<(&db_changes::ReviewRow, i64)> = Vec::new();
        for review in reviews.iter().rev() {
            if !matches!(review.verdict.as_str(), "approve" | "request_changes") {
                continue;
            }
            let Some(author_id) = review.author_id else {
                continue;
            };
            if latest.iter().any(|(_, seen)| *seen == author_id) {
                continue;
            }
            latest.push((review, author_id));
        }
        let mut approvals = 0i64;
        let mut requesters: Vec<String> = Vec::new();
        for (review, author_id) in latest {
            if review.state != "submitted" {
                continue;
            }
            let Some(author) = self.user_by_id(author_id).await? else {
                continue;
            };
            if !self
                .permission_on(&access.repo, Some(&author))
                .await?
                .is_some_and(|p| p >= Permission::Write)
            {
                continue;
            }
            match review.verdict.as_str() {
                "approve" => {
                    if !current_only || review.revision_id == current.id {
                        approvals += 1;
                    }
                }
                _ => requesters.push(author.handle),
            }
        }
        if approvals < rule.required_approvals {
            let need = rule.required_approvals - approvals;
            failures.push(format!(
                "needs {need} more approval{}",
                if need == 1 { "" } else { "s" }
            ));
        }
        if rule.block_on_request_changes != 0 && !requesters.is_empty() {
            requesters.sort();
            requesters.dedup();
            failures.push(format!("changes requested by {}", requesters.join(", ")));
        }

        let required_contexts = parse_strings(&rule.required_contexts);
        if !required_contexts.is_empty() {
            let checks =
                db_checks::latest_checks_for_sha(self.db(), access.repo.id, &current.head_sha)
                    .await?;
            for context in &required_contexts {
                match checks.iter().find(|c| &c.context == context) {
                    Some(row) if row.state == "success" => {}
                    Some(row) => {
                        failures.push(format!("required context `{context}` is {}", row.state))
                    }
                    None => failures.push(format!("required context `{context}` has no status")),
                }
            }
        }

        // Head freshness + session evidence share the live base tip and the
        // merge base; both run on blocking threads (never a worktree). Git
        // failures never pass the gate: they record a failure reason.
        let repo_path = self.repo_path(access.repo.id);
        let head_sha = current.head_sha.clone();
        let base_branch = change.base_branch.clone();
        let fresh = tokio::task::spawn_blocking(move || {
            let branches = read::branch_list(&repo_path)?;
            let tip = branches
                .into_iter()
                .find(|b| b.name == base_branch)
                .map(|b| b.tip.id);
            let merge_base = match &tip {
                Some(tip) => read::merge_base(&repo_path, &head_sha, tip)?,
                None => None,
            };
            Ok::<_, starforged_git::GitError>((tip, merge_base))
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?;
        let (base_tip, merge_base) = match fresh {
            Ok(pair) => pair,
            Err(e) => {
                failures.push(format!("could not verify freshness: {e}"));
                (None, None)
            }
        };

        if rule.require_up_to_date != 0 {
            match (&base_tip, &merge_base) {
                (Some(tip), Some(mb)) if mb == tip => {}
                (Some(_), _) => {
                    failures.push(format!("head is behind base '{}'", change.base_branch))
                }
                (None, _) => {
                    if !failures.iter().any(|f| f.starts_with("could not verify")) {
                        failures.push(format!("base branch '{}' is missing", change.base_branch))
                    }
                }
            }
        }

        if rule.require_threads_resolved != 0 {
            let open = db_changes::threads_of_change(self.db(), change.id)
                .await?
                .into_iter()
                .filter(|t| t.anchor_revision_id == current.id && t.resolved == 0)
                .count();
            if open > 0 {
                failures.push(format!(
                    "{open} unresolved thread{}",
                    if open == 1 { "" } else { "s" }
                ));
            }
        }

        if rule.require_session_evidence != 0 {
            let evidence = self
                .session_evidence_failures(
                    access.repo.id,
                    &current.head_sha,
                    base_tip.as_deref(),
                    MAX_EVIDENCE_COMMITS,
                    MAX_EVIDENCE_TRAILERS_PER_COMMIT,
                )
                .await?;
            failures.extend(evidence);
        }

        let methods = parse_strings(&rule.allowed_methods);
        let methods_note = if methods.is_empty() {
            String::new()
        } else {
            format!(" (methods: {})", methods.join(", "))
        };

        let (passed, reason) = if failures.is_empty() {
            (true, format!("all required gates pass{methods_note}"))
        } else {
            (false, format!("{}{methods_note}", failures.join("; ")))
        };
        Ok(GateResult {
            rule: rule_label(&rule.pattern),
            passed,
            reason,
        })
    }

    /// Failure reasons for the session-evidence check (empty means pass).
    /// Fail-closed throughout: an unverifiable history — too many commits,
    /// too many trailers, a missing base, or any git error — is a failure,
    /// never a pass. `max_commits` / `max_trailers` are parameters (not the
    /// constants) so tests can exercise the caps without pushing a thousand
    /// commits.
    async fn session_evidence_failures(
        &self,
        repo_id: i64,
        head_sha: &str,
        base_tip: Option<&str>,
        max_commits: usize,
        max_trailers: usize,
    ) -> CoreResult<Vec<String>> {
        let Some(base) = base_tip else {
            return Ok(vec![
                "session evidence: unable to verify history (base branch is missing)".to_owned(),
            ]);
        };
        let repo_path = self.repo_path(repo_id);
        let (head, base) = (head_sha.to_owned(), base.to_owned());
        let walked = tokio::task::spawn_blocking(move || {
            let from = read::merge_base(&repo_path, &head, &base)?;
            // `merge_base..head`: when unrelated, `from` is the head
            // itself and the range is empty.
            let from = from.unwrap_or(head.clone());
            read::range_log(&repo_path, &from, &head, max_commits + 1)
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()));
        let (commits, total) = match walked {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                return Ok(vec![format!(
                    "session evidence: unable to verify history: {e}"
                )]);
            }
            Err(e) => return Err(e),
        };
        if total > max_commits {
            return Ok(vec![format!(
                "session evidence: unable to verify history ({total} commits exceed the {max_commits}-commit walk limit)"
            )]);
        }
        let mut failures = Vec::new();
        for commit in commits {
            let trailers = session_trailers(&commit.message);
            if trailers.len() > max_trailers {
                failures.push(format!(
                    "session evidence: unable to verify history (commit {} carries {} session trailers, limit {max_trailers})",
                    short(&commit.id),
                    trailers.len()
                ));
                continue;
            }
            for ulid in trailers {
                match db_sessions::session_by_ulid(self.db(), repo_id, &ulid).await? {
                    Some(row) if row.quarantine != "quarantined" => {}
                    Some(_) => failures.push(format!("session `{ulid}` is quarantined")),
                    None => failures.push(format!(
                        "commit {} names unknown session `{ulid}`",
                        short(&commit.id)
                    )),
                }
            }
            if failures.len() > 10 {
                failures.push(
                    "session evidence: unable to verify history (too many unverified commits)"
                        .to_owned(),
                );
                break;
            }
        }
        Ok(failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::{seed_branches, test_core, user};
    use starforged_db::sessions::{NewSession, insert_session};
    use starforged_db::trails as db_trails;

    const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";

    struct Harness {
        core: Core,
        _fixture: crate::testing::Fixture,
        alice: User,
        bob: User,
        carol: User,
        repo_id: i64,
        trail_n: i64,
        k: i64,
    }

    impl Harness {
        async fn setup() -> Harness {
            let (core, _fixture) = test_core().await;
            let alice = user(&core, "alice").await;
            let bob = user(&core, "bob").await;
            let carol = user(&core, "carol").await;
            let created = core
                .create_repo(
                    &alice,
                    CreateRepo {
                        name: "proj-gates".into(),
                        description: String::new(),
                        visibility: Visibility::Private,
                        readme: false,
                    },
                )
                .await
                .unwrap();
            core.set_collaborator(&alice, "alice", "proj-gates", "bob", Permission::Write)
                .await
                .unwrap();
            core.set_collaborator(&alice, "alice", "proj-gates", "carol", Permission::Read)
                .await
                .unwrap();
            seed_branches(&core, created.id, &["main", "feature"]);
            let trail = core
                .create_trail(&alice, "alice", "proj-gates", "work", "do the thing")
                .await
                .unwrap();
            core.create_branch_change(
                &alice,
                "alice",
                "proj-gates",
                trail.number,
                "feature",
                "main",
            )
            .await
            .unwrap();
            Harness {
                core,
                _fixture,
                alice,
                bob,
                carol,
                repo_id: created.id,
                trail_n: trail.number,
                k: 1,
            }
        }

        #[allow(clippy::too_many_arguments)]
        async fn rule(
            &self,
            pattern: Option<&str>,
            approvals: i64,
            block_rc: bool,
            contexts: &str,
            up_to_date: bool,
            threads: bool,
            session_ev: bool,
            methods: &str,
        ) {
            db_checks::insert_gate_rule(
                self.core.db(),
                self.repo_id,
                pattern,
                approvals,
                false,
                block_rc,
                contexts,
                up_to_date,
                threads,
                session_ev,
                methods,
                1_700_000_000,
            )
            .await
            .unwrap();
        }

        async fn rule_flags(&self, dismiss: bool, block_rc: bool) {
            db_checks::insert_gate_rule(
                self.core.db(),
                self.repo_id,
                None,
                1,
                dismiss,
                block_rc,
                "[]",
                false,
                false,
                false,
                "[]",
                1_700_000_000,
            )
            .await
            .unwrap();
        }
        async fn rule_n(&self, approvals: i64, dismiss: bool) {
            db_checks::insert_gate_rule(
                self.core.db(),
                self.repo_id,
                None,
                approvals,
                dismiss,
                false,
                "[]",
                false,
                false,
                false,
                "[]",
                1_700_000_000,
            )
            .await
            .unwrap();
        }
        async fn report(&self) -> GateReport {
            self.core
                .evaluate_gates(
                    Some(&self.alice),
                    "alice",
                    "proj-gates",
                    self.trail_n,
                    self.k,
                )
                .await
                .unwrap()
        }

        async fn approve(&self, author: &User) {
            self.core
                .submit_review(
                    author,
                    "alice",
                    "proj-gates",
                    self.trail_n,
                    self.k,
                    None,
                    "approve",
                    "lgtm",
                    None,
                    &[],
                )
                .await
                .unwrap();
        }

        async fn verdict(&self, author: &User, verdict: &str) {
            self.core
                .submit_review(
                    author,
                    "alice",
                    "proj-gates",
                    self.trail_n,
                    self.k,
                    None,
                    verdict,
                    "note",
                    None,
                    &[],
                )
                .await
                .unwrap();
        }

        fn bare(&self) -> std::path::PathBuf {
            self.core.repo_path(self.repo_id)
        }
    }

    /// Current tip of `branch` in the bare repo.
    fn tip_of(bare: &std::path::Path, branch: &str) -> String {
        let out = std::process::Command::new("git")
            .args(["rev-parse", branch])
            .env("GIT_DIR", bare)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "rev-parse: {out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// Commits `body` as `file` onto `branch` of the bare repo, using plumbing
    /// (`commit-tree` + `update-ref`) so no hooks fire. Returns the new tip.
    fn push_commit(
        bare: &std::path::Path,
        branch: &str,
        file: &str,
        body: &[u8],
        message: &str,
    ) -> String {
        use std::io::Write as _;
        use std::process::Stdio;
        let index = tempfile::NamedTempFile::new().unwrap();
        let index_path = index.path().to_owned();
        let run = |args: &[&str], stdin: Option<&[u8]>| {
            let mut cmd = std::process::Command::new("git");
            cmd.args(["-c", "user.name=T", "-c", "user.email=t@example.test"]);
            cmd.args(args);
            cmd.env("GIT_DIR", bare);
            cmd.env("GIT_INDEX_FILE", &index_path);
            cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
            cmd.env("GIT_CONFIG_NOSYSTEM", "1");
            cmd.env("GIT_AUTHOR_NAME", "T");
            cmd.env("GIT_AUTHOR_EMAIL", "t@example.test");
            cmd.env("GIT_COMMITTER_NAME", "T");
            cmd.env("GIT_COMMITTER_EMAIL", "t@example.test");
            if stdin.is_some() {
                cmd.stdin(Stdio::piped());
            }
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            if let Some(input) = stdin {
                child.stdin.take().unwrap().write_all(input).unwrap();
            }
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        let parent = run(&["rev-parse", branch], None);
        let blob = run(&["hash-object", "-w", "--stdin"], Some(body));
        run(&["read-tree", &parent], None);
        run(
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("100644,{blob},{file}"),
            ],
            None,
        );
        let tree = run(&["write-tree"], None);
        let new = run(&["commit-tree", &tree, "-p", &parent, "-m", message], None);
        run(&["update-ref", &format!("refs/heads/{branch}"), &new], None);
        new
    }

    async fn insert_session_row(
        core: &Core,
        repo_id: i64,
        uploader: i64,
        ulid: &str,
        quarantine: &str,
    ) {
        insert_session(
            core.db(),
            &NewSession {
                repo_id,
                ulid,
                uploader_id: uploader,
                agent_name: "claude-code",
                agent_version: "1.0",
                models: "[\"opus\"]",
                title: "t",
                branch: "feature",
                head_sha: &"0".repeat(40),
                started_at: 1_700_000_000,
                ended_at: None,
                parent_ulid: None,
                usage_input: 0,
                usage_output: 0,
                usage_cache_read: 0,
                usage_cache_write: 0,
                usage_reasoning: 0,
                files_touched: "[]",
                turn_count: 1,
                tool_call_count: 1,
                lifecycle: "complete",
                quarantine,
                quarantine_reason: "",
                quarantine_detail: "",
                visibility: "inherit",
                raw_enabled: 0,
                redaction_fingerprint: "fp",
                redaction_counts: "{}",
                capture_mode: "discovery",
                cli_version: "9.9.9",
                adapter_verified: 1,
            },
        )
        .await
        .unwrap();
    }

    #[test]
    fn glob_matcher_basics() {
        assert!(pattern_matches(None, "main"));
        assert!(pattern_matches(Some(""), "main"));
        assert!(pattern_matches(Some("main"), "main"));
        assert!(!pattern_matches(Some("main"), "main2"));
        assert!(pattern_matches(Some("release/*"), "release/v1"));
        assert!(!pattern_matches(Some("release/*"), "release"));
        assert!(pattern_matches(Some("release-?"), "release-1"));
        assert!(!pattern_matches(Some("release-?"), "release-12"));
        assert!(pattern_matches(Some("*"), "anything/at-all"));
    }

    #[tokio::test]
    async fn no_rules_pass() {
        let h = Harness::setup().await;
        let report = h.report().await;
        assert!(report.passed);
        assert!(report.results.is_empty());
    }

    #[tokio::test]
    async fn approvals_short_by_one_then_pass() {
        let h = Harness::setup().await;
        h.rule(None, 2, false, "[]", false, false, false, "[]")
            .await;
        let report = h.report().await;
        assert!(!report.passed);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].reason, "needs 2 more approvals");
        h.approve(&h.bob.clone()).await;
        let report = h.report().await;
        assert!(!report.passed);
        assert_eq!(report.results[0].reason, "needs 1 more approval");
        h.approve(&h.alice.clone()).await;
        let report = h.report().await;
        assert!(report.passed);
        assert!(report.results[0].passed);
    }

    #[tokio::test]
    async fn read_only_approval_does_not_count() {
        let h = Harness::setup().await;
        h.rule(None, 1, false, "[]", false, false, false, "[]")
            .await;
        h.approve(&h.carol.clone()).await;
        let report = h.report().await;
        assert!(!report.passed);
        assert_eq!(report.results[0].reason, "needs 1 more approval");
    }

    #[tokio::test]
    async fn request_changes_blocks_until_dismissed() {
        let h = Harness::setup().await;
        h.rule(None, 0, true, "[]", false, false, false, "[]").await;
        assert!(h.report().await.passed);
        let (review, _) = h
            .core
            .submit_review(
                &h.bob,
                "alice",
                "proj-gates",
                h.trail_n,
                h.k,
                None,
                "request_changes",
                "nope",
                None,
                &[],
            )
            .await
            .unwrap();
        let report = h.report().await;
        assert!(!report.passed);
        assert!(
            report.results[0]
                .reason
                .contains("changes requested by bob")
        );
        h.core
            .dismiss_review(&h.alice, "alice", "proj-gates", h.trail_n, h.k, review.id)
            .await
            .unwrap();
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn double_approval_by_one_reviewer_counts_once() {
        let h = Harness::setup().await;
        h.rule_n(2, false).await;
        h.approve(&h.bob.clone()).await;
        h.approve(&h.bob.clone()).await;
        let report = h.report().await;
        assert!(!report.passed);
        assert_eq!(report.results[0].reason, "needs 1 more approval");
        h.approve(&h.alice.clone()).await;
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn request_changes_then_approve_by_same_reviewer_clears() {
        let h = Harness::setup().await;
        h.rule(None, 1, true, "[]", false, false, false, "[]").await;
        h.verdict(&h.bob.clone(), "request_changes").await;
        assert!(!h.report().await.passed);
        h.approve(&h.bob.clone()).await;
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn approve_then_request_changes_by_same_reviewer_blocks() {
        let h = Harness::setup().await;
        h.rule(None, 1, true, "[]", false, false, false, "[]").await;
        h.approve(&h.bob.clone()).await;
        assert!(h.report().await.passed);
        h.verdict(&h.bob.clone(), "request_changes").await;
        let report = h.report().await;
        assert!(!report.passed);
        assert!(
            report.results[0].reason.contains("needs 1 more approval"),
            "{}",
            report.results[0].reason
        );
        assert!(
            report.results[0]
                .reason
                .contains("changes requested by bob"),
            "{}",
            report.results[0].reason
        );
    }

    #[tokio::test]
    async fn comment_after_request_changes_stays_blocked() {
        let h = Harness::setup().await;
        h.rule(None, 0, true, "[]", false, false, false, "[]").await;
        h.verdict(&h.bob.clone(), "request_changes").await;
        assert!(!h.report().await.passed);
        h.verdict(&h.bob.clone(), "comment").await;
        let report = h.report().await;
        assert!(!report.passed);
        assert!(
            report.results[0]
                .reason
                .contains("changes requested by bob"),
            "{}",
            report.results[0].reason
        );
    }

    #[tokio::test]
    async fn push_superseded_request_is_neither_vote_nor_block() {
        let h = Harness::setup().await;
        h.rule_flags(true, true).await;
        h.verdict(&h.bob.clone(), "request_changes").await;
        let tip = push_commit(&h.bare(), "feature", "a.txt", b"a\n", "second rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        h.approve(&h.bob.clone()).await;
        let tip = push_commit(&h.bare(), "feature", "b.txt", b"b\n", "third rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        // The r2 approval was dismissed by the r3 push, and the r1 request
        // it superseded no longer speaks: a fresh approval is needed, and
        // nobody is requesting changes.
        let report = h.report().await;
        assert!(!report.passed);
        assert_eq!(report.results[0].reason, "needs 1 more approval");
    }

    #[tokio::test]
    async fn required_context_pending_then_success() {
        let h = Harness::setup().await;
        h.rule(None, 0, false, "[\"ci/unit\"]", false, false, false, "[]")
            .await;
        let head = h
            .core
            .get_change(Some(&h.alice), "alice", "proj-gates", h.trail_n, h.k, None)
            .await
            .unwrap()
            .selected
            .head_sha;
        h.core
            .submit_status(
                &h.alice,
                "alice",
                "proj-gates",
                &head,
                "pending",
                "ci/unit",
                None,
                None,
            )
            .await
            .unwrap();
        let report = h.report().await;
        assert!(!report.passed);
        assert!(report.results[0].reason.contains("ci/unit"));
        h.core
            .submit_status(
                &h.alice,
                "alice",
                "proj-gates",
                &head,
                "success",
                "ci/unit",
                None,
                None,
            )
            .await
            .unwrap();
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn head_behind_base_fails() {
        let h = Harness::setup().await;
        h.rule(None, 0, false, "[]", true, false, false, "[]").await;
        assert!(h.report().await.passed);
        push_commit(&h.bare(), "main", "moved.txt", b"moved\n", "advance base");
        let report = h.report().await;
        assert!(!report.passed);
        assert!(report.results[0].reason.contains("behind base"));
    }

    #[tokio::test]
    async fn unresolved_thread_blocks_until_resolved() {
        let h = Harness::setup().await;
        h.rule(None, 0, false, "[]", false, true, false, "[]").await;
        assert!(h.report().await.passed);
        let thread = h
            .core
            .create_thread(
                &h.bob,
                "alice",
                "proj-gates",
                h.trail_n,
                h.k,
                None,
                "feature.txt",
                "head",
                1,
                1,
                "fix this",
            )
            .await
            .unwrap();
        let report = h.report().await;
        assert!(!report.passed);
        assert!(report.results[0].reason.contains("unresolved thread"));
        h.core
            .resolve_thread(
                &h.alice,
                "alice",
                "proj-gates",
                h.trail_n,
                h.k,
                thread.id,
                true,
            )
            .await
            .unwrap();
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn session_evidence_missing_present_quarantined() {
        let h = Harness::setup().await;
        h.rule(None, 0, false, "[]", false, false, true, "[]").await;
        assert!(h.report().await.passed);
        let tip = push_commit(
            &h.bare(),
            "feature",
            "evid.txt",
            b"evidence\n",
            &format!("add evidence\n\nStarforge-Session: {ULID_A}\n"),
        );
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        let report = h.report().await;
        assert!(!report.passed);
        assert!(
            report.results[0].reason.contains(ULID_A),
            "{}",
            report.results[0].reason
        );
        insert_session_row(&h.core, h.repo_id, h.alice.id, ULID_A, "none").await;
        assert!(h.report().await.passed);
        insert_session_row(&h.core, h.repo_id, h.alice.id, ULID_B, "quarantined").await;
        let tip = push_commit(
            &h.bare(),
            "feature",
            "evid2.txt",
            b"more\n",
            &format!("more evidence\n\nStarforge-Session: {ULID_B}\n"),
        );
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        let report = h.report().await;
        assert!(!report.passed);
        assert!(
            report.results[0].reason.contains("quarantined"),
            "{}",
            report.results[0].reason
        );
    }

    #[tokio::test]
    async fn two_rules_and_together() {
        let h = Harness::setup().await;
        h.rule(None, 1, false, "[]", false, false, false, "[]")
            .await;
        h.rule(None, 0, false, "[\"ci/x\"]", false, false, false, "[]")
            .await;
        h.approve(&h.bob.clone()).await;
        let report = h.report().await;
        assert!(!report.passed);
        assert_eq!(report.results.len(), 2);
        assert!(report.results[0].passed);
        assert!(!report.results[1].passed);
        let head = h
            .core
            .get_change(Some(&h.alice), "alice", "proj-gates", h.trail_n, h.k, None)
            .await
            .unwrap()
            .selected
            .head_sha;
        h.core
            .submit_status(
                &h.alice,
                "alice",
                "proj-gates",
                &head,
                "success",
                "ci/x",
                None,
                None,
            )
            .await
            .unwrap();
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn pattern_mismatch_skips_rule() {
        let h = Harness::setup().await;
        h.rule(
            Some("release/*"),
            5,
            true,
            "[\"ci/nope\"]",
            true,
            true,
            true,
            "[\"merge\"]",
        )
        .await;
        let report = h.report().await;
        assert!(report.passed);
        assert!(report.results.is_empty());
    }

    #[tokio::test]
    async fn dismiss_on_push_clears_old_approval() {
        let h = Harness::setup().await;
        h.rule_flags(true, false).await;
        h.approve(&h.bob.clone()).await;
        assert!(h.report().await.passed);
        let tip = push_commit(&h.bare(), "feature", "next.txt", b"next\n", "second rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        // The old approval no longer counts.
        let report = h.report().await;
        assert!(!report.passed);
        assert!(report.results[0].reason.contains("needs 1 more approval"));
        // The row survives as dismissed history.
        let trail = db_trails::trail_by_number(h.core.db(), h.repo_id, h.trail_n)
            .await
            .unwrap()
            .unwrap();
        let change = db_changes::change_by_trail_number(h.core.db(), trail.id, h.k)
            .await
            .unwrap()
            .unwrap();
        let reviews = db_changes::reviews_of_change(h.core.db(), change.id)
            .await
            .unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].state, "dismissed");
        // A fresh approval on the current revision counts again.
        h.approve(&h.alice.clone()).await;
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn dismiss_timeline_marks_new_revision() {
        let h = Harness::setup().await;
        h.rule_flags(true, false).await;
        h.approve(&h.bob.clone()).await;
        let tip = push_commit(&h.bare(), "feature", "next.txt", b"next\n", "second rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        let trail = db_trails::trail_by_number(h.core.db(), h.repo_id, h.trail_n)
            .await
            .unwrap()
            .unwrap();
        let events = db_trails::timeline_of_trail(h.core.db(), trail.id)
            .await
            .unwrap();
        let dismissed = events
            .iter()
            .find(|e| e.kind == "review.dismissed")
            .expect("a review.dismissed event");
        let payload: serde_json::Value = serde_json::from_str(&dismissed.payload).unwrap();
        assert_eq!(payload["reason"], "new revision");
        assert_eq!(payload["revision"], 2);
        assert_eq!(payload["change"], 1);
    }

    #[tokio::test]
    async fn flag_off_old_approval_still_counts() {
        let h = Harness::setup().await;
        h.rule_flags(false, false).await;
        h.approve(&h.bob.clone()).await;
        assert!(h.report().await.passed);
        let tip = push_commit(&h.bare(), "feature", "next.txt", b"next\n", "second rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        // Earlier-revision approvals keep counting when the flag is off.
        assert!(h.report().await.passed);
        let trail = db_trails::trail_by_number(h.core.db(), h.repo_id, h.trail_n)
            .await
            .unwrap()
            .unwrap();
        let change = db_changes::change_by_trail_number(h.core.db(), trail.id, h.k)
            .await
            .unwrap()
            .unwrap();
        let reviews = db_changes::reviews_of_change(h.core.db(), change.id)
            .await
            .unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].state, "submitted");
    }

    #[tokio::test]
    async fn request_changes_survives_push_until_explicit_dismiss() {
        let h = Harness::setup().await;
        h.rule_flags(true, true).await;
        let (review, _) = h
            .core
            .submit_review(
                &h.bob,
                "alice",
                "proj-gates",
                h.trail_n,
                h.k,
                None,
                "request_changes",
                "nope",
                None,
                &[],
            )
            .await
            .unwrap();
        assert!(!h.report().await.passed);
        let tip = push_commit(&h.bare(), "feature", "next.txt", b"next\n", "second rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        // The blocking review survives the push and still blocks.
        let trail = db_trails::trail_by_number(h.core.db(), h.repo_id, h.trail_n)
            .await
            .unwrap()
            .unwrap();
        let change = db_changes::change_by_trail_number(h.core.db(), trail.id, h.k)
            .await
            .unwrap()
            .unwrap();
        let reviews = db_changes::reviews_of_change(h.core.db(), change.id)
            .await
            .unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].state, "submitted");
        let report = h.report().await;
        assert!(!report.passed);
        assert!(
            report.results[0]
                .reason
                .contains("changes requested by bob")
        );
        // Explicit triage dismissal unblocks the request; a fresh approval
        // satisfies the approval rule.
        h.core
            .dismiss_review(&h.alice, "alice", "proj-gates", h.trail_n, h.k, review.id)
            .await
            .unwrap();
        h.approve(&h.alice.clone()).await;
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn evidence_commit_cap_fails_closed() {
        let h = Harness::setup().await;
        for i in 0..3 {
            push_commit(
                &h.bare(),
                "feature",
                &format!("f{i}.txt"),
                b"x\n",
                &format!("commit {i}"),
            );
        }
        let head = tip_of(&h.bare(), "feature");
        let base = tip_of(&h.bare(), "main");
        let failures = h
            .core
            .session_evidence_failures(h.repo_id, &head, Some(&base), 2, 64)
            .await
            .unwrap();
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("unable to verify"), "{}", failures[0]);
        // The same history under the production cap verifies fine (no trailers).
        h.core
            .record_branch_move(h.repo_id, "feature", None, &head, None)
            .await
            .unwrap();
        h.rule(None, 0, false, "[]", false, false, true, "[]").await;
        assert!(h.report().await.passed);
    }

    #[tokio::test]
    async fn evidence_trailer_cap_fails_closed() {
        let h = Harness::setup().await;
        let head = push_commit(
            &h.bare(),
            "feature",
            "evid.txt",
            b"x\n",
            "t\n\nStarforge-Session: 01ARZ3NDEKTSV4RRFFQ69G5FAV\nStarforge-Session: 01ARZ3NDEKTSV4RRFFQ69G5FAW\nStarforge-Session: 01ARZ3NDEKTSV4RRFFQ69G5FAX\n",
        );
        let base = tip_of(&h.bare(), "main");
        let failures = h
            .core
            .session_evidence_failures(h.repo_id, &head, Some(&base), 64, 2)
            .await
            .unwrap();
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("unable to verify"), "{}", failures[0]);
    }

    #[tokio::test]
    async fn evidence_git_failure_fails_closed() {
        let h = Harness::setup().await;
        let missing = "0".repeat(40);
        let failures = h
            .core
            .session_evidence_failures(h.repo_id, &missing, Some(&missing), 64, 64)
            .await
            .unwrap();
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("unable to verify"), "{}", failures[0]);
    }

    #[tokio::test]
    async fn mixed_flags_keep_old_approvals() {
        let h = Harness::setup().await;
        h.rule_n(1, true).await;
        h.rule_n(2, false).await;
        h.approve(&h.bob.clone()).await;
        let tip = push_commit(&h.bare(), "feature", "next.txt", b"next\n", "second rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        h.approve(&h.alice.clone()).await;
        // The flag-ON rule counts alice's current-revision approval; the
        // flag-OFF rule still counts bob's older one. No dismissal fired.
        let report = h.report().await;
        assert!(report.passed, "{report:?}");
        assert_eq!(report.results.len(), 2);
        let trail = db_trails::trail_by_number(h.core.db(), h.repo_id, h.trail_n)
            .await
            .unwrap()
            .unwrap();
        let change = db_changes::change_by_trail_number(h.core.db(), trail.id, h.k)
            .await
            .unwrap()
            .unwrap();
        let reviews = db_changes::reviews_of_change(h.core.db(), change.id)
            .await
            .unwrap();
        assert_eq!(reviews.len(), 2);
        assert!(reviews.iter().all(|r| r.state == "submitted"));
    }

    #[tokio::test]
    async fn both_flags_on_dismiss_and_fail() {
        let h = Harness::setup().await;
        h.rule_n(1, true).await;
        h.rule_n(2, true).await;
        h.approve(&h.bob.clone()).await;
        let tip = push_commit(&h.bare(), "feature", "next.txt", b"next\n", "second rev");
        h.core
            .record_branch_move(h.repo_id, "feature", None, &tip, None)
            .await
            .unwrap();
        h.approve(&h.alice.clone()).await;
        // Unanimous flags dismiss bob's older approval: the 1-approval rule
        // passes on alice's vote, the 2-approval rule fails on it.
        let report = h.report().await;
        assert!(!report.passed);
        assert_eq!(report.results.len(), 2);
        assert!(report.results[0].passed);
        assert!(!report.results[1].passed);
        assert!(report.results[1].reason.contains("needs 1 more approval"));
        let trail = db_trails::trail_by_number(h.core.db(), h.repo_id, h.trail_n)
            .await
            .unwrap()
            .unwrap();
        let change = db_changes::change_by_trail_number(h.core.db(), trail.id, h.k)
            .await
            .unwrap()
            .unwrap();
        let reviews = db_changes::reviews_of_change(h.core.db(), change.id)
            .await
            .unwrap();
        assert_eq!(reviews.len(), 2);
        assert_eq!(reviews[0].state, "dismissed");
        assert_eq!(reviews[1].state, "submitted");
    }
}
