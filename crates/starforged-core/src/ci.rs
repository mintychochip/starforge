//! CI principals (M6-0 F1–F3, spec M6 decisions 6/9/10): the two CI actors
//! beside the PAT user — a self-hosted runner and one job execution — each
//! resolved from a bearer token that is stored only as its SHA-256 hash.
//!
//! A [`JobPrincipal`] is capped to one `(job, repo, commit)` triple taken
//! from the `ci_jobs` row (never from request input), acting for
//! `ci_jobs.created_by`. There is no user `Write` requirement on any path
//! here: the job was authorized at creation, and every method below re-checks
//! that the triggering user is still active and still has `read` on the job's
//! repository. Losing that access revokes the job's tokens
//! ([`Core::authenticate_job`]), so a stolen or lingering job token dies with
//! the user's access. Jobs without `created_by` (system-triggered) have no
//! principal and cannot authenticate until a later phase gives them one.
//!
//! [`RunnerPrincipal`] carries the runner's repo and labels; claims are
//! repo-scoped and label-matched by the M6a control plane.
//!
//! Token prefixes (one per kind, enforced at the extractors):
//! runner `sfr_` ([`RUNNER_TOKEN_PREFIX`]), job `sfj_`
//! ([`JOB_TOKEN_PREFIX`]), PAT `sfp_` ([`crate::tokens::TOKEN_PREFIX`]).

use starforged_db::{
    changes as db_changes, checks as db_checks, ci as db_ci, now, repos as db_repos,
    sessions as db_sessions, tokens as db_tokens,
};

use crate::checks::{StatusDto, status_dto, validate_status};
use crate::ci_spec::CiJobSpec;
use crate::permission::Permission;
use crate::repos::to_repo;
use crate::tokens::{self, Scope, format_scopes};
use crate::webhooks::HookEvent;
use crate::{Core, CoreError, CoreResult, crypto};

/// Bearer prefix of a runner auth token (stored only as SHA-256).
pub const RUNNER_TOKEN_PREFIX: &str = "sfr_";
/// Bearer prefix of a per-job token (stored only as SHA-256).
pub const JOB_TOKEN_PREFIX: &str = "sfj_";
/// Bearer prefix of a registration token (stored only as SHA-256).
pub const REGISTRATION_TOKEN_PREFIX: &str = "sfrt_";
/// Lifetime of a registration token: one hour.
pub const REGISTRATION_TOKEN_TTL_SECS: i64 = 3600;

/// Who a per-job token acts for: one job on one repo at one commit, on behalf
/// of the user who triggered it. Every CI path takes this, so no request
/// parameter can widen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobPrincipal {
    pub job_id: i64,
    pub user_id: i64,
    pub repo_id: i64,
    pub commit_sha: String,
}

/// Who a runner auth token acts for: one runner on one repo with its labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerPrincipal {
    pub runner_id: i64,
    pub repo_id: i64,
    pub labels: Vec<String>,
}

/// A short-lived git credential minted for a job ([`Core::mint_git_credential`]).
/// The secret is returned once; only its hash is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedGitCredential {
    /// The `sfp_` PAT secret, shown once.
    pub secret: String,
    /// The `access_tokens` row id (also stored in `ci_jobs.git_token_id`).
    pub token_id: i64,
}
/// A registration token minted for one repo ([`Core::create_runner_registration_token`]).
/// The `sfrt_…` secret is returned once; only its hash is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedRegistrationToken {
    /// The registration-token secret, shown once.
    pub secret: String,
    /// Unix seconds at which the token expires (one hour after minting).
    pub expires_at: i64,
}

/// The result of a successful runner registration ([`Core::register_runner`]):
/// the new runner's id and its `sfr_…` auth token, shown once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredRunner {
    pub runner_id: i64,
    /// The runner auth-token secret, shown once; only its hash is stored.
    pub auth_secret: String,
}

/// A runner as listed to repository users: never carries token material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerView {
    pub id: i64,
    pub repo_id: i64,
    pub name: String,
    pub labels: Vec<String>,
    pub ephemeral: bool,
    pub version: String,
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
}

impl From<starforged_db::ci::RunnerRow> for RunnerView {
    fn from(row: starforged_db::ci::RunnerRow) -> Self {
        RunnerView {
            id: row.id,
            repo_id: row.repo_id,
            name: row.name,
            labels: serde_json::from_str(&row.labels).unwrap_or_default(),
            ephemeral: row.ephemeral != 0,
            version: row.version,
            last_seen_at: row.last_seen_at,
            created_at: row.created_at,
        }
    }
}

/// A job claimed by a runner ([`Core::claim_ci_job`]): the parsed spec, the
/// per-claim lease fence the runner must present on every later call, and
/// the per-job token (`sfj_…`, shown once) the job execution acts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedCiJob {
    pub job_id: i64,
    pub job_name: String,
    pub commit_sha: String,
    pub spec: CiJobSpec,
    /// The per-claim `lease_token` fence (`X-Starforge-Fence`).
    pub fence: String,
    /// The per-job token secret, shown once; only its hash is stored.
    pub job_token: String,
    pub deadline: i64,
    pub lease_until: i64,
    /// `{base_url}/{owner}/{repo}.git` for the job's repository: the runner
    /// clones from here and resets the remote to this credential-free URL
    /// after fetching.
    pub clone_url: String,
}

/// The outcome of one [`Core::trace_ci_job`] append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceOutcome {
    /// The chunk was appended (or was an exact retry of an appended chunk).
    Accepted,
    /// The range does not continue the stored log; the API answers 416.
    RangeMismatch,
    /// The job is missing.
    NotFound,
    /// The runner does not own the claim, the fence is stale, or the job is
    /// no longer claimed/running; the API answers 409.
    FenceMismatch,
    /// The job was canceled (or a cancel was requested): cancel wins.
    Canceled,
    /// The append would exceed the 100 MiB per-job log cap.
    PayloadTooLarge,
}

/// The outcome of one [`Core::finish_ci_job`] report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishOutcome {
    /// The job finished; its terminal state is recorded.
    Finished,
    /// The job is missing.
    NotFound,
    /// The runner does not own the claim, the fence is stale, or the job is
    /// no longer claimed/running; the API answers 409.
    FenceMismatch,
    /// The job was canceled (or a cancel was requested): cancel wins.
    Canceled,
}

/// The label rules shared with CI job specs ([`crate::ci_spec`]): 1–64 chars
/// of `[A-Za-z0-9_-]`, at most 16 per runner, no duplicates.
fn validate_runner_labels(labels: &[String]) -> CoreResult<()> {
    if labels.len() > 16 {
        return Err(CoreError::Invalid(format!(
            "{} labels, over the 16-label limit",
            labels.len()
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for label in labels {
        if label.is_empty() || label.len() > 64 {
            return Err(CoreError::Invalid(format!(
                "runner label `{label}` must be 1-64 characters"
            )));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(CoreError::Invalid(format!(
                "runner label `{label}` may only contain [A-Za-z0-9_-]"
            )));
        }
        if !seen.insert(label.as_str()) {
            return Err(CoreError::Invalid(format!(
                "duplicate runner label `{label}`"
            )));
        }
    }
    Ok(())
}

/// The gate outcome of [`Core::checked_claim`], shared by the trace,
/// finish, and git-credential paths so every one of them rejects stale
/// fences and honors cancel the same way.
enum ClaimGate {
    NotFound,
    FenceMismatch,
    Canceled,
}

/// Strips ANSI escape sequences and control characters from a log chunk
/// before it is stored (plan security model: log injection). Keeps tab,
/// newline, and carriage return, which a terminal log legitimately uses;
/// drops every other byte below 0x20 and DEL, plus CSI/OSC sequences.
fn strip_log_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0x1b => {
                // ESC: drop the escape sequence (CSI: ESC [ ... final byte;
                // OSC: ESC ] ... terminated by BEL or ESC \; single char
                // otherwise).
                if i + 1 >= bytes.len() {
                    break;
                }
                match bytes[i + 1] {
                    b'[' => {
                        let mut j = i + 2;
                        while j < bytes.len() && !(0x40..=0x7e).contains(&bytes[j]) {
                            j += 1;
                        }
                        i = (j + 1).min(bytes.len());
                    }
                    b']' => {
                        let mut j = i + 2;
                        while j < bytes.len()
                            && bytes[j] != 0x07
                            && !(bytes[j] == 0x1b && j + 1 < bytes.len() && bytes[j + 1] == b'\\')
                        {
                            j += 1;
                        }
                        i = if j < bytes.len() && bytes[j] == 0x07 {
                            j + 1
                        } else {
                            (j + 2).min(bytes.len())
                        };
                    }
                    _ => i += 2,
                }
            }
            b'\t' | b'\n' | b'\r' => {
                out.push(bytes[i]);
                i += 1;
            }
            b if b < 0x20 || b == 0x7f => i += 1,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

impl Core {
    /// Resolves a runner auth token (`sfr_…`) to its [`RunnerPrincipal`].
    /// Unknown and revoked runners fail with `Unauthenticated`; a valid
    /// token records a heartbeat (`last_seen_at`) on the runner row.
    pub async fn authenticate_runner(&self, secret: &str) -> CoreResult<RunnerPrincipal> {
        if !secret.starts_with(RUNNER_TOKEN_PREFIX) {
            return Err(CoreError::Unauthenticated);
        }
        let row = db_ci::runner_by_token_hash(self.db(), &crypto::sha256_hex(secret))
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        db_ci::touch_runner(self.db(), row.id, None, now()).await?;
        let labels: Vec<String> = serde_json::from_str(&row.labels).unwrap_or_default();
        Ok(RunnerPrincipal {
            runner_id: row.id,
            repo_id: row.repo_id,
            labels,
        })
    }

    /// Resolves a per-job token (`sfj_…`) to its [`JobPrincipal`]: the token
    /// must be live (unrevoked, unexpired), the job must be claimed or
    /// running, and the triggering user must still be active with `read` on
    /// the job's repository. Any failure is `Unauthenticated` — and when the
    /// user has lost access, the job's tokens are revoked first, so the loss
    /// is terminal for every outstanding token of the job.
    pub async fn authenticate_job(&self, secret: &str) -> CoreResult<JobPrincipal> {
        if !secret.starts_with(JOB_TOKEN_PREFIX) {
            return Err(CoreError::Unauthenticated);
        }
        let now_ts = now();
        let token = db_ci::job_token_by_hash(self.db(), &crypto::sha256_hex(secret), now_ts)
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        // Access loss revokes every live token of the job, then denies: the
        // closure is a future polled once (at most one branch returns it).
        let revoke_and_deny = || async {
            db_ci::revoke_job_tokens_for_job(self.db(), token.job_id, now_ts).await?;
            Err::<JobPrincipal, CoreError>(CoreError::Unauthenticated)
        };
        let job = db_ci::ci_job_by_id(self.db(), token.job_id)
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        if job.state != "claimed" && job.state != "running" {
            return Err(CoreError::Unauthenticated);
        }
        let user_id = job.created_by.ok_or(CoreError::Unauthenticated)?;
        let user = match self.user_by_id(user_id).await? {
            Some(user) if user.active => user,
            _ => return revoke_and_deny().await,
        };
        let repo_row = db_repos::by_id(self.db(), job.repo_id)
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        match self
            .require_repo(
                Some(&user),
                &repo_row.owner_handle,
                &repo_row.name,
                Permission::Read,
            )
            .await
        {
            Ok(_) => {}
            // A database failure is not an access loss: keep the tokens and
            // surface the error instead of revoking on a transient outage.
            Err(CoreError::Db(err)) => return Err(CoreError::Db(err)),
            Err(_) => return revoke_and_deny().await,
        }
        Ok(JobPrincipal {
            job_id: job.id,
            user_id: user.id,
            repo_id: job.repo_id,
            commit_sha: job.commit_sha,
        })
    }

    /// The internal CI status path (decision 9): writes the check for the
    /// job's own commit (`sha` must equal the principal's `commit_sha`),
    /// refusing archived repositories, and dispatches the `check` webhook
    /// with the triggering user as sender and `ci_job_id` in the subject.
    /// There is no user `Write` check and no audit row (status writes are
    /// audit-free like [`Core::submit_status`]); the principal is the cap.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_ci_status(
        &self,
        principal: &JobPrincipal,
        sha: &str,
        state: &str,
        context: &str,
        target_url: Option<&str>,
        description: Option<&str>,
    ) -> CoreResult<StatusDto> {
        validate_status(sha, state, context, target_url, description)?;
        if sha != principal.commit_sha {
            return Err(CoreError::Forbidden);
        }
        // A job writes only its own `ci/<job-name>` context: writing another
        // job's context would satisfy that job's gate.
        let job = db_ci::ci_job_by_id(self.db(), principal.job_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if context != format!("ci/{}", job.job_name) {
            return Err(CoreError::Forbidden);
        }
        let repo_row = db_repos::by_id(self.db(), principal.repo_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let repo = to_repo(repo_row)?;
        if repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let url = target_url.filter(|u| !u.is_empty());
        let row = db_checks::insert_check(
            self.db(),
            repo.id,
            sha,
            context,
            state,
            url,
            description,
            Some(principal.user_id),
            now(),
        )
        .await?;
        let sender = self.sender_of(principal.user_id).await;
        tracing::info!(
            repo = %repo.full_name(),
            %sha,
            %context,
            %state,
            ci_job_id = principal.job_id,
            "ci status submitted"
        );
        self.dispatch_event(
            repo.id,
            HookEvent {
                event: "check",
                action: None,
                cause: None,
                sender: sender.clone(),
                subject: serde_json::json!({
                    "sha": sha,
                    "context": context,
                    "state": state,
                    "target_url": url,
                    "description": description,
                    "creator": sender,
                    "ci_job_id": principal.job_id,
                }),
            },
        )
        .await;
        status_dto(self, row).await
    }

    /// Emits the `ci` webhook for one lifecycle transition (decision 14:
    /// `queued`/`started`/`finished`/`canceled`). The `check` event still
    /// covers status transitions; this event carries the run identity.
    async fn emit_ci_event(
        &self,
        job: &db_ci::CiJobRow,
        action: &'static str,
        state: &str,
        exit_code: Option<i64>,
    ) {
        let sender = match job.created_by {
            Some(user_id) => self.sender_of(user_id).await,
            None => None,
        };
        self.dispatch_event(
            job.repo_id,
            HookEvent {
                event: "ci",
                action: Some(action),
                cause: None,
                sender,
                subject: serde_json::json!({
                    "ci_job_id": job.id,
                    "job_name": job.job_name,
                    "commit_sha": job.commit_sha,
                    "state": state,
                    "runner_id": job.runner_id,
                    "exit_code": exit_code,
                    "created_by": job.created_by,
                }),
            },
        )
        .await;
    }

    /// Writes the terminal `ci/<job>` check for a job that ends without a
    /// runner result, unless the check is already terminal (the cancel
    /// request writes it immediately; the runner's later acknowledgement
    /// must not overwrite `canceled by <user>`). Dispatches the `check`
    /// webhook on a write. Returns whether a check was written.
    async fn write_ci_terminal_check(
        &self,
        job: &db_ci::CiJobRow,
        check_state: &str,
        description: &str,
        actor: Option<i64>,
    ) -> CoreResult<bool> {
        let Some(repo_row) = db_repos::by_id(self.db(), job.repo_id).await? else {
            return Ok(false);
        };
        let repo = to_repo(repo_row)?;
        if repo.archived_at.is_some() {
            return Ok(false);
        }
        let context = format!("ci/{}", job.job_name);
        let existing =
            db_checks::latest_checks_for_sha(self.db(), job.repo_id, &job.commit_sha).await?;
        if existing.iter().any(|check| {
            check.context == context
                && matches!(check.state.as_str(), "success" | "failure" | "error")
        }) {
            return Ok(false);
        }
        let creator = actor.or(job.created_by);
        db_checks::insert_check(
            self.db(),
            job.repo_id,
            &job.commit_sha,
            &context,
            check_state,
            None,
            Some(description),
            creator,
            now(),
        )
        .await?;
        let sender = match creator {
            Some(user_id) => self.sender_of(user_id).await,
            None => None,
        };
        self.dispatch_event(
            job.repo_id,
            HookEvent {
                event: "check",
                action: None,
                cause: None,
                sender: sender.clone(),
                subject: serde_json::json!({
                    "sha": job.commit_sha,
                    "context": context,
                    "state": check_state,
                    "target_url": null,
                    "description": description,
                    "creator": sender,
                    "ci_job_id": job.id,
                }),
            },
        )
        .await;
        Ok(true)
    }

    /// The single terminal path for a job that ends without a runner
    /// result (user cancel, supersede, lease expiry, cancel
    /// acknowledgement): writes the terminal check (once) and emits the
    /// `ci` event. `job_state` is `canceled` or `failed`.
    pub(crate) async fn terminate_ci_job(
        &self,
        job: &db_ci::CiJobRow,
        job_state: &'static str,
        check_state: &str,
        description: &str,
        actor: Option<i64>,
    ) -> CoreResult<()> {
        self.write_ci_terminal_check(job, check_state, description, actor)
            .await?;
        let action = if job_state == "canceled" {
            "canceled"
        } else {
            "finished"
        };
        self.emit_ci_event(job, action, job_state, job.exit_code)
            .await;
        Ok(())
    }

    /// After canceling a job last read as `queued`, records the attempt a
    /// runner claimed in between, which the cancel ended. A job still on
    /// the attempt read before (no new claim) records nothing: its
    /// `claimed_at` is a label-mismatch bounce or an attempt already
    /// recorded at requeue.
    async fn record_attempt_claimed_since(&self, before: &db_ci::CiJobRow) -> CoreResult<()> {
        if let Some(after) = db_ci::ci_job_by_id(self.db(), before.id).await?
            && after.attempts > before.attempts
        {
            db_ci::record_attempt_usage(self.db(), &after, now()).await?;
        }
        Ok(())
    }

    /// Sweeps CI jobs whose runner stopped serving them (decision 13).
    /// Claimed or running jobs whose lease expired go back to `queued`, or
    /// end `failed` once out of attempts (`canceled` when a cancel was
    /// requested). Jobs whose deadline passed by more than
    /// [`Core::CI_DEADLINE_GRACE_SECS`] end `failed`. Every job that ends
    /// here writes its terminal check and emits the `ci` event; a requeued
    /// job does neither. Jobs are handled independently: a failure on one
    /// is logged and the sweep continues. The job workers run this every
    /// [`Core::CI_SWEEP_INTERVAL_SECS`]; tests call it directly.
    pub async fn sweep_ci_jobs(&self) -> CoreResult<()> {
        let now_ts = now();
        let reaped =
            db_ci::requeue_expired_ci_jobs(self.db(), now_ts, Self::CI_MAX_ATTEMPTS).await?;
        for id in reaped {
            let outcome = match db_ci::ci_job_by_id(self.db(), id).await {
                Ok(Some(job)) => match job.state.as_str() {
                    "canceled" => {
                        self.terminate_ci_job(&job, "canceled", "error", "canceled", None)
                            .await
                    }
                    "failed" => {
                        self.terminate_ci_job(
                            &job,
                            "failed",
                            "failure",
                            "the runner stopped before finishing",
                            None,
                        )
                        .await
                    }
                    _ => Ok(()),
                },
                Ok(None) => Ok(()),
                Err(err) => Err(err.into()),
            };
            if let Err(err) = outcome {
                tracing::warn!(ci_job_id = id, error = %err, "recording a reaped CI job failed");
            }
        }
        let overdue =
            db_ci::fail_overdue_ci_jobs(self.db(), now_ts - Self::CI_DEADLINE_GRACE_SECS, now_ts)
                .await?;
        for id in overdue {
            let outcome = match db_ci::ci_job_by_id(self.db(), id).await {
                Ok(Some(job)) => {
                    self.terminate_ci_job(
                        &job,
                        "failed",
                        "failure",
                        "the job exceeded its timeout",
                        None,
                    )
                    .await
                }
                Ok(None) => Ok(()),
                Err(err) => Err(err.into()),
            };
            if let Err(err) = outcome {
                tracing::warn!(ci_job_id = id, error = %err, "recording an overdue CI job failed");
            }
        }
        Ok(())
    }

    /// Runs [`Core::sweep_ci_jobs`] when one is due. Every job worker calls
    /// this on each loop; the compare-exchange on the due time lets one of
    /// them sweep per [`Core::CI_SWEEP_INTERVAL_SECS`]. Errors are logged,
    /// never returned: the worker must keep running jobs.
    pub(crate) async fn run_ci_sweep_if_due(&self) {
        use std::sync::atomic::Ordering;
        let now_ts = now();
        let due = self.inner.ci_sweep_due.load(Ordering::Relaxed);
        if now_ts < due
            || self
                .inner
                .ci_sweep_due
                .compare_exchange(
                    due,
                    now_ts + Self::CI_SWEEP_INTERVAL_SECS,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }
        if let Err(err) = self.sweep_ci_jobs().await {
            tracing::warn!(error = %err, "CI sweep failed");
        }
    }

    /// Mints the short-lived, repo-scoped git credential for a claimed or
    /// running job (decision 10): an `sfp_` PAT with `repo:read repo:write`
    /// expiring at `min(job deadline, now + 1h)`. The token id is stored in
    /// `ci_jobs.git_token_id` so finish/cancel can revoke it
    /// ([`Core::revoke_job_credentials`]); the secret is returned once. The
    /// job row must still match the principal, and the mint is audited.
    pub async fn mint_git_credential(
        &self,
        principal: &JobPrincipal,
    ) -> CoreResult<MintedGitCredential> {
        let job = db_ci::ci_job_by_id(self.db(), principal.job_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if job.repo_id != principal.repo_id || job.commit_sha != principal.commit_sha {
            return Err(CoreError::Forbidden);
        }
        if job.state != "claimed" && job.state != "running" {
            return Err(CoreError::Invalid("job is not claimed".into()));
        }
        let expires_at = job.deadline.min(now() + 3600);
        if expires_at <= now() {
            return Err(CoreError::Invalid("job deadline has passed".into()));
        }
        let secret = format!("{}{}", tokens::TOKEN_PREFIX, crypto::random_hex(32));
        let hint = &secret[secret.len() - 4..];
        let name = format!("ci-job-{}-git", principal.job_id);
        let token_id = db_tokens::insert(
            self.db(),
            &db_tokens::NewToken {
                user_id: principal.user_id,
                name: &name,
                token_hash: &crypto::sha256_hex(&secret),
                token_hint: hint,
                scopes: &format_scopes(&[Scope::RepoRead, Scope::RepoWrite]),
                expires_at,
            },
        )
        .await?;
        db_ci::set_ci_job_git_token(self.db(), principal.job_id, token_id).await?;
        self.audit(
            Some(principal.user_id),
            "ci.git_credential.mint",
            &format!("ci_job:{}", principal.job_id),
            "",
        )
        .await?;
        Ok(MintedGitCredential { secret, token_id })
    }

    /// Revokes everything one job execution was given: the per-job tokens and
    /// the short-lived git PAT referenced by `ci_jobs.git_token_id`. Used at
    /// finish/cancel and when [`Core::authenticate_job`] detects access loss.
    pub async fn revoke_job_credentials(&self, job_id: i64) -> CoreResult<()> {
        let now_ts = now();
        db_ci::revoke_job_tokens_for_job(self.db(), job_id, now_ts).await?;
        if let Some(job) = db_ci::ci_job_by_id(self.db(), job_id).await?
            && let (Some(token_id), Some(user_id)) = (job.git_token_id, job.created_by)
        {
            db_tokens::revoke(self.db(), user_id, token_id).await?;
        }
        Ok(())
    }

    /// Mints a one-time runner registration token for the repository
    /// (decision: registration tokens are hashed, one-time, 1 h TTL). The
    /// caller must hold at least `Admin` on the repo; `labels` scope the
    /// token (a runner may later claim only a subset of them), and
    /// `ephemeral` records the intended runner kind at mint time. Only the
    /// SHA-256 of the `sfrt_…` secret is stored; the secret is returned once.
    pub async fn create_runner_registration_token(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        labels: &[String],
        ephemeral: bool,
    ) -> CoreResult<MintedRegistrationToken> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        validate_runner_labels(labels)?;
        let now_ts = now();
        let expires_at = now_ts + REGISTRATION_TOKEN_TTL_SECS;
        let secret = format!("{}{}", REGISTRATION_TOKEN_PREFIX, crypto::random_hex(32));
        let labels_json = serde_json::to_string(labels).unwrap_or_else(|_| "[]".into());
        let row = db_ci::insert_registration_token(
            self.db(),
            &db_ci::NewRegistrationToken {
                repo_id: access.repo.id,
                token_hash: &crypto::sha256_hex(&secret),
                labels: &labels_json,
                created_by: Some(user.id),
                expires_at,
                now: now_ts,
            },
        )
        .await?;
        self.audit(
            Some(user.id),
            "ci.runner_registration_token.create",
            &format!("runner_registration_token:{}", row.id),
            &format!(
                "repo={} labels={} ephemeral={}",
                access.repo.full_name(),
                labels_json,
                ephemeral
            ),
        )
        .await?;
        Ok(MintedRegistrationToken { secret, expires_at })
    }

    /// Registers a runner against a registration token: the token is
    /// consumed exactly once (unknown, used, and expired tokens are
    /// indistinguishable `Unauthenticated`), and a runner is created on
    /// the token's repository with a fresh `sfr_…` auth token shown once.
    /// The runner's `labels` must be a subset of the token's labels, so a
    /// runner can never widen its own scope.
    pub async fn register_runner(
        &self,
        secret: &str,
        name: &str,
        labels: &[String],
        version: &str,
        ephemeral: bool,
    ) -> CoreResult<RegisteredRunner> {
        if !secret.starts_with(REGISTRATION_TOKEN_PREFIX) {
            return Err(CoreError::Unauthenticated);
        }
        if name.trim().is_empty() {
            return Err(CoreError::Invalid("runner name must not be empty".into()));
        }
        validate_runner_labels(labels)?;
        let now_ts = now();
        let token =
            db_ci::consume_registration_token(self.db(), &crypto::sha256_hex(secret), now_ts)
                .await?
                .ok_or(CoreError::Unauthenticated)?;
        let token_labels: Vec<String> = serde_json::from_str(&token.labels).unwrap_or_default();
        if !labels.iter().all(|label| token_labels.contains(label)) {
            return Err(CoreError::Invalid(
                "runner labels exceed the registration token's labels".into(),
            ));
        }
        let label_set: Vec<String> = if labels.is_empty() {
            token_labels
        } else {
            labels.to_vec()
        };
        let labels_json = serde_json::to_string(&label_set).unwrap_or_else(|_| "[]".into());
        let auth_secret = format!("{}{}", RUNNER_TOKEN_PREFIX, crypto::random_hex(32));
        let hint = &auth_secret[auth_secret.len() - 4..];
        let runner = db_ci::insert_runner(
            self.db(),
            &db_ci::NewRunner {
                repo_id: token.repo_id,
                name: name.trim(),
                token_hash: &crypto::sha256_hex(&auth_secret),
                token_hint: hint,
                labels: &labels_json,
                ephemeral,
                max_concurrent: 1,
                version,
                now: now_ts,
            },
        )
        .await?;
        self.audit(
            None,
            "ci.runner.register",
            &format!("runner:{}", runner.id),
            &format!("repo_id={} labels={}", token.repo_id, labels_json),
        )
        .await?;
        Ok(RegisteredRunner {
            runner_id: runner.id,
            auth_secret,
        })
    }

    /// Lists the repo's live runners (callers need at least `Maintain`).
    /// Views never carry token hashes or secrets.
    pub async fn list_runners(
        &self,
        viewer: Option<&crate::accounts::User>,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<RunnerView>> {
        let access = self
            .require_repo(viewer, owner, repo, Permission::Maintain)
            .await?;
        Ok(db_ci::runners_for_repo(self.db(), access.repo.id)
            .await?
            .into_iter()
            .map(RunnerView::from)
            .collect())
    }

    /// Revokes a runner: the caller must hold at least `Admin` on the
    /// runner's repository. A revoked runner stops authenticating
    /// immediately ([`Core::authenticate_runner`]), and every job it was
    /// executing is released back to `queued` with that attempt's
    /// credentials revoked ([`Core::revoke_job_credentials`]), so the job
    /// token and git PAT it was given stop working at once.
    pub async fn revoke_runner(
        &self,
        user: &crate::accounts::User,
        runner_id: i64,
    ) -> CoreResult<()> {
        let runner = db_ci::runner_by_id(self.db(), runner_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if runner.revoked_at.is_some() {
            return Err(CoreError::NotFound);
        }
        let repo_row = db_repos::by_id(self.db(), runner.repo_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.require_repo(
            Some(user),
            &repo_row.owner_handle,
            &repo_row.name,
            Permission::Admin,
        )
        .await?;
        if !db_ci::revoke_runner(self.db(), runner_id, now()).await? {
            return Err(CoreError::NotFound);
        }
        for job in db_ci::ci_jobs_for_runner(self.db(), runner_id).await? {
            self.revoke_job_credentials(job.id).await?;
            if let Some(fence) = job.lease_token.as_deref()
                && db_ci::release_ci_job(self.db(), job.id, fence).await?
            {
                db_ci::record_attempt_usage(self.db(), &job, now()).await?;
            }
        }
        self.audit(
            Some(user.id),
            "ci.runner.revoke",
            &format!("runner:{runner_id}"),
            &format!("repo_id={}", runner.repo_id),
        )
        .await?;
        Ok(())
    }

    /// Lease granted to a claimed job, in seconds (plan decision 13).
    pub const CLAIM_LEASE_SECS: i64 = 60;
    /// Claim attempts before giving up on label routing (a job whose spec
    /// or labels never match would otherwise be re-released forever).
    pub const CLAIM_MAX_ATTEMPTS: usize = 10;
    /// Per-job cap on stored log bytes: 100 MiB.
    pub const MAX_JOB_LOG_BYTES: i64 = 100 * 1024 * 1024;
    /// Claims per job before a reaped job fails instead of requeueing
    /// (plan decision 13, `ci.max_attempts`).
    pub const CI_MAX_ATTEMPTS: i64 = 3;
    /// How often the job workers sweep CI jobs for expired leases and
    /// passed deadlines ([`Core::sweep_ci_jobs`]).
    pub const CI_SWEEP_INTERVAL_SECS: i64 = 30;
    /// Time past a job's deadline before the sweep fails it. The runner
    /// enforces the same timeout itself and reports its own result first;
    /// the sweep only catches a runner that keeps its lease but never
    /// finishes.
    pub const CI_DEADLINE_GRACE_SECS: i64 = 60;

    /// Claims the oldest due queued job of the runner's repository
    /// (decision 13): `state = 'claimed'` under a fresh per-claim
    /// `lease_token` fence, with the deadline measured from this claim
    /// (the job's timeout, default one hour), and mints the per-job token
    /// (`sfj_…`, expiry `deadline + 600`) the execution will act with. A
    /// job that waited in the queue therefore gets its full timeout and a
    /// live token. A job whose `runs_on` labels are a non-empty set that
    /// is not a subset of the runner's labels is released back to
    /// `queued` and the next job is tried (at most
    /// [`Core::CLAIM_MAX_ATTEMPTS`] claims); a job with an unparseable
    /// spec is released the same way. `None` when no job can be claimed
    /// for this runner.
    pub async fn claim_ci_job(&self, runner: &RunnerPrincipal) -> CoreResult<Option<ClaimedCiJob>> {
        for _ in 0..Self::CLAIM_MAX_ATTEMPTS {
            let fence = crypto::random_hex(32);
            let now_ts = now();
            let Some(job) = db_ci::claim_next_ci_job(
                self.db(),
                runner.runner_id,
                runner.repo_id,
                now_ts,
                Self::CLAIM_LEASE_SECS,
                &fence,
                now_ts + crate::ci_spec::MAX_TIMEOUT.as_secs() as i64,
            )
            .await?
            else {
                return Ok(None);
            };
            let spec: CiJobSpec = match serde_json::from_str(&job.spec) {
                Ok(spec) => spec,
                Err(_) => {
                    db_ci::release_ci_job(self.db(), job.id, &fence).await?;
                    continue;
                }
            };
            if !spec.runs_on.is_empty()
                && !spec
                    .runs_on
                    .iter()
                    .all(|label| runner.labels.contains(label))
            {
                db_ci::release_ci_job(self.db(), job.id, &fence).await?;
                continue;
            }
            let deadline = now_ts + job_timeout_secs(&spec);
            if !db_ci::set_ci_job_deadline(self.db(), job.id, &fence, deadline).await? {
                // The claim was lost (canceled or reaped) before the
                // deadline landed; look for the next job.
                continue;
            }
            let job_token = format!("{}{}", JOB_TOKEN_PREFIX, crypto::random_hex(32));
            let hint = &job_token[job_token.len() - 4..];
            db_ci::insert_job_token(
                self.db(),
                &db_ci::NewCiJobToken {
                    job_id: job.id,
                    token_hash: &crypto::sha256_hex(&job_token),
                    token_hint: hint,
                    expires_at: deadline + 600,
                    now: now_ts,
                },
            )
            .await?;
            self.emit_ci_event(&job, "started", "claimed", None).await;
            let repo = db_repos::by_id(self.db(), job.repo_id).await?;
            let clone_url = match repo {
                Some(repo) => format!(
                    "{}/{}/{}.git",
                    self.config().base_url.trim_end_matches('/'),
                    repo.owner_handle,
                    repo.name
                ),
                None => String::new(),
            };
            return Ok(Some(ClaimedCiJob {
                job_id: job.id,
                job_name: job.job_name.clone(),
                commit_sha: job.commit_sha.clone(),
                spec,
                lease_until: job.lease_until.unwrap_or(now_ts + Self::CLAIM_LEASE_SECS),
                fence,
                job_token,
                deadline,
                clone_url,
            }));
        }
        Ok(None)
    }

    /// The running/fence/cancel pre-check shared by the trace and finish
    /// paths: the runner must own the claim and present the current fence,
    /// and a requested cancel is applied terminally here (cancel wins).
    /// Returns the job row when the call may proceed.
    async fn checked_claim(
        &self,
        runner: &RunnerPrincipal,
        job_id: i64,
        fence: &str,
    ) -> CoreResult<Result<starforged_db::ci::CiJobRow, ClaimGate>> {
        let Some(job) = db_ci::ci_job_by_id(self.db(), job_id).await? else {
            return Ok(Err(ClaimGate::NotFound));
        };
        if job.repo_id != runner.repo_id
            || job.runner_id != Some(runner.runner_id)
            || job.lease_token.as_deref() != Some(fence)
        {
            return Ok(Err(ClaimGate::FenceMismatch));
        }
        if job.state == "canceled" || job.cancel_requested != 0 {
            if job.state != "canceled"
                && db_ci::cancel_ci_job(self.db(), job_id, Some(fence), now()).await?
            {
                db_ci::record_attempt_usage(self.db(), &job, now()).await?;
                self.terminate_ci_job(&job, "canceled", "error", "canceled", None)
                    .await?;
            }
            return Ok(Err(ClaimGate::Canceled));
        }
        if job.state != "claimed" && job.state != "running" {
            return Ok(Err(ClaimGate::FenceMismatch));
        }
        Ok(Ok(job))
    }

    /// Appends one log chunk for a claimed job: the runner's claim and
    /// fence must match, a requested cancel is applied terminally (cancel
    /// wins), and the range must continue the stored log — `start` must
    /// equal the current end, or match an already-stored chunk exactly
    /// (idempotent retry). Chunks are capped at 100 MiB of offsets per
    /// job; ANSI escapes and control characters are stripped before the
    /// bytes go to the CAS blob store, and the chunk row records the
    /// blob's BLAKE3.
    pub async fn trace_ci_job(
        &self,
        runner: &RunnerPrincipal,
        job_id: i64,
        fence: &str,
        start: i64,
        end: i64,
        bytes: &[u8],
    ) -> CoreResult<TraceOutcome> {
        let _job = match self.checked_claim(runner, job_id, fence).await? {
            Ok(job) => job,
            Err(ClaimGate::NotFound) => return Ok(TraceOutcome::NotFound),
            Err(ClaimGate::FenceMismatch) => return Ok(TraceOutcome::FenceMismatch),
            Err(ClaimGate::Canceled) => return Ok(TraceOutcome::Canceled),
        };
        // The first accepted trace marks the job running (the runner is
        // executing it); later traces keep the state. Every trace also
        // renews the 60-second lease, so a runner that is streaming logs
        // never loses its claim while the job runs.
        db_ci::set_ci_job_running(self.db(), job_id, fence).await?;
        if !db_ci::renew_ci_job_lease(self.db(), job_id, fence, now() + Self::CLAIM_LEASE_SECS)
            .await?
        {
            return Ok(TraceOutcome::FenceMismatch);
        }
        if end < start || end - start != bytes.len() as i64 {
            return Ok(TraceOutcome::RangeMismatch);
        }
        let chunks = db_ci::log_chunks_for_job(self.db(), job_id).await?;
        let current_end = db_ci::log_end_offset(self.db(), job_id).await?;
        if chunks
            .iter()
            .any(|c| c.start_offset == start && c.end_offset == end)
        {
            return Ok(TraceOutcome::Accepted);
        }
        if start != current_end {
            return Ok(TraceOutcome::RangeMismatch);
        }
        if end > Self::MAX_JOB_LOG_BYTES {
            return Ok(TraceOutcome::PayloadTooLarge);
        }
        let stripped = strip_log_bytes(bytes);
        let blob = self
            .config()
            .blob_store
            .put(&stripped)
            .await
            .map_err(|e| CoreError::Internal(format!("log blob store: {e}")))?;
        db_ci::append_log_chunk(
            self.db(),
            &db_ci::NewLogChunk {
                job_id,
                start_offset: start,
                end_offset: end,
                blake3: &blob.hash,
                now: now(),
            },
        )
        .await?;
        Ok(TraceOutcome::Accepted)
    }

    /// Renews the lease for a claimed/running job (runner heartbeat). The
    /// runner presents its fence; a canceled job answers a conflict so the
    /// runner stops. Traces renew the lease too; the heartbeat covers long
    /// commands that produce no log output.
    pub async fn heartbeat_ci_job(
        &self,
        runner: &RunnerPrincipal,
        job_id: i64,
        fence: &str,
    ) -> CoreResult<()> {
        match self.checked_claim(runner, job_id, fence).await? {
            Ok(_) => {
                if db_ci::renew_ci_job_lease(
                    self.db(),
                    job_id,
                    fence,
                    now() + Self::CLAIM_LEASE_SECS,
                )
                .await?
                {
                    Ok(())
                } else {
                    Err(CoreError::Conflict("stale runner fence".into()))
                }
            }
            Err(ClaimGate::NotFound) => Err(CoreError::NotFound),
            Err(ClaimGate::FenceMismatch) => Err(CoreError::Conflict("stale runner fence".into())),
            Err(ClaimGate::Canceled) => Err(CoreError::Conflict("job is canceled".into())),
        }
    }

    /// Finishes a claimed job (decision 9): writes the `ci/<job_name>`
    /// check through [`Core::submit_ci_status`], links the job's sessions,
    /// and records the terminal state under the lease fence. A requested
    /// cancel is applied instead (cancel wins) and answers
    /// [`FinishOutcome::Canceled`]; a stale fence answers
    /// [`FinishOutcome::FenceMismatch`]. `state` must be `succeeded`,
    /// `failed`, or `error`; a job without `created_by` (system-triggered)
    /// cannot write a status and answers `Invalid`.
    #[allow(clippy::too_many_arguments)] // one call site (the runner finish route)
    pub async fn finish_ci_job(
        &self,
        runner: &RunnerPrincipal,
        job_id: i64,
        fence: &str,
        state: &str,
        exit_code: Option<i64>,
        checksum: Option<&str>,
        session_ulids: &[String],
    ) -> CoreResult<FinishOutcome> {
        let job = match self.checked_claim(runner, job_id, fence).await? {
            Ok(job) => job,
            Err(ClaimGate::NotFound) => return Ok(FinishOutcome::NotFound),
            Err(ClaimGate::FenceMismatch) => return Ok(FinishOutcome::FenceMismatch),
            Err(ClaimGate::Canceled) => return Ok(FinishOutcome::Canceled),
        };
        let check_state = match state {
            "succeeded" => "success",
            "failed" => "failure",
            "error" => "error",
            other => {
                return Err(CoreError::Invalid(format!(
                    "finish state `{other}` must be succeeded, failed, or error"
                )));
            }
        };
        let user_id = job
            .created_by
            .ok_or_else(|| CoreError::Invalid("job has no triggering user".into()))?;
        let principal = JobPrincipal {
            job_id: job.id,
            user_id,
            repo_id: job.repo_id,
            commit_sha: job.commit_sha.clone(),
        };
        self.submit_ci_status(
            &principal,
            &job.commit_sha,
            check_state,
            &format!("ci/{}", job.job_name),
            None,
            checksum,
        )
        .await?;
        for ulid in session_ulids {
            if let Some(session) =
                db_sessions::session_by_ulid(self.db(), job.repo_id, ulid).await?
            {
                db_ci::insert_job_session(self.db(), job.id, ulid, now()).await?;
                db_ci::set_session_ci_job(self.db(), session.id, job.id).await?;
            }
        }
        if !db_ci::finish_ci_job(
            self.db(),
            job.id,
            fence,
            state,
            exit_code,
            checksum,
            "",
            now(),
        )
        .await?
        {
            return Ok(FinishOutcome::FenceMismatch);
        }
        db_ci::record_attempt_usage(self.db(), &job, now()).await?;
        self.emit_ci_event(&job, "finished", state, exit_code).await;
        self.revoke_job_credentials(job.id).await?;
        self.audit(
            job.created_by,
            "ci.job.finish",
            &format!("ci_job:{}", job.id),
            &format!("state={state} exit_code={exit_code:?}"),
        )
        .await?;
        Ok(FinishOutcome::Finished)
    }

    /// Requests the cancellation of one run (decision: cancel is a user
    /// request, the runner observes it on its next trace/finish call and
    /// cancel wins the race). The caller must hold at least `Write` on the
    /// repository, and the job must belong to that repository. Audited.
    pub async fn cancel_ci_job(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        job_id: i64,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        let job = db_ci::ci_job_by_id(self.db(), job_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if job.repo_id != access.repo.id {
            return Err(CoreError::NotFound);
        }
        let description = format!("canceled by {}", user.handle);
        if job.state == "queued" {
            // No runner owns a queued job, so cancel it terminally here;
            // otherwise it would wait for a claim that may never come.
            if !db_ci::cancel_ci_job(self.db(), job_id, None, now()).await? {
                return Err(CoreError::NotFound);
            }
            self.record_attempt_claimed_since(&job).await?;
            self.terminate_ci_job(&job, "canceled", "error", &description, Some(user.id))
                .await?;
        } else {
            // A claimed/running job is canceled by its runner on the next
            // trace/finish; write the terminal check now so the gate does
            // not stay pending while the runner notices.
            if !db_ci::request_cancel_ci_job(self.db(), job_id, now()).await? {
                return Err(CoreError::NotFound);
            }
            self.write_ci_terminal_check(&job, "error", &description, Some(user.id))
                .await?;
        }
        self.audit(
            Some(user.id),
            "ci.job.cancel",
            &format!("ci_job:{job_id}"),
            &format!("repo={}", access.repo.full_name()),
        )
        .await?;
        Ok(())
    }

    /// Mints the short-lived git credential for a job claimed by this
    /// runner (decision 10): the runner must own the claim and present the
    /// current fence, then the mint runs as the job's principal so the
    /// usual job-state and deadline checks apply. The secret is returned
    /// once (the API serves it with a 201).
    pub async fn git_credential_for_runner(
        &self,
        runner: &RunnerPrincipal,
        job_id: i64,
        fence: &str,
    ) -> CoreResult<MintedGitCredential> {
        let job = match self.checked_claim(runner, job_id, fence).await? {
            Ok(job) => job,
            Err(ClaimGate::NotFound) => return Err(CoreError::NotFound),
            Err(ClaimGate::FenceMismatch) => {
                return Err(CoreError::Conflict("stale runner fence".into()));
            }
            Err(ClaimGate::Canceled) => {
                return Err(CoreError::Invalid("job is canceled".into()));
            }
        };
        let user_id = job
            .created_by
            .ok_or_else(|| CoreError::Invalid("job has no triggering user".into()))?;
        self.mint_git_credential(&JobPrincipal {
            job_id: job.id,
            user_id,
            repo_id: job.repo_id,
            commit_sha: job.commit_sha,
        })
        .await
    }
}
// ===== CI triggers, artifacts, and secrets (M6c C1–C3) =====
/// Current time in unix seconds (re-export for the API layer, which only
/// depends on `starforged-core`).
pub fn now_secs() -> i64 {
    now()
}

/// Bearer prefix of a one-time artifact upload/download token (`sfa_…`).
pub const ARTIFACT_TOKEN_PREFIX: &str = "sfa_";
/// Lifetime of an artifact upload token: 10 minutes.
pub const ARTIFACT_TOKEN_TTL_SECS: i64 = 600;
/// Per-artifact size cap: 1 GiB.
pub const MAX_ARTIFACT_BYTES: i64 = 1024 * 1024 * 1024;
/// Artifact retention window: 30 days.
pub const ARTIFACT_TTL_SECS: i64 = 30 * 24 * 3600;
/// Default job deadline when the spec sets no timeout: 1 hour.
pub const DEFAULT_JOB_TIMEOUT_SECS: i64 = 3600;

/// A job's timeout in seconds: the spec's `timeout`, or
/// [`DEFAULT_JOB_TIMEOUT_SECS`]. The deadline is this long after a claim.
fn job_timeout_secs(spec: &CiJobSpec) -> i64 {
    spec.timeout_duration()
        .map(|d| d.as_secs() as i64)
        .unwrap_or(DEFAULT_JOB_TIMEOUT_SECS)
}

/// `ci.allow_secrets_on_refs_for` (plan decision 7): `refs/for` runs get no
/// secrets unless the repo opts in. The server-wide default is false.
pub const ALLOW_SECRETS_ON_REFS_FOR: bool = false;
/// `ci.env_secrets` (plan decision 7): env injection of secrets is an
/// explicit per-repo opt-in for providers without an egress proxy. The
/// server-wide default is false; resolution below returns values to the
/// sandbox daemon for proxy header injection, never to the sandbox
/// environment or the runner.
pub const ENV_SECRETS: bool = false;

/// A CI run as listed to repository users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiRunView {
    pub job_id: i64,
    pub repo_id: i64,
    pub commit_sha: String,
    pub job_name: String,
    pub state: String,
    pub created_by: Option<i64>,
    pub created_at: i64,
    pub finished_at: Option<i64>,
}

impl From<starforged_db::ci::CiJobRow> for CiRunView {
    fn from(row: starforged_db::ci::CiJobRow) -> Self {
        CiRunView {
            job_id: row.id,
            repo_id: row.repo_id,
            commit_sha: row.commit_sha,
            job_name: row.job_name,
            state: row.state,
            created_by: row.created_by,
            created_at: row.created_at,
            finished_at: row.finished_at,
        }
    }
}

/// Run detail: the job plus its artifact metadata and linked sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiRunDetail {
    pub run: CiRunView,
    pub artifacts: Vec<ArtifactView>,
    pub sessions: Vec<String>,
}

/// An artifact of a CI job: CAS identity (BLAKE3) plus the optional
/// client-provided SHA-256. No filesystem path is ever exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactView {
    pub id: i64,
    pub job_id: i64,
    pub name: String,
    pub size: i64,
    pub blake3: String,
    pub sha256: Option<String>,
    pub expires_at: i64,
}

impl From<starforged_db::ci::CiArtifactRow> for ArtifactView {
    fn from(row: starforged_db::ci::CiArtifactRow) -> Self {
        ArtifactView {
            id: row.id,
            job_id: row.job_id,
            name: row.name,
            size: row.size,
            blake3: row.blake3,
            sha256: row.sha256,
            expires_at: row.expires_at,
        }
    }
}

/// Input for [`Core::create_ci_secret`] (create or rotate): the plaintext
/// `value` is sealed before storage and never logged or returned. The
/// `bind_host`/`bind_header` pair names the one egress destination the
/// value may be injected for; both empty means unbound, and exactly one
/// set is rejected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CiSecretInput {
    pub name: String,
    pub value: String,
    pub bind_host: String,
    pub bind_header: String,
}

/// A repository secret as listed to administrators: metadata only, never
/// the sealed value and never the plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretView {
    pub id: i64,
    pub repo_id: i64,
    pub name: String,
    pub redact_in_sessions: bool,
    pub bind_host: String,
    pub bind_header: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<starforged_db::ci::CiSecretRow> for SecretView {
    fn from(row: starforged_db::ci::CiSecretRow) -> Self {
        SecretView {
            id: row.id,
            repo_id: row.repo_id,
            name: row.name,
            redact_in_sessions: row.redact_in_sessions,
            bind_host: row.bind_host,
            bind_header: row.bind_header,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// One secret resolved for a running job, held in memory only for
/// egress-proxy header injection. `Debug` redacts the value so a stray log
/// line can never carry it.
pub struct ResolvedSecret {
    pub secret_id: i64,
    pub name: String,
    pub host: String,
    pub header: String,
    pub value: String,
}

impl std::fmt::Debug for ResolvedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSecret")
            .field("secret_id", &self.secret_id)
            .field("name", &self.name)
            .field("host", &self.host)
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Validates one artifact name (plan security model: traversal): relative,
/// non-empty, at most 256 chars, no `..`/`.`/empty segments, no backslashes,
/// no whitespace or control characters.
pub fn validate_artifact_name(name: &str) -> CoreResult<()> {
    if name.is_empty() || name.len() > 256 {
        return Err(CoreError::Invalid(
            "artifact name must be 1-256 characters".into(),
        ));
    }
    for segment in name.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CoreError::Invalid(format!(
                "artifact name `{name}` must be a relative path without `.` or `..` segments"
            )));
        }
    }
    if name
        .chars()
        .any(|c| c <= ' ' || c == '\\' || c.is_control())
    {
        return Err(CoreError::Invalid(format!(
            "artifact name `{name}` must not contain whitespace or control characters"
        )));
    }
    Ok(())
}

/// Validates one secret name: 1–128 chars of `[A-Za-z0-9_]` (the `ci_spec`
/// rule, enforced here too so the API rejects names a spec cannot carry).
pub fn validate_secret_name(name: &str) -> CoreResult<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(CoreError::Invalid(
            "secret name must be 1-128 characters".into(),
        ));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(CoreError::Invalid(
            "secret name may only contain [A-Za-z0-9_]".into(),
        ));
    }
    Ok(())
}

/// Validates one secret binding host: a hostname or IP literal with an
/// optional `:port` (an IPv6 literal takes the `[::1]` bracket form).
/// Empty means the secret is unbound.
pub fn validate_bind_host(host: &str) -> CoreResult<()> {
    if host.is_empty() {
        return Ok(());
    }
    if host.len() > 253 || host.chars().any(char::is_whitespace) {
        return Err(CoreError::Invalid(
            "bind_host must be a hostname or IP with an optional port".into(),
        ));
    }
    // Split an optional trailing :port (bracketed IPv6 keeps its colons).
    let (name, port): (String, Option<String>) = if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, tail)) = rest.split_once(']') else {
            return Err(CoreError::Invalid(
                "bind_host must be a hostname or IP with an optional port".into(),
            ));
        };
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(CoreError::Invalid(format!(
                "bind_host `{host}` must be a hostname or IP with an optional port"
            )));
        }
        let port = if tail.is_empty() {
            None
        } else {
            Some(
                tail.strip_prefix(':')
                    .ok_or_else(|| {
                        CoreError::Invalid(format!(
                            "bind_host `{host}` must be a hostname or IP with an optional port"
                        ))
                    })?
                    .to_owned(),
            )
        };
        (inner.to_owned(), port)
    } else {
        match host.rsplit_once(':') {
            Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => {
                (head.to_owned(), Some(tail.to_owned()))
            }
            _ => (host.to_owned(), None),
        }
    };
    if let Some(port) = port {
        let port: u32 = port
            .parse()
            .map_err(|_| CoreError::Invalid(format!("bind_host `{host}` port must be 1-65535")))?;
        if !(1..=65535).contains(&port) {
            return Err(CoreError::Invalid(format!(
                "bind_host `{host}` port must be 1-65535"
            )));
        }
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let name = name.trim_end_matches('.');
    if name.is_empty()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
    {
        return Err(CoreError::Invalid(format!(
            "bind_host `{host}` must be a hostname or IP with an optional port"
        )));
    }
    Ok(())
}

/// Validates one secret binding header: an HTTP header field-name token
/// (RFC 9110 `tchar`). Empty means the secret is unbound.
pub fn validate_bind_header(header: &str) -> CoreResult<()> {
    if header.is_empty() {
        return Ok(());
    }
    if !header.bytes().all(|b| {
        matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        ) || b.is_ascii_alphanumeric()
    }) {
        return Err(CoreError::Invalid(
            "bind_header must be an HTTP header token".into(),
        ));
    }
    Ok(())
}

/// Glob match for artifact names: `**` matches across `/`, `*` matches
/// within one segment, `?` matches one non-`/` character.
pub fn artifact_glob_matches(pattern: &str, name: &str) -> bool {
    if !pattern.contains(['*', '?']) {
        return pattern == name;
    }
    let pat: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = name.chars().collect();
    glob_match(&pat, &text)
}

fn glob_match(pat: &[char], text: &[char]) -> bool {
    if pat.is_empty() {
        return text.is_empty();
    }
    if pat.len() >= 2 && pat[0] == '*' && pat[1] == '*' {
        // `**` consumes any run of characters including `/` (and an
        // optional following `/`).
        let rest = &pat[2..];
        let rest = if rest.first() == Some(&'/') {
            &rest[1..]
        } else {
            rest
        };
        for skip in 0..=text.len() {
            if glob_match(rest, &text[skip..]) {
                return true;
            }
        }
        return false;
    }
    if pat[0] == '*' {
        for skip in 0..=text.len() {
            if skip > 0 && text[skip - 1] == '/' {
                break;
            }
            if glob_match(&pat[1..], &text[skip..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pat[0] == '?' {
        if text[0] == '/' {
            return false;
        }
        return glob_match(&pat[1..], &text[1..]);
    }
    pat[0] == text[0] && glob_match(&pat[1..], &text[1..])
}

impl Core {
    /// Reads and parses `.starforge/ci.toml` at `commit_sha` from the
    /// repository's git tree (never the worktree). `Ok(None)` when the
    /// repository has no spec at that commit; a malformed spec is
    /// `Invalid` and, when `creator` is known, also records a `ci/spec`
    /// error check on the commit.
    pub async fn read_ci_spec_at_commit(
        &self,
        repo_id: i64,
        commit_sha: &str,
        creator: Option<i64>,
    ) -> CoreResult<Option<crate::ci_spec::CiSpec>> {
        let path = self.repo_path(repo_id);
        let blob = starforged_git::read::blob_bytes(&path, commit_sha, ".starforge/ci.toml")
            .map_err(|e| CoreError::Git(e.to_string()))?;
        let Some(bytes) = blob else {
            return Ok(None);
        };
        let text = String::from_utf8(bytes)
            .map_err(|_| CoreError::Invalid("ci.toml is not UTF-8".into()))?;
        match crate::ci_spec::CiSpec::parse(&text) {
            Ok(spec) => Ok(Some(spec)),
            Err(err) => {
                if let Some(user_id) = creator {
                    let _ = db_checks::insert_check(
                        self.db(),
                        repo_id,
                        commit_sha,
                        "ci/spec",
                        "error",
                        None,
                        Some(&err.to_string()),
                        Some(user_id),
                        now(),
                    )
                    .await;
                }
                Err(err)
            }
        }
    }

    /// Enqueues one job of `spec` for `commit_sha`, deduplicating on the
    /// `(repo, commit, job)` partial unique index (a collision means an
    /// active job already exists). Writes the `pending` `ci/<job>` check
    /// and dispatches the `ci` queued webhook. Returns the new job id, or
    /// `None` when an active job already covers this `(repo, commit, job)`.
    #[allow(clippy::too_many_arguments)]
    async fn enqueue_ci_job(
        &self,
        repo_id: i64,
        trail_id: Option<i64>,
        change_id: Option<i64>,
        revision_id: Option<i64>,
        commit_sha: &str,
        base_sha: Option<&str>,
        job: &crate::ci_spec::CiJobSpec,
        created_by: Option<i64>,
    ) -> CoreResult<Option<i64>> {
        // The native minutes quota (`[ci.limits]`): a used-up month refuses
        // the run and says why on its check instead of queueing it.
        if let Some(message) = self.ci_minutes_quota_exhausted(repo_id).await? {
            self.record_ci_quota_refusal(repo_id, commit_sha, &job.name, &message, created_by)
                .await?;
            return Ok(None);
        }
        let now_ts = now();
        let timeout_secs = job_timeout_secs(job);
        let spec_json = serde_json::to_string(job).unwrap_or_else(|_| "{}".into());
        let row = match db_ci::insert_ci_job(
            self.db(),
            &db_ci::NewCiJob {
                repo_id,
                trail_id,
                change_id,
                revision_id,
                commit_sha,
                base_sha,
                job_name: &job.name,
                spec: &spec_json,
                run_at: now_ts,
                deadline: now_ts + timeout_secs,
                created_by,
                now: now_ts,
            },
        )
        .await
        {
            Ok(row) => row,
            Err(err) if err.is_unique_violation() => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        // The `pending` check gates the commit until the job reports.
        let _ = db_checks::insert_check(
            self.db(),
            repo_id,
            commit_sha,
            &format!("ci/{}", job.name),
            "pending",
            None,
            None,
            created_by,
            now_ts,
        )
        .await;
        self.emit_ci_event(&row, "queued", "queued", None).await;
        self.audit(
            created_by,
            "ci.job.enqueue",
            &format!("ci_job:{}", row.id),
            &format!("repo_id={repo_id} job={} commit={commit_sha}", job.name),
        )
        .await?;
        Ok(Some(row.id))
    }

    /// Push trigger (C1): enqueues every job of the spec at `commit_sha`
    /// whose push trigger matches `branch`. `created_by` is the pusher.
    pub async fn ci_trigger_push(
        &self,
        repo_id: i64,
        branch: &str,
        commit_sha: &str,
        pusher: Option<i64>,
    ) -> CoreResult<Vec<i64>> {
        let Some(spec) = self
            .read_ci_spec_at_commit(repo_id, commit_sha, pusher)
            .await?
        else {
            return Ok(Vec::new());
        };
        if !spec
            .triggers
            .push
            .iter()
            .any(|pattern| starforged_git::refpolicy::pattern_matches(Some(pattern), branch))
        {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for job in &spec.jobs {
            if let Some(id) = self
                .enqueue_ci_job(repo_id, None, None, None, commit_sha, None, job, pusher)
                .await?
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Trail trigger (C1): enqueues every job of the spec at the change's
    /// current head when `action` (`opened`/`updated`) is in the spec's
    /// trail triggers. Supersedes the change's other active jobs first (a
    /// new revision cancels queued/claimed/running jobs of older
    /// revisions). `created_by` is the Trail author (the change creator,
    /// falling back to `actor`).
    pub async fn ci_trigger_trail(
        &self,
        repo_id: i64,
        action: &str,
        commit_sha: &str,
        actor: Option<i64>,
    ) -> CoreResult<Vec<i64>> {
        let Some(spec) = self
            .read_ci_spec_at_commit(repo_id, commit_sha, actor)
            .await?
        else {
            return Ok(Vec::new());
        };
        if !spec.triggers.trail.iter().any(|entry| entry == action) {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for change in db_changes::changes_with_current_head(self.db(), repo_id, commit_sha).await? {
            for stale in db_ci::active_ci_jobs_for_change(self.db(), repo_id, change.id).await? {
                if db_ci::cancel_ci_job(self.db(), stale.id, None, now()).await? {
                    if stale.state == "queued" {
                        self.record_attempt_claimed_since(&stale).await?;
                    } else {
                        db_ci::record_attempt_usage(self.db(), &stale, now()).await?;
                    }
                    self.terminate_ci_job(
                        &stale,
                        "canceled",
                        "error",
                        "superseded by a newer revision",
                        actor,
                    )
                    .await?;
                }
            }
            let created_by = change.creator_id.or(actor);
            for job in &spec.jobs {
                if let Some(id) = self
                    .enqueue_ci_job(
                        repo_id,
                        Some(change.trail_id),
                        Some(change.id),
                        change.current_revision_id,
                        commit_sha,
                        None,
                        job,
                        created_by,
                    )
                    .await?
                {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// Manual trigger (C1): `POST /repos/{owner}/{repo}/ci/runs` with
    /// `{ref, job?}`. Resolves `ref` in the repository (default: the
    /// default branch), reads the spec at that commit (trigger filters do
    /// not apply to a manual run), and enqueues the named job or all jobs.
    /// The caller must hold at least `Write` on the repository.
    pub async fn ci_trigger_manual(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        reference: Option<&str>,
        job_name: Option<&str>,
    ) -> CoreResult<Vec<i64>> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        let path = self.repo_path(access.repo.id);
        let reference = reference
            .map(str::to_owned)
            .unwrap_or_else(|| access.repo.default_branch.clone());
        let resolved = starforged_git::read::resolve(&path, &reference)
            .map_err(|e| CoreError::Git(e.to_string()))?
            .ok_or_else(|| CoreError::Invalid(format!("unknown ref `{reference}`")))?;
        let Some(spec) = self
            .read_ci_spec_at_commit(access.repo.id, &resolved.commit_id, Some(user.id))
            .await?
        else {
            return Err(CoreError::Invalid(
                "no .starforge/ci.toml at the requested ref".into(),
            ));
        };
        let jobs: Vec<&crate::ci_spec::CiJobSpec> = match job_name {
            Some(name) => {
                let Some(job) = spec.jobs.iter().find(|job| job.name == name) else {
                    return Err(CoreError::Invalid(format!("unknown CI job `{name}`")));
                };
                vec![job]
            }
            None => spec.jobs.iter().collect(),
        };
        if let Some(message) = self.ci_minutes_quota_exhausted(access.repo.id).await? {
            return Err(CoreError::Invalid(message));
        }
        let mut ids = Vec::new();
        for job in jobs {
            if let Some(id) = self
                .enqueue_ci_job(
                    access.repo.id,
                    None,
                    None,
                    None,
                    &resolved.commit_id,
                    None,
                    job,
                    Some(user.id),
                )
                .await?
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Post-receive scan trigger (C1, called by the git transports after a
    /// successful push, alongside `scan_push_changes`): for every changed
    /// branch tip, the push trigger; for every changed `refs/for/*` tip,
    /// the Trail trigger whose action is `opened` for revision 1 and
    /// `updated` for later revisions. Failures are returned so the
    /// transport can warn-log; a push never fails because of CI.
    pub async fn ci_trigger_push_scan(
        &self,
        repo_id: i64,
        pusher: Option<i64>,
        before: &std::collections::BTreeMap<String, String>,
        after: &std::collections::BTreeMap<String, String>,
    ) -> CoreResult<()> {
        for (name, tip) in after {
            if before.get(name) == Some(tip) {
                continue;
            }
            if let Some(branch) = name.strip_prefix("refs/heads/") {
                self.ci_trigger_push(repo_id, branch, tip, pusher).await?;
            } else if name.starts_with("refs/for/") {
                let action = match db_changes::changes_with_current_head(self.db(), repo_id, tip)
                    .await?
                    .into_iter()
                    .next()
                {
                    Some(change) => match change.current_revision_id {
                        Some(revision_id) => {
                            match db_changes::revision_by_id(self.db(), revision_id).await? {
                                Some(revision) if revision.number > 1 => "updated",
                                _ => "opened",
                            }
                        }
                        None => "opened",
                    },
                    None => continue,
                };
                self.ci_trigger_trail(repo_id, action, tip, pusher).await?;
            }
        }
        Ok(())
    }

    /// Lists the repository's CI runs (jobs), newest first. Callers need at
    /// least `Read` on the repo.
    pub async fn list_ci_runs(
        &self,
        viewer: Option<&crate::accounts::User>,
        owner: &str,
        repo: &str,
        limit: i64,
    ) -> CoreResult<Vec<CiRunView>> {
        let access = self
            .require_repo(viewer, owner, repo, Permission::Read)
            .await?;
        let limit = limit.clamp(1, 200);
        Ok(
            db_ci::list_ci_jobs_for_repo(self.db(), access.repo.id, limit)
                .await?
                .into_iter()
                .map(CiRunView::from)
                .collect(),
        )
    }

    /// One CI run with its artifact metadata and linked sessions. Callers
    /// need at least `Read` on the repository; a job of another repository
    /// is `NotFound`.
    pub async fn get_ci_run(
        &self,
        viewer: Option<&crate::accounts::User>,
        owner: &str,
        repo: &str,
        job_id: i64,
    ) -> CoreResult<CiRunDetail> {
        let access = self
            .require_repo(viewer, owner, repo, Permission::Read)
            .await?;
        let job = db_ci::ci_job_by_id(self.db(), job_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if job.repo_id != access.repo.id {
            return Err(CoreError::NotFound);
        }
        let artifacts = db_ci::artifacts_for_job(self.db(), job_id)
            .await?
            .into_iter()
            .map(ArtifactView::from)
            .collect();
        let sessions = db_ci::job_sessions_for_job(self.db(), job_id)
            .await?
            .into_iter()
            .map(|row| row.session_ulid)
            .collect();
        Ok(CiRunDetail {
            run: CiRunView::from(job),
            artifacts,
            sessions,
        })
    }

    /// The full log text of one CI job (C4 web run detail): chunks in
    /// offset order, concatenated. Callers need at least `Read` on the
    /// repository; a job of another repository is `NotFound`. The trace
    /// path already stripped control/ANSI bytes and secret-scanned the
    /// chunks, so this returns displayable text; callers must still render
    /// it escaped (the log is runner-supplied).
    pub async fn get_ci_job_logs(
        &self,
        viewer: Option<&crate::accounts::User>,
        owner: &str,
        repo: &str,
        job_id: i64,
    ) -> CoreResult<String> {
        let access = self
            .require_repo(viewer, owner, repo, Permission::Read)
            .await?;
        let job = db_ci::ci_job_by_id(self.db(), job_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if job.repo_id != access.repo.id {
            return Err(CoreError::NotFound);
        }
        let chunks = db_ci::log_chunks_for_job(self.db(), job_id).await?;
        let mut out = String::new();
        for chunk in chunks {
            let bytes = self
                .config()
                .blob_store
                .get_by_hash(&chunk.blake3)
                .await
                .map_err(|e| CoreError::Internal(format!("reading CI log blob: {e}")))?;
            out.push_str(&String::from_utf8_lossy(&bytes));
        }
        Ok(out)
    }

    /// The secret-trust rule (plan decision 7) for one job: secrets resolve
    /// only on a protected branch or a Trail change with maintainer
    /// approval. `refs/for` runs are only trusted when
    /// [`ALLOW_SECRETS_ON_REFS_FOR`] is set (false by default).
    pub async fn secrets_trusted_for_job(
        &self,
        job: &starforged_db::ci::CiJobRow,
    ) -> CoreResult<bool> {
        if let Some(change_id) = job.change_id {
            // Trail/`refs/for` job: trusted only with an approval, or with
            // the explicit per-repo opt-in.
            if ALLOW_SECRETS_ON_REFS_FOR {
                return Ok(true);
            }
            let reviews = db_changes::reviews_of_change(self.db(), change_id).await?;
            return Ok(reviews.iter().any(|review| review.verdict == "approved"));
        }
        // Branch job: trusted when a protected branch currently points at
        // the job's commit (a gate rule whose pattern matches that branch).
        let path = self.repo_path(job.repo_id);
        let branches =
            starforged_git::read::branch_list(&path).map_err(|e| CoreError::Git(e.to_string()))?;
        let patterns: Vec<Option<String>> = db_checks::gate_rules_for_repo(self.db(), job.repo_id)
            .await?
            .into_iter()
            .map(|rule| rule.pattern)
            .collect();
        Ok(branches
            .iter()
            .filter(|branch| branch.tip.id == job.commit_sha)
            .any(|branch| {
                patterns.iter().any(|pattern| {
                    starforged_git::refpolicy::pattern_matches(pattern.as_deref(), &branch.name)
                })
            }))
    }

    /// Creates or rotates one repository secret (decision 7): the value is
    /// sealed with [`CiSecretBox`] (`ci-secrets-v1`) and only the ciphertext
    /// is stored. The caller must hold at least `Admin` on the repo. The
    /// plaintext never reaches the database, the audit trail, or logs —
    /// the audit row carries the secret name only.
    pub async fn create_ci_secret(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        input: &CiSecretInput,
        redact_in_sessions: bool,
    ) -> CoreResult<SecretView> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        validate_secret_name(&input.name)?;
        if input.value.is_empty() {
            return Err(CoreError::Invalid("secret value must not be empty".into()));
        }
        validate_bind_host(&input.bind_host)?;
        validate_bind_header(&input.bind_header)?;
        if input.bind_host.is_empty() != input.bind_header.is_empty() {
            return Err(CoreError::Invalid(
                "bind_host and bind_header must be set together".into(),
            ));
        }
        let sealed = self.seal_ci_secret(&input.value);
        let row = db_ci::upsert_secret(
            self.db(),
            &db_ci::NewCiSecret {
                repo_id: access.repo.id,
                name: &input.name,
                sealed_value: &sealed,
                bind_host: &input.bind_host,
                bind_header: &input.bind_header,
                redact_in_sessions,
                created_by: Some(user.id),
                now: now(),
            },
        )
        .await?;
        self.audit(
            Some(user.id),
            "ci.secret.create",
            &format!("ci_secret:{}", row.id),
            &format!("repo={} name={}", access.repo.full_name(), input.name),
        )
        .await?;
        Ok(SecretView::from(row))
    }

    /// Lists a repository's secret names (callers need at least `Admin`).
    /// Views never carry sealed values or plaintexts.
    pub async fn list_ci_secrets(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<SecretView>> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        Ok(db_ci::secrets_for_repo(self.db(), access.repo.id)
            .await?
            .into_iter()
            .map(SecretView::from)
            .collect())
    }

    /// Deletes a repository secret. The caller must hold at least `Admin`
    /// on the repo; `ci_job_secrets` rows cascade away with the secret.
    pub async fn delete_ci_secret(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        name: &str,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        if !db_ci::delete_secret(self.db(), access.repo.id, name).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "ci.secret.delete",
            &format!("ci_secret:{name}"),
            &format!("repo={}", access.repo.full_name()),
        )
        .await?;
        Ok(())
    }

    /// Resolves the bound secrets a job named in its spec, for the server's
    /// own sandbox create (Phase 4): the values travel only as
    /// `SecretValue` bindings to the sandbox daemon over its local
    /// token-authenticated socket — never to the runner, whose claim
    /// response carries names only. Each resolved secret is recorded in
    /// `ci_job_secrets` (so the server can decrypt it in memory for dynamic
    /// session redaction) and the resolution is audited with names only.
    /// A spec-named secret that does not exist, or has no host binding, is
    /// `Invalid`; a job the trust rule
    /// ([`Core::secrets_trusted_for_job`]) denies cannot resolve any.
    pub async fn resolve_job_secret_bindings(
        &self,
        job: &starforged_db::ci::CiJobRow,
    ) -> CoreResult<Vec<ResolvedSecret>> {
        let spec: CiJobSpec = serde_json::from_str(&job.spec)
            .map_err(|_| CoreError::Invalid("job spec is not parseable".into()))?;
        if spec.secrets.is_empty() {
            return Ok(Vec::new());
        }
        if !self.secrets_trusted_for_job(job).await? {
            return Err(CoreError::Invalid(
                "repository secrets are not available to this run".into(),
            ));
        }
        let mut resolved = Vec::new();
        let mut names = Vec::new();
        for name in &spec.secrets {
            let Some(row) = db_ci::secret_by_name(self.db(), job.repo_id, name).await? else {
                return Err(CoreError::Invalid(format!(
                    "secret {name} does not exist for this repository"
                )));
            };
            if row.bind_host.is_empty() || row.bind_header.is_empty() {
                return Err(CoreError::Invalid(format!(
                    "secret {name} has no host binding"
                )));
            }
            let value = self.open_ci_secret(&row.sealed_value)?;
            db_ci::insert_job_secret(self.db(), job.id, row.id, now()).await?;
            names.push(name.clone());
            resolved.push(ResolvedSecret {
                secret_id: row.id,
                name: name.clone(),
                host: row.bind_host,
                header: row.bind_header,
                value,
            });
        }
        self.audit(
            job.created_by,
            "ci.job.secrets.resolve",
            &format!("ci_job:{}", job.id),
            &format!("secrets=[{}]", names.join(",")),
        )
        .await?;
        Ok(resolved)
    }

    /// Mints a one-time artifact upload token ([`ARTIFACT_TOKEN_PREFIX`])
    /// bound to `(job, name, size, sha256)`. The runner must own the claim
    /// and present the current fence; `name` must match one of the job's
    /// declared artifact globs. The token's SHA-256 is stored; the token
    /// secret is returned once and expires in 10 minutes.
    pub async fn authorize_artifact_upload(
        &self,
        runner: &RunnerPrincipal,
        job_id: i64,
        fence: &str,
        name: &str,
        size: i64,
        sha256: &str,
    ) -> CoreResult<String> {
        let job = match self.checked_claim(runner, job_id, fence).await? {
            Ok(job) => job,
            Err(ClaimGate::NotFound) => return Err(CoreError::NotFound),
            Err(ClaimGate::FenceMismatch) => {
                return Err(CoreError::Conflict("stale runner fence".into()));
            }
            Err(ClaimGate::Canceled) => {
                return Err(CoreError::Invalid("job is canceled".into()));
            }
        };
        validate_artifact_name(name)?;
        if !(0..=MAX_ARTIFACT_BYTES).contains(&size) {
            return Err(CoreError::Invalid(format!(
                "artifact size {size} exceeds the {MAX_ARTIFACT_BYTES}-byte cap"
            )));
        }
        self.check_artifact_quota(job.repo_id, size).await?;
        let sha256 = sha256.to_ascii_lowercase();
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::Invalid(
                "sha256 must be 64 hex characters".into(),
            ));
        }
        let spec: CiJobSpec = serde_json::from_str(&job.spec)
            .map_err(|_| CoreError::Invalid("job spec is not parseable".into()))?;
        if !spec
            .artifacts
            .iter()
            .any(|glob| artifact_glob_matches(glob, name))
        {
            return Err(CoreError::Forbidden);
        }
        let token = format!("{}{}", ARTIFACT_TOKEN_PREFIX, crypto::random_hex(32));
        db_ci::insert_artifact_token(
            self.db(),
            job.id,
            &crypto::sha256_hex(&token),
            name,
            size,
            &sha256,
            now() + ARTIFACT_TOKEN_TTL_SECS,
            now(),
        )
        .await?;
        Ok(token)
    }

    /// The outstanding artifact token row for `token`, checked against the
    /// job and name and against expiry. Download does not consume the
    /// token; upload does (see [`Core::upload_ci_artifact`]).
    async fn checked_artifact_token(
        &self,
        token: &str,
        job_id: i64,
        name: &str,
    ) -> CoreResult<starforged_db::ci::ArtifactTokenRow> {
        if !token.starts_with(ARTIFACT_TOKEN_PREFIX) {
            return Err(CoreError::Unauthenticated);
        }
        let row = db_ci::artifact_token_by_hash(self.db(), &crypto::sha256_hex(token))
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        if row.job_id != job_id || row.artifact_name != name {
            return Err(CoreError::Forbidden);
        }
        if row.expires_at <= now() {
            return Err(CoreError::Unauthenticated);
        }
        Ok(row)
    }

    /// Uploads one artifact with an authorized one-time token: the token's
    /// `(job, name, size, sha256)` binding must match exactly, the bytes
    /// must hash to the bound SHA-256, and the size cap applies. The bytes
    /// go to the BLAKE3 CAS blob store (refcounts are the `ci_artifacts`
    /// rows per hash), expire after 30 days, and consume the token — a
    /// replay is refused.
    pub async fn upload_ci_artifact(
        &self,
        token: &str,
        job_id: i64,
        name: &str,
        bytes: &[u8],
        sha256: &str,
    ) -> CoreResult<ArtifactView> {
        validate_artifact_name(name)?;
        if bytes.len() as i64 > MAX_ARTIFACT_BYTES {
            return Err(CoreError::Invalid(format!(
                "artifact exceeds the {MAX_ARTIFACT_BYTES}-byte cap"
            )));
        }
        let row = self.checked_artifact_token(token, job_id, name).await?;
        if row.used_at.is_some() {
            return Err(CoreError::Conflict("artifact token already used".into()));
        }
        if row.size != bytes.len() as i64 || row.sha256 != sha256.to_ascii_lowercase() {
            return Err(CoreError::Forbidden);
        }
        use sha2::Digest as _;
        let actual_sha256 = hex::encode(sha2::Sha256::digest(bytes));
        if actual_sha256 != row.sha256 {
            return Err(CoreError::Invalid(
                "artifact bytes do not match the authorized sha256".into(),
            ));
        }
        // The storage quota is checked again with the bytes in hand: tokens
        // authorized in parallel must not together overshoot it.
        let job = db_ci::ci_job_by_id(self.db(), job_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.check_artifact_quota(job.repo_id, bytes.len() as i64)
            .await?;
        let blob = self
            .config()
            .blob_store
            .put(bytes)
            .await
            .map_err(|e| CoreError::Internal(format!("artifact blob store: {e}")))?;
        let artifact = db_ci::insert_artifact(
            self.db(),
            &db_ci::NewArtifact {
                job_id,
                name,
                size: bytes.len() as i64,
                blake3: &blob.hash,
                sha256: Some(&row.sha256),
                expires_at: now() + ARTIFACT_TTL_SECS,
                now: now(),
            },
        )
        .await?;
        if !db_ci::consume_artifact_token(self.db(), row.id, now()).await? {
            return Err(CoreError::Conflict("artifact token already used".into()));
        }
        Ok(ArtifactView::from(artifact))
    }

    /// Downloads one artifact's bytes: the caller presents either an
    /// authorized artifact token for `(job, name)` or the job token of the
    /// executing job ([`JobPrincipal`] built from `ci_jobs`). Expired
    /// artifacts read as missing.
    pub async fn download_ci_artifact(
        &self,
        job_id: i64,
        name: &str,
        download: &ArtifactDownloadAuth,
    ) -> CoreResult<(Vec<u8>, ArtifactView)> {
        validate_artifact_name(name)?;
        match download {
            ArtifactDownloadAuth::Token(token) => {
                self.checked_artifact_token(token, job_id, name).await?;
            }
            ArtifactDownloadAuth::Job(principal) => {
                if principal.job_id != job_id {
                    return Err(CoreError::Forbidden);
                }
            }
        }
        let row = db_ci::artifact_by_name(self.db(), job_id, name, now())
            .await?
            .ok_or(CoreError::NotFound)?;
        let bytes = self
            .config()
            .blob_store
            .get_by_hash(&row.blake3)
            .await
            .map_err(|e| CoreError::Internal(format!("reading artifact blob: {e}")))?;
        Ok((bytes, ArtifactView::from(row)))
    }

    /// Deletes expired artifact rows and collects blobs whose CAS refcount
    /// dropped to zero. Returns the deleted artifact ids.
    pub async fn gc_expired_artifacts(&self) -> CoreResult<Vec<i64>> {
        let expired = db_ci::expired_artifacts(self.db(), now(), 1000).await?;
        let mut ids = Vec::new();
        for row in expired {
            if db_ci::delete_artifact(self.db(), row.id).await?
                && db_ci::artifact_refcount(self.db(), &row.blake3).await? == 0
            {
                let _ = self
                    .config()
                    .blob_store
                    .delete(&starforged_blob::BlobRef {
                        hash: row.blake3.clone(),
                        size: row.size as u64,
                        key: row.blake3.clone(),
                    })
                    .await;
            }
            ids.push(row.id);
        }
        Ok(ids)
    }
}

/// How a caller authenticates an artifact download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactDownloadAuth {
    /// An authorized `sfa_…` artifact token bound to `(job, name)`.
    Token(String),
    /// The executing job's token principal.
    Job(JobPrincipal),
}

// ===== CI secret value-based redaction (M6c C6) =====

/// The sealed box for CI secret values (plan M6 decision 7): XChaCha20-Poly1305
/// under an HKDF key derived from the server `secret_key` with info
/// `"ci-secrets-v1"`. The existing [`CoreConfig`] carries no raw secret-key
/// bytes, so the key material is the already-derived webhook key bytes —
/// itself an HKDF output of `secret_key` — re-derived into the CI domain.
/// `c1:`-prefixed sealed strings. The derived key never renders in `Debug`.
#[derive(Clone)]
pub struct CiSecretBox {
    key: [u8; 32],
}

impl CiSecretBox {
    /// Derives the CI-secret key from the webhook-key bytes (domain-separated
    /// by the `ci-secrets-v1` HKDF info).
    pub fn for_webhook_key(webhook_key: &[u8; 32]) -> Self {
        use ring::hkdf::{HKDF_SHA256, Salt};
        let salt = Salt::new(HKDF_SHA256, b"starforge");
        let prk = salt.extract(webhook_key);
        let mut okm = [0_u8; 32];
        prk.expand(&[b"ci-secrets-v1".as_slice()], HKDF_SHA256)
            .expect("hkdf expand to 32 bytes")
            .fill(&mut okm)
            .expect("hkdf fill of a 32-byte buffer");
        CiSecretBox { key: okm }
    }

    fn cipher(&self) -> chacha20poly1305::XChaCha20Poly1305 {
        use chacha20poly1305::{Key, XChaCha20Poly1305, aead::KeyInit};
        let key = Key::try_from(&self.key[..]).expect("32-byte XChaCha key");
        XChaCha20Poly1305::new(&key)
    }

    /// Seals `plain` with a fresh random nonce. Panics only if the OS random
    /// number generator is unavailable, matching [`crypto::random_hex`].
    pub fn seal(&self, plain: &[u8]) -> String {
        use base64::Engine as _;
        use chacha20poly1305::{
            XNonce,
            aead::{Aead as _, Payload},
        };
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).expect("the OS random number generator is available");
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::try_from(&nonce[..]).expect("24-byte XChaCha nonce"),
                Payload {
                    msg: plain,
                    aad: b"",
                },
            )
            .expect("XChaCha20-Poly1305 encryption does not fail");
        let mut packed = nonce.to_vec();
        packed.extend_from_slice(&ciphertext);
        format!(
            "c1:{}",
            base64::engine::general_purpose::STANDARD.encode(&packed)
        )
    }

    /// Opens a value produced by [`CiSecretBox::seal`]. Any malformed or
    /// tampered input is an error, never a plain fallback.
    pub fn open(&self, sealed: &str) -> CoreResult<Vec<u8>> {
        use base64::Engine as _;
        use chacha20poly1305::{
            XNonce,
            aead::{Aead as _, Payload},
        };
        let b64 = sealed
            .strip_prefix("c1:")
            .ok_or_else(|| CoreError::Invalid("unknown CI secret format".into()))?;
        let packed = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| CoreError::Invalid("corrupt sealed CI secret".into()))?;
        if packed.len() < 24 + 16 {
            return Err(CoreError::Invalid("corrupt sealed CI secret".into()));
        }
        let (nonce, ciphertext) = packed.split_at(24);
        self.cipher()
            .decrypt(
                &XNonce::try_from(nonce)
                    .map_err(|_| CoreError::Invalid("corrupt sealed CI secret".into()))?,
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| CoreError::Invalid("cannot decrypt the sealed CI secret".into()))
    }
}

impl std::fmt::Debug for CiSecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CiSecretBox(<redacted>)")
    }
}

/// Marker written in place of a CI secret value (and every encoded form of
/// it) in session text.
pub const CI_REDACTION: &str = "[redacted]";

/// Percent-encodes every byte outside the unreserved set as uppercase `%XX`.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Every text form a CI secret value can take in a transcript: the exact
/// value, its base64 (standard and URL-safe, padded and unpadded), hex
/// (lower and upper), JSON-string-escaped forms, and URL percent-encoded
/// form. Transcripts are JSONL, so a secret planted in text reaches the
/// stored bytes once-escaped; a secret planted in already-escaped form
/// reaches them twice-escaped (`\"` becomes `\\"`). Successive escaping
/// levels are emitted (three deep: decoded text, one wire decode, two wire
/// decodes). Longest first, so overlapping matches redact the longest span.
pub fn secret_variants(value: &str) -> Vec<String> {
    fn push(out: &mut Vec<String>, candidate: String) {
        if !candidate.is_empty() && !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    let mut out = Vec::new();
    push(&mut out, value.to_owned());
    {
        use base64::Engine as _;
        let std = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        let url = base64::engine::general_purpose::URL_SAFE.encode(value.as_bytes());
        for encoded in [&std, &url] {
            push(&mut out, encoded.clone());
            push(&mut out, encoded.trim_end_matches('=').to_owned());
        }
    }
    let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
    push(&mut out, hex.clone());
    push(&mut out, hex.to_uppercase());
    // Successive JSON-string-escaping levels: each level matches one more
    // layer of JSON encoding between the planted text and the stored bytes.
    let mut escaped = value.to_owned();
    for _ in 0..3 {
        let Ok(json) = serde_json::to_string(&escaped) else {
            break;
        };
        let Some(inner) = json
            .strip_prefix('"')
            .and_then(|text| text.strip_suffix('"'))
        else {
            break;
        };
        push(&mut out, inner.to_owned());
        escaped = inner.to_owned();
    }
    push(&mut out, url_encode(value));
    out.sort_by_key(|variant| std::cmp::Reverse(variant.len()));
    out
}

/// All variants of every value, deduplicated, longest first.
pub fn all_variants(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        for variant in secret_variants(value) {
            if !out.contains(&variant) {
                out.push(variant);
            }
        }
    }
    out.sort_by_key(|variant| std::cmp::Reverse(variant.len()));
    out
}

/// The longest variant length across `values` (0 when empty): the overlap
/// window a newly ingested segment needs from its predecessor.
pub fn ci_variant_len(values: &[String]) -> usize {
    all_variants(values)
        .iter()
        .map(|variant| variant.len())
        .max()
        .unwrap_or(0)
}

/// Replaces every CI secret value (exact + base64/URL-encoded/hex/JSON-escaped
/// forms) in `text` with [`CI_REDACTION`].
pub fn redact_ci_secrets(text: &str, values: &[String]) -> String {
    let mut out = text.to_owned();
    for variant in all_variants(values) {
        if out.contains(&variant) {
            out = out.replace(&variant, CI_REDACTION);
        }
    }
    out
}

/// Like [`redact_ci_secrets`], except it also redacts values split across the
/// boundary between the previous segment's tail (`prev_tail`, the last
/// [`ci_variant_len`] bytes of the predecessor) and `text`: any variant
/// occurring across that boundary has its in-`text` portion redacted. Each
/// segment stands alone afterwards — no single stored segment, page, search
/// preview, or index entry ever carries the value, and the concatenation of
/// rendered text cannot re-derive it across the seam either.
pub fn redact_ci_secrets_with_history(text: &str, prev_tail: &str, values: &[String]) -> String {
    if prev_tail.is_empty() {
        return redact_ci_secrets(text, values);
    }
    let tail_len = prev_tail.len();
    let mut adjusted = text.to_owned();
    for variant in all_variants(values) {
        let combined = format!("{prev_tail}{adjusted}");
        let mut spans = Vec::new();
        for (start, _) in combined.match_indices(variant.as_str()) {
            let end = start + variant.len();
            if start < tail_len && end > tail_len {
                spans.push((start, end));
            }
        }
        // Rightmost first, so earlier positions stay valid as ranges shift.
        for (start, end) in spans.into_iter().rev() {
            let local_start = start.saturating_sub(tail_len);
            let local_end = (end - tail_len).min(adjusted.len());
            if local_start < local_end
                && adjusted.is_char_boundary(local_start)
                && adjusted.is_char_boundary(local_end)
            {
                adjusted.replace_range(local_start..local_end, CI_REDACTION);
            }
        }
    }
    redact_ci_secrets(&adjusted, values)
}

impl Core {
    /// Seals one CI secret value for storage in `ci_secrets.sealed_value`
    /// (C3's create/rotate path calls this; tests seal fixtures with it).
    pub fn seal_ci_secret(&self, value: &str) -> String {
        CiSecretBox::for_webhook_key(&self.config().webhook_key.0).seal(value.as_bytes())
    }

    /// Opens a sealed CI secret value in memory. Tries the CI box first,
    /// then the mirror-credential box, then the webhook box, so values
    /// sealed under any of the server boxes open. The plaintext is returned
    /// to the caller only; it is never logged.
    pub fn open_ci_secret(&self, sealed: &str) -> CoreResult<String> {
        let bytes = CiSecretBox::for_webhook_key(&self.config().webhook_key.0)
            .open(sealed)
            .or_else(|_| self.config().credential_box.open(sealed))
            .or_else(|_| {
                crate::webhooks::open_secret(&self.config().webhook_key.0, sealed)
                    .map(|text| text.into_bytes())
            })?;
        String::from_utf8(bytes)
            .map_err(|_| CoreError::Internal("decrypted CI secret is not UTF-8".into()))
    }

    /// The in-memory plaintext values of every redaction-enabled secret
    /// resolved for `job_id` (`ci_job_secrets -> ci_secrets`). Undecryptable
    /// rows are skipped. A missing secrets schema (migration 0038 not yet
    /// applied) yields no values rather than an error, so ingest never
    /// breaks on it.
    pub async fn ci_secret_values_for_job(&self, job_id: i64) -> Vec<String> {
        let rows = match db_ci::job_secrets_for_job(self.db(), job_id).await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::debug!(job_id, error = %err, "CI secret resolution unavailable");
                return Vec::new();
            }
        };
        let mut values = Vec::new();
        for row in rows {
            if !row.redact_in_sessions {
                continue;
            }
            match self.open_ci_secret(&row.sealed_value) {
                Ok(value) if !value.is_empty() => values.push(value),
                _ => {}
            }
        }
        values
    }

    /// The in-memory plaintext values for the secrets of the job that
    /// uploaded `session_id` (`sessions.ci_job_id`), empty for non-CI
    /// sessions.
    pub async fn ci_secret_values_for_session(&self, session_id: i64) -> Vec<String> {
        let Some(job_id) = db_ci::session_ci_job_id(self.db(), session_id)
            .await
            .unwrap_or(None)
        else {
            return Vec::new();
        };
        self.ci_secret_values_for_job(job_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starforged_db::ci::{NewCiJob, NewCiJobToken, NewRunner};

    use crate::accounts::User;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::{test_core, user};

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct Seeded {
        runner_secret: String,
        job_secret: String,
        runner_id: i64,
        job_id: i64,
        repo_id: i64,
    }

    async fn seed(core: &Core, alice: &User) -> Seeded {
        let repo = core
            .create_repo(
                alice,
                "alice",
                CreateRepo {
                    name: "proj".into(),
                    description: String::new(),
                    visibility: Visibility::Private,
                    readme: false,
                },
            )
            .await
            .unwrap();
        seed_jobs(core, alice, repo.id, SHA).await
    }

    async fn seed_jobs(core: &Core, alice: &User, repo_id: i64, sha: &str) -> Seeded {
        let now_ts = now();
        let runner_secret = format!("{RUNNER_TOKEN_PREFIX}{}", crypto::random_hex(32));
        let runner = db_ci::insert_runner(
            core.db(),
            &NewRunner {
                repo_id,
                name: "r1",
                token_hash: &crypto::sha256_hex(&runner_secret),
                token_hint: &runner_secret[runner_secret.len() - 4..],
                labels: r#"["linux"]"#,
                ephemeral: false,
                max_concurrent: 1,
                version: "1.0",
                now: now_ts,
            },
        )
        .await
        .unwrap();
        let job = db_ci::insert_ci_job(
            core.db(),
            &NewCiJob {
                repo_id,
                trail_id: None,
                change_id: None,
                revision_id: None,
                commit_sha: sha,
                base_sha: None,
                job_name: "test",
                spec: "{}",
                run_at: now_ts,
                deadline: now_ts + 3600,
                created_by: Some(alice.id),
                now: now_ts,
            },
        )
        .await
        .unwrap();
        // Claim it so the job token is live: only claimed/running accept.
        let claimed = db_ci::claim_next_ci_job(
            core.db(),
            runner.id,
            repo_id,
            now_ts,
            60,
            "fence-test",
            now_ts + 3600,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(claimed.id, job.id);
        let job_secret = format!("{JOB_TOKEN_PREFIX}{}", crypto::random_hex(32));
        db_ci::insert_job_token(
            core.db(),
            &NewCiJobToken {
                job_id: job.id,
                token_hash: &crypto::sha256_hex(&job_secret),
                token_hint: &job_secret[job_secret.len() - 4..],
                expires_at: now_ts + 3600 + 600,
                now: now_ts,
            },
        )
        .await
        .unwrap();
        Seeded {
            runner_secret,
            job_secret,
            runner_id: runner.id,
            job_id: job.id,
            repo_id,
        }
    }

    #[tokio::test]
    async fn runner_token_auth_resolves_and_touches() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let s = seed(&core, &alice).await;
        let principal = core.authenticate_runner(&s.runner_secret).await.unwrap();
        assert_eq!(principal.runner_id, s.runner_id);
        assert_eq!(principal.repo_id, s.repo_id);
        assert_eq!(principal.labels, vec!["linux".to_owned()]);
        // Wrong prefixes never resolve as runners.
        assert!(matches!(
            core.authenticate_runner(&s.job_secret).await,
            Err(CoreError::Unauthenticated)
        ));
        assert!(matches!(
            core.authenticate_runner("sfr_unknown").await,
            Err(CoreError::Unauthenticated)
        ));
        assert!(matches!(
            core.authenticate_runner("sfp_whatever").await,
            Err(CoreError::Unauthenticated)
        ));
        // A revoked runner stops authenticating.
        db_ci::revoke_runner(core.db(), s.runner_id, now())
            .await
            .unwrap();
        assert!(matches!(
            core.authenticate_runner(&s.runner_secret).await,
            Err(CoreError::Unauthenticated)
        ));
    }

    #[tokio::test]
    async fn job_token_auth_resolves_capped_principal() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let s = seed(&core, &alice).await;
        let principal = core.authenticate_job(&s.job_secret).await.unwrap();
        assert_eq!(
            principal,
            JobPrincipal {
                job_id: s.job_id,
                user_id: alice.id,
                repo_id: s.repo_id,
                commit_sha: SHA.to_owned(),
            }
        );
        // No cross-kind confusion.
        assert!(matches!(
            core.authenticate_job(&s.runner_secret).await,
            Err(CoreError::Unauthenticated)
        ));
        // A canceled job's token is dead.
        db_ci::cancel_ci_job(core.db(), s.job_id, None, now())
            .await
            .unwrap();
        assert!(matches!(
            core.authenticate_job(&s.job_secret).await,
            Err(CoreError::Unauthenticated)
        ));
    }

    #[tokio::test]
    async fn job_token_dies_with_user_access() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        // Bob only has read on Alice's private repo; the job is his.
        let repo = core
            .create_repo(
                &alice,
                "alice",
                CreateRepo {
                    name: "proj".into(),
                    description: String::new(),
                    visibility: Visibility::Private,
                    readme: false,
                },
            )
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        let s = seed_jobs(&core, &bob, repo.id, SHA).await;
        assert!(core.authenticate_job(&s.job_secret).await.is_ok());
        // Losing the collaborator grant revokes the job's tokens terminally.
        core.remove_collaborator(&alice, "alice", "proj", "bob")
            .await
            .unwrap();
        assert!(matches!(
            core.authenticate_job(&s.job_secret).await,
            Err(CoreError::Unauthenticated)
        ));
        // Even a re-grant does not revive it.
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        assert!(matches!(
            core.authenticate_job(&s.job_secret).await,
            Err(CoreError::Unauthenticated)
        ));
    }

    #[tokio::test]
    async fn submit_ci_status_is_capped_to_job_commit() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let s = seed(&core, &alice).await;
        let principal = core.authenticate_job(&s.job_secret).await.unwrap();
        let dto = core
            .submit_ci_status(
                &principal,
                SHA,
                "success",
                "ci/test",
                None,
                Some("all green"),
            )
            .await
            .unwrap();
        assert_eq!((dto.sha.as_str(), dto.state.as_str()), (SHA, "success"));
        assert_eq!(dto.creator_handle.as_deref(), Some("alice"));
        // Another commit is outside the principal.
        assert!(matches!(
            core.submit_ci_status(
                &principal,
                &"b".repeat(40),
                "success",
                "ci/test",
                None,
                None
            )
            .await,
            Err(CoreError::Forbidden)
        ));
        // Another job's context is outside the principal, even on the job's
        // own commit: writing it would satisfy that job's gate.
        assert!(matches!(
            core.submit_ci_status(&principal, SHA, "success", "ci/other", None, None)
                .await,
            Err(CoreError::Forbidden)
        ));
        // An archived repo refuses CI submissions.
        starforged_db::repos::set_archived(core.db(), s.repo_id, Some(now()))
            .await
            .unwrap();
        assert!(matches!(
            core.submit_ci_status(&principal, SHA, "success", "ci/test", None, None)
                .await,
            Err(CoreError::Invalid(_))
        ));
    }
    fn meta(ulid: &str) -> serde_json::Value {
        serde_json::json!({
            "format": "starforge.session/v1",
            "id": ulid,
            "agent": {"name": "claude-code", "version": "1.0"},
            "models": ["opus"],
            "title": "ci session",
            "started_at": "2026-11-04T00:00:00Z",
            "ended_at": null,
            "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "parent_id": null,
            "usage": {"input": 1, "output": 2, "cache_read": 3, "cache_write": 4, "reasoning": 5},
            "files_touched": ["src/main.rs"],
            "redaction": {"fingerprint": "fp-test", "counts": {}},
            "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
        })
    }

    fn segment(lines: &[String]) -> (Vec<u8>, String) {
        let mut jsonl = lines.join("\n");
        jsonl.push('\n');
        let bytes = starforge_format::compress(jsonl.as_bytes());
        let hash = starforge_format::blake3_hex(&bytes);
        (bytes, hash)
    }

    const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB0";

    #[tokio::test]
    async fn job_upload_binds_session_and_denies_cross_job() {
        use crate::ingest::{IngestAuth, SegmentPut};

        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let s = seed(&core, &alice).await;
        let principal = core.authenticate_job(&s.job_secret).await.unwrap();
        let auth = core
            .authorize_job_upload(&principal, "alice", "proj")
            .await
            .unwrap();
        assert!(matches!(&auth, IngestAuth::CiJob(principal) if principal.job_id == s.job_id));
        // The job uploads its session; the uploader is the triggering user
        // and the row is bound to the job.
        let (row, created) = core
            .upsert_session_meta(&auth, ULID, &meta(ULID))
            .await
            .unwrap();
        assert!(created);
        assert_eq!(row.uploader_id, alice.id);
        let bound: Option<i64> = sqlx::query_scalar("SELECT ci_job_id FROM sessions WHERE id = $1")
            .bind(row.id)
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(bound, Some(s.job_id));
        let (bytes, hash) = segment(&[String::from(
            r#"{"v":1,"seq":0,"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"hi"}"#,
        )]);
        assert!(matches!(
            core.put_segment(&auth, ULID, 0, &bytes, Some(hash))
                .await
                .unwrap(),
            SegmentPut::Stored(_)
        ));
        core.complete_session(&auth, ULID).await.unwrap();
        // A different repository is outside the principal, even though the
        // triggering user owns it.
        core.create_repo(
            &alice,
            "alice",
            CreateRepo {
                name: "other".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            core.authorize_job_upload(&principal, "alice", "other")
                .await,
            Err(CoreError::Forbidden)
        ));
        // A second job of the same repo cannot write the first job's session.
        let second = seed_jobs(&core, &alice, s.repo_id, &"c".repeat(40)).await;
        let other = core.authenticate_job(&second.job_secret).await.unwrap();
        assert_ne!(other.job_id, s.job_id);
        let other_auth = core
            .authorize_job_upload(&other, "alice", "proj")
            .await
            .unwrap();
        assert!(matches!(
            core.upsert_session_meta(&other_auth, ULID, &meta(ULID))
                .await,
            Err(CoreError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn git_credential_mints_short_lived_and_revokes() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let s = seed(&core, &alice).await;
        let principal = core.authenticate_job(&s.job_secret).await.unwrap();
        let minted = core.mint_git_credential(&principal).await.unwrap();
        assert!(minted.secret.starts_with(tokens::TOKEN_PREFIX));
        let job = db_ci::ci_job_by_id(core.db(), s.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.git_token_id, Some(minted.token_id));
        // The credential is a working repo-scoped PAT...
        assert!(
            core.authenticate_token(&minted.secret)
                .await
                .is_ok_and(|auth| auth.user.id == alice.id)
        );
        // ...and job credential revocation kills both the git PAT and the
        // job tokens.
        core.revoke_job_credentials(s.job_id).await.unwrap();
        assert!(matches!(
            core.authenticate_token(&minted.secret).await,
            Err(CoreError::Unauthenticated)
        ));
        assert!(matches!(
            core.authenticate_job(&s.job_secret).await,
            Err(CoreError::Unauthenticated)
        ));
    }

    #[test]
    fn ci_secret_box_round_trips_and_debug_redacts() {
        let bx = CiSecretBox::for_webhook_key(&[7_u8; 32]);
        let sealed = bx.seal(b"ci-secret-value");
        assert!(sealed.starts_with("c1:"), "{sealed}");
        assert_eq!(bx.open(&sealed).unwrap(), b"ci-secret-value");
        // Flip exactly one ciphertext character to a different value (the
        // nonce is random, so a fixed replacement is a no-op 1 time in 64).
        let flipped = if &sealed[3..4] == "A" { "B" } else { "A" };
        let tampered = format!("{}{flipped}{}", &sealed[..3], &sealed[4..]);
        assert!(bx.open(&tampered).is_err());
        assert_eq!(format!("{bx:?}"), "CiSecretBox(<redacted>)");
    }

    #[test]
    fn redact_ci_secrets_covers_all_forms() {
        let secret = "Sk-live\"9f3A\\!@#";
        let values = vec![secret.to_owned()];
        let variants = secret_variants(secret);
        assert!(variants.contains(&secret.to_owned()));
        let text = variants
            .iter()
            .map(|variant| format!("x {variant} y"))
            .collect::<Vec<_>>()
            .join("\n");
        let redacted = redact_ci_secrets(&text, &values);
        for variant in &variants {
            assert!(!redacted.contains(variant), "leaked {variant:?}");
        }
        assert!(redacted.contains(CI_REDACTION));
        assert_eq!(redacted.matches(CI_REDACTION).count(), variants.len());
    }

    #[test]
    fn redact_ci_secrets_with_history_covers_split_values() {
        let secret = "twelve-character-secret";
        let values = vec![secret.to_owned()];
        let split_at = 9;
        // Head of the value at the end of the previous segment, tail at the
        // start of the next: only the in-segment portion is redacted, but
        // neither side carries the full value afterwards.
        let redacted = redact_ci_secrets_with_history(
            &format!("{} tail rest", &secret[split_at..]),
            &format!("head {}", &secret[..split_at]),
            &values,
        );
        assert!(!redacted.contains(secret), "{redacted}");
        assert!(!redacted.contains(&secret[split_at..]), "{redacted}");
        // Unsplitted occurrences in the same segment redact as usual.
        let redacted = redact_ci_secrets_with_history(&format!("a {secret} b"), "", &values);
        assert!(!redacted.contains(secret), "{redacted}");
        assert!(redacted.contains(CI_REDACTION));
    }

    #[test]
    fn ci_variant_len_is_longest_variant() {
        let values = vec!["abc".to_owned(), "longer-secret".to_owned()];
        assert!(ci_variant_len(&values) >= "longer-secret".len());
        assert_eq!(ci_variant_len(&[]), 0);
    }

    #[tokio::test]
    async fn ci_secret_seal_open_round_trip_and_tamper() {
        let (core, _f) = test_core().await;
        let sealed = core.seal_ci_secret("super-secret-value");
        assert!(sealed.starts_with("c1:"), "{sealed}");
        assert!(
            !sealed.contains("super-secret-value"),
            "no plaintext at rest"
        );
        assert_eq!(core.open_ci_secret(&sealed).unwrap(), "super-secret-value");
        // Tampering is an error, never a plaintext fallback.
        let tampered = format!("{}A", &sealed[..sealed.len() - 1]);
        assert!(core.open_ci_secret(&tampered).is_err());
        assert!(core.open_ci_secret("not-sealed").is_err());
        // The mirror box keys differently (domain separation).
        let mirror_sealed = core.config().credential_box.seal(b"v");
        assert!(
            CiSecretBox::for_webhook_key(&core.config().webhook_key.0)
                .open(&mirror_sealed)
                .is_err()
        );
    }

    #[test]
    fn artifact_name_and_glob_rules() {
        assert!(validate_artifact_name("out.bin").is_ok());
        assert!(validate_artifact_name("target/debug/app").is_ok());
        for bad in [
            "../evil", "a/../b", "/abs", "a//b", "a/./b", "", "a b", "a\\b",
        ] {
            assert!(validate_artifact_name(bad).is_err(), "{bad}");
        }
        assert!(artifact_glob_matches("target/**", "target/debug/app"));
        assert!(artifact_glob_matches("*.bin", "out.bin"));
        assert!(!artifact_glob_matches("*.bin", "a/b.bin"));
        assert!(artifact_glob_matches("out.bin", "out.bin"));
        assert!(!artifact_glob_matches("out.bin", "other.bin"));
    }

    #[test]
    fn secret_name_rule_matches_spec() {
        assert!(validate_secret_name("CARGO_REGISTRY_TOKEN").is_ok());
        assert!(validate_secret_name("has-dash").is_err());
        assert!(validate_secret_name("").is_err());
        assert!(validate_secret_name(&"A".repeat(129)).is_err());
    }

    #[test]
    fn bind_host_and_header_rules() {
        for ok in [
            "",
            "api.example.com",
            "api.example.com:8443",
            "127.0.0.1",
            "127.0.0.1:3128",
            "localhost",
            "[::1]",
            "[::1]:8443",
            "api.example.com.",
        ] {
            assert!(validate_bind_host(ok).is_ok(), "{ok}");
        }
        for bad in [
            "has space.com",
            "api.example.com:0",
            "api.example.com:65536",
            "api.example.com:notaport",
            "-bad-.com",
            "bad..com",
            "https://api.example.com",
            "[::1",
        ] {
            assert!(validate_bind_host(bad).is_err(), "{bad}");
        }
        for ok in ["", "Authorization", "X-Auth-Token", "x_api.key~1"] {
            assert!(validate_bind_header(ok).is_ok(), "{ok}");
        }
        for bad in ["has space", "colon: here", "(paren)", "under_score,comma"] {
            assert!(validate_bind_header(bad).is_err(), "{bad}");
        }
    }
}
