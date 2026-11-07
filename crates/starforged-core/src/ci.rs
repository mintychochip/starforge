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
    checks as db_checks, ci as db_ci, now, repos as db_repos, sessions as db_sessions,
    tokens as db_tokens,
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
            if let Some(fence) = job.lease_token.as_deref() {
                db_ci::release_ci_job(self.db(), job.id, fence).await?;
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

    /// Claims the oldest due queued job of the runner's repository
    /// (decision 13): `state = 'claimed'` under a fresh per-claim
    /// `lease_token` fence, and mints the per-job token (`sfj_…`, expiry
    /// `deadline + 600`) the execution will act with. A job whose
    /// `runs_on` labels are a non-empty set that is not a subset of the
    /// runner's labels is released back to `queued` and the next job is
    /// tried (at most [`Core::CLAIM_MAX_ATTEMPTS`] claims); a job with an
    /// unparseable spec is released the same way. `None` when no job can
    /// be claimed for this runner.
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
            let job_token = format!("{}{}", JOB_TOKEN_PREFIX, crypto::random_hex(32));
            let hint = &job_token[job_token.len() - 4..];
            db_ci::insert_job_token(
                self.db(),
                &db_ci::NewCiJobToken {
                    job_id: job.id,
                    token_hash: &crypto::sha256_hex(&job_token),
                    token_hint: hint,
                    expires_at: job.deadline + 600,
                    now: now_ts,
                },
            )
            .await?;
            return Ok(Some(ClaimedCiJob {
                job_id: job.id,
                job_name: job.job_name.clone(),
                commit_sha: job.commit_sha.clone(),
                spec,
                lease_until: job.lease_until.unwrap_or(now_ts + Self::CLAIM_LEASE_SECS),
                fence,
                job_token,
                deadline: job.deadline,
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
            if job.state != "canceled" {
                db_ci::cancel_ci_job(self.db(), job_id, Some(fence), now()).await?;
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
        // executing it); later traces keep the state.
        db_ci::set_ci_job_running(self.db(), job_id, fence).await?;
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
        if !db_ci::request_cancel_ci_job(self.db(), job_id, now()).await? {
            return Err(CoreError::NotFound);
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
        let claimed =
            db_ci::claim_next_ci_job(core.db(), runner.id, repo_id, now_ts, 60, "fence-test")
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
}
