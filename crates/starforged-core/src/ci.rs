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
    checks as db_checks, ci as db_ci, now, repos as db_repos, tokens as db_tokens,
};

use crate::checks::{StatusDto, status_dto, validate_status};
use crate::permission::Permission;
use crate::repos::to_repo;
use crate::tokens::{self, Scope, format_scopes};
use crate::webhooks::HookEvent;
use crate::{Core, CoreError, CoreResult, crypto};

/// Bearer prefix of a runner auth token (stored only as SHA-256).
pub const RUNNER_TOKEN_PREFIX: &str = "sfr_";
/// Bearer prefix of a per-job token (stored only as SHA-256).
pub const JOB_TOKEN_PREFIX: &str = "sfj_";

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
