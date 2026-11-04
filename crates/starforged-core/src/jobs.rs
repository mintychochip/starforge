//! Background jobs (forge-basics design §8): a durable queue in the `jobs` table, run by workers inside
//! `starforged serve`. Tests run due jobs directly with [`Core::run_due_jobs`].

use std::time::Duration;

use serde::{Deserialize, Serialize};
use starforged_db::jobs::{self, NewJob};
use starforged_db::{now, web_sessions};

use crate::mail::Email;
use crate::{Core, CoreError, CoreResult};

/// A job is tried this many times before it is marked `failed`.
pub const MAX_ATTEMPTS: i64 = 5;
/// How long a claimed job may run before its worker is presumed dead and the job is queued again.
pub const LEASE_SECS: i64 = 600;
/// Idle workers look for due jobs this often; enqueueing wakes one immediately.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

/// Delay before the next attempt after `attempts` failed ones, or `None` when all [`MAX_ATTEMPTS`] are used.
pub fn retry_delay(attempts: i64) -> Option<i64> {
    match attempts {
        1 => Some(60),
        2 => Some(300),
        3 => Some(1_800),
        4 => Some(7_200),
        _ => None,
    }
}

/// Everything a worker can run, stored as JSON in `jobs.payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Job {
    /// Hourly housekeeping: expired web sessions and, from later tasks, other expired rows.
    HourlyCleanup,
    /// Daily: deletes `done` jobs after 7 days and `failed` jobs after 30.
    DailyPrune,
    /// One email. The worker blanks `body` once it is sent: links in it carry secrets.
    SendEmail {
        to: String,
        subject: String,
        body: String,
    },
}

impl Job {
    /// The `jobs.kind` column; equal to the payload's `kind` tag.
    pub fn kind(&self) -> &'static str {
        match self {
            Job::HourlyCleanup => "hourly_cleanup",
            Job::DailyPrune => "daily_prune",
            Job::SendEmail { .. } => "send_email",
        }
    }

    /// How often a recurring job runs. Recurring jobs use their kind as the deduplication key, so at most one
    /// copy is pending.
    fn recurrence(&self) -> Option<i64> {
        match self {
            Job::HourlyCleanup => Some(HOUR),
            Job::DailyPrune => Some(DAY),
            Job::SendEmail { .. } => None,
        }
    }
}

impl Core {
    /// Queues `job` to run now.
    pub async fn enqueue(&self, job: &Job) -> CoreResult<()> {
        self.enqueue_at(job, now()).await
    }

    /// Queues `job` to run at `run_at` (unix seconds). A recurring job that is already pending is left alone.
    pub async fn enqueue_at(&self, job: &Job, run_at: i64) -> CoreResult<()> {
        let payload = serde_json::to_string(job).map_err(|e| CoreError::Internal(e.to_string()))?;
        let dedupe_key = job.recurrence().map(|_| job.kind());
        jobs::insert(
            self.db(),
            &NewJob {
                kind: job.kind(),
                payload: &payload,
                dedupe_key,
                run_at,
            },
        )
        .await?;
        self.inner.job_wakeup.notify_one();
        Ok(())
    }

    /// Runs every due job in this task and returns how many ran. `serve` uses workers; tests call this.
    pub async fn run_due_jobs(&self) -> CoreResult<usize> {
        let mut ran = 0;
        while self.run_one_job().await? {
            ran += 1;
        }
        Ok(ran)
    }

    /// Claims and runs one due job; `false` when none is due.
    async fn run_one_job(&self) -> CoreResult<bool> {
        let start = now();
        jobs::requeue_expired(self.db(), start, MAX_ATTEMPTS).await?;
        let Some(row) = jobs::claim_next(self.db(), start, LEASE_SECS).await? else {
            return Ok(false);
        };
        let job = serde_json::from_str::<Job>(&row.payload);
        let outcome = match &job {
            Ok(job) => self.execute(row.id, job).await,
            Err(err) => Err(CoreError::Internal(format!(
                "unreadable job payload: {err}"
            ))),
        };
        let finished = match outcome {
            Ok(()) => {
                jobs::complete(self.db(), row.id).await?;
                true
            }
            Err(err) => {
                // A payload that cannot be read will not become readable later.
                let retry_at = if job.is_ok() {
                    retry_delay(row.attempts).map(|delay| now() + delay)
                } else {
                    None
                };
                tracing::warn!(job = row.id, kind = %row.kind, attempts = row.attempts, error = %err, "job failed");
                jobs::fail(self.db(), row.id, &err.to_string(), retry_at).await?;
                retry_at.is_none()
            }
        };
        // A recurring job schedules its next run once it is finished, whether it succeeded or gave up.
        if finished
            && let Ok(job) = &job
            && let Some(interval) = job.recurrence()
        {
            self.enqueue_at(job, now() + interval).await?;
        }
        Ok(true)
    }

    async fn execute(&self, id: i64, job: &Job) -> CoreResult<()> {
        match job {
            Job::HourlyCleanup => self.hourly_cleanup().await,
            Job::DailyPrune => {
                let ts = now();
                jobs::prune(self.db(), ts - 7 * DAY, ts - 30 * DAY).await?;
                Ok(())
            }
            Job::SendEmail { to, subject, body } => {
                let mailer = self
                    .config()
                    .mailer
                    .as_ref()
                    .ok_or_else(|| CoreError::Internal("mail is not configured".into()))?;
                mailer
                    .send(&Email {
                        to: to.clone(),
                        subject: subject.clone(),
                        body: body.clone(),
                    })
                    .await?;
                self.blank_email(id, to, subject).await
            }
        }
    }

    async fn hourly_cleanup(&self) -> CoreResult<()> {
        let ts = now();
        web_sessions::delete_expired(self.db(), ts).await?;
        starforged_db::email_tokens::delete_expired(self.db(), ts).await?;
        starforged_db::invites::delete_expired_before(self.db(), ts - 30 * DAY).await?;
        // Every link in a message is dead 7 days after it was sent (invites live longest), so a failed
        // message's body is kept no longer than that.
        for row in jobs::failed_of_kind_before(self.db(), "send_email", ts - 7 * DAY).await? {
            if let Ok(Job::SendEmail { to, subject, body }) =
                serde_json::from_str::<Job>(&row.payload)
                && !body.is_empty()
            {
                self.blank_email(row.id, &to, &subject).await?;
            }
        }
        Ok(())
    }

    /// Replaces a message's body with nothing, keeping the recipient and subject for the admin Jobs page.
    async fn blank_email(&self, id: i64, to: &str, subject: &str) -> CoreResult<()> {
        let blank = Job::SendEmail {
            to: to.to_owned(),
            subject: subject.to_owned(),
            body: String::new(),
        };
        let payload =
            serde_json::to_string(&blank).map_err(|e| CoreError::Internal(e.to_string()))?;
        jobs::set_payload(self.db(), id, &payload).await?;
        Ok(())
    }

    async fn worker(self) {
        loop {
            match self.run_one_job().await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => tracing::error!(error = %err, "job worker"),
            }
            tokio::select! {
                () = self.inner.job_wakeup.notified() => {}
                () = tokio::time::sleep(POLL_INTERVAL) => {}
            }
        }
    }
}

/// Queues the recurring jobs (when none is pending) and starts `count` workers on the current runtime.
pub async fn start_workers(core: &Core, count: usize) -> CoreResult<()> {
    for job in [Job::HourlyCleanup, Job::DailyPrune] {
        core.enqueue(&job).await?;
    }
    for _ in 0..count {
        tokio::spawn(core.clone().worker());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use starforged_db::web_sessions::NewWebSession;

    use super::*;
    use crate::testing::{test_core, user};

    #[test]
    fn payloads_are_tagged_with_the_kind() {
        for job in [Job::HourlyCleanup, Job::DailyPrune] {
            let json = serde_json::to_string(&job).unwrap();
            assert_eq!(json, format!(r#"{{"kind":"{}"}}"#, job.kind()));
            assert_eq!(serde_json::from_str::<Job>(&json).unwrap(), job);
        }
    }

    #[test]
    fn retries_back_off_then_stop() {
        let delays: Vec<Option<i64>> = (1..=MAX_ATTEMPTS).map(retry_delay).collect();
        assert_eq!(
            delays,
            vec![Some(60), Some(300), Some(1_800), Some(7_200), None]
        );
    }

    #[tokio::test]
    async fn recurring_jobs_run_then_reschedule() {
        let (core, _f) = test_core().await;
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        assert_eq!(
            core.run_due_jobs().await.unwrap(),
            1,
            "one pending copy per recurring kind"
        );
        assert_eq!(
            core.run_due_jobs().await.unwrap(),
            0,
            "the next run is an hour away"
        );
        let rows: Vec<(String, i64)> = sqlx::query_as("SELECT state, run_at FROM jobs ORDER BY id")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "done");
        assert_eq!(rows[1].0, "queued");
        assert!(rows[1].1 >= now() + 3_600 - 5, "next run at {}", rows[1].1);
    }

    #[tokio::test]
    async fn hourly_cleanup_removes_expired_sessions() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        for (hash, expires_at) in [("old", 10), ("current", now() + 3_600)] {
            web_sessions::insert(
                core.db(),
                &NewWebSession {
                    session_hash: hash,
                    user_id: alice.id,
                    csrf_token: "csrf",
                    expires_at,
                    user_agent: "",
                    ip: "",
                },
            )
            .await
            .unwrap();
        }
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let left: Vec<String> = sqlx::query_scalar("SELECT session_hash FROM web_sessions")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        assert_eq!(left, vec!["current".to_owned()]);
    }
    #[tokio::test]
    async fn hourly_cleanup_deletes_expired_email_tokens() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        for (purpose, token_hash, expires_at) in [
            ("verify_email", "expired", 10),
            ("reset_password", "live", now() + 3_600),
        ] {
            starforged_db::email_tokens::replace(
                core.db(),
                &starforged_db::email_tokens::NewEmailToken {
                    user_id: alice.id,
                    purpose,
                    token_hash,
                    email: "alice@example.com",
                    expires_at,
                },
            )
            .await
            .unwrap();
        }
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let left: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM email_tokens")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        assert_eq!(left, vec!["live".to_owned()]);
    }

    #[tokio::test]
    async fn unreadable_payloads_fail_without_retrying() {
        let (core, _f) = test_core().await;
        jobs::insert(
            core.db(),
            &NewJob {
                kind: "mystery",
                payload: r#"{"kind":"mystery"}"#,
                dedupe_key: None,
                run_at: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(core.run_due_jobs().await.unwrap(), 1);
        let (state, error): (String, String) = sqlx::query_as("SELECT state, last_error FROM jobs")
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(state, "failed");
        assert!(error.contains("unreadable job payload"), "{error}");
    }

    #[tokio::test]
    async fn workers_run_due_jobs_in_the_background() {
        let (core, _f) = test_core().await;
        start_workers(&core, 2).await.unwrap();
        for _ in 0..100 {
            let done: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE state = 'done'")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
            if done == 2 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("the workers did not run the two recurring jobs");
    }

    #[tokio::test]
    async fn hourly_cleanup_blanks_week_old_failed_mail() {
        let (core, _f) = test_core().await;
        let message = Job::SendEmail {
            to: "a@example.com".into(),
            subject: "Hello".into(),
            body: "a secret link".into(),
        };
        core.enqueue(&message).await.unwrap();
        core.enqueue(&message).await.unwrap();
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM jobs ORDER BY id")
            .fetch_all(core.db().pool())
            .await
            .unwrap();
        for (id, failed_at) in [(ids[0], now() - 8 * DAY), (ids[1], now() - DAY)] {
            sqlx::query("UPDATE jobs SET state = 'failed', updated_at = $1 WHERE id = $2")
                .bind(failed_at)
                .bind(id)
                .execute(core.db().pool())
                .await
                .unwrap();
        }
        core.enqueue(&Job::HourlyCleanup).await.unwrap();
        core.run_due_jobs().await.unwrap();
        let mut bodies = Vec::new();
        for id in ids {
            let payload: String = sqlx::query_scalar("SELECT payload FROM jobs WHERE id = $1")
                .bind(id)
                .fetch_one(core.db().pool())
                .await
                .unwrap();
            match serde_json::from_str::<Job>(&payload).unwrap() {
                Job::SendEmail { body, .. } => bodies.push(body),
                other => panic!("unexpected job {other:?}"),
            }
        }
        assert_eq!(bodies, vec![String::new(), "a secret link".to_owned()]);
    }
}
