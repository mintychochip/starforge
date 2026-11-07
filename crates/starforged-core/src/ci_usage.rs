//! CI usage and quotas by supplier (M6). Each source of CI compute for a
//! repository is a supplier, and whoever runs the compute owns its usage
//! and its limits:
//!
//! - `native`: Starforge's own registered runners. Starforge meters every
//!   job attempt (runner wall-clock time, recorded in `ci_usage` when the
//!   attempt ends) and the repository's unexpired artifacts, and enforces
//!   the operator's `[ci.limits]`: minutes per calendar month when a run is
//!   queued, artifact storage when an upload is authorized.
//! - `depot`: a repository linked to a Depot organization. Depot meters and
//!   enforces its own plan allowances and usage caps; Starforge reads the
//!   linked repository's usage from Depot's `UsageService.GetUsage` and
//!   never blocks Depot work. Depot's API exposes no limits, so its report
//!   carries none.
//!
//! Periods are calendar months in UTC.

use serde::{Deserialize, Serialize};
use starforged_db::{checks as db_checks, ci as db_ci, now};
use time::OffsetDateTime;

use crate::ci_usage_depot::{DEFAULT_API_URL, DepotUsageClient};
use crate::permission::Permission;
use crate::{Core, CoreError, CoreResult};

/// External suppliers a repository can be linked to.
pub const LINKABLE_SUPPLIERS: [&str; 1] = ["depot"];

/// The `[ci]` section of the server configuration. A missing section (or
/// key) defaults to no limits and no external supplier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiConfig {
    /// Quotas for native runners (all `0`-disabled).
    #[serde(default)]
    pub limits: CiLimits,
    /// The Depot supplier: where to read linked repositories' usage.
    #[serde(default)]
    pub depot: DepotSupplierConfig,
}

/// Native-runner quotas, per repository. `0` disables a limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiLimits {
    /// Runner minutes per calendar month (UTC). Checked when a run is
    /// queued; an attempt's minutes count when it ends.
    #[serde(default)]
    pub minutes_per_month: u64,
    /// Bytes of unexpired CI artifacts. Checked when an upload is
    /// authorized.
    #[serde(default)]
    pub artifact_bytes: u64,
}

/// Settings for reading usage from Depot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepotSupplierConfig {
    /// Base URL of the Depot API.
    #[serde(default = "default_depot_api_url")]
    pub api_url: String,
    /// Depot organization token, used only to read usage. Never logged or
    /// rendered in `Debug`. Empty disables the Depot supplier.
    #[serde(default)]
    pub api_token: String,
}

fn default_depot_api_url() -> String {
    DEFAULT_API_URL.to_owned()
}

impl Default for DepotSupplierConfig {
    fn default() -> Self {
        Self {
            api_url: default_depot_api_url(),
            api_token: String::new(),
        }
    }
}

impl std::fmt::Debug for DepotSupplierConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DepotSupplierConfig")
            .field("api_url", &self.api_url)
            .field("api_token", &"<redacted>")
            .finish()
    }
}

/// One measured quantity in a supplier's report.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageMetric {
    /// Stable metric name, e.g. `runner_minutes`.
    pub name: &'static str,
    /// Unit of `used` and `limit`, e.g. `minutes`, `bytes`, `vcpu_minutes`.
    pub unit: &'static str,
    pub used: f64,
    /// The enforced limit, when the supplier has one Starforge can see.
    pub limit: Option<f64>,
}

/// Usage of one supplier for the current period.
#[derive(Debug, Clone, PartialEq)]
pub struct SupplierUsage {
    /// `native` or a linked supplier (`depot`).
    pub supplier: &'static str,
    /// Who enforces the limits: `starforge` for native runners, the
    /// supplier itself otherwise.
    pub enforced_by: &'static str,
    /// The supplier's name for the repository (linked suppliers only).
    pub external_ref: Option<String>,
    pub period_start: i64,
    pub period_end: i64,
    pub metrics: Vec<UsageMetric>,
    /// Why the supplier's usage could not be read, when it could not.
    pub error: Option<String>,
}

/// A repository's link to an external supplier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplierLink {
    pub supplier: String,
    pub external_ref: String,
    pub updated_at: i64,
}

/// `[start, end)` of the calendar month (UTC) that contains `ts`.
pub fn month_bounds(ts: i64) -> (i64, i64) {
    let Ok(at) = OffsetDateTime::from_unix_timestamp(ts) else {
        return (ts, ts);
    };
    let start = at
        .replace_day(1)
        .map(|d| d.replace_time(time::Time::MIDNIGHT))
        .unwrap_or(at);
    let end = match start.month() {
        time::Month::December => start
            .replace_year(start.year() + 1)
            .and_then(|d| d.replace_month(time::Month::January)),
        month => start.replace_month(month.next()),
    }
    .unwrap_or(start);
    (start.unix_timestamp(), end.unix_timestamp())
}

/// `YYYY-MM-DD` (UTC) of `ts`.
fn ymd(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .map(|at| {
            format!(
                "{:04}-{:02}-{:02}",
                at.year(),
                u8::from(at.month()),
                at.day()
            )
        })
        .unwrap_or_default()
}

/// Rounds to two decimals for reporting.
fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// Validates a supplier's repository name: `owner/name` of ASCII letters,
/// digits, `.`, `_`, and `-`, at most 200 characters.
fn validate_external_ref(external_ref: &str) -> CoreResult<()> {
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    let mut parts = external_ref.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(CoreError::Invalid(
            "external_ref must be `owner/name`".into(),
        ));
    };
    if external_ref.len() > 200 || !valid_part(owner) || !valid_part(name) {
        return Err(CoreError::Invalid(
            "external_ref must be `owner/name` of letters, digits, `.`, `_`, or `-`".into(),
        ));
    }
    Ok(())
}

impl Core {
    /// Usage for the repository's current month, one report per supplier:
    /// `native` first, then each linked supplier. A linked supplier whose
    /// usage cannot be read reports the reason in `error` instead of
    /// failing the call. Requires at least Maintain.
    pub async fn ci_usage(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<SupplierUsage>> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        let now_ts = now();
        let (start, end) = month_bounds(now_ts);
        let mut reports = vec![self.native_usage(access.repo.id, start, end).await?];
        for link in db_ci::supplier_links_for_repo(self.db(), access.repo.id).await? {
            if link.supplier == "depot" {
                reports.push(
                    self.depot_usage(&link.external_ref, start, end, now_ts)
                        .await,
                );
            }
        }
        Ok(reports)
    }

    async fn native_usage(&self, repo_id: i64, start: i64, end: i64) -> CoreResult<SupplierUsage> {
        let limits = &self.config().ci.limits;
        let seconds = db_ci::usage_seconds_since(self.db(), repo_id, start).await?;
        let attempts = db_ci::usage_attempts_since(self.db(), repo_id, start).await?;
        let artifact_bytes = db_ci::live_artifact_bytes(self.db(), repo_id, now()).await?;
        let limit = |value: u64| (value > 0).then_some(value as f64);
        Ok(SupplierUsage {
            supplier: "native",
            enforced_by: "starforge",
            external_ref: None,
            period_start: start,
            period_end: end,
            metrics: vec![
                UsageMetric {
                    name: "runner_minutes",
                    unit: "minutes",
                    used: round2(seconds as f64 / 60.0),
                    limit: limit(limits.minutes_per_month),
                },
                UsageMetric {
                    name: "attempts",
                    unit: "attempts",
                    used: attempts as f64,
                    limit: None,
                },
                UsageMetric {
                    name: "artifact_bytes",
                    unit: "bytes",
                    used: artifact_bytes as f64,
                    limit: limit(limits.artifact_bytes),
                },
            ],
            error: None,
        })
    }

    async fn depot_usage(
        &self,
        external_ref: &str,
        start: i64,
        end: i64,
        now_ts: i64,
    ) -> SupplierUsage {
        let mut report = SupplierUsage {
            supplier: "depot",
            enforced_by: "depot",
            external_ref: Some(external_ref.to_owned()),
            period_start: start,
            period_end: end,
            metrics: Vec::new(),
            error: None,
        };
        let config = &self.config().ci.depot;
        if config.api_token.is_empty() {
            report.error = Some("Depot is not configured on this server".into());
            return report;
        }
        let client = DepotUsageClient::new(&config.api_url, &config.api_token);
        match client.get_usage(start, now_ts).await {
            Ok(usage) => {
                let repo = usage.for_repo(external_ref);
                let metric = |name, unit, used: f64| UsageMetric {
                    name,
                    unit,
                    used: round2(used),
                    limit: None,
                };
                report.metrics = vec![
                    metric(
                        "depot_ci_vcpu_minutes",
                        "vcpu_minutes",
                        repo.depot_ci_vcpu_minutes_billed,
                    ),
                    metric("depot_ci_minutes", "minutes", repo.depot_ci_minutes_elapsed),
                    metric(
                        "depot_ci_attempts",
                        "attempts",
                        repo.depot_ci_attempts as f64,
                    ),
                    metric(
                        "github_actions_minutes",
                        "minutes",
                        repo.github_actions_minutes_billed,
                    ),
                    metric(
                        "github_actions_jobs",
                        "jobs",
                        repo.github_actions_jobs as f64,
                    ),
                ];
            }
            Err(err) => {
                tracing::warn!(supplier = "depot", error = %err, "reading CI usage failed");
                report.error = Some(format!("Depot usage is unavailable ({err})"));
            }
        }
        report
    }

    /// Links the repository to an external CI supplier (`depot`), naming
    /// the repository as the supplier reports it (`owner/name`); replaces
    /// an existing link. Requires at least Admin. Audited.
    pub async fn set_ci_supplier_link(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        supplier: &str,
        external_ref: &str,
    ) -> CoreResult<SupplierLink> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        if !LINKABLE_SUPPLIERS.contains(&supplier) {
            return Err(CoreError::Invalid(format!(
                "unknown CI supplier `{supplier}`"
            )));
        }
        validate_external_ref(external_ref)?;
        let row = db_ci::upsert_supplier_link(
            self.db(),
            access.repo.id,
            supplier,
            external_ref,
            Some(user.id),
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "ci.supplier.link",
            &format!("repo:{}", access.repo.id),
            &format!("supplier={supplier} external_ref={external_ref}"),
        )
        .await?;
        Ok(SupplierLink {
            supplier: row.supplier,
            external_ref: row.external_ref,
            updated_at: row.updated_at,
        })
    }

    /// Removes the repository's link to a supplier. `NotFound` when there
    /// is none. Requires at least Admin. Audited.
    pub async fn delete_ci_supplier_link(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        supplier: &str,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        if !db_ci::delete_supplier_link(self.db(), access.repo.id, supplier).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "ci.supplier.unlink",
            &format!("repo:{}", access.repo.id),
            &format!("supplier={supplier}"),
        )
        .await?;
        Ok(())
    }

    /// The minutes quota check for a run about to be queued: when the
    /// repository's native runner minutes for this month are used up,
    /// returns the message to report (naming the reset date); `None` when
    /// the run may be queued. Best-effort: an attempt's minutes count once
    /// it ends, so runs already queued or running when the quota fills
    /// still finish and are counted afterwards.
    pub(crate) async fn ci_minutes_quota_exhausted(
        &self,
        repo_id: i64,
    ) -> CoreResult<Option<String>> {
        let limit = self.config().ci.limits.minutes_per_month;
        if limit == 0 {
            return Ok(None);
        }
        let (start, end) = month_bounds(now());
        let used = db_ci::usage_seconds_since(self.db(), repo_id, start).await?;
        let limit_secs = i64::try_from(limit).unwrap_or(i64::MAX).saturating_mul(60);
        if used < limit_secs {
            return Ok(None);
        }
        Ok(Some(format!(
            "the CI minutes quota for this month ({limit} minutes) is used up; it resets on {}",
            ymd(end)
        )))
    }

    /// Writes the quota refusal as the job's `ci/<job>` check, so a gate
    /// that requires it shows why the run did not start. A check that
    /// already exists for the commit is left alone: `pending` means an
    /// active run already covers it, and a terminal state is a past result
    /// a refusal must not overwrite.
    pub(crate) async fn record_ci_quota_refusal(
        &self,
        repo_id: i64,
        commit_sha: &str,
        job_name: &str,
        message: &str,
        created_by: Option<i64>,
    ) -> CoreResult<()> {
        let context = format!("ci/{job_name}");
        let existing = db_checks::latest_checks_for_sha(self.db(), repo_id, commit_sha).await?;
        if existing.iter().any(|check| check.context == context) {
            return Ok(());
        }
        db_checks::insert_check(
            self.db(),
            repo_id,
            commit_sha,
            &context,
            "error",
            None,
            Some(message),
            created_by,
            now(),
        )
        .await?;
        self.audit(
            created_by,
            "ci.job.quota",
            &format!("repo:{repo_id}"),
            &format!("job={job_name} commit={commit_sha}"),
        )
        .await
    }

    /// Refuses an artifact that would take the repository's unexpired CI
    /// artifacts past the artifact storage quota. Checked when an upload is
    /// authorized and again when its bytes arrive, so parallel
    /// authorizations cannot together overshoot the quota.
    pub(crate) async fn check_artifact_quota(&self, repo_id: i64, size: i64) -> CoreResult<()> {
        let limit = self.config().ci.limits.artifact_bytes;
        if limit == 0 {
            return Ok(());
        }
        let stored = db_ci::live_artifact_bytes(self.db(), repo_id, now()).await?;
        if stored.saturating_add(size) > i64::try_from(limit).unwrap_or(i64::MAX) {
            return Err(CoreError::Invalid(format!(
                "the CI artifact storage quota ({limit} bytes) would be exceeded: {stored} bytes are stored"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_bounds_cover_the_utc_calendar_month() {
        // 2026-11-07T12:00:00Z
        assert_eq!(month_bounds(1_794_052_800), (1_793_491_200, 1_796_083_200));
        // December rolls into January of the next year.
        let (start, end) = month_bounds(1_797_000_000);
        assert_eq!(ymd(start), "2026-12-01");
        assert_eq!(ymd(end), "2027-01-01");
        // The first second of a month belongs to it; the last to the previous.
        assert_eq!(month_bounds(1_793_491_200).0, 1_793_491_200);
        assert_eq!(month_bounds(1_793_491_199).1, 1_793_491_200);
    }

    #[test]
    fn external_ref_must_be_owner_slash_name() {
        assert!(validate_external_ref("acme/app").is_ok());
        assert!(validate_external_ref("Acme-1/app.v2_x").is_ok());
        for bad in [
            "acme",
            "acme/",
            "/app",
            "acme/app/x",
            "acme/a b",
            "acme/äpp",
        ] {
            assert!(validate_external_ref(bad).is_err(), "{bad}");
        }
        assert!(validate_external_ref(&format!("a/{}", "b".repeat(200))).is_err());
    }
}
