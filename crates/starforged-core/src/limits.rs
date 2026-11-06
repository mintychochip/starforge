//! Abuse controls (spec §11.6, plan M5a): login attempts per IP and per
//! account, API requests per token, and new `refs/for` changes per user.
//! All limits are configurable (`[limits]`); `0` disables a limit.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use starforged_db::{audit, changes as db_changes};

use crate::{Core, CoreError, CoreResult};

/// The outcome of one [`Core::check_api_rate`] call. `reset_at` is the unix
/// second at which the current fixed window ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateDecision {
    pub allowed: bool,
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: i64,
}

/// Current time in unix seconds (the database clock, as everywhere in the
/// service layer).
pub fn now_secs() -> i64 {
    starforged_db::now()
}

/// One fixed-window counter map (`key` → `(window start, count in window)`),
/// pruned on access at most every 60 s (plan M5a D1). In-memory by design: a
/// restart resets the windows, which a single-process deployment accepts.
#[derive(Debug, Default)]
pub struct FixedWindows {
    windows: Mutex<Windows>,
}

#[derive(Debug, Default)]
struct Windows {
    counts: HashMap<String, (i64, u64)>,
    last_prune: Option<Instant>,
}

impl FixedWindows {
    /// Checks (and, when allowed, counts) one hit of `key` in the fixed
    /// window of `window_secs` seconds starting at `now`.
    pub fn check(&self, key: &str, window_secs: i64, limit: u64, now: i64) -> RateDecision {
        let window_start = now - now.rem_euclid(window_secs);
        let reset_at = window_start + window_secs;
        if limit == 0 {
            return RateDecision {
                allowed: true,
                limit: 0,
                remaining: 0,
                reset_at,
            };
        }
        let mut windows = self.windows.lock().unwrap();
        let due = windows
            .last_prune
            .is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(60));
        if due {
            windows
                .counts
                .retain(|_, (start, _)| *start == window_start);
            windows.last_prune = Some(Instant::now());
        }
        let entry = windows
            .counts
            .entry(key.to_owned())
            .or_insert((window_start, 0));
        if entry.0 != window_start {
            *entry = (window_start, 0);
        }
        if entry.1 >= limit {
            RateDecision {
                allowed: false,
                limit,
                remaining: 0,
                reset_at,
            }
        } else {
            entry.1 += 1;
            RateDecision {
                allowed: true,
                limit,
                remaining: limit - entry.1,
                reset_at,
            }
        }
    }
}

/// The in-memory counters: per-IP login attempts (1-minute window) and
/// per-token API requests (1-hour window).
#[derive(Debug, Default)]
pub struct Limiters {
    pub login_ip: FixedWindows,
    pub api_token: FixedWindows,
}

impl Core {
    /// Counts one API request for `token_id` against the per-token hourly
    /// limit and reports the decision (allowed, limit, remaining, reset).
    /// `0` disables the limit.
    pub fn check_api_rate(&self, token_id: i64) -> RateDecision {
        self.inner.limits.api_token.check(
            &token_id.to_string(),
            3600,
            self.config().api_per_token_per_hour,
            starforged_db::now(),
        )
    }

    /// Refuses the login attempt when the per-IP or per-account limit is
    /// spent, writing one `auth.login_rate_limited` audit row per refused
    /// attempt. `login` is the normalized (trimmed, lowercased) name, so
    /// unknown names are limited identically to known ones (no oracle).
    pub(crate) async fn check_login_limits(
        &self,
        login: &str,
        ip: &str,
        user_agent: &str,
    ) -> CoreResult<()> {
        let cfg = self.config();
        if cfg.login_per_ip_per_minute > 0 {
            let decision = self.inner.limits.login_ip.check(
                ip,
                60,
                cfg.login_per_ip_per_minute,
                starforged_db::now(),
            );
            if !decision.allowed {
                return Err(self.refuse_login(login, ip, user_agent, "per-ip").await?);
            }
        }
        if cfg.login_per_account_per_hour > 0 {
            let target = format!("login:{login}");
            let failures = audit::count_action_target_since(
                self.db(),
                "auth.login_failed",
                &target,
                starforged_db::now() - 3600,
            )
            .await?;
            if failures >= cfg.login_per_account_per_hour as i64 {
                return Err(self
                    .refuse_login(login, ip, user_agent, "per-account")
                    .await?);
            }
        }
        Ok(())
    }

    /// Writes the `auth.login_rate_limited` audit row for one refused login
    /// attempt and returns the [`CoreError::RateLimited`] verdict. The row
    /// names the limit that fired in `detail`; the web layer answers with a
    /// generic 429 either way.
    async fn refuse_login(
        &self,
        login: &str,
        ip: &str,
        user_agent: &str,
        limit: &str,
    ) -> CoreResult<CoreError> {
        let target = format!("login:{login}");
        self.metrics().inc_rate_limited(limit);
        self.audit_client(
            None,
            "auth.login_rate_limited",
            &target,
            limit,
            ip,
            user_agent,
        )
        .await?;
        Ok(CoreError::RateLimited)
    }

    /// Remaining new `refs/for` changes for `user_id` in the current hour
    /// (`agit` changes created in ALL repositories), or `None` when the limit
    /// is disabled.
    pub async fn refs_for_budget(&self, user_id: i64) -> CoreResult<Option<i64>> {
        let limit = self.config().refs_for_new_changes_per_hour;
        if limit == 0 {
            return Ok(None);
        }
        let used =
            db_changes::count_agit_changes_since(self.db(), user_id, starforged_db::now() - 3600)
                .await?;
        Ok(Some((limit as i64 - used).max(0)))
    }

    /// The pusher's own open agit topics in `repo_id` as `base/topic` lines,
    /// for the git-RPC snapshot (plan M5a D2).
    pub async fn refs_for_topics(&self, repo_id: i64, user_id: i64) -> CoreResult<Vec<String>> {
        db_changes::open_agit_topics_for_repo(self.db(), repo_id, user_id)
            .await?
            .into_iter()
            .map(|(base, topic)| format!("{base}/{topic}"))
            .map(Ok)
            .collect()
    }

    /// True when the pusher's hourly new-change budget is spent (the
    /// post-receive ingest re-check, plan M5a D2).
    pub async fn refs_for_over_budget(&self, user_id: i64) -> CoreResult<bool> {
        Ok(self.refs_for_budget(user_id).await? == Some(0))
    }
}
