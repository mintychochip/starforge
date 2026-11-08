//! Notifications (Phase 2): the Trail inbox, repository watches and Trail
//! subscriptions. Routes and jobs delegate here; callers outside the crate
//! see the view and preference methods, while the event entry point
//! [`Core::notify`] stays crate-internal so only domain actions fan out.

use std::collections::HashSet;

use starforged_db::changes as db_changes;
use starforged_db::notifications as db_notifications;
use starforged_db::now;
use starforged_db::repos as db_repos;
use starforged_db::trails as db_trails;
use starforged_db::users as db_users;

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, validate};

/// Whether a repository watch receives everything or nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchMode {
    Watching,
    Ignoring,
}

impl WatchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            WatchMode::Watching => "watching",
            WatchMode::Ignoring => "ignoring",
        }
    }

    pub fn parse(s: &str) -> Option<WatchMode> {
        match s {
            "watching" => Some(WatchMode::Watching),
            "ignoring" => Some(WatchMode::Ignoring),
            _ => None,
        }
    }
}

/// One repository the user watches or ignores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedRepo {
    pub owner: String,
    pub repo: String,
    pub mode: WatchMode,
}

/// The shape shared by the web inbox and the API.
#[derive(Debug, Clone)]
pub struct NotificationView {
    pub id: i64,
    pub owner: String,
    pub repo: String,
    pub trail_number: Option<i64>,
    pub title: String,
    pub kind: String,
    pub reason: String,
    pub actor: Option<String>,
    pub url: String,
    pub created_at: i64,
    pub read: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotifyKind {
    TrailOpened,
    Commented,
    ReviewRequested,
    Assigned,
    ReviewSubmitted,
    ThreadComment,
    Merged,
    Closed,
    Reopened,
    ChangeOpened,
    RevisionPushed,
}

impl NotifyKind {
    fn as_str(self) -> &'static str {
        match self {
            NotifyKind::TrailOpened => "trail_opened",
            NotifyKind::Commented => "comment",
            NotifyKind::ReviewRequested => "review_requested",
            NotifyKind::Assigned => "assigned",
            NotifyKind::ReviewSubmitted => "review_submitted",
            NotifyKind::ThreadComment => "thread_comment",
            NotifyKind::Merged => "merged",
            NotifyKind::Closed => "closed",
            NotifyKind::Reopened => "reopened",
            NotifyKind::ChangeOpened => "change_opened",
            NotifyKind::RevisionPushed => "revision_pushed",
        }
    }

    fn event_phrase(self) -> &'static str {
        match self {
            NotifyKind::TrailOpened => "opened",
            NotifyKind::Commented => "commented on",
            NotifyKind::ReviewRequested => "requested your review on",
            NotifyKind::Assigned => "assigned you to",
            NotifyKind::ReviewSubmitted => "submitted a review on",
            NotifyKind::ThreadComment => "commented on a thread in",
            NotifyKind::Merged => "merged",
            NotifyKind::Closed => "closed",
            NotifyKind::Reopened => "reopened",
            NotifyKind::ChangeOpened => "opened a change on",
            NotifyKind::RevisionPushed => "pushed a revision to",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NotifyEvent<'a> {
    pub repo_id: i64,
    pub trail_id: i64,
    pub kind: NotifyKind,
    pub actor_id: Option<i64>,
    pub targets: &'a [i64],
    pub text: Option<&'a str>,
}
struct EmailFacts<'a> {
    repo: &'a crate::repos::Repo,
    trail: &'a db_trails::TrailRow,
    actor: &'a str,
    event: &'a str,
    link: &'a str,
    settings_link: &'a str,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReasonFlags {
    is_target: bool,
    is_mentioned: bool,
    is_author: bool,
    is_participant: bool,
    is_subscribed: bool,
    is_watching: bool,
}

fn preferred_reason(kind: NotifyKind, f: ReasonFlags) -> Option<&'static str> {
    match kind {
        NotifyKind::ReviewRequested => {
            if f.is_target {
                Some("review_requested")
            } else {
                None
            }
        }
        NotifyKind::Assigned => {
            if f.is_target {
                Some("assigned")
            } else {
                None
            }
        }
        NotifyKind::TrailOpened => {
            if f.is_mentioned {
                Some("mention")
            } else if f.is_watching {
                Some("watching")
            } else {
                None
            }
        }
        NotifyKind::ChangeOpened | NotifyKind::RevisionPushed => {
            if f.is_subscribed {
                Some("subscribed")
            } else if f.is_watching {
                Some("watching")
            } else {
                None
            }
        }
        NotifyKind::Commented
        | NotifyKind::ReviewSubmitted
        | NotifyKind::ThreadComment
        | NotifyKind::Merged
        | NotifyKind::Closed
        | NotifyKind::Reopened => {
            if f.is_mentioned {
                Some("mention")
            } else if f.is_author {
                Some("author")
            } else if f.is_participant {
                Some("participant")
            } else if f.is_subscribed {
                Some("subscribed")
            } else if f.is_watching {
                Some("watching")
            } else {
                None
            }
        }
    }
}

fn is_fence(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("```") || t.starts_with("~~~")
}

fn is_handle_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

fn strip_inline_code(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < n {
        if chars[i] == '`' {
            let mut run = 0;
            while i + run < n && chars[i + run] == '`' {
                run += 1;
            }
            let mut j = i + run;
            let mut close = None;
            while j < n {
                if chars[j] == '`' {
                    let mut r = 0;
                    while j + r < n && chars[j + r] == '`' {
                        r += 1;
                    }
                    if r == run {
                        close = Some(j);
                        break;
                    }
                    j += r;
                } else {
                    j += 1;
                }
            }
            if let Some(end) = close {
                i = end + run;
                continue;
            }
            i += run;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn scan_mentions(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' {
            let mut j = i + 1;
            let mut run = String::new();
            while j < chars.len() && is_handle_char(chars[j]) {
                run.push(chars[j]);
                j += 1;
            }
            if !run.is_empty() {
                let lower = run.to_ascii_lowercase();
                if validate::handle(&lower).is_ok() {
                    out.push(lower);
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

pub(crate) fn extract_mentions(text: &str) -> Vec<String> {
    let mut handles: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut in_fence = false;
    for line in text.lines() {
        if handle_limit_reached(&handles) {
            break;
        }
        if is_fence(line) {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let visible = strip_inline_code(line);
        for handle in scan_mentions(&visible) {
            if handle_limit_reached(&handles) {
                break;
            }
            if seen.insert(handle.clone()) {
                handles.push(handle);
            }
        }
    }
    handles
}

fn handle_limit_reached(handles: &[String]) -> bool {
    handles.len() >= 50
}

impl Core {
    pub(crate) async fn notify(&self, ev: NotifyEvent<'_>) {
        if let Err(err) = self.notify_inner(ev).await {
            tracing::warn!(error = %err, kind = ev.kind.as_str(), "notification fan-out failed");
        }
    }

    async fn notify_inner(&self, ev: NotifyEvent<'_>) -> CoreResult<()> {
        let Some(trail) = db_trails::trail_by_id(self.db(), ev.trail_id).await? else {
            return Ok(());
        };
        let Some(repo_row) = db_repos::by_id(self.db(), ev.repo_id).await? else {
            return Ok(());
        };
        let repo = crate::repos::to_repo(repo_row)?;
        if repo.deleted_at.is_some() {
            return Ok(());
        }
        let title = trail.title.clone();
        let url = format!("/{}/{}/trails/{}", repo.owner, repo.name, trail.number);
        let kind_str = ev.kind.as_str();

        let participants = self.participant_ids(&trail).await?;

        let mut watchers = HashSet::new();
        let mut ignoring = HashSet::new();
        for row in db_notifications::watches_of_repo(self.db(), repo.id).await? {
            if row.mode == "watching" {
                watchers.insert(row.user_id);
            } else if row.mode == "ignoring" {
                ignoring.insert(row.user_id);
            }
        }
        let mut subscribers = HashSet::new();
        let mut unsubscribed = HashSet::new();
        for row in db_notifications::subscriptions_of_trail(self.db(), trail.id).await? {
            if row.subscribed {
                subscribers.insert(row.user_id);
            } else {
                unsubscribed.insert(row.user_id);
            }
        }

        let mut mentioned = HashSet::new();
        if let Some(text) = ev.text {
            for handle in extract_mentions(text) {
                if let Some(row) = db_users::by_handle(self.db(), &handle).await? {
                    mentioned.insert(row.id);
                }
            }
        }
        let targets: HashSet<i64> = ev.targets.iter().copied().collect();

        let candidates: HashSet<i64> = match ev.kind {
            NotifyKind::TrailOpened => {
                let mut set: HashSet<i64> = watchers.clone();
                set.extend(mentioned.iter().copied());
                set
            }
            NotifyKind::ReviewRequested | NotifyKind::Assigned => targets.clone(),
            NotifyKind::ChangeOpened | NotifyKind::RevisionPushed => {
                let mut set: HashSet<i64> = watchers.clone();
                set.extend(subscribers.iter().copied());
                set
            }
            NotifyKind::Commented
            | NotifyKind::ReviewSubmitted
            | NotifyKind::ThreadComment
            | NotifyKind::Merged
            | NotifyKind::Closed
            | NotifyKind::Reopened => {
                let mut set: HashSet<i64> = participants.clone();
                set.extend(watchers.iter().copied());
                set.extend(subscribers.iter().copied());
                set.extend(mentioned.iter().copied());
                set
            }
        };
        let ts = now();
        // (recipient user id, reason) for the email pass below.
        let mut mailed: Vec<(i64, String)> = Vec::new();
        let mut ordered: Vec<i64> = candidates.into_iter().collect();
        ordered.sort_unstable();
        for user_id in ordered {
            if ev.actor_id == Some(user_id) {
                continue;
            }
            let is_target = targets.contains(&user_id);
            if ignoring.contains(&user_id) && !is_target {
                continue;
            }
            let is_mentioned = mentioned.contains(&user_id);
            if unsubscribed.contains(&user_id) && !is_target && !is_mentioned {
                continue;
            }
            let Some(user) = self.user_by_id(user_id).await? else {
                continue;
            };
            if self.permission_on(&repo, Some(&user)).await?.is_none() {
                continue;
            }
            let flags = ReasonFlags {
                is_target,
                is_mentioned,
                is_author: trail.author_id == Some(user_id),
                is_participant: participants.contains(&user_id),
                is_subscribed: subscribers.contains(&user_id),
                is_watching: watchers.contains(&user_id),
            };
            let Some(reason) = preferred_reason(ev.kind, flags) else {
                continue;
            };
            db_notifications::insert(
                self.db(),
                &db_notifications::NewNotification {
                    user_id,
                    repo_id: repo.id,
                    trail_id: Some(trail.id),
                    kind: kind_str,
                    reason,
                    actor_id: ev.actor_id,
                    title: &title,
                    url: &url,
                },
                ts,
            )
            .await?;
            mailed.push((user_id, reason.to_owned()));
        }

        if self.mail_enabled() && !mailed.is_empty() {
            let actor_name = match ev.actor_id {
                Some(id) => self
                    .user_by_id(id)
                    .await?
                    .map(|u| u.handle)
                    .unwrap_or_else(|| "Someone".to_owned()),
                None => "Someone".to_owned(),
            };
            let base_url = self.config().base_url.clone();
            let absolute_link = format!("{base_url}{url}");
            let settings_link = format!("{base_url}/settings/notifications");
            let event = ev.kind.event_phrase();
            let facts = EmailFacts {
                repo: &repo,
                trail: &trail,
                actor: &actor_name,
                event,
                link: &absolute_link,
                settings_link: &settings_link,
            };
            for (user_id, reason) in mailed {
                if let Err(err) = self.send_notification_email(user_id, &facts, &reason).await {
                    tracing::warn!(error = %err, user = user_id, "notification email failed");
                }
            }
        }
        Ok(())
    }

    async fn send_notification_email(
        &self,
        user_id: i64,
        facts: &EmailFacts<'_>,
        reason: &str,
    ) -> CoreResult<()> {
        if !db_notifications::notification_email_enabled(self.db(), user_id).await? {
            return Ok(());
        }
        let Some(user) = self.user_by_id(user_id).await? else {
            return Ok(());
        };
        if !user.email_verified {
            return Ok(());
        }
        let Some(address) = user.email.clone() else {
            return Ok(());
        };
        let email = crate::mail::notification_email(
            &address,
            &facts.repo.owner,
            &facts.repo.name,
            &facts.trail.title,
            facts.trail.number,
            facts.actor,
            facts.event,
            facts.link,
            reason,
            facts.settings_link,
        )?;
        self.queue_email(email).await?;
        Ok(())
    }

    async fn participant_ids(&self, trail: &db_trails::TrailRow) -> CoreResult<HashSet<i64>> {
        let mut set = HashSet::new();
        if let Some(author) = trail.author_id {
            set.insert(author);
        }
        for id in db_trails::assignees_of(self.db(), trail.id).await? {
            set.insert(id);
        }
        for id in db_trails::review_requests_of(self.db(), trail.id).await? {
            set.insert(id);
        }
        for comment in db_trails::comments_of(self.db(), trail.id).await? {
            if let Some(author) = comment.author_id {
                set.insert(author);
            }
        }
        for change in db_changes::changes_of_trail(self.db(), trail.id).await? {
            for review in db_changes::reviews_of_change(self.db(), change.id).await? {
                if let Some(author) = review.author_id {
                    set.insert(author);
                }
            }
            for thread in db_changes::threads_of_change(self.db(), change.id).await? {
                for comment in db_changes::comments_of_thread(self.db(), thread.id).await? {
                    if let Some(author) = comment.author_id {
                        set.insert(author);
                    }
                }
            }
        }
        Ok(set)
    }

    async fn notification_view(
        &self,
        row: db_notifications::NotificationRow,
    ) -> CoreResult<NotificationView> {
        let repo_row = db_repos::by_id(self.db(), row.repo_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let repo = crate::repos::to_repo(repo_row)?;
        let trail_number = match row.trail_id {
            Some(trail_id) => db_trails::trail_by_id(self.db(), trail_id)
                .await?
                .map(|t| t.number),
            None => None,
        };
        let actor = match row.actor_id {
            Some(actor_id) => self.user_by_id(actor_id).await?.map(|u| u.handle),
            None => None,
        };
        Ok(NotificationView {
            id: row.id,
            owner: repo.owner.clone(),
            repo: repo.name.clone(),
            trail_number,
            title: row.title,
            kind: row.kind,
            reason: row.reason,
            actor,
            url: row.url,
            created_at: row.created_at,
            read: row.read_at.is_some(),
        })
    }

    async fn readable_repo(
        &self,
        user: &User,
        repo_id: i64,
    ) -> CoreResult<Option<crate::repos::Repo>> {
        let Some(repo_row) = db_repos::by_id(self.db(), repo_id).await? else {
            return Ok(None);
        };
        let repo = crate::repos::to_repo(repo_row)?;
        if repo.deleted_at.is_some() {
            return Ok(None);
        }
        if self.permission_on(&repo, Some(user)).await?.is_none() {
            return Ok(None);
        }
        Ok(Some(repo))
    }

    async fn repo_and_trail(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
    ) -> CoreResult<(crate::repos::Repo, db_trails::TrailRow)> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        let trail = db_trails::trail_by_number(self.db(), access.repo.id, number)
            .await?
            .ok_or(CoreError::NotFound)?;
        Ok((access.repo, trail))
    }

    /// The user's notifications, newest first. Rows for repositories the
    /// user can no longer read are dropped.
    pub async fn notifications_for(
        &self,
        user: &User,
        include_read: bool,
        limit: i64,
    ) -> CoreResult<Vec<NotificationView>> {
        let mut views = Vec::new();
        for row in db_notifications::list_for_user(self.db(), user.id, include_read, limit).await? {
            if self.readable_repo(user, row.repo_id).await?.is_none() {
                continue;
            }
            views.push(self.notification_view(row).await?);
        }
        Ok(views)
    }

    /// Unread notifications on repositories the user can still read only.
    pub async fn unread_notification_count(&self, user: &User) -> CoreResult<i64> {
        let mut total = 0_i64;
        for entry in db_notifications::unread_counts_by_repo(self.db(), user.id).await? {
            if self.readable_repo(user, entry.repo_id).await?.is_some() {
                total += entry.unread;
            }
        }
        Ok(total)
    }

    pub async fn mark_notification_read(
        &self,
        user: &User,
        id: i64,
    ) -> CoreResult<NotificationView> {
        let existing = db_notifications::by_id_for_user(self.db(), id, user.id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if self.readable_repo(user, existing.repo_id).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        let row = db_notifications::mark_read(self.db(), user.id, id, now())
            .await?
            .ok_or(CoreError::NotFound)?;
        self.notification_view(row).await
    }

    pub async fn mark_all_notifications_read(&self, user: &User) -> CoreResult<u64> {
        Ok(db_notifications::mark_all_read(self.db(), user.id, now()).await?)
    }

    pub async fn repo_watch(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Option<WatchMode>> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        let row = db_notifications::watch_for(self.db(), user.id, access.repo.id).await?;
        match row {
            Some(w) => WatchMode::parse(&w.mode)
                .map(Some)
                .ok_or_else(|| CoreError::Internal("unknown watch mode".into())),
            None => Ok(None),
        }
    }

    pub async fn set_repo_watch(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        mode: Option<WatchMode>,
    ) -> CoreResult<()> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        match mode {
            Some(m) => {
                db_notifications::upsert_watch(
                    self.db(),
                    user.id,
                    access.repo.id,
                    m.as_str(),
                    now(),
                )
                .await?;
            }
            None => {
                db_notifications::remove_watch(self.db(), user.id, access.repo.id).await?;
            }
        };
        Ok(())
    }

    pub async fn trail_subscription(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
    ) -> CoreResult<bool> {
        let (_repo, trail) = self.repo_and_trail(user, owner, repo, number).await?;
        if let Some(row) = db_notifications::subscription_for(self.db(), user.id, trail.id).await? {
            return Ok(row.subscribed);
        }
        Ok(self.participant_ids(&trail).await?.contains(&user.id))
    }

    pub async fn set_trail_subscription(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        subscribed: bool,
    ) -> CoreResult<()> {
        let (_repo, trail) = self.repo_and_trail(user, owner, repo, number).await?;
        db_notifications::upsert_subscription(self.db(), user.id, trail.id, subscribed, now())
            .await?;
        Ok(())
    }

    pub async fn clear_trail_subscription(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
    ) -> CoreResult<()> {
        let (_repo, trail) = self.repo_and_trail(user, owner, repo, number).await?;
        db_notifications::remove_subscription(self.db(), user.id, trail.id).await?;
        Ok(())
    }

    pub async fn notification_email(&self, user: &User) -> CoreResult<bool> {
        Ok(db_notifications::notification_email_enabled(self.db(), user.id).await?)
    }

    pub async fn set_notification_email(&self, user: &User, enabled: bool) -> CoreResult<()> {
        db_notifications::set_notification_email(self.db(), user.id, enabled).await?;
        Ok(())
    }

    /// Every repository the user watches or ignores that they can still read.
    pub async fn watched_repos(&self, user: &User) -> CoreResult<Vec<WatchedRepo>> {
        let mut out = Vec::new();
        for row in db_notifications::watches_of_user(self.db(), user.id).await? {
            let Some(repo) = self.readable_repo(user, row.repo_id).await? else {
                continue;
            };
            let Some(mode) = WatchMode::parse(&row.mode) else {
                continue;
            };
            out.push(WatchedRepo {
                owner: repo.owner,
                repo: repo.name,
                mode,
            });
        }
        out.sort_by(|a, b| a.owner.cmp(&b.owner).then_with(|| a.repo.cmp(&b.repo)));
        Ok(out)
    }

    /// Deletes notifications read more than 90 days ago and any notification
    /// created more than 365 days ago.
    pub(crate) async fn prune_notifications(&self, now: i64) -> CoreResult<()> {
        db_notifications::prune(self.db(), now - 90 * 86_400, now - 365 * 86_400).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn mentions_ignore_code_and_fences() {
        let text = "hi @alice, not `@bob` here\n```rust\n@carol\n```\nsee @dave and `@erin`\n";
        let found = super::extract_mentions(text);
        assert!(found.contains(&"alice".to_string()), "{found:?}");
        assert!(found.contains(&"dave".to_string()), "{found:?}");
        assert!(!found.contains(&"bob".to_string()), "{found:?}");
        assert!(!found.contains(&"carol".to_string()), "{found:?}");
        assert!(!found.contains(&"erin".to_string()), "{found:?}");
    }

    #[test]
    fn mentions_lowercase_and_validated() {
        assert_eq!(
            super::extract_mentions("hi @AlIcE @BOB-1 @-bad"),
            vec!["alice".to_string(), "bob-1".to_string()]
        );
    }

    #[test]
    fn mentions_cap_at_fifty() {
        let mut text = String::new();
        for i in 0..60 {
            text.push_str(&format!("@user{i} "));
        }
        assert_eq!(super::extract_mentions(&text).len(), 50);
    }

    #[test]
    fn reason_prefers_mention_over_participant_chain() {
        use super::{NotifyKind, ReasonFlags, preferred_reason};
        let flags = ReasonFlags {
            is_target: false,
            is_mentioned: true,
            is_author: true,
            is_participant: true,
            is_subscribed: true,
            is_watching: true,
        };
        assert_eq!(
            preferred_reason(NotifyKind::Commented, flags),
            Some("mention")
        );
        let flags = ReasonFlags {
            is_target: false,
            is_mentioned: false,
            is_author: true,
            is_participant: true,
            is_subscribed: true,
            is_watching: true,
        };
        assert_eq!(
            preferred_reason(NotifyKind::Commented, flags),
            Some("author")
        );
        let flags = ReasonFlags {
            is_target: false,
            is_mentioned: false,
            is_author: false,
            is_participant: true,
            is_subscribed: true,
            is_watching: true,
        };
        assert_eq!(
            preferred_reason(NotifyKind::Commented, flags),
            Some("participant")
        );
    }

    #[test]
    fn reason_target_wins_for_review_requested() {
        use super::{NotifyKind, ReasonFlags, preferred_reason};
        let flags = ReasonFlags {
            is_target: true,
            is_mentioned: true,
            is_author: false,
            is_participant: true,
            is_subscribed: false,
            is_watching: true,
        };
        assert_eq!(
            preferred_reason(NotifyKind::ReviewRequested, flags),
            Some("review_requested")
        );
        let flags = ReasonFlags {
            is_target: true,
            is_mentioned: false,
            is_author: false,
            is_participant: false,
            is_subscribed: false,
            is_watching: false,
        };
        assert_eq!(
            preferred_reason(NotifyKind::Assigned, flags),
            Some("assigned")
        );
    }

    #[test]
    fn reason_trail_opened_excludes_participants() {
        use super::{NotifyKind, ReasonFlags, preferred_reason};
        let flags = ReasonFlags {
            is_target: false,
            is_mentioned: false,
            is_author: true,
            is_participant: true,
            is_subscribed: true,
            is_watching: false,
        };
        assert_eq!(preferred_reason(NotifyKind::TrailOpened, flags), None);
        let flags = ReasonFlags {
            is_target: false,
            is_mentioned: false,
            is_author: true,
            is_participant: true,
            is_subscribed: true,
            is_watching: true,
        };
        assert_eq!(
            preferred_reason(NotifyKind::TrailOpened, flags),
            Some("watching")
        );
    }

    #[test]
    fn reason_change_prefers_subscribed_over_watching() {
        use super::{NotifyKind, ReasonFlags, preferred_reason};
        let flags = ReasonFlags {
            is_target: false,
            is_mentioned: true,
            is_author: false,
            is_participant: true,
            is_subscribed: true,
            is_watching: true,
        };
        assert_eq!(
            preferred_reason(NotifyKind::RevisionPushed, flags),
            Some("subscribed")
        );
        let flags = ReasonFlags {
            is_target: false,
            is_mentioned: false,
            is_author: false,
            is_participant: true,
            is_subscribed: false,
            is_watching: true,
        };
        assert_eq!(
            preferred_reason(NotifyKind::ChangeOpened, flags),
            Some("watching")
        );
    }
}
