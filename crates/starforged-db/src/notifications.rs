//! `notifications`, `repo_watches` and `trail_subscriptions`: the Trail
//! inbox plus the two subscription tables that feed it.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationRow {
    pub id: i64,
    pub user_id: i64,
    pub repo_id: i64,
    pub trail_id: Option<i64>,
    pub kind: String,
    pub reason: String,
    pub actor_id: Option<i64>,
    pub title: String,
    pub url: String,
    pub created_at: i64,
    pub read_at: Option<i64>,
}

pub struct NewNotification<'a> {
    pub user_id: i64,
    pub repo_id: i64,
    pub trail_id: Option<i64>,
    pub kind: &'a str,
    pub reason: &'a str,
    pub actor_id: Option<i64>,
    pub title: &'a str,
    pub url: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoWatchRow {
    pub user_id: i64,
    pub repo_id: i64,
    pub mode: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailSubscriptionRow {
    pub user_id: i64,
    pub trail_id: i64,
    pub subscribed: bool,
    pub created_at: i64,
}

fn notification_from_row(row: &AnyRow) -> DbResult<NotificationRow> {
    Ok(NotificationRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        repo_id: row.try_get("repo_id")?,
        trail_id: row.try_get("trail_id")?,
        kind: row.try_get("kind")?,
        reason: row.try_get("reason")?,
        actor_id: row.try_get("actor_id")?,
        title: row.try_get("title")?,
        url: row.try_get("url")?,
        created_at: row.try_get("created_at")?,
        read_at: row.try_get("read_at")?,
    })
}

fn watch_from_row(row: &AnyRow) -> DbResult<RepoWatchRow> {
    Ok(RepoWatchRow {
        user_id: row.try_get("user_id")?,
        repo_id: row.try_get("repo_id")?,
        mode: row.try_get("mode")?,
        created_at: row.try_get("created_at")?,
    })
}

fn subscription_from_row(row: &AnyRow) -> DbResult<TrailSubscriptionRow> {
    let subscribed: i64 = row.try_get("subscribed")?;
    Ok(TrailSubscriptionRow {
        user_id: row.try_get("user_id")?,
        trail_id: row.try_get("trail_id")?,
        subscribed: subscribed != 0,
        created_at: row.try_get("created_at")?,
    })
}

/// Inserts one inbox row for `user_id` at `now`.
pub async fn insert(db: &Db, n: &NewNotification<'_>, now: i64) -> DbResult<NotificationRow> {
    let row = sqlx::query(concat!(
        "INSERT INTO notifications (user_id, repo_id, trail_id, kind, reason, actor_id, title, url, created_at, read_at) ",
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL) RETURNING ",
        "id, user_id, repo_id, trail_id, kind, reason, actor_id, title, url, created_at, read_at",
    ))
    .bind(n.user_id)
    .bind(n.repo_id)
    .bind(n.trail_id)
    .bind(n.kind)
    .bind(n.reason)
    .bind(n.actor_id)
    .bind(n.title)
    .bind(n.url)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    notification_from_row(&row)
}

/// The user's notifications, newest first, at most `limit` rows.
/// `include_read` false keeps only unread rows.
pub async fn list_for_user(
    db: &Db,
    user_id: i64,
    include_read: bool,
    limit: i64,
) -> DbResult<Vec<NotificationRow>> {
    let rows = if include_read {
        sqlx::query(concat!(
            "SELECT id, user_id, repo_id, trail_id, kind, reason, actor_id, title, url, created_at, read_at ",
            "FROM notifications WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
        ))
        .bind(user_id)
        .bind(limit)
        .fetch_all(db.read_pool())
        .await?
    } else {
        sqlx::query(concat!(
            "SELECT id, user_id, repo_id, trail_id, kind, reason, actor_id, title, url, created_at, read_at ",
            "FROM notifications WHERE user_id = $1 AND read_at IS NULL ORDER BY created_at DESC, id DESC LIMIT $2"
        ))
        .bind(user_id)
        .bind(limit)
        .fetch_all(db.read_pool())
        .await?
    };
    rows.iter().map(notification_from_row).collect()
}

/// How many notifications the user has not read yet.
pub async fn unread_count(db: &Db, user_id: i64) -> DbResult<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(db.read_pool())
    .await?;
    Ok(count)
}

/// Unread notification counts grouped by repository for one user.
/// Callers filter by the viewer's current read permission per repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoUnreadCount {
    pub repo_id: i64,
    pub unread: i64,
}

/// The user's unread notifications counted per repository, by repository id.
pub async fn unread_counts_by_repo(db: &Db, user_id: i64) -> DbResult<Vec<RepoUnreadCount>> {
    let rows = sqlx::query(concat!(
        "SELECT repo_id, COUNT(*) AS unread ",
        "FROM notifications WHERE user_id = $1 AND read_at IS NULL ",
        "GROUP BY repo_id ORDER BY repo_id ASC"
    ))
    .bind(user_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(RepoUnreadCount {
                repo_id: row.try_get("repo_id")?,
                unread: row.try_get("unread")?,
            })
        })
        .collect()
}

/// The user's own notification with `id`, if any.
pub async fn by_id_for_user(db: &Db, id: i64, user_id: i64) -> DbResult<Option<NotificationRow>> {
    let row = sqlx::query(concat!(
        "SELECT id, user_id, repo_id, trail_id, kind, reason, actor_id, title, url, created_at, read_at ",
        "FROM notifications WHERE id = $1 AND user_id = $2"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(notification_from_row).transpose()
}

/// Marks the user's own notification read at `now`. `None` when no row
/// of the user has `id`; another user's row is never touched.
pub async fn mark_read(
    db: &Db,
    user_id: i64,
    id: i64,
    now: i64,
) -> DbResult<Option<NotificationRow>> {
    let result = sqlx::query(
        "UPDATE notifications SET read_at = COALESCE(read_at, $1) WHERE id = $2 AND user_id = $3",
    )
    .bind(now)
    .bind(id)
    .bind(user_id)
    .execute(db.pool())
    .await?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    let row = sqlx::query(concat!(
        "SELECT id, user_id, repo_id, trail_id, kind, reason, actor_id, title, url, created_at, read_at ",
        "FROM notifications WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(db.pool())
    .await?;
    Ok(Some(notification_from_row(&row)?))
}

/// Marks every unread notification of the user read at `now`.
/// Returns how many rows changed.
pub async fn mark_all_read(db: &Db, user_id: i64, now: i64) -> DbResult<u64> {
    let result =
        sqlx::query("UPDATE notifications SET read_at = $1 WHERE user_id = $2 AND read_at IS NULL")
            .bind(now)
            .bind(user_id)
            .execute(db.pool())
            .await?;
    Ok(result.rows_affected())
}

/// Deletes notifications read before `read_cutoff` and any notification
/// created before `all_cutoff`. Returns how many rows were deleted.
pub async fn prune(db: &Db, read_cutoff: i64, all_cutoff: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "DELETE FROM notifications WHERE (read_at IS NOT NULL AND read_at < $1) OR (created_at < $2)",
    )
    .bind(read_cutoff)
    .bind(all_cutoff)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected())
}

/// The user's watch row for the repository, if any.
pub async fn watch_for(db: &Db, user_id: i64, repo_id: i64) -> DbResult<Option<RepoWatchRow>> {
    let row = sqlx::query(concat!(
        "SELECT user_id, repo_id, mode, created_at ",
        "FROM repo_watches WHERE user_id = $1 AND repo_id = $2"
    ))
    .bind(user_id)
    .bind(repo_id)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(watch_from_row).transpose()
}

/// Inserts or updates the user's watch mode for the repository.
pub async fn upsert_watch(
    db: &Db,
    user_id: i64,
    repo_id: i64,
    mode: &str,
    now: i64,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO repo_watches (user_id, repo_id, mode, created_at) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (user_id, repo_id) DO UPDATE SET mode = excluded.mode",
    )
    .bind(user_id)
    .bind(repo_id)
    .bind(mode)
    .bind(now)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Deletes the user's watch row for the repository.
/// `false` when there was none.
pub async fn remove_watch(db: &Db, user_id: i64, repo_id: i64) -> DbResult<bool> {
    let result = sqlx::query("DELETE FROM repo_watches WHERE user_id = $1 AND repo_id = $2")
        .bind(user_id)
        .bind(repo_id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Every watch row of the repository.
pub async fn watches_of_repo(db: &Db, repo_id: i64) -> DbResult<Vec<RepoWatchRow>> {
    let rows = sqlx::query(concat!(
        "SELECT user_id, repo_id, mode, created_at ",
        "FROM repo_watches WHERE repo_id = $1 ORDER BY user_id ASC"
    ))
    .bind(repo_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(watch_from_row).collect()
}

/// Every watch row of the user.
pub async fn watches_of_user(db: &Db, user_id: i64) -> DbResult<Vec<RepoWatchRow>> {
    let rows = sqlx::query(concat!(
        "SELECT user_id, repo_id, mode, created_at ",
        "FROM repo_watches WHERE user_id = $1 ORDER BY repo_id ASC"
    ))
    .bind(user_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(watch_from_row).collect()
}

/// The user's subscription row for the Trail, if any.
pub async fn subscription_for(
    db: &Db,
    user_id: i64,
    trail_id: i64,
) -> DbResult<Option<TrailSubscriptionRow>> {
    let row = sqlx::query(concat!(
        "SELECT user_id, trail_id, subscribed, created_at ",
        "FROM trail_subscriptions WHERE user_id = $1 AND trail_id = $2"
    ))
    .bind(user_id)
    .bind(trail_id)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(subscription_from_row).transpose()
}

/// Inserts or updates the user's subscription for the Trail.
pub async fn upsert_subscription(
    db: &Db,
    user_id: i64,
    trail_id: i64,
    subscribed: bool,
    now: i64,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO trail_subscriptions (user_id, trail_id, subscribed, created_at) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (user_id, trail_id) DO UPDATE SET subscribed = excluded.subscribed",
    )
    .bind(user_id)
    .bind(trail_id)
    .bind(i64::from(subscribed))
    .bind(now)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Deletes the user's subscription row for the Trail.
/// `false` when there was none.
pub async fn remove_subscription(db: &Db, user_id: i64, trail_id: i64) -> DbResult<bool> {
    let result =
        sqlx::query("DELETE FROM trail_subscriptions WHERE user_id = $1 AND trail_id = $2")
            .bind(user_id)
            .bind(trail_id)
            .execute(db.pool())
            .await?;
    Ok(result.rows_affected() == 1)
}

/// Every subscription row of the Trail.
pub async fn subscriptions_of_trail(db: &Db, trail_id: i64) -> DbResult<Vec<TrailSubscriptionRow>> {
    let rows = sqlx::query(concat!(
        "SELECT user_id, trail_id, subscribed, created_at ",
        "FROM trail_subscriptions WHERE trail_id = $1 ORDER BY user_id ASC"
    ))
    .bind(trail_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(subscription_from_row).collect()
}

/// Whether the user opts in to notification emails. Missing users read as off.
pub async fn notification_email_enabled(db: &Db, user_id: i64) -> DbResult<bool> {
    let value: Option<i64> = sqlx::query_scalar("SELECT notify_email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db.read_pool())
        .await?;
    Ok(value.unwrap_or_default() != 0)
}

/// Sets the user's notification-email opt-in.
pub async fn set_notification_email(db: &Db, user_id: i64, enabled: bool) -> DbResult<()> {
    sqlx::query("UPDATE users SET notify_email = $1 WHERE id = $2")
        .bind(i64::from(enabled))
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
    use crate::testing::TestDb;
    use crate::trails::{self, NewTrail};
    use crate::users::{self, NewUser};

    fn user(handle: &str) -> NewUser<'_> {
        NewUser {
            handle,
            display_name: "",
            email: None,
            email_verified: false,
            password_hash: None,
            is_admin: false,
        }
    }

    async fn setup() -> (TestDb, i64, i64, i64, i64) {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("alice")).await.unwrap();
        let bob = users::insert(&t.db, &user("bob")).await.unwrap();
        let repo = repos::insert(
            &t.db,
            &NewRepo {
                owner_id: alice,
                name: "demo",
                description: "",
                visibility: "private",
                default_branch: "main",
            },
        )
        .await
        .unwrap();
        let trail = trails::insert_trail(
            &t.db,
            &NewTrail {
                repo_id: repo,
                title: "fix it",
                intent: "do the thing",
                author_id: alice,
            },
            1_700_000_000,
        )
        .await
        .unwrap()
        .id;
        (t, alice, bob, repo, trail)
    }

    fn notification<'a>(
        user_id: i64,
        repo: i64,
        trail: i64,
        title: &'a str,
    ) -> NewNotification<'a> {
        NewNotification {
            user_id,
            repo_id: repo,
            trail_id: Some(trail),
            kind: "comment",
            reason: "participant",
            actor_id: None,
            title,
            url: "/alice/demo/trails/1",
        }
    }

    #[tokio::test]
    async fn insert_lists_newest_first_and_covers_unread() {
        let (t, alice, _bob, repo, trail) = setup().await;
        let old = insert(&t.db, &notification(alice, repo, trail, "old"), 100)
            .await
            .unwrap();
        let new = insert(&t.db, &notification(alice, repo, trail, "new"), 300)
            .await
            .unwrap();
        let mid = insert(&t.db, &notification(alice, repo, trail, "mid"), 200)
            .await
            .unwrap();
        let all = list_for_user(&t.db, alice, true, 10).await.unwrap();
        assert_eq!(
            all.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(),
            vec!["new", "mid", "old"]
        );
        assert_eq!(all[0].id, new.id);
        assert_eq!(all[2].id, old.id);
        mark_read(&t.db, alice, new.id, 400).await.unwrap();
        let unread = list_for_user(&t.db, alice, false, 10).await.unwrap();
        assert_eq!(
            unread.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(),
            vec!["mid", "old"]
        );
        assert_eq!(unread.len(), 2);
        let _ = mid;
    }

    #[tokio::test]
    async fn unread_count_tracks_reads() {
        let (t, alice, _bob, repo, trail) = setup().await;
        let a = insert(&t.db, &notification(alice, repo, trail, "a"), 100)
            .await
            .unwrap();
        insert(&t.db, &notification(alice, repo, trail, "b"), 200)
            .await
            .unwrap();
        assert_eq!(unread_count(&t.db, alice).await.unwrap(), 2);
        mark_read(&t.db, alice, a.id, 300).await.unwrap();
        assert_eq!(unread_count(&t.db, alice).await.unwrap(), 1);
        assert_eq!(mark_all_read(&t.db, alice, 400).await.unwrap(), 1);
        assert_eq!(unread_count(&t.db, alice).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn mark_read_touches_only_own_rows() {
        let (t, alice, bob, repo, trail) = setup().await;
        let mine = insert(&t.db, &notification(alice, repo, trail, "mine"), 100)
            .await
            .unwrap();
        let foreign = mark_read(&t.db, bob, mine.id, 200).await.unwrap();
        assert!(foreign.is_none());
        let still = list_for_user(&t.db, alice, false, 10).await.unwrap();
        assert_eq!(still.len(), 1);
        let read = mark_read(&t.db, alice, mine.id, 300)
            .await
            .unwrap()
            .expect("own read");
        assert_eq!(read.read_at, Some(300));
        let again = mark_read(&t.db, alice, mine.id, 400)
            .await
            .unwrap()
            .expect("re-read keeps the row");
        assert_eq!(again.read_at, Some(300));
    }

    #[tokio::test]
    async fn watch_upserts_and_deletes() {
        let (t, _alice, bob, repo, _trail) = setup().await;
        // Users are (alice, bob) in setup order; bob watches.
        let watcher = bob;
        assert!(watch_for(&t.db, watcher, repo).await.unwrap().is_none());
        upsert_watch(&t.db, watcher, repo, "watching", 100)
            .await
            .unwrap();
        assert_eq!(
            watch_for(&t.db, watcher, repo).await.unwrap().unwrap().mode,
            "watching"
        );
        upsert_watch(&t.db, watcher, repo, "ignoring", 200)
            .await
            .unwrap();
        let rows = watches_of_repo(&t.db, repo).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].mode, "ignoring");
        assert_eq!(rows[0].created_at, 100);
        assert!(remove_watch(&t.db, watcher, repo).await.unwrap());
        assert!(!remove_watch(&t.db, watcher, repo).await.unwrap());
        assert!(watches_of_user(&t.db, watcher).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn subscription_upserts_and_deletes() {
        let (t, _alice, bob, _repo, trail) = setup().await;
        assert!(subscription_for(&t.db, bob, trail).await.unwrap().is_none());
        upsert_subscription(&t.db, bob, trail, true, 100)
            .await
            .unwrap();
        assert!(
            subscription_for(&t.db, bob, trail)
                .await
                .unwrap()
                .unwrap()
                .subscribed
        );
        upsert_subscription(&t.db, bob, trail, false, 200)
            .await
            .unwrap();
        let rows = subscriptions_of_trail(&t.db, trail).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].subscribed);
        assert!(remove_subscription(&t.db, bob, trail).await.unwrap());
        assert!(!remove_subscription(&t.db, bob, trail).await.unwrap());
    }

    #[tokio::test]
    async fn prune_respects_read_and_any_cutoffs() {
        let (t, alice, _bob, repo, trail) = setup().await;
        let now = 1_700_000_000;
        let read_cutoff = now - 90 * 86_400;
        let all_cutoff = now - 365 * 86_400;
        // Fresh unread: kept on both rules.
        let fresh = insert(&t.db, &notification(alice, repo, trail, "fresh"), now)
            .await
            .unwrap();
        // Old unread (created 100 days ago): kept, only the any-rule removes it.
        let old_unread = insert(
            &t.db,
            &notification(alice, repo, trail, "old unread"),
            now - 100 * 86_400,
        )
        .await
        .unwrap();
        // Very old unread (created 400 days ago): removed by the any-rule.
        let _ancient = insert(
            &t.db,
            &notification(alice, repo, trail, "ancient"),
            now - 400 * 86_400,
        )
        .await
        .unwrap();
        // Read long ago: removed by the read-rule.
        let old_read = insert(
            &t.db,
            &notification(alice, repo, trail, "old read"),
            now - 100 * 86_400,
        )
        .await
        .unwrap();
        mark_read(&t.db, alice, old_read.id, now - 100 * 86_400)
            .await
            .unwrap();
        // Read recently (created 100 days ago, read 10 days ago): kept.
        let recent_read = insert(
            &t.db,
            &notification(alice, repo, trail, "recent read"),
            now - 100 * 86_400,
        )
        .await
        .unwrap();
        mark_read(&t.db, alice, recent_read.id, now - 10 * 86_400)
            .await
            .unwrap();
        assert!(old_read.id != 0);
        assert!(recent_read.id != 0);
        let deleted = prune(&t.db, read_cutoff, all_cutoff).await.unwrap();
        assert_eq!(deleted, 2);
        let left = list_for_user(&t.db, alice, true, 10).await.unwrap();
        let titles: Vec<&str> = left.iter().map(|r| r.title.as_str()).collect();
        assert!(titles.contains(&"fresh"));
        assert!(titles.contains(&"old unread"));
        assert!(titles.contains(&"recent read"));
        assert!(!titles.contains(&"ancient"));
        assert!(!titles.contains(&"old read"));
        assert_eq!(
            left.iter().find(|r| r.id == fresh.id).unwrap().title,
            "fresh"
        );
        assert_eq!(
            left.iter().find(|r| r.id == old_unread.id).unwrap().title,
            "old unread"
        );
        assert_eq!(
            left.iter().find(|r| r.id == recent_read.id).unwrap().title,
            "recent read"
        );
    }

    #[tokio::test]
    async fn notify_email_defaults_on_and_toggles() {
        let (t, alice, _bob, _repo, _trail) = setup().await;
        assert!(notification_email_enabled(&t.db, alice).await.unwrap());
        set_notification_email(&t.db, alice, false).await.unwrap();
        assert!(!notification_email_enabled(&t.db, alice).await.unwrap());
        set_notification_email(&t.db, alice, true).await.unwrap();
        assert!(notification_email_enabled(&t.db, alice).await.unwrap());
    }
}
