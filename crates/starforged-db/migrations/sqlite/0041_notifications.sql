-- Starforge Phase 2: Trail notifications, repository watches and Trail subscriptions.
-- Keep in lockstep with ../postgres/0041_notifications.sql.
--
-- `notifications` holds one inbox row per recipient per event. `trail_id` is
-- NULL for repository-level events; `actor_id` is NULL for system events.
-- `read_at` is NULL while the notification is unread.
-- `repo_watches` records each user's repository watch mode; at most one row
-- per (user, repo). `trail_subscriptions` records the explicit subscription
-- choice per (user, trail); absence means the participation default.
-- `users.notify_email` is the per-user opt-in for notification emails.

ALTER TABLE users ADD COLUMN notify_email INTEGER NOT NULL DEFAULT 1;

CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    trail_id INTEGER REFERENCES trails (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    read_at INTEGER
);
CREATE INDEX notifications_user_read_created ON notifications (user_id, read_at, created_at);
CREATE INDEX notifications_created ON notifications (created_at);

CREATE TABLE repo_watches (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('watching', 'ignoring')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, repo_id)
);
CREATE INDEX repo_watches_repo ON repo_watches (repo_id);

CREATE TABLE trail_subscriptions (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    trail_id INTEGER NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    subscribed INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, trail_id)
);
CREATE INDEX trail_subscriptions_trail ON trail_subscriptions (trail_id);
