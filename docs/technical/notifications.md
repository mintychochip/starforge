# Notifications

## Purpose

This page defines notifications for Trails. A notification records one event for one recipient. The inbox stores the row. Email mirrors the row when an operator enables mail.

## Scope

The code in `starforged-core/src/notifications.rs` owns recipient rules. The code in `starforged-db/src/notifications.rs` owns rows. The code in `starforged-web/src/pages/notifications.rs` owns pages. The code in `starforged-api/src/notifications.rs` owns API routes.

## How it works

### Event kinds

`NotifyKind` carries 11 kinds. The kinds list new Trails, comments, review requests, assignments, submitted reviews, thread comments, merges, closes, reopens, new changes, and pushed revisions. The kind strings use snake case. The rows store the string in `notifications.kind`.

### Participants and watchers

Participants include the Trail author, assignees, review request targets, Trail commenters, reviewers, and thread commenters on the changes of the Trail. Watchers hold a `repo_watches` row with mode `watching`. Subscribers hold a `trail_subscriptions` row with `subscribed=1`. Mentioned users hold an `@handle` token in event text.

### Recipient rules

A new Trail notifies watchers and mentioned users. A comment, submitted review, thread comment, merge, close, or reopen notifies participants, watchers, subscribers, and mentioned users. A review request or assignment notifies target users only. A new change or a pushed revision notifies watchers and subscribers.

`Core::notify` never notifies the actor. `Core::notify` filters every recipient through `permission_on` for the repository. Permission filtering keeps only users with read access. A repository row with mode `ignoring` suppresses every row except targets. A Trail row with `subscribed=0` suppresses every row except targets and mentions.

Each event writes at most one row per recipient. The reason follows a fixed priority. Target reasons `review_requested` and `assigned` rank first. The reason `mention` ranks next. The reasons `author`, `participant`, `subscribed`, and `watching` rank in that order.

The title stores the Trail title. The URL stores `/{owner}/{repo}/trails/{number}`.

### Mentions

The scanner reads `@handle` tokens in Markdown text. The handle charset matches `validate::handle` and the scanner lowercases each token. The scanner skips fenced code blocks and inline code. The scanner counts at most 50 mentions per text. Unknown handles fail silently.

### Inbox and badge

`notifications_for` lists the newest rows first. The method honors `include_read` and `limit`. The method drops rows for repositories without read access. `unread_notification_count` counts unread rows for one user. `mark_notification_read` marks one row for the owner only. Other owners receive `NotFound`.

`mark_all_notifications_read` marks every unread row for one user.

`Core::web_session` fills `unread_notifications` in `WebSession`. The count uses `unread_notification_count`. An error logs a warning and fills zero.

### Watches and subscriptions

`WatchMode` carries `Watching` and `Ignoring`. The strings read `watching` and `ignoring`. `repo_watch` returns the stored mode. It answers `NotFound` when the user lacks read access. `set_repo_watch` writes or deletes one row. A `None` mode deletes the row.

`trail_subscription` returns an explicit row first. Without a row the method returns true for participants and false for others. `set_trail_subscription` writes one row. `clear_trail_subscription` deletes one row. `watched_repos` lists readable watched repositories only.

### Email

Email runs only with three conditions. `mail_enabled` must return true. The user toggle `notify_email` must equal 1. The user must hold a verified email. The core queues one email per row. The template lives at `crates/starforged-core/templates/mail/notification.txt`.

The subject uses `[{owner}/{repo}] {title} (#{number})`. The body names the actor and the event. The body carries the reason and the absolute link. The body links to `{base_url}/settings/notifications`.

### Retention

`prune_notifications` deletes read rows older than 90 days. It also deletes every row older than 365 days. The hourly cleanup job calls the function. Ages use unix seconds.

## Interfaces

`NotifyEvent` carries repository id, Trail id, kind, actor id, target ids, and text. The text holds Markdown for mention scan. `NotificationView` carries id, owner, repository, Trail number, title, kind, reason, actor handle, URL, creation time, and a read flag. System events carry `None` for the actor.

`notification_email` reads the user toggle. `set_notification_email` writes the user toggle. The toggle defaults to 1 in the schema.

## Failure behavior

`Core::notify` never fails the caller. The method logs a warning and returns on error. Read paths return domain errors to callers.

## Verification

Unit tests cover recipient rules, mention scan, reason priority, exclusions, and permission filtering. Unit tests cover watches, subscriptions, email toggle, and prune ages. Integration tests cover the inbox, badge, pages, and API routes.

## Related

Read [trails](trails.md) for Trail state. Read [web and auth](web-and-auth.md) for page routes. Read [HTTP API](http-api.md) for API routes. Read [storage and database](storage-and-database.md) for migration `0041`.

<!-- ste-sources
crates/starforged-core/src/notifications.rs
crates/starforged-db/src/notifications.rs
crates/starforged-web/src/pages/notifications.rs
crates/starforged-api/src/notifications.rs
-->
