# Notifications

Starforge notifies you about activity on Trails you take part in, watch, or are mentioned in. Each notification lands in your inbox. When email is enabled, Starforge also sends one email per notification.

## Your inbox

Open `/notifications` to see unread notifications. Add `?all=1` to see read and unread notifications. Newest notifications appear first. Click a notification to open its Trail and mark it read at the same time.

Use `POST /notifications/{id}/read` to mark one notification read. Use `POST /notifications/read-all` to mark every notification read. The number of unread notifications appears beside the Notifications link in the navigation bar for signed in users.

A notification shows the Trail title, the kind of event, why you received it, and who caused it. The reason tells you the connection to the Trail. The clickable link opens the Trail.

## Who receives a notification

Starforge builds the recipient list for each event. The actor never receives a notification for their own action. A user receives a notification only when they can read the repository. Starforge sends nothing to a user without read access.

Recipients include Trail participants, repository watchers, Trail subscribers, and mentioned users. Trail participants include the author, assignees, review request targets, Trail commenters, reviewers, and thread commenters on the changes of that Trail.

The kind of event decides the exact list:

- A new Trail notifies watchers and mentioned users.
- A comment, review, thread comment, merge, close, or reopen notifies participants, watchers, subscribers, and mentioned users.
- A review request or assignment notifies the target user only.
- A new change or a pushed revision notifies watchers and subscribers.

Each recipient gets one notification per event. The reason follows a fixed priority. A review request or assignment reason wins first. A mention reason wins next. After that the reasons rank as author, participant, subscribed, and watching. The priority matters when you fit more than one group.

## Mentions

Write `@handle` in a Trail comment, review, or thread to mention a user. Starforge matches the handle against account names and notifies that user with reason `mention`.

Starforge reads mentions in Markdown text. Fenced code blocks and inline code do not create mentions. Starforge counts at most 50 mentions per text. Unknown handles are ignored. A mentioned user receives a notification even when a subscription row unsubscribed them.

## Watching a repository

Watch a repository to learn about its Trails and changes. Watching adds you as a `watching` recipient for the repository. You can watch a repository from `POST /{owner}/{repo}/watch` with mode `watching`.

Ignoring a repository sets mode `ignoring`. An ignoring row suppresses every notification except direct targets such as review requests and assignments. You can set ignoring with the same route and mode `ignoring`.

Use mode `none` to delete the watch row. After deletion, Starforge treats you as not watching and not ignoring.

## Trail subscriptions

A Trail subscription controls notifications for one Trail. Subscribe with `subscribed=1` in `POST /{owner}/{repo}/trails/{number}/subscription`. Unsubscribe with `subscribed=0`. The subscribed state adds you as a recipient for many event kinds.

Without an explicit row, Starforge treats participants as subscribed. Non participants are not subscribed by default. A `subscribed=0` row suppresses notifications except for direct targets and mentions.

## Email

Email needs three conditions at once. The instance must enable mail with `mail.url`. Your account must hold a verified email address. Your per user toggle `notify_email` must equal 1.

Starforge sends one email per notification when all three conditions hold. The subject reads `[{owner}/{repo}] {title} (#{number})`. The body names the actor and the event, the reason, and the absolute link to the Trail. The body also links to `/settings/notifications`.

Open `/settings/notifications` to flip the email toggle. The same page lists repositories you watch, with an unwatch control for each one. You can turn email off and keep the inbox entries.

## Automatic cleanup

Starforge prunes old notifications on an hourly job. Read notifications older than 90 days are deleted. Every notification older than 365 days is deleted. The inbox therefore keeps only recent history.

## API

The API mirrors the web pages under `/api/v1`. Every route below needs a bearer token with the `repo:read` scope.

- `GET /user/notifications?all=true&limit=N` returns `{"notifications": [...]}`.
- `POST /user/notifications/{id}/read` marks one notification read and returns it.
- `POST /user/notifications/read-all` returns `{"marked": n}`.
- `GET /repos/{owner}/{repo}/subscription` returns `{"mode": "watching" | "ignoring" | null}`.
- `PUT /repos/{owner}/{repo}/subscription` with `{"mode": "watching" | "ignoring"}` sets the watch.
- `DELETE /repos/{owner}/{repo}/subscription` deletes the watch row and answers `204`.
- `GET /repos/{owner}/{repo}/trails/{number}/subscription` returns `{"subscribed": bool}`.
- `PUT /repos/{owner}/{repo}/trails/{number}/subscription` with `{"subscribed": bool}` sets the subscription.
- `DELETE /repos/{owner}/{repo}/trails/{number}/subscription` resets to the participation default and answers `204`.

Each notification object carries id, repository as `owner/name`, Trail number, title, kind, reason, actor handle, absolute url, creation time, and read flag. Creation time uses the same format as the trails API.
