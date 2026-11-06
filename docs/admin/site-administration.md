# Site administration

Admins manage the instance under **Admin** (`/admin`): instance counts with the sign-up mode and mail
status, then **Users**, **Invites**, **Repositories**, **Organizations**, and **Jobs** tabs. Users can be created
(pre-verified), suspended, granted or revoked admin, deleted, or issued a password reset; invites are
created and revoked; deleted repositories are restored or purged before the daily job removes them for
good; failed background jobs are retried or dropped.

Every `/admin` page and action answers 404 to anyone who is not a site admin, so the area is
indistinguishable from a missing page. Guards refuse to suspend or delete yourself, and the last active
admin cannot be suspended, demoted, or deleted. Each admin action is recorded in the audit log.

Every state-changing action writes exactly one append-only audit row
(`crates/starforged-db/src/audit.rs`): the actor, the action (for example
`auth.login`, `repo.visibility`, `session.publish`, `user.suspend`), the
target (`user:alice`, `repo:alice/proj`, `token:12`, `session:<ULID>`,
`job:7`, `org:acme`, `team:acme/core`), a detail string, the client IP and
user agent where the caller supplies them (sign-ins carry both; most other
actions record empty values), and the timestamp. Refused actions write no
row, except failed sign-ins (`auth.login_failed` with the normalized login
name as the target, including unknown names) and refused sign-ins over a
limit (`auth.login_rate_limited`). Audit rows never contain session
transcript content, tokens, or other secrets.

Site admins read the log at `/admin/audit` (newest first, 50 per page with a
keyset cursor; filters for actor handle, action exact or prefix like
`session.`, target substring, and from/to dates) and through
`GET /api/v1/admin/audit?actor=&action=&target=&from=&to=&after=&limit=`
with an `admin`-scoped token. Non-admins get 404 on the page, and the API
requires a site admin. Columns (time, actor, action, target, IP, user agent)
are escaped.

New instances are invite-only: sign-up needs an invite link from a site admin. Until the admin pages ship, create
accounts with `starforged admin user create`. Set `registration.mode = "open"` to let anyone sign up, or `"domains"`
with `registration.allowed_domains` to accept only addresses at those domains (this mode requires email).

Email is optional. With `[mail]` configured, new accounts confirm their address before they can sign in, the sign-in
page offers "Forgot password?", and invites can be emailed. `smtp://` always uses STARTTLS;
`smtp://localhost:25?tls=none` is accepted only for a mail server on the same machine. Check the settings with:

```bash
./target/release/starforged admin mail test --to you@example.com
```

For local development, `url = "file:///tmp/starforge-mail"` writes each message to that directory instead of sending
it.

Signed-in users manage their display name, email address, password, sessions, and tokens under **Settings**, and
can delete their account there once they own no repositories. Account deletion requires typing the account's
handle to confirm, and is refused while the account owns repositories that are not deleted, is the only
active site administrator, or is the only owner of an organization (make another user an admin/owner first).
It deletes every session the account uploaded — through the same session-delete path as a session delete,
so blob reference counts are decremented and index documents are removed — before the user row itself;
tokens and collaborator grants go with the account, deleted repositories are purged, and audit entries stay
with the actor cleared. If a deletion is interrupted, rerunning it finishes the job (idempotent).
