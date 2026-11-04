# Starforge M0.5 Forge Basics — Design

- **Date:** 2026-11-03
- **Status:** Approved section by section during brainstorming; this document is the written spec for review.
- **Parent spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md` (the "main spec"). Where this document is
  silent, the main spec and the M0 plan's global constraints apply.
- **Milestone:** M0.5, between M0 (hosting skeleton) and M1 (traces end to end).

## 1. Summary

M0 runs a usable git host, but only an administrator with shell access can create accounts, and repositories cannot
be renamed, archived, or deleted. M0.5 adds the views and operations a self-hosted instance needs day to day:

- **Accounts:** registration modes, invites, email verification, password reset, and account settings.
- **Repositories:** settings, an initial README, renames with redirects, archiving, and deletion with a 7-day
  restore window.
- **Code views:** branches, tags, compare, and syntax highlighting in the file view.
- **Site administration:** users, invites, repositories, and background jobs.
- **Foundations:** a durable jobs queue and optional email over SMTP.

### Out of scope (stays in its main-spec milestone)

| Item | Milestone |
|---|---|
| SSO-only registration mode, OIDC, TOTP two-factor, SSH keys | M3 |
| Transferring repositories between owners (matters once orgs exist) | M3 |
| htmx | M2 |
| Audit-log UI, rate limits, quotas | M5 |
| Highlighting in diffs | M1 or later |

The one exception to the M5 rate-limit deferral is the email throttle (§4.4), because open sign-up without it lets
anyone use the instance to flood an inbox.

## 2. Decisions

| # | Decision | Choice | Rationale |
|---|---|---|---|
| F1 | Email | Optional SMTP; without it, invite links are copied by hand and admins reset passwords | The allow-list mode and self-service password reset need verified addresses |
| F2 | Background work | A `jobs` table with workers inside `starforged` | Survives restarts, retries failures, and M1 ingest (main spec §7.7) reuses it |
| F3 | Highlighting | syntect with bat's syntax set (two-face), pure-Rust regex, CSS classes | No C dependencies; about 200 languages; the CSP forbids inline styles |
| F4 | Email delivery | Queued as jobs; lettre over SMTP with rustls | Pages never wait on the mail server; failures retry and are visible to admins |
| F5 | Default registration mode | `invite` | A new instance is closed until its admin decides otherwise |
| F6 | Renames | Old names redirect (301) to the new name for web, git, and API reads | Existing clones and links keep working |
| F7 | Deletion | Soft delete; the name stays reserved; restorable for 7 days; then purged by a job | Matches main spec §8.5 |

## 3. Configuration

Two new sections in `starforged.toml`, both optional and both overridable with `STARFORGE__SECTION__KEY`:

```toml
[registration]
mode = "invite"            # "invite" (default) | "open" | "domains"
allowed_domains = []       # lowercase domains; used only by "domains"

[mail]
url = ""                   # empty: no email
from = "Starforge <forge@example.com>"
```

`mail.url` forms:

| Form | Meaning |
|---|---|
| `smtp://user:pass@host:587` | SMTP with STARTTLS required; the connection fails rather than send in clear |
| `smtp://host:25?tls=none` | SMTP without TLS; accepted only when `host` is a loopback address |
| `smtps://user:pass@host:465` | SMTP over implicit TLS |
| `file:///path/to/dir` | Writes each message as an `.eml` file; for development and tests |

TLS uses rustls with the operating system's trust store, so mail servers with a private certificate authority work.

Startup validation fails when:
- `registration.mode` is `domains` and `mail.url` is empty, or `allowed_domains` is empty;
- `mail.url` is set but has another scheme, or `tls=none` names a non-loopback host;
- `mail.url` is set and `mail.from` is not a valid mailbox.

## 4. Accounts

### 4.1 Registration

Sign-up is at `/join`: handle, email, password, and an optional display name. It reuses M0's validators (reserved
handles; passwords of 10–1024 characters). The handle and email must be unused.

| Mode | Who can sign up |
|---|---|
| `invite` | Holders of a valid invite link `/join?invite=<code>`. |
| `open` | Anyone. |
| `domains` | Anyone whose email address is at one of `allowed_domains`. |

Only `open` and `domains` modes link to sign-up, from the sign-in page and the signed-out home page. An invite link
lets its holder sign up in every mode, because invites are issued by site admins.

Invites are single-use, expire after 7 days, and may be bound to one email address. An email-bound invite only
accepts that address. Codes are 256-bit random values stored as SHA-256 hashes.

### 4.2 Email verification

Only when mail is configured:
- A new account receives a verification link and cannot sign in until the link is used.
- The "verify your email first" message appears only after a correct password, so the sign-in form never reveals
  which accounts exist. The message offers a resend form: it takes an email address, answers identically whether or
  not an unverified account uses it, and obeys the throttle (§4.4).
- Signing up through an email-bound invite marks the address verified, since the invite was delivered there.

Without mail, accounts are active immediately and addresses stay unverified. Migration 0002 marks every existing
address verified, because M0 accounts were created by an administrator.

### 4.3 Email tokens

One mechanism serves every emailed link:

| Purpose | Link | Lifetime |
|---|---|---|
| Verify email | `/verify/<token>` | 24 hours |
| Confirm a new email address | `/verify/<token>` | 24 hours |
| Reset password (emailed, by the user or an admin) | `/reset/<token>` | 1 hour |
| Reset password (link shown to an admin when mail is off, §7) | `/reset/<token>` | 24 hours |

Tokens are 256-bit random values stored as SHA-256 hashes. Each works once. Issuing a token invalidates the same
user's earlier unused tokens with the same purpose.

### 4.4 Email throttle

At most one email per address per purpose every 5 minutes. A request inside the window gets the same response as
any other but sends nothing.

### 4.5 Password reset

- **With mail:** "Forgot password?" on the sign-in page leads to `/forgot`. Any submitted address gets the same
  answer: "If an account uses that address, we sent a link."
- **Without mail:** the "Forgot password?" link is hidden; a site admin generates a one-time link (§7).

Completing a reset signs out all of that user's web sessions. Personal access tokens are separate credentials and
keep working.

### 4.6 Account settings

All under `/settings`, for signed-in users:

| Page | Behavior |
|---|---|
| Profile | Display name. |
| Email | With mail: a confirmation link goes to the new address, which replaces the old one only when confirmed. Without mail: the change applies at once, unverified. |
| Password | Current password plus the new one. Success signs out the user's other sessions. |
| Sessions | Each web session's browser, IP, sign-in time, and last activity, with the current session marked. Revoke one, or sign out everywhere else. |
| Tokens | The M0 token page, moved under settings navigation. |
| Repositories | The user's deleted repositories still inside the grace period, each with Restore. |
| Delete account | Confirm by typing the handle. Refused while the user owns non-deleted repositories, or when the user is the only site admin. Purges the user's deleted repositories immediately and removes sessions, tokens, and collaborator grants. Audit entries survive with the actor cleared. |

### 4.7 Audit

Sign-up, email verification, password changes and resets, email changes, session revocation, and account deletion
are recorded in `audit_log`.

## 5. Repositories

### 5.1 Initial README

The new-repository form gains "Initialize with a README"; `POST /api/v1/user/repos` gains `readme: true`. The server
writes the first commit with git plumbing in the bare repository (`hash-object`, `mktree`, `commit-tree`,
`update-ref`) on the default branch. `README.md` contains the name as a heading and the description. The author and
committer are the user's display name (or handle) with their verified email, or `<handle>@users.noreply.<host>`
where `<host>` comes from `server.base_url`.

### 5.2 Settings and permissions

The settings page is `/{owner}/{repo}/settings`; the existing collaborators page joins its navigation. Permissions
follow main spec §6.1:

| Setting | Minimum permission |
|---|---|
| Description | maintain |
| Default branch (an existing branch) | maintain |
| Visibility, rename, archive and unarchive, delete | admin |
| Collaborators | admin (unchanged) |

Changing the default branch also points the bare repository's `HEAD` at it, so new clones check it out.

### 5.3 Rename and redirects

A rename records the old name in `repo_redirects`.
- Web pages, git `info/refs`, and API GETs on the old name answer `301` to the new name, keeping the rest of the path
  and the query.
- git follows a redirect on its first request and uses the redirected URL for the rest of the operation
  (`http.followRedirects=initial`, git's default), so existing clones keep pulling and pushing.
- A redirect is followed only when the viewer can read the target repository. Otherwise the old name answers exactly
  like a missing repository, so redirects never reveal a private repository.
- Creating or renaming a repository onto an old name removes that redirect.
- Redirects point at the repository id, so a chain of renames resolves in one hop.

### 5.4 Archive

An archived repository refuses pushes: both git receive-pack endpoints answer `403` with the plain-text body
`This repository is archived; pushes are disabled.` git shows that body to the pusher as `remote: …`. Pages show a
read-only banner. The API's repository JSON gains `archived`. Settings stay editable, including unarchive.

### 5.5 Delete, restore, purge

- Deleting requires typing `owner/name`. The repository then answers 404 everywhere (pages, git, API) and leaves
  every listing, but its name stays reserved.
- For 7 days the owning user (from account settings) or a site admin (from the admin pages) can restore it.
- A daily job purges deletions older than 7 days: it renames the directory into `data/tmp/`, deletes the database
  rows (collaborators and redirects cascade), then removes the directory. Each step is safe to repeat.

### 5.6 Audit

Visibility changes, renames, archive and unarchive, deletion, restoration, purges, and default-branch changes are
recorded in `audit_log`.

## 6. Code views

The repository navigation becomes Code · Commits · Branches · Tags · Settings (Settings for maintainers and up).

- **Branches** (`/{owner}/{repo}/branches`): the default branch first with a badge, then the rest by latest commit
  time; each row shows the last commit's summary, author, and age, and a "Compare" link against the default branch.
- **Tags** (`/{owner}/{repo}/tags`): newest first, by tagger date for annotated tags and commit date otherwise; each
  row shows the short commit id and the annotation's first line.
- **Compare** (`/{owner}/{repo}/compare` with a two-ref picker; `/{owner}/{repo}/compare/{base}...{head}`):
  - commits reachable from `head` but not from `base`, newest first, at most 250 with an "and N more" line;
  - the diff from the merge base to `head`, with the commit page's limits (10,000 lines, 4 MiB);
  - refs may contain `/`; a valid ref cannot contain `...`, so the split is unambiguous;
  - both refs are resolved to object ids before git runs; an unknown ref answers 404;
  - comparisons stay within one repository.
- **Highlighting in the file view:**
  - the language comes from the file name, then from a shebang line;
  - each line renders as self-contained HTML (spans closed and reopened at line breaks), so line anchors `#L<n>`
    work and the anchored line is highlighted;
  - syntect escapes file text; tests prove that HTML in source files is escaped;
  - files over 512 KiB, or with a line over 5,000 characters, render escaped without highlighting;
  - highlighting runs on the blocking thread pool;
  - one dark theme matches the current interface; `/static/highlight.css` is generated once at startup, with class
    names prefixed `hl-`.

## 7. Site administration

The admin area is `/admin`, for site administrators only; everyone else gets 404. Every form carries the CSRF token,
and every action is recorded in `audit_log`.

| Page | Contents |
|---|---|
| Overview | Counts of users, repositories, and queued and failed jobs; the registration mode and mail status (from config, read-only); the git version. |
| Users | A searchable list. Per user: suspend or unsuspend (suspending also ends their web sessions; their tokens already stop working); grant or revoke site admin; reset password (by email when mail is configured, otherwise a one-time link shown to the admin, valid 24 hours); delete (the rules of §4.6). Create a user directly (the address counts as verified), or invite them instead. |
| Invites | Create an invite, optionally bound to an address (emailed when mail is configured; the link is shown once either way). List them with status: pending, used, expired, or revoked. Revoke. |
| Repositories | Every repository, including private and deleted ones, with owner, visibility, and archived state. Restore or purge now for deleted ones. |
| Jobs | Queued, running, and failed jobs with attempt counts and the last error. Retry or delete failed ones. |

Guards: the last active site admin cannot be demoted, suspended, or deleted, and admins cannot suspend or delete
themselves from the admin pages.

## 8. Jobs

### 8.1 Table and claiming

`jobs` holds a kind, a JSON payload, a state (`queued`, `running`, `done`, `failed`), the time it is due, the attempt
count, the last error, a lease expiry, and an optional deduplication key.

A worker claims a due job with `UPDATE jobs SET state = 'running', … WHERE id = $1 AND state = 'queued'` and checks
the affected row count. This works identically on SQLite and Postgres, and two workers can never claim the same job.

### 8.2 Workers

- `serve` runs two workers, so one long `git maintenance` run never delays a password-reset email.
- Enqueueing wakes a worker immediately; otherwise workers look for due jobs every 5 seconds.
- A running job holds a 10-minute lease. A job still `running` after its lease expires (the process died) returns to
  `queued`.

### 8.3 Retries and retention

| Outcome | Next state |
|---|---|
| Success | `done`; deleted after 7 days |
| Failure, attempts left | `queued`, due after 1 min, 5 min, 30 min, then 2 h |
| Fifth failure | `failed`; kept for 30 days for the admin Jobs page |

### 8.4 Scheduled work

| Job | When |
|---|---|
| Purge deletions older than 7 days | Daily |
| Delete old `done` and `failed` jobs | Daily |
| Remove expired web sessions and email tokens, and invites that expired more than 30 days ago | Hourly |
| `git maintenance run --auto` for one repository | After each successful push to it |

Scheduled kinds set a deduplication key covered by a partial unique index over pending jobs
(`WHERE state IN ('queued', 'running')`; both engines support it), so at most one copy of each is pending.

## 9. Mail

- Messages are plain text, rendered from templates: verify email, confirm a new email address, reset password, and
  invite.
- A mail job's payload holds the message, including its link and token. The worker blanks the message after sending;
  the hourly cleanup blanks failed mail jobs older than 7 days, by which time every link in them has expired (invite
  links last 7 days; email tokens at most 24 hours).
- `starforged admin mail test --to <address>` sends one message directly, without the queue, and prints the result,
  for checking SMTP settings.

## 10. Routes

| Area | Routes |
|---|---|
| Sign-up and recovery | `GET/POST /join`; `GET /verify/{token}`; `POST /verify/resend`; `GET/POST /forgot`; `GET/POST /reset/{token}` |
| Account settings | `/settings/profile`, `/settings/email`, `/settings/password`, `/settings/sessions`, `/settings/tokens`, `/settings/repositories`, `/settings/delete` (each `GET` plus its `POST` actions) |
| Repository | `/{owner}/{repo}/settings` (`GET` plus `POST` actions for general settings, visibility, rename, archive, unarchive, delete); `/branches`; `/tags`; `/compare`; `/compare/{*spec}` |
| Admin | `/admin`, `/admin/users`, `/admin/users/{handle}`, `/admin/invites`, `/admin/repositories`, `/admin/jobs` (each `GET` plus its `POST` actions) |
| API | `POST /api/v1/user/repos` accepts `readme`; repository JSON adds `archived`; reads of a renamed repository answer `301` |
| Static | `/static/highlight.css` |

The new top-level path segments `join`, `verify`, `forgot`, and `reset` join the reserved handles (`admin` and
`settings` are already reserved).

## 11. Data model (migrations 0002 onward, both engines)

M0.5 is built in three implementation plans; each adds its own numbered migration files, in the order the plans run.

| Table | Change |
|---|---|
| `users` | Add `email_verified` (0/1); set to 1 for existing rows that have an email. |
| `repos` | Add `archived_at` and `deleted_at` (nullable times). |
| `invites` | New: code hash (unique), optional email, creator, creation and expiry times, used time and user, revoked time. |
| `email_tokens` | New: user, purpose (`verify_email`, `change_email`, `reset_password`), token hash (unique), the address it was sent to, creation, expiry, and use times. |
| `jobs` | New: as §8.1, with an index on `(state, run_at)` and the partial unique index on the deduplication key. |
| `repo_redirects` | New: `(owner_id, lower_name)` primary key pointing at `repo_id`; rows cascade with the repository and the owner. |

The M0 portability rules hold: ascending `$n` placeholders, integer booleans and unix times, and identical tables,
constraints, and indexes on both engines.

## 12. Security notes

- **No existence leaks:** soft-deleted repositories answer exactly like missing ones; redirects require read access to
  the target; password reset and resend answer identically for unknown addresses; the "verify first" message needs a
  correct password; the admin area answers 404 to non-admins.
- **Secrets:** invite codes and email tokens are stored only as SHA-256 hashes and compared through their hash; mail
  bodies holding links are blanked after sending.
- **Sessions:** password changes and resets end other sessions; suspension ends all of the user's sessions.
- **Escaping:** highlighted source is escaped by syntect before it is marked safe in templates; tests cover it.
- **CSRF:** every new form carries the session's CSRF token; sign-up, forgot-password, resend, and reset forms (used
  while signed out) use the M0 pre-session CSRF cookie.

## 13. Testing

The M0 layers continue: unit tests per crate, integration tests against the in-process server, and both engines
through `scripts/check.sh`. The test harness gains an inbox: the `file://` transport writes to a temporary
directory, and helpers read links from the newest message.

Behaviors with tests:
- sign-up in each mode, and email verification blocking sign-in;
- reset links that work once, expire, and end other sessions;
- the email throttle;
- maintain versus admin permissions on repository settings;
- rename redirects, including `git clone` of an old URL, and 404 when the target is private;
- archived repositories refusing pushes, with the message git shows;
- delete, then 404, then restore; the purge job removing the directory;
- escaped highlighting and line anchors;
- admin pages answering 404 to non-admins; the last-admin guards;
- job claiming exclusivity, retries with backoff, lease expiry, and deduplication.

The end-to-end binary test adds an open-mode sign-up with `file://` mail: sign up, read the `.eml`, verify, sign in.

## 14. Delivery

An implementation plan under `docs/superpowers/plans/`, then a task-by-task build with a review after every task and
a whole-branch review at the end, as in M0. After merging, the running instance restarts on the new binary and
applies migration 0002 automatically.
