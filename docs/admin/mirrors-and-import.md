# Mirrors and import

Repositories can be created from an existing git repository, and any
repository can continuously sync with external remotes (spec §8.6). All of it
goes through one outbound URL policy and one sealed-credential store.

**One-time import.** `POST /api/v1/user/repos` and `POST /api/v1/orgs/{org}/repos`
accept an `"import": {"url", "auth": {"kind": ...}}` body, and the web
**New repository** form has an "Import from URL" section. The repository is
created empty in the `pending` state and the `ImportRepo` job runs
`git fetch --prune <url> +refs/heads/*:refs/heads/* +refs/tags/*:refs/tags/*`
(only branches and tags; `refs/notes/*`, `refs/pull/*`, and friends never
arrive), then points `HEAD` at the remote's default branch (`git ls-remote
--symref`, falling back to `main`). State moves `pending → running →
done|failed`; pushes are refused while `pending` or `running`. A failed
import shows the scrubbed error with **Retry import** and **Delete import**
(the repository returns to a normal empty one).

- **HTTPS** imports carry a username and password/token in the `auth` object.
- **SSH** imports (`ssh://…` or scp-like `user@host:path`) are generated an
  ed25519 deploy keypair server-side: the public key is shown (response
  field `ssh_public_key`, and beside the import banner) for installing
  upstream, the repository waits in `pending`, and **Start import** (or
  `POST …/import/start`) runs the fetch once the key is installed.

**Pull mirrors.** `PUT /api/v1/repos/{owner}/{repo}/mirror/pull`
`{"url", "auth", "interval_secs"}` (≥ 300, default 3600, at most 30 days)
configures one pull mirror per repository (web: **Settings → Mirrors**).
The `PullMirror` job fetches with the import refspecs and `--prune`, runs the
same branch-move ingest as post-receive (revisions and mergeability), and
dispatches `push` webhooks with `sender: null`; it re-enqueues itself at the
interval (after a failure, at a 300 s backoff). `POST …/mirror/pull/sync` is
"sync now" (deduplicated per repository). While enabled,
`repos.mirror` is true: direct branch/tag pushes are refused and Trail
merges are refused with "this repository is a pull mirror", while `refs/for`,
comments, and reviews keep working. `POST …/mirror/pull/enabled`
`{"enabled": bool}` toggles without forgetting the configuration, and
`DELETE` removes the mirror; both restore pushes.

**Push mirrors.** `POST /api/v1/repos/{owner}/{repo}/mirror/push`
`{"url", "auth"}` adds one (at most 10, **Settings → Mirrors** lists them
with their last result and error). After every accepted push, the post-receive
scan enqueues one `PushMirror` job per remote at now + 30 s, deduplicated per
remote, so pushes inside the window coalesce. The job runs
`git push --prune <url> +refs/heads/*:refs/heads/* +refs/tags/*:refs/tags/*` —
a true mirror of branches and tags (`refs/trails/*` and `refs/for/*` never
leave). Each run updates `last_attempt_at`, `last_success_at`, and the scrubbed
`last_error`; a failure backs off 300 s, a success does not reschedule until
the next push. `POST …/mirror/push/{id}/sync` runs immediately (deduplicated
per remote) and `DELETE …/mirror/push/{id}` removes one. Mirrors never block
the repository's own pushes.

**Credential storage.** HTTPS credentials and SSH private keys are stored only
sealed at rest: XChaCha20-Poly1305 under an HKDF-SHA256 key derived from
`security.secret_key` (salt `"starforge"`, info `"mirror-credentials-v1"`).
They are never displayed after saving — every view carries only
`has_credentials: bool` and, for SSH, the public key — and they never travel
in argv, URLs, logs, or error messages (HTTPS credentials become an
`http.extraHeader` via `GIT_CONFIG_*` environment entries; SSH private keys
are written to a `0600` temporary file for one command and removed, including
on failure; git stderr is scrubbed of URL userinfo before it is stored as
`last_error` or rendered). `Debug` output of credential values is redacted
likewise.

**A `secret_key` warning.** The seal is derived from `security.secret_key`.
Changing or losing it makes every stored remote credential unreadable: jobs
fail (the import goes `failed`) with the clear error
"credentials unreadable; re-enter them", never a panic. Re-enter the
credentials on the settings page or the update/start endpoints to recover.

**URL policy.** Every import/pull/push URL — API and web, at save time and
again before every fetch or push — passes
`Core::check_remote_url`:

- Allowed schemes: `https`, and `ssh` (`ssh://` and scp-like `user@host:path`),
  plus `http` only when the resolved host is loopback **and**
  `remotes.allow_file_urls` is set. Refused (422): `file://`, local paths,
  `ext::`, `fd::`, and every other transport (git runs under
  `-c protocol.allow=never` with the allowed schemes explicitly allowed),
  unless `remotes.allow_file_urls` is set (default false; documented as
  test-only — it also admits loopback hosts).
- Hosts are resolved and refused by the webhook SSRF rules — private,
  loopback (unless flagged), link-local including the `169.254.169.254`
  metadata endpoint, unique-local, multicast, and other non-global ranges;
  IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped and classified as its inner
  IPv4 address — unless the test flag admits loopback.
- The first allowed resolved address is pinned (`http.curloptResolve` for
  HTTPS, `HostName` with `HostKeyAlias` for SSH), and git refuses redirects
  (`http.followRedirects=false`), so a DNS change between the check and git's
  own lookup cannot redirect the connection; the run-time re-check fails
  closed if the host has rebound to a private address.
- Dash-prefixed URLs, users, and hosts are refused outright (SSH
  `-oProxyCommand=` injection), as are whitespace/control characters. A
  password pasted into an `http`/`https`/`ssh` URL's userinfo is stripped: the stored and returned
  URL never carries it (`file://` URLs carrying userinfo are refused instead).

**Access and audit.** Mirror configuration is maintain+ (the `mirrors`
capability); below-threshold readers get `403`, non-readers `404`, and readers
can `GET` the configuration. Import mirrors the same matrix (readers see the
state via `GET …/import`; start/delete need maintain+). Archived repositories
refuse new configuration, imports, and mirror additions with `422` while
staying readable. Scheduled pull syncs pause with "repository is archived; mirror paused" and
resume on unarchive; "sync now" returns `422`, push mirrors keep running, and enable/disable/delete
stay allowed. Every configuration change writes one audit row (`repo.import`, `mirror.create`,
`mirror.update`, `mirror.delete`, plus `mirror.credentials_changed` when credentials are set or
replaced). Web forms are CSRF-gated like every other state-changing form.

**API.** `GET`/`DELETE /repos/{owner}/{repo}/import` and
`POST …/import/start` (optional body replaces credentials); `PUT`/`GET`/`DELETE
/repos/{owner}/{repo}/mirror/pull`, `POST …/mirror/pull/sync`,
`POST …/mirror/pull/enabled`; `POST`/`GET …/mirror/push`,
`DELETE …/mirror/push/{id}`, `POST …/mirror/push/{id}/sync`. The create-repo
bodies carry `"import"` as above. Responses carry `url`, `auth`,
`has_credentials`, `ssh_public_key` (SSH), the interval and enabled flag (pull),
and the last attempt/success times and scrubbed `last_error` — never a secret.

An empty repository (no Trails yet, not archived) can import its issues and pull
requests from GitHub, from **Settings → GitHub import**
(`/{owner}/{repo}/settings/github-import`, repository admins only) or the API below.
The repository must already hold the git history (pushed, mirrored, or imported),
since pull-request heads are fetched from `refs/pull/<n>/head`.

**Prerequisites and token.** A GitHub personal access token with read-only access:
the `repo` scope for a private repository, or public-read access for a public one.
The token is sealed at rest (the credential box), deleted when the import finishes
or fails, and never logged or rendered. Outbound requests go only to
`github.api_url` (default `https://api.github.com`, GitHub Enterprise allowed),
with a 30 s timeout, a 10 MiB response cap, no redirects, and pagination that
follows only same-origin `Link: rel="next"` URLs.

**Mapping.** GitHub numbers are preserved (issues and PRs share one number space;
new Trails continue after the highest imported number, gaps stay gaps), and an
import refuses a repository that already has Trails (`422`):

| GitHub | Starforge |
|---|---|
| Issue | Trail without changes (open or closed) |
| Pull request | Trail with one `imported` change (open, closed, or merged); head from `refs/pull/<n>/head` |
| Issue / PR comment | Trail comment |
| Review comment | Review thread on revision 1 where its line exists, else a quoted Trail comment |
| Labels / assignees | Labels by name; assignees by matched local user |
| Author | Local user with a matching verified email, else a placeholder |

**Placeholders.** When no local user matches the GitHub author's verified email,
the author column stays empty and the original GitHub handle renders as
`handle (imported)` — escaped text, never a link to a local account. Assignees
who match no local repository member are dropped and listed in the import
summary (the settings page and the API status). Labels are created by name.
Imported bodies are Markdown through the sanitizing pipeline. The import writes
one `trail.imported` timeline row per Trail, dispatches no webhooks, and records
`repo.github_import_started` / `repo.github_import_finished` audit rows.

**Rate limits and resumption.** A `403`/`429` with `X-RateLimit-Remaining: 0` or
`Retry-After` pauses the import at its cursor and re-enqueues the job at the
reset time (capped at 1 h) — not a failure. Other errors follow the retry
ladder; after 5 failures the import is `failed` with the scrubbed error, and the
sealed token is deleted either way. An import runs once per repository: every
object is keyed by its GitHub id, so a resumed run never duplicates a Trail,
comment, or review.

**API.** `POST /api/v1/repos/{owner}/{repo}/import/github` with
`{"repository": "octo/proj", "token": "…"}` starts the import (admin only;
below-threshold callers get `403`, non-readers `404`, archived or non-empty
repositories `422`) and answers `202` with the status object. The token is
accepted only in the body and is never echoed. `GET` on the same path reports
the status for readers: `state` (`pending`, `running`, `rate_limited`,
`completed`, `failed`), the cursor, the object counts
(`issues_count`, `pulls_count`, `comments_count`, `reviews_count`,
`review_comments_count`), `dropped_assignees`, `has_token`, and the last
scrubbed `error`.
