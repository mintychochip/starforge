# Glossary

## Purpose

This page defines each approved term and the code name for that term. A writer uses the approved term and never the synonym. A reviewer uses this page to reject a synonym in review. A developer uses the code column to find the type, table, or function for the term.

## Scope

The table defines words that appear in code, in the database schema, and in the user interface. A row gives one short definition and the exact code location. A row also links to the page that uses the term most. Prose in the other pages follows the same terms.

## Definitions

### Identity and access

| Term | Meaning | Code name | Pages |
|---|---|---|---|
| repository | A git repository that Starforge hosts | `repos`, `RepoRow` | [git hosting](git-hosting.md) |
| owner | A user or an org that owns repositories | `owners` table | [web and auth](web-and-auth.md) |
| user | One local account with a unique handle | `users`, `UserRow` | [web and auth](web-and-auth.md) |
| org | One named group with members and a base permission | `owners` with `kind = org`, `orgs` | [web and auth](web-and-auth.md) |
| team | One org subgroup that grants a permission level | `teams` table | [web and auth](web-and-auth.md) |
| collaborator | One direct per-repository grant to a user | `collaborators` table | [web and auth](web-and-auth.md) |
| member | One user with an explicit grant: ownership, org base, team, or collaborator grant | `is_repo_member` | [web and auth](web-and-auth.md) |
| permission level | One of read, triage, write, maintain, or admin | `Permission` in `permission.rs` | [security](security.md) |
| visibility | One of public, internal, or private | `RepoRow.visibility` | [git hosting](git-hosting.md) |
| handle | The unique account name | `owners.handle` | [web and auth](web-and-auth.md) |
| uploader | The user who uploaded one session | `sessions.uploader_id` | [sessions](sessions.md) |
| sign-in page | The page that starts a web session | `pages/login.rs` | [web and auth](web-and-auth.md) |

### Collaboration

| Term | Meaning | Code name | Pages |
|---|---|---|---|
| Trail | The collaboration object with intent, changes, reviews, and gates | `trails`, `TrailView` | [trails](trails.md) |
| change | A proposed head ref into a base branch of a Trail | `changes`, `refs/for` | [trails](trails.md) |
| revision | An immutable snapshot of a change | `revisions`, `refs/trails/<n>/changes/<k>/rev/<r>` | [trails](trails.md) |
| review | A verdict and body on a revision | `reviews`, `ReviewView` | [trails](trails.md) |
| thread | A line-anchored discussion on a change | `review_threads`, `ThreadView` | [trails](trails.md) |
| check | A commit status record with a context and a state | `checks`, `submit_status` | [trails](trails.md) |
| gate | A merge requirement on a protected branch | `gates.rs`, `evaluate_gates` | [trails](trails.md) |
| gate rule | One stored gate configuration for branch patterns | `gate_rules`, `GateRuleDto` | [trails](trails.md) |
| status | The API name for a commit status record. Prose uses check | `StatusDto`, `combined_status` | [trails](trails.md) |
| import | Copy data into Starforge one time | `import_state`, `Job::ImportRepo` | [import and mirrors](import-and-mirrors.md) |
| mirror | A repository that copies refs from another repository | `repo_remotes`, `repos.mirror` | [import and mirrors](import-and-mirrors.md) |

### Sessions and traces

| Term | Meaning | Code name | Pages |
|---|---|---|---|
| session | One agent conversation that the CLI captures | `sessions`, `SessionRow` | [sessions](sessions.md) |
| web session | A browser sign-in record | `web_sessions` table | [web and auth](web-and-auth.md) |
| trace | The captured event stream of a session | Trace Format v1 | [trace and redaction](trace-and-redaction.md) |
| segment | One uploaded slice of a session | `segments`, `SegmentRow` | [sessions](sessions.md) |
| capture | Read an agent store and write a session | `starforge-capture` | [sessions](sessions.md) |
| adapter | The code that reads one agent format | `starforge-capture` adapters | [sessions](sessions.md) |
| redaction | Removal of a secret from a value | `starforge-redact` | [trace and redaction](trace-and-redaction.md) |
| quarantine | Block access to a session that has a secret | `sessions.quarantine` | [trace and redaction](trace-and-redaction.md) |
| publish | Make a session on a public repository visible to all readers | `sessions.visibility = published` | [sessions](sessions.md) |
| purge | Delete data permanently | `purge_deleted_repos` | [sessions](sessions.md) |
| spool | Pending uploads on the CLI before a push | `starforge spool` | [cli](cli.md) |
| blob | Content-addressed bytes for trace and turns | `blobs`, `starforged-blob` | [storage and database](storage-and-database.md) |
| ULID | The unique identifier that names a session | `sessions.ulid` | [sessions](sessions.md) |

### Operations and security

| Term | Meaning | Code name | Pages |
|---|---|---|---|
| data directory | The directory with the database, repositories, and blobs | `storage.data_dir` | [configuration](configuration.md) |
| configuration | The values in `starforged.toml` and the environment | `crates/starforged/src/config.rs` | [configuration](configuration.md) |
| job | One background work unit with a retry ladder | `jobs`, `Job` in `jobs.rs` | [operations](operations.md) |
| queue | The database-backed list of pending jobs | `jobs` table | [operations](operations.md) |
| cursor | A resume position for capture or import | `cursor_kind`, `cursor_page`, `cursor_number` | [import and mirrors](import-and-mirrors.md) |
| webhook | One subscribed HTTP callback with an event filter | `webhooks`, `webhooks.rs` | [webhooks](webhooks.md) |
| delivery | One webhook HTTP attempt with its result | `webhook_deliveries`, `Job::WebhookDelivery` | [webhooks](webhooks.md) |
| token | A personal access token or an OAuth token | `access_tokens`, `tokens.rs` | [http api](http-api.md) |
| scope | A permission string on a token | `Scope` in `tokens.rs` | [http api](http-api.md) |
| deploy key | One repository SSH key for bots and mirrors | `sshkeys.rs`, `deploy_keys` | [git hosting](git-hosting.md) |
| SSRF | A forced request from the server to an inside address | `host_allowed` in `webhooks.rs` | [security](security.md) |

### Rules for correct use

Sentences in the other pages use the terms in the tables. A writer adds a new term to this glossary or to the project dictionary in [ste100.md](ste100.md). The writer does this before the term appears in prose. A reviewer checks a new term against the dictionary and the code column. A row changes in the same commit as the code change. See the [maintenance page](maintenance.md) for the change procedure.

### Usage notes

The dictionary splits session and web session.
A session is one agent conversation that the CLI captures.
A web session is one browser sign-in record. The code keeps the split
in table names `sessions` and `web_sessions`.

The dictionary splits check and status.
Prose uses check for the commit status concept. The API resource names
`/statuses`, `StatusDto`, `submit_status`, and `combined_status` stay in code form.

The dictionary splits owner and uploader.
An owner is a user or an org in the handle namespace. An uploader is
the user who uploaded a session. Code keeps the split in `owners` and
`sessions.uploader_id`.

### Rejected synonyms

The table lists common synonyms and the approved term for each one.
The project dictionary in [ste100.md](ste100.md) is authoritative, and this table is a subset.
Code names, CLI paths, and native agent files keep their spelling. A writer replaces a synonym only when it names the same concept.

| Rejected word | Approved term |
|---|---|
| `repo` | repository |
| `version` | revision |
| `comment` | review |
| `comment thread` | thread |
| `rule` | gate rule |
| `log in` | sign in |
| `boot` | start |
| `set up` | configure |
| `since` | because |
| `may`, `might` | can |
| `should`, `shall` | must |
| `e.g.` | for example |
| `i.e.` | that is |
| `leverage` | use |
| `login page` | sign-in page |
| `username` | handle |
| `PR` | change |
| `transcript` for a trace | trace |
| `chunk` | segment |
| `collect` | capture |
| `connector` | adapter |
| `scrub` for trace secrets | redact |
| `isolate` | quarantine |
| `share` | publish |
| `remove data` | delete or purge |
| `API key` | token |
| `token permission` | scope |
| `replica` | mirror |
| `data dir` | data directory |
| `config` | configuration |
| `launch` | start |
| `kill` | stop |
| `ensure` | make sure |
| `utilize` | use |
| `prior to` | before |
| `subsequent to` | after |

## Verification

Execute each step and confirm the expected result.

- Run `python3 scripts/ste_check.py docs/technical/glossary.md`.
- Confirm the checker reports 0 errors and 0 warnings.
- Confirm each code name in the tables matches the source files.
- Confirm each link in the tables points at an existing page.
- Confirm a new term appears in `ste100.md` before prose uses the term.

## Related

Read the [writing rules](ste100.md) for the full project dictionary. Read [architecture](architecture.md) for the crate layer map. Read [operations](operations.md) for jobs, health, and backup. Read [testing](testing.md) for the test layers and engine matrix.
