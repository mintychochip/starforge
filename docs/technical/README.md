# Starforge technical documentation

## Purpose

This directory holds the technical documentation for the Starforge
repository. The documents explain how the code works, why it has this shape,
and how to change it without damage.

The audience is a developer or an operator who must maintain the code. The
documents do not replace the user guide in `docs/user` or the administration
guide in `docs/admin`.

## Rules

The documents use ASD-STE100 Simplified Technical English. Read
[ste100.md](ste100.md) before you change a page. The rules make the text
short, direct, and unambiguous.

Each page except this index, the style guide, the glossary, and the maintenance page lists its source paths in a `ste-sources` comment. The checker
confirms that the paths exist and that the text follows the mechanical rules.

## Document map

| Page | Content |
|---|---|
| [architecture.md](architecture.md) | Process model, request flow, crate layers, data flow |
| [crates.md](crates.md) | Every workspace crate, its job, and its tests |
| [configuration.md](configuration.md) | Configuration keys, precedence, validation, secrets |
| [storage-and-database.md](storage-and-database.md) | Data directory, schema, migrations, blob store, backup |
| [accounts-and-permissions.md](accounts-and-permissions.md) | Accounts, registration, sign-in, tokens, orgs, teams, permissions |
| [repositories.md](repositories.md) | Repository model, creation, rename, transfer, archive, delete |
| [git-hosting.md](git-hosting.md) | Smart HTTP, SSH, ref policy, push hooks, merge |
| [trails.md](trails.md) | Trail model, changes, revisions, reviews, gates |
| [web-and-auth.md](web-and-auth.md) | Web routes, templates, web sessions, CSRF, sign-in |
| [http-api.md](http-api.md) | REST API conventions, scopes, errors, pagination |
| [sessions.md](sessions.md) | Capture, spool, sync, ingest, quotas, viewer |
| [trace-and-redaction.md](trace-and-redaction.md) | Trace Format v1, segments, redaction, quarantine |
| [search.md](search.md) | Tantivy index, query path, code search |
| [webhooks.md](webhooks.md) | Events, signatures, delivery, retries |
| [import-and-mirrors.md](import-and-mirrors.md) | Git import, GitHub import, pull and push mirrors |
| [cli.md](cli.md) | `starforge` commands, discovery, hooks, spool |
| [operations.md](operations.md) | Startup, jobs, health, metrics, doctor, backup |
| [security.md](security.md) | Trust boundaries, authentication, authorization, abuse controls |
| [testing.md](testing.md) | Test layers, engine matrix, browser tests, CI |
| [glossary.md](glossary.md) | Approved terms and their code names |
| [maintenance.md](maintenance.md) | How to keep the documents correct |

## Check

Run the checker before you commit a document:

```bash
python3 scripts/ste_check.py --strict
python3 -m unittest discover -s scripts/tests
```

CI runs the same two commands. A failure blocks the merge. The checker needs Python 3.11 or newer.

## Maintenance

Read [maintenance.md](maintenance.md). Change the page in the same commit as
the code. Do not wait for a later cleanup.
