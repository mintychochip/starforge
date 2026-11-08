# Documentation maintenance

## Purpose

This page defines how to keep the technical documents correct. The documents
describe code that changes. A document that no longer matches the code is a
defect.

## Rule

Change the document in the same commit as the code change. Do not open a
separate cleanup task. The reviewer must reject a behavior change without a
document change.

## Source anchors

Each page except this one, the index, the glossary, and the style guide has a
comment with its source paths:

```markdown
<!-- ste-sources
crates/starforge-format/src/session.rs
crates/starforge-format/src/events.rs
-->
```

The checker fails when a path moves or disappears. When you move a file,
update every page that lists the old path.

The comment is a list of entry points, not every file. List the files that a
reader must open to verify the page.

## Change triggers

| Change | Required document work |
|---|---|
| New or removed crate | Update [crates.md](crates.md) and [architecture.md](architecture.md) |
| New or changed config key | Update [configuration.md](configuration.md) and the admin guide |
| New registration mode or auth factor | Update [accounts-and-permissions.md](accounts-and-permissions.md) and [security.md](security.md) |
| New repository lifecycle state | Update [repositories.md](repositories.md) |
| New or changed route | Update [web-and-auth.md](web-and-auth.md) or [http-api.md](http-api.md) |
| New or changed CLI command | Update [cli.md](cli.md) |
| New migration or table | Update [storage-and-database.md](storage-and-database.md) |
| New agent adapter | Update [sessions.md](sessions.md) and [trace-and-redaction.md](trace-and-redaction.md) |
| New webhook event | Update [webhooks.md](webhooks.md) |
| New permission or scope | Update [security.md](security.md), [http-api.md](http-api.md), and [glossary.md](glossary.md) |
| New gate field or merge rule | Update [trails.md](trails.md) |
| New job kind | Update [operations.md](operations.md) |
| New test layer or CI job | Update [testing.md](testing.md) |

## Review checklist

The reviewer checks the facts first and the style second.

1. Does each claim match the source?
2. Does the page list the source paths?
3. Does the page link to the related pages?
4. Does the page use the approved terms from [glossary.md](glossary.md)?
5. Does the page omit a behavior that a maintainer must know?
6. Does the check pass?

## Check the documents

Run both commands before you commit:

```bash
python3 scripts/ste_check.py --strict
python3 -m unittest discover -s scripts/tests
```

The first command checks the text, the source paths, the links, the indexes,
and the crate coverage. The second command tests the checker.

## Add a page

1. Copy the section order from a related page.
2. Write the purpose and the scope.
3. Describe the behavior and the failure modes.
4. Add the interfaces and the verification paths.
5. Add the `ste-sources` comment.
6. Add the page to the table in [README.md](README.md).
7. Run the checks.

## Move or delete code

1. Find the old path in `docs/technical`.
2. Update the page that owns the behavior.
3. Update the `ste-sources` comment.
4. Run the checks.

When you delete a behavior, delete its page section. Do not keep a paragraph
about code that no longer exists.

## Audit

Run one audit in each release cycle:

- Read [crates.md](crates.md) against the workspace members.
- Read [configuration.md](configuration.md) against the configuration
  structure.
- Read [http-api.md](http-api.md) against the OpenAPI document.
- Read [glossary.md](glossary.md) against the terms in the pages.
- Run the checker and the tests.

## CI

The `docs` job in `.github/workflows/ci.yml` runs the checker and the tests.
The job uses the Python version on the runner. Beyond the checkout step, the two Python commands need no network access.
