# CI supplier usage adapters — design

- **Date:** 2026-11-08
- **Status:** proposed; implementation starts with GitHub Actions and Buildkite.
- **Parent:** `docs/superpowers/specs/2026-11-03-starforge-design.md` §M6,
  `crates/starforged-core/src/ci_usage.rs`.

## Goal

Read CI usage from the external suppliers a repository is linked to and show
it on the existing CI usage page. Starforge never enforces an external
supplier's limits: the supplier meters and enforces them. The native runner
remains the only supplier Starforge enforces.

## Suppliers and APIs

| Supplier | API | Scope | Notes |
|---|---|---|---|
| **GitHub Actions** | `GET /organizations/{org}/settings/billing/usage` (enhanced billing platform) | Organization; `usageItems[].repositoryName` names a repository | Sum `quantity` for `product == "Actions"`; `unitType` distinguishes minutes and storage. Needs an org admin token. |
| **Buildkite** | `GET /v2/organizations/{org}/usage` | Organization | `pipelines` carries self-hosted job minutes, hosted vCPU minutes, and concurrency; `artifacts` carries storage bytes. Needs `read_organizations`. |
| **Blacksmith** | `blacksmith usage --format json` (CLI) | Organization | No documented REST API. The CLI is the programmatic path; the server runs an operator-installed binary. |
| **Namespace** | Namespace Cloud `UsageService` (Connect) | Organization | The proto is `proto/namespace/cloud/compute/v1beta/usage.proto`; the exact request/response shape must be confirmed before implementation. |

## Decisions

1. **Report-only.** External suppliers keep `enforced_by = <supplier>` and
   carry no `limit` unless the API returns one. Starforge never blocks a
   linked supplier's work.
2. **`external_ref` is the supplier's scope.** For GitHub it is `org` or
   `org/repo`; for Buildkite, Blacksmith, and Namespace it is the
   organization slug. A repository link to an org-scoped supplier reports the
   org's usage; the page labels the scope.
3. **One client per supplier, one shared HTTP client.** Each client is a
   small adapter with a typed error, like `DepotUsageClient`. Tokens are
   never logged or rendered in `Debug`.
4. **Config sections.** `[ci.github]`, `[ci.buildkite]`, `[ci.blacksmith]`,
   and `[ci.namespace]`, each with `api_url`, `token`, and (where needed)
   `org` and `cli_path`. Empty token disables the supplier.
5. **Migration 0048 relaxes the supplier link constraint.** Migration 0039
   created `ci_supplier_links.supplier` with `CHECK (supplier IN ('depot'))`.
   Migration 0048 rebuilds the table on SQLite (as 0045 did) and drops and
   re-adds the check on Postgres, allowing `depot`, `github`, `buildkite`,
   `blacksmith`, and `namespace`.
6. **Per-supplier `external_ref` rules.** `depot` takes `owner/name`;
   `github` takes `org` or `org/repo`; `buildkite`, `blacksmith`, and
   `namespace` take an organization slug. `validate_external_ref` takes the
   supplier and applies the matching rule.
7. **Blacksmith uses the CLI.** The server executes `blacksmith usage
   --format json` with a bounded timeout and parses the JSON. The operator
   installs the CLI; a missing binary reports an error on the usage page, not
   a server failure.
8. **Namespace waits for a confirmed proto.** Do not guess the Connect
   message shape. Add the client only after the proto and a real response are
   available.

## Scope

**In scope:** GitHub Actions and Buildkite clients, config, supplier links,
API/UI labels, fake-server tests. Blacksmith CLI adapter. Namespace research.

**Out of scope:** enforcement of external limits, billing reconciliation,
per-run attribution for org-scoped suppliers, and supplier OAuth.

## Failure handling

| Failure | Behavior |
|---|---|
| Missing token | The supplier is disabled; the link reports `error: not configured`. |
| 401/403 | `error: authentication rejected`; no retry. |
| 5xx/timeout | `error: supplier unavailable`; the page keeps the last report? No cache in v1; it reports the error. |
| Malformed JSON | `error: invalid supplier response`. |
| Blacksmith binary missing | `error: blacksmith CLI not found`. |

## Verification

- Fake HTTP servers for GitHub and Buildkite, asserting the request path,
  auth header, period, and decoded metrics.
- A fake `blacksmith` script for the CLI adapter.
- `api_ci_usage` tests on SQLite and Postgres for the link/report routes.
- `scripts/check.sh` and `STARFORGE_TEST_PG=1 scripts/check.sh`.
