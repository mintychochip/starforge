# CI supplier usage adapters — implementation plan

- **Design:** `docs/superpowers/specs/2026-11-08-starforge-ci-suppliers-design.md`
- **Status:** proposed.

## Task 0 — Supplier link constraint [FR-5]

- [ ] Migration 0048 (SQLite + Postgres): allow `depot`, `github`,
      `buildkite`, `blacksmith`, and `namespace` in
      `ci_supplier_links.supplier`. SQLite rebuilds the table; Postgres drops
      `ci_supplier_links_supplier_check` and adds the new CHECK.
- [ ] `validate_external_ref(supplier, external_ref)`: `depot` is
      `owner/name`; `github` is `org` or `org/repo`; the others are an org
      slug.
- [ ] Postgres run of the link CRUD tests.

## Task 1 — GitHub Actions client [FR-1]

- [ ] `crates/starforged-core/src/ci_usage_github.rs`:
      `GET {api_url}/organizations/{org}/settings/billing/usage` with
      `Authorization: Bearer <token>`, `Accept: application/vnd.github+json`,
      `X-GitHub-Api-Version: 2026-03-10`, and `year`/`month`/`day` for the
      period. Sum `usageItems` where `product == "Actions"`; group by
      `unitType` (`minutes`, `gigabyte-hours`). When `external_ref` contains
      `/`, filter `repositoryName`.
- [ ] `[ci.github]` config (`api_url`, `token`), `LINKABLE_SUPPLIERS` adds
      `github`, and `supplier_usage` dispatches to the client.
- [ ] Fake-server tests: path, auth, period, per-repo filter, error mapping.

## Task 2 — Buildkite client [FR-2]

- [ ] `crates/starforged-core/src/ci_usage_buildkite.rs`:
      `GET {api_url}/v2/organizations/{org}/usage?from=YYYY-MM-DD&to=...`
      with `Authorization: Bearer <token>`. Read `pipelines` metrics
      (self-hosted job minutes, hosted vCPU minutes, concurrency) and
      `artifacts` storage bytes. `external_ref` is the org slug.
- [ ] `[ci.buildkite]` config; `LINKABLE_SUPPLIERS` adds `buildkite`.
- [ ] Fake-server tests.

## Task 3 — Blacksmith CLI adapter [FR-3]

- [ ] `crates/starforged-core/src/ci_usage_blacksmith.rs`: run
      `blacksmith usage --since <period> --format json` with a bounded
      timeout; parse the JSON into metrics. `[ci.blacksmith]` config
      (`cli_path`, `token` via env?).
- [ ] Fake script test; missing-binary error.

## Task 4 — Namespace research [FR-4]

- [ ] Fetch `proto/namespace/cloud/compute/v1beta/usage.proto`; confirm the
      Connect service path and message fields. Implement only with a real
      response fixture. Otherwise document the deferral.

## Task 5 — Links, UI, docs [FR-5]

- [ ] Extend the supplier link validation and the CI usage page label with
      the supplier scope (org vs repository).
- [ ] Docs: `docs/admin/ci.md`, `docs/technical/ci-and-sandboxes.md`,
      `docs/technical/configuration.md`, CHANGELOG.
- [ ] `api_ci_usage` tests on SQLite and Postgres.

## Verification

- `cargo nextest run -p starforged --test api_ci_usage`
- `cargo nextest run -p starforged-core` (client unit tests)
- `STARFORGE_TEST_PG=1 scripts/check.sh`
