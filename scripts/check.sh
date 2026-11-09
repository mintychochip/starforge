#!/usr/bin/env bash
# Format check, lints, tests, and the technical-docs check.
# Tests run under cargo-nextest: the full workspace on SQLite, then the
# SQL-sensitive packages on Postgres 17 (STARFORGE_TEST_PG=1).
# STARFORGE_GATE_FULL_PG=1 runs the whole workspace on Postgres instead.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# nextest runs the tests in parallel across binaries. Fall back to cargo
# test for contributors without it.
if cargo nextest --version >/dev/null 2>&1; then
  cargo nextest run --workspace
else
  echo "cargo-nextest not found; falling back to cargo test --workspace" >&2
  cargo test --workspace
fi
# nextest skips doctests; keep them in the gate.
cargo test --workspace --doc

# Technical documents use ASD-STE100; the checker enforces the mechanical rules.
python3 scripts/ste_check.py --strict
python3 -m unittest discover -s scripts/tests

if [[ "${STARFORGE_TEST_PG:-0}" == "1" ]]; then
  engine="$(command -v podman || command -v docker)"
  name="starforge-test-pg-$$"
  # The suite creates hundreds of databases with concurrent migrations; the
  # container default of 64 MiB /dev/shm runs out of dynamic shared memory.
  "$engine" run -d --rm --name "$name" -e POSTGRES_PASSWORD=starforge \
    --shm-size=1g -p 127.0.0.1:55439:5432 docker.io/library/postgres:17 \
    -c max_connections=500 >/dev/null
  trap '"$engine" stop -t 2 "$name" >/dev/null' EXIT
  for _ in $(seq 1 60); do
    "$engine" exec "$name" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break
    sleep 0.5
  done
  export STARFORGE_TEST_PG_URL="postgres://postgres:starforge@127.0.0.1:55439/postgres"
  if [[ "${STARFORGE_GATE_FULL_PG:-0}" == "1" ]]; then
    if cargo nextest --version >/dev/null 2>&1; then
      cargo nextest run --workspace
    else
      cargo test --workspace
    fi
  else
    # The SQLite run above covers the whole workspace. Postgres reruns the
    # packages whose tests exercise SQL behavior: the DB layer, and the
    # integration tests for backup/restore, pooling, search, audit
    # retention, admin display, the CI tables (the cache SQL runs through
    # api_ci_runs and api_ci_usage), and the cross-repository/checkpoint SQL.
    if cargo nextest --version >/dev/null 2>&1; then
      cargo nextest run -p starforged-db
      cargo nextest run -p starforged \
        --test backup_restore --test db_pool --test search_index \
        --test admin_pages --test audit_retention --test api_ci_runs \
        --test api_ci_usage --test cross_repo_changes --test api_checkpoints \
        --test merge_changes --test checkpoint_e2e
    else
      cargo test -p starforged-db
      cargo test -p starforged \
        --test backup_restore --test db_pool --test search_index \
        --test admin_pages --test audit_retention --test api_ci_runs \
        --test api_ci_usage --test cross_repo_changes --test api_checkpoints \
        --test merge_changes --test checkpoint_e2e
    fi
  fi
fi
