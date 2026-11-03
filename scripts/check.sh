#!/usr/bin/env bash
# Format check, lints, and tests. STARFORGE_TEST_PG=1 also runs the suite against a throwaway
# Postgres 17 container (podman or docker).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

if [[ "${STARFORGE_TEST_PG:-0}" == "1" ]]; then
  engine="$(command -v podman || command -v docker)"
  name="starforge-test-pg-$$"
  "$engine" run -d --rm --name "$name" -e POSTGRES_PASSWORD=starforge \
    -p 127.0.0.1:55439:5432 docker.io/library/postgres:17 >/dev/null
  trap '"$engine" stop -t 2 "$name" >/dev/null' EXIT
  for _ in $(seq 1 60); do
    "$engine" exec "$name" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break
    sleep 0.5
  done
  STARFORGE_TEST_PG_URL="postgres://postgres:starforge@127.0.0.1:55439/postgres" cargo test --workspace
fi
