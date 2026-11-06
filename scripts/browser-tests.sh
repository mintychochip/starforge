#!/usr/bin/env bash
# Browser tests (plan M5d D5): build starforged, start it on a free port
# with a temp data dir, seed user/repo/push/session/Trail/change via
# tests/browser/seed.py, run the Playwright suite, and tear everything
# down even on failure. Node 22 is required; nothing here joins the Rust
# build.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/starforged"
MANIFEST="tests/browser/.seed-manifest.json"
PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
DATA="$(mktemp -d)"

SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA"
  rm -f "$MANIFEST"
}
trap cleanup EXIT

cargo build -p starforged

(
  cd "$DATA"
  "$BIN" init --data-dir "$DATA" \
    --base-url "http://127.0.0.1:$PORT" \
    --http-addr "127.0.0.1:$PORT"
  STARFORGE__SSH__ENABLED=false "$BIN" serve >"$DATA/serve.log" 2>&1 &
  echo $! >"$DATA/server.pid"
)
SERVER_PID="$(cat "$DATA/server.pid")"

for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null || {
  echo "starforged did not become healthy; serve log:" >&2
  cat "$DATA/serve.log" >&2
  exit 1
}

python3 tests/browser/seed.py \
  --base-url "http://127.0.0.1:$PORT" \
  --bin "$BIN" \
  --config "$DATA/starforged.toml" \
  --manifest "$MANIFEST"

cd tests/browser
npm ci
npx playwright install chromium
npx playwright test
