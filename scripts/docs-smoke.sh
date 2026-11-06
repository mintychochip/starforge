#!/usr/bin/env bash
# Run the documented quick start end to end against a fresh server:
# init -> serve -> /healthz -> admin user + token -> create repo via the API
# -> push over HTTP -> clone back. The quick start documents no `starforge`
# CLI call, so none is made here. Creates everything under a temp dir and
# tears down on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
# Always build: a stale binary from an earlier checkout must not pass the smoke.
cargo build -p starforged -p starforge-cli
STARFORGED="$TARGET_DIR/debug/starforged"
STARFORGE="$TARGET_DIR/debug/starforge"
[[ -x "$STARFORGED" ]] || { echo "error: starforged binary not found at $STARFORGED" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "$SERVER_PID" ]] && wait "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Free ports: bind port 0 is not directly usable via --http-addr, so probe
# with python3 and fall back to a fixed uncommon pair.
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
PY
)"
BASE="http://127.0.0.1:$PORT"

cd "$WORK"
export STARFORGE__SSH__ENABLED=false
"$STARFORGED" init --data-dir ./data --http-addr "127.0.0.1:$PORT" --base-url "$BASE"
printf 'a long password\n' | "$STARFORGED" admin user create --handle me --admin --password-stdin

"$STARFORGED" serve >server.log 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do
  curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.2
  if (( i == 50 )); then echo "server did not become healthy" >&2; exit 1; fi
done

TOKEN="$("$STARFORGED" admin token create --user me --name smoke --scopes repo:read,repo:write)"
[[ -n "$TOKEN" ]] || { echo "empty token" >&2; exit 1; }

curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"demo","visibility":"private","readme":false}' "$BASE/api/v1/user/repos" >/dev/null

git init -q -b main client
cd client
git config user.email smoke@example.com
git config user.name smoke
echo hello > hello.txt
git add hello.txt
git commit -qm init
git push -q "http://me:$TOKEN@127.0.0.1:$PORT/me/demo.git" main

cd ..
git clone -q "http://me:$TOKEN@127.0.0.1:$PORT/me/demo.git" clone
[[ "$(cat clone/hello.txt)" == "hello" ]] || { echo "clone content mismatch" >&2; exit 1; }

echo "docs-smoke: ok"
