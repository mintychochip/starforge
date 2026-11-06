#!/usr/bin/env bash
# Run the documented quick start end to end against a fresh server:
# init -> admin user create -> serve -> /healthz -> admin token -> create
# repo via the API -> push over HTTP -> clone back -> CLI login via the
# device flow (approved through the web) -> push a Trail change. Creates
# everything under a temp dir and tears down on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
# Always build: a stale binary from an earlier checkout must not pass the smoke.
cargo build -p starforged -p starforge-cli
STARFORGED="$TARGET_DIR/debug/starforged"
STARFORGE="$TARGET_DIR/debug/starforge"
[[ -x "$STARFORGED" ]] || { echo "error: starforged binary not found at $STARFORGED" >&2; exit 1; }
[[ -x "$STARFORGE" ]] || { echo "error: starforge binary not found at $STARFORGE" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVER_PID=""
LOGIN_PID=""
cleanup() {
  [[ -n "$LOGIN_PID" ]] && kill "$LOGIN_PID" 2>/dev/null || true
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "$LOGIN_PID" ]] && wait "$LOGIN_PID" 2>/dev/null || true
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
export STARFORGE_HOME="$WORK/cli-home"
mkdir -p "$STARFORGE_HOME"

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

# --- CLI login via device flow, approved through the web ---
"$STARFORGE" auth login "$BASE" >login.log 2>&1 &
LOGIN_PID=$!
USER_CODE=""
for i in $(seq 1 100); do
  if [[ -f login.log ]]; then
    USER_CODE="$(sed -n 's/.*Enter code: *//p' login.log | head -n1 | tr -d '[:space:]')"
    [[ -n "$USER_CODE" ]] && break
  fi
  sleep 0.2
  if (( i == 100 )); then echo "no device code in login.log" >&2; exit 1; fi
done

JAR="$WORK/cookies.txt"
LOGIN_HTML="$(curl -fsS -c "$JAR" "$BASE/login")"
LOGIN_CSRF="$(printf '%s' "$LOGIN_HTML" | sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' | head -n1)"
[[ -n "$LOGIN_CSRF" ]] || { echo "no login _csrf" >&2; exit 1; }
curl -fsSL -b "$JAR" -c "$JAR" --data-urlencode "_csrf=$LOGIN_CSRF" \
  --data-urlencode "next=/" --data-urlencode "login=me" \
  --data-urlencode "password=a long password" "$BASE/login" >/dev/null

DEVICE_HTML="$(curl -fsS -b "$JAR" "$BASE/oauth/device")"
DEVICE_CSRF="$(printf '%s' "$DEVICE_HTML" | sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' | head -n1)"
[[ -n "$DEVICE_CSRF" ]] || { echo "no device _csrf" >&2; exit 1; }
curl -fsS -b "$JAR" --data-urlencode "_csrf=$DEVICE_CSRF" \
  --data-urlencode "user_code=$USER_CODE" --data-urlencode "decision=approve" \
  "$BASE/oauth/device/approve" >/dev/null

for i in $(seq 1 100); do
  if ! kill -0 "$LOGIN_PID" 2>/dev/null; then break; fi
  sleep 0.2
  if (( i == 100 )); then echo "CLI login did not exit" >&2; exit 1; fi
done
wait "$LOGIN_PID" || { echo "CLI login failed" >&2; exit 1; }
LOGIN_PID=""

# --- Push a Trail change from the clone ---
cd clone
git checkout -qb smoke
echo change > change.txt
git add change.txt
git commit -qm "smoke change"
"$STARFORGE" trail push --title "smoke change"
cd ..

# Assert the Trail exists through the API.
TRAILS="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/repos/me/demo/trails")"
printf '%s' "$TRAILS" | grep -q "smoke change" || { echo "Trail not found in API response: $TRAILS" >&2; exit 1; }

echo "docs-smoke: ok"
