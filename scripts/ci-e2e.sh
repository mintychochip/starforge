#!/usr/bin/env bash
# Real CI end-to-end (plan M6d D7): a real server, runner, sandboxd, and
# rootless podman run a fixture repo's `.starforge/ci.toml`. The sandbox
# keeps `--network none`; sandboxd copies its static binary in and starts
# the forwarder, and the host connects into the forwarder's Unix socket.
# The runner clones and syncs through the per-sandbox egress proxy over
# HTTPS; the job uploads an artifact and a Pi session.
#
# Gated by STARFORGE_TEST_SANDBOX=1 (podman + the sf-ci-test image).
# Uses the local x86_64 musl release tarball for the in-sandbox CLI.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${STARFORGE_TEST_SANDBOX:-0}" != "1" ]]; then
  echo "ci-e2e: set STARFORGE_TEST_SANDBOX=1 to run" >&2
  exit 0
fi
for tool in podman python3 openssl curl git; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "ci-e2e: missing $tool" >&2
    exit 1
  }
done

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo build -p starforged -p starforge-cli -p starforge-runner -p starforge-sandboxd
# The daemon copies its own binary into the (musl/Alpine) sandbox to run the
# forwarder, so the e2e daemon must be the static musl build, not the
# glibc debug binary.
if [[ -x "$HOME/.local/bin/zig" ]]; then
  export PATH="$HOME/.local/bin:$PATH"
fi
cargo zigbuild --release --target x86_64-unknown-linux-musl -p starforge-sandboxd
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
SERVER_BIN="$TARGET_DIR/debug/starforged"
RUNNER_BIN="$TARGET_DIR/debug/starforge-runner"
SANDBOXD_BIN="$TARGET_DIR/x86_64-unknown-linux-musl/release/starforge-sandboxd"
TARBALL="$(ls "$TARGET_DIR"/release-artifacts/starforged-*-x86_64-unknown-linux-musl.tar.gz 2>/dev/null | head -1 || true)"
if [[ -z "$TARBALL" ]]; then
  echo "ci-e2e: run scripts/build-release.sh first (missing x86_64 musl tarball)" >&2
  exit 1
fi

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
SERVER_PORT="$(free_port)"
HTTPS_PORT="$(free_port)"
BASE="http://127.0.0.1:$SERVER_PORT"
PUBLIC="https://localhost:$HTTPS_PORT"

echo "==> certificates"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -subj "/CN=starforge-e2e-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$WORK/server.key" -out "$WORK/server.csr" -subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\n' >"$WORK/server.ext"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 1 -out "$WORK/server.pem" -extfile "$WORK/server.ext" >/dev/null 2>&1

echo "==> sandbox image"
if ! podman image exists localhost/sf-ci-e2e:latest; then
  mkdir -p "$WORK/image"
  cp "$TARBALL" "$WORK/image/starforge.tar.gz"
  cp crates/starforge-cli/tests/fixtures/pi-session.jsonl "$WORK/image/pi-session.jsonl"
  cat >"$WORK/image/Containerfile" <<'EOF'
FROM localhost/sf-ci-test:latest
USER root
COPY starforge.tar.gz /tmp/starforge.tar.gz
RUN mkdir -p /tmp/starforge && tar -xzf /tmp/starforge.tar.gz -C /tmp/starforge \
  && cp /tmp/starforge/x86_64-unknown-linux-musl/starforge /usr/local/bin/starforge \
  && chmod 0755 /usr/local/bin/starforge \
  && rm -rf /tmp/starforge /tmp/starforge.tar.gz
COPY pi-session.jsonl /opt/starforge/pi-session.jsonl
USER sandbox
EOF
  podman build -t localhost/sf-ci-e2e:latest -f "$WORK/image/Containerfile" "$WORK/image"
fi

echo "==> https reverse proxy"
python3 scripts/https_proxy.py "$SERVER_PORT" "$HTTPS_PORT" \
  "$WORK/server.pem" "$WORK/server.key" >"$WORK/https-proxy.log" 2>&1 &
PIDS+=("$!")
for _ in $(seq 1 100); do
  python3 - "$HTTPS_PORT" <<'PY' && break
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2)
s.close()
PY
  sleep 0.1
done
if ! python3 - "$HTTPS_PORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2)
s.close()
PY
then
  echo "ci-e2e: https proxy did not start" >&2
  cat "$WORK/https-proxy.log" >&2 || true
  exit 1
fi

echo "==> server"
(
  cd "$WORK"
  "$SERVER_BIN" init --data-dir ./data --http-addr "127.0.0.1:$SERVER_PORT" --base-url "$PUBLIC"
  printf 'a long password\n' | "$SERVER_BIN" admin user create --handle me --admin --password-stdin
  "$SERVER_BIN" admin token create --user me --name e2e --scopes repo:read,repo:write,sandbox:run >"$WORK/token"
)
TOKEN="$(cat "$WORK/token")"
(
  cd "$WORK"
  # The e2e uses HTTP only; keep the default SSH port free for a live
  # instance that may already hold 0.0.0.0:2222.
  export STARFORGE__SSH__ENABLED=false
  export STARFORGE__SANDBOX__LOCAL__SOCKET="$WORK/sandboxd.sock"
  export STARFORGE__SANDBOX__LOCAL__TOKEN_FILE="$WORK/sandboxd.token"
  exec "$SERVER_BIN" serve >"$WORK/server.log" 2>&1
) &
PIDS+=("$!")
for _ in $(seq 1 100); do
  curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
if ! curl -fsS "$BASE/healthz" >/dev/null; then
  echo "ci-e2e: server did not become healthy" >&2
  cat "$WORK/server.log" >&2 || true
  exit 1
fi

echo "==> repository and fixture push"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"proj","visibility":"private"}' "$BASE/api/v1/user/repos" >/dev/null
mkdir -p "$WORK/work"
git -C "$WORK/work" init -q -b main
git -C "$WORK/work" config user.name e2e
git -C "$WORK/work" config user.email e2e@example.test
mkdir -p "$WORK/work/.starforge"
cat >"$WORK/work/.starforge/ci.toml" <<'TOML'
version = 1

[triggers]
push = ["main"]

[[job]]
name = "test"
image = "localhost/sf-ci-e2e:latest"
commands = [
  "mkdir -p out && echo artifact > out/result.bin",
  "mkdir -p \"$HOME/.pi/agent/sessions/--x--\" \"$STARFORGE_HOME/.pi/agent/sessions/--x--\" && sed 's|/work/repo|/workspace|g' /opt/starforge/pi-session.jsonl > \"$HOME/.pi/agent/sessions/--x--/01ARZ3NDEKTSV4RRFFQ69G5FAV.jsonl\" && cp \"$HOME/.pi/agent/sessions/--x--/01ARZ3NDEKTSV4RRFFQ69G5FAV.jsonl\" \"$STARFORGE_HOME/.pi/agent/sessions/--x--/01ARZ3NDEKTSV4RRFFQ69G5FAV.jsonl\"",
]
timeout = "10m"
artifacts = ["out/**"]
env = { HOME = "/tmp", STARFORGE_HOME = "/tmp/.starforge" }
TOML
echo "# e2e" >"$WORK/work/README.md"
git -C "$WORK/work" add -A
git -C "$WORK/work" commit -q -m "e2e fixture"
git -C "$WORK/work" push -q "http://git:$TOKEN@127.0.0.1:$SERVER_PORT/me/proj.git" main

echo "==> sandboxd"
# Two phases. The proxy smoke is a user sandbox: the public API cannot set
# the server-only `forge` field, so the daemon needs the operator CIDR for
# its loopback origin. The job phase restarts the daemon WITHOUT the CIDR,
# so the job's clone, sync, and artifact upload can only pass through the
# server-set `forge` exact entry (the SSRF gate refuses loopback otherwise).
start_sandboxd() {
  rm -f "$WORK/sandboxd.sock"
  "$SANDBOXD_BIN" \
    --socket "$WORK/sandboxd.sock" --token-file "$WORK/sandboxd.token" \
    --image localhost/sf-ci-e2e \
    --egress-dir "$WORK/egress" \
    --egress-ca-dir "$WORK/ca" \
    --egress-upstream-ca "$WORK/ca.pem" \
    --egress-https-port "$HTTPS_PORT" \
    "$@" \
    >>"$WORK/sandboxd.log" 2>&1 &
  PIDS+=("$!")
  for _ in $(seq 1 100); do
    [[ -S "$WORK/sandboxd.sock" && -f "$WORK/sandboxd.token" ]] && break
    sleep 0.1
  done
  [[ -S "$WORK/sandboxd.sock" && -f "$WORK/sandboxd.token" ]]
}
start_sandboxd --egress-allow-cidr 127.0.0.1/32

echo "==> proxy smoke"
SANDBOX="$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"owner\":\"me\",\"repo\":\"proj\",\"template\":\"localhost/sf-ci-e2e:latest\",\"runtime\":\"podman\",\"network\":{\"allow_out\":[\"localhost\"]},\"idempotency_key\":\"proxy-smoke\"}" \
  "$BASE/api/v1/sandboxes")"
SANDBOX_ID="$(printf '%s' "$SANDBOX" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
EXEC="$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"command\":[\"sh\",\"-c\",\"curl -sS -o /dev/null -w '%{http_code}' --proxy \\\"\$HTTPS_PROXY\\\" https://localhost:$HTTPS_PORT/healthz\"]}" \
  "$BASE/api/v1/sandboxes/$SANDBOX_ID/exec")"
printf '%s' "$EXEC" | python3 -c '
import json, sys
chunks = json.load(sys.stdin)
out = "".join(c.get("data", "") for c in chunks if c.get("stream") == "stdout")
err = "".join(c.get("data", "") for c in chunks if c.get("stream") == "stderr")
assert out.strip() == "200", (out, err)
print("proxy smoke: 200")
'
# The sandbox has `--network none`: neither its own loopback (except the
# forwarder) nor the old pasta gateway may reach a host service.
echo "==> host-loopback probe (must be blocked)"
PROBE_PORT="$(free_port)"
python3 -m http.server "$PROBE_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
PIDS+=("$!")
for _ in $(seq 1 50); do
  python3 - "$PROBE_PORT" <<'PY' && break
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2)
s.close()
PY
  sleep 0.1
done
for target in "http://127.0.0.1:$PROBE_PORT/" "http://10.0.2.2:$PROBE_PORT/"; do
  EXEC="$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"command\":[\"sh\",\"-c\",\"curl --noproxy '*' -m 3 -sS -o /dev/null -w '%{http_code}' $target || echo BLOCKED\"]}" \
    "$BASE/api/v1/sandboxes/$SANDBOX_ID/exec")"
  printf '%s' "$EXEC" | python3 -c '
import json, sys
chunks = json.load(sys.stdin)
out = "".join(c.get("data", "") for c in chunks if c.get("stream") == "stdout").strip()
assert out != "200", ("host loopback reachable:", out)
print("blocked:", out)
'
done
curl -fsS -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/sandboxes/$SANDBOX_ID" >/dev/null

echo "==> sandboxd (job phase, no egress CIDR)"
# Stop the smoke daemon and start a clean one with no special-use allowance.
SMOKE_PID="${PIDS[${#PIDS[@]}-1]}"
kill "$SMOKE_PID" 2>/dev/null || true
wait "$SMOKE_PID" 2>/dev/null || true
start_sandboxd
# The job's egress must be the server-set forge entry, not a CIDR.
if grep -q -- "--egress-allow-cidr" <(printf '%s' "$(ps -o args= -p "${PIDS[${#PIDS[@]}-1]}" 2>/dev/null)"); then
  echo "ci-e2e: job-phase sandboxd must not carry --egress-allow-cidr" >&2
  exit 1
fi

echo "==> runner"
REG_TOKEN="$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"labels":["e2e"],"ephemeral":false}' \
  "$BASE/api/v1/repos/me/proj/runners/registration-token" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
RUNNER_TOKEN="$(curl -fsS -X POST -H 'Content-Type: application/json' \
  -d "{\"registration_token\":\"$REG_TOKEN\",\"name\":\"e2e\",\"labels\":[\"e2e\"],\"version\":\"test\",\"ephemeral\":false}" \
  "$BASE/api/v1/runners/register" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["auth_token"])')"
"$RUNNER_BIN" \
  --server "$BASE" \
  --sandbox-server "$PUBLIC" \
  --token "$RUNNER_TOKEN" \
  --repo-url "$PUBLIC/me/proj" \
  --runtime podman \
  --label e2e \
  --concurrency 1 \
  >"$WORK/runner.log" 2>&1 &
PIDS+=("$!")

print_job_log() {
  python3 - "$WORK" "$JOB_ID" <<'PY'
import pathlib, sqlite3, sys
work = pathlib.Path(sys.argv[1])
job = int(sys.argv[2] or 0)
db = work / "data" / "starforge.db"
if job and db.exists():
    conn = sqlite3.connect(db)
    for (h,) in conn.execute(
        "SELECT blake3 FROM ci_job_logs WHERE job_id = ? ORDER BY start_offset", (job,)
    ):
        path = work / "data" / "data" / "blobs" / h[:2] / h
        if path.exists():
            print(path.read_text(errors="replace"), end="")
PY
}

echo "==> waiting for the job"
JOB_ID=""
STATE=""
for _ in $(seq 1 240); do
  RUNS="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/repos/me/proj/ci/runs?limit=10")"
  read -r JOB_ID STATE < <(printf '%s' "$RUNS" | python3 -c '
import json, sys
runs = [r for r in json.load(sys.stdin)["runs"] if r["job_name"] == "test"]
if runs:
    print(runs[0]["job_id"], runs[0]["state"])
')
  case "$STATE" in
    succeeded) break ;;
    failed|error|canceled)
      echo "ci-e2e: job $JOB_ID ended $STATE" >&2
      print_job_log >&2
      tail -n 80 "$WORK/runner.log" "$WORK/sandboxd.log" "$WORK/server.log" "$WORK/https-proxy.log" >&2 || true
      exit 1
      ;;
  esac
  sleep 1
done
[[ "$STATE" == "succeeded" ]] || {
  echo "ci-e2e: timed out waiting for the job (last state: ${STATE:-none})" >&2
  print_job_log >&2
  tail -n 80 "$WORK/runner.log" "$WORK/sandboxd.log" "$WORK/server.log" "$WORK/https-proxy.log" >&2 || true
  exit 1
}

echo "==> run detail"
print_job_log
DETAIL="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/repos/me/proj/ci/runs/$JOB_ID")"
printf '%s' "$DETAIL" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["state"] == "succeeded", d
names = [a["name"] for a in d["artifacts"]]
assert "out/result.bin" in names, names
assert d["sessions"], "no session linked to the job"
print("ci-e2e: job", d["job_id"], "succeeded; artifacts", names, "sessions", d["sessions"])
'
echo "ci-e2e: ok"
