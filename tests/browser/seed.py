#!/usr/bin/env python3
"""Seed a throwaway Starforge server for the browser tests (plan M5d D5).

Runs against a live `starforged` (started by scripts/browser-tests.sh):
creates two users via the admin CLI, a repo via the API, pushes real git
history over HTTP, uploads a session through the ingest API (zstd +
BLAKE3, exactly as the CLI spool upload does), wires a commit claim, a
Trail with a branch change, a gate rule requiring one approval, and a
write collaborator. Writes the specs' manifest as JSON.

Requires Python 3 with `zstandard` and `blake3`.
"""

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import blake3
import zstandard

ULID = "01ARZ3NDEKTSV4RRFFQ69G5FD1"
TS = "2026-11-04T00:00:00Z"
PASS = "correct horse battery"


def run(cmd, cwd=None, stdin=None, check=True):
    out = subprocess.run(
        cmd, cwd=cwd, input=stdin, capture_output=True, text=True
    )
    if check and out.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}", file=sys.stderr)
        print(out.stdout + out.stderr, file=sys.stderr)
        sys.exit(1)
    return out


def api(base, method, path, token=None, body=None, headers=None):
    req = urllib.request.Request(base + path, method=method)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, data=data) as resp:
            payload = resp.read()
    except urllib.error.HTTPError as exc:
        print(f"API {method} {path} -> {exc.code}: {exc.read().decode()}", file=sys.stderr)
        sys.exit(1)
    return json.loads(payload) if payload else {}


def event(seq, kind, **payload):
    line = {"v": 1, "seq": seq, "ts": TS, "kind": kind}
    line.update(payload)
    return json.dumps(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--bin", required=True, help="path to starforged binary")
    ap.add_argument("--config", required=True, help="starforged.toml path")
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    # Users via the admin CLI (passwords on stdin, no argv leak).
    for handle in ("alice", "bob"):
        run(
            [args.bin, "--config", args.config, "admin", "user", "create",
             "--handle", handle, "--email", f"{handle}@example.test",
             "--password-stdin"],
            stdin=PASS + "\n",
        )

    # Alice's token: repo + trail + session-upload scopes.
    token = run(
        [args.bin, "--config", args.config, "admin", "token", "create",
         "--user", "alice", "--name", "seed",
         "--scopes", "repo:read,repo:write,trail:write,session:upload"]
    ).stdout.strip()

    # Repository via the API.
    api(base, "POST", "/api/v1/user/repos", token,
        {"name": "proj", "visibility": "private"})

    # Real git history over HTTP: main + feature/x with a file change.
    host = base.removeprefix("http://")
    git_url = f"http://git:{token}@{host}/alice/proj.git"
    work_dir = tempfile.TemporaryDirectory(prefix="sf-browser-seed-")
    work = work_dir.name
    w = Path(work)
    run(["git", "init", "-q", "-b", "main"], cwd=work)
    (w / "a.txt").write_text("one\n")
    run(["git", "add", "a.txt"], cwd=work)
    run(["git", "-c", "user.email=a@example.test", "-c", "user.name=a",
         "commit", "-qm", "initial"], cwd=work)
    run(["git", "checkout", "-qb", "feature/x"], cwd=work)
    (w / "a.txt").write_text("one\ntwo\n")
    run(["git", "add", "a.txt"], cwd=work)
    run(["git", "-c", "user.email=a@example.test", "-c", "user.name=a",
         "commit", "-qm", "feat one"], cwd=work)
    sha_a = run(["git", "rev-parse", "HEAD"], cwd=work).stdout.strip()
    (w / "b.txt").write_text("bee\n")
    run(["git", "add", "b.txt"], cwd=work)
    run(["git", "-c", "user.email=a@example.test", "-c", "user.name=a",
         "commit", "-qm", "feat two"], cwd=work)
    sha = run(["git", "rev-parse", "HEAD"], cwd=work).stdout.strip()
    run(["git", "push", "-q", git_url, "main", "feature/x"], cwd=work)

    # Session upload: meta + one compressed segment.
    meta = {
        "format": "starforge.session/v1",
        "id": ULID,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": "browser fixture",
        "started_at": TS,
        "ended_at": None,
        "repo": {"branch": "feature/x",
                 "head_at_start": "b" * 40},
        "parent_id": None,
        "usage": {"input": 1, "output": 2, "cache_read": 3,
                  "cache_write": 4, "reasoning": 5},
        "files_touched": ["a.txt"],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9",
                    "adapter_version_verified": True},
    }
    sess = f"/api/v1/repos/alice/proj/sessions/{ULID}"
    api(base, "PUT", sess, token, meta)
    lines = [
        event(0, "user_message", text="first turn"),
        event(1, "assistant_message", text="answer one", model="m1",
              usage={"input": 10, "output": 20, "cache_read": 30,
                     "cache_write": 40, "reasoning": 50}),
        event(2, "user_message", text="turn with the quasar-needle inside"),
        event(3, "tool_call",
              tool={"name": "needle-tool", "input": {"x": "secret-input"}}),
        event(4, "user_message", text="third turn"),
    ]
    raw = ("\n".join(lines) + "\n").encode()
    segment = zstandard.ZstdCompressor(level=3).compress(raw)
    req = urllib.request.Request(base + sess + "/segments/0", method="PUT")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-Starforge-Blake3", blake3.blake3(segment).hexdigest())
    with urllib.request.urlopen(req, data=segment) as resp:
        assert resp.status == 200, resp.status

    # Commit claims: one marker after turn-2 (first feature commit) and
    # one after turn-4 (feature tip), so the split view can switch
    # between two real commits through the ES module.
    api(base, "POST", sess + "/links", token,
        {"links": [{"sha": sha_a, "confidence": "exact",
                    "seq_start": 0, "seq_end": 2},
                   {"sha": sha, "confidence": "exact",
                    "seq_start": 3, "seq_end": 4}]})
    # Bob is a write collaborator, so his approval counts toward gates.
    api(base, "PUT", "/api/v1/repos/alice/proj/collaborators/bob", token,
        {"permission": "write"})

    # Trail + branch change + a gate rule requiring one approval.
    trail = api(base, "POST", "/api/v1/repos/alice/proj/trails", token,
                {"title": "feature work", "intent": "ship it"})
    number = trail["number"]
    change = api(base, "POST",
                 f"/api/v1/repos/alice/proj/trails/{number}/changes", token,
                 {"kind": "branch", "head_branch": "feature/x",
                  "base_branch": "main"})
    k = change["k"]
    api(base, "POST", "/api/v1/repos/alice/proj/gate-rules", token,
        {"required_approvals": 1})

    manifest = {
        "baseUrl": base,
        "owner": "alice",
        "repo": "proj",
        "sessionUlid": ULID,
        "headSha": sha,
        "otherSha": sha_a,
        "trailNumber": number,
        "changeK": k,
        "users": {
            "alice": {"handle": "alice", "password": PASS},
            "bob": {"handle": "bob", "password": PASS},
        },
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
