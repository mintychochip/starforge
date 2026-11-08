# Local sandboxes

`starforge sandbox` runs a command in a local sandbox through
`starforge-sandboxd` — no server, no CI job. Use it to run an agent or a
build in the same isolation a CI job gets, with the same egress proxy.

## Start the daemon

Build or install `starforge-sandboxd` and run it with an image allowlist
and an egress directory:

```shell
starforge-sandboxd \
  --socket /run/starforge/sandboxd.sock \
  --token-file /run/starforge/sandboxd.token \
  --image localhost/starforge-sandbox:0.1.0-rc.1 \
  --egress-dir /var/lib/starforge/egress
```

The daemon writes a fresh token on every start; the CLI reads it. The
daemon must be the static build, because it copies itself into the
sandbox to run the egress forwarder.

## Run a command

```shell
starforge sandbox run \
  --image localhost/starforge-sandbox:0.1.0-rc.1 \
  --allow-host github.com \
  -- sh -c 'git clone https://github.com/owner/repo /workspace && cd /workspace && make test'
```

The command's stdout and stderr stream to your terminal. The exit code is
the command's exit code. The sandbox is killed at the end.

- `--keep` keeps the sandbox and prints its id.
- `--env KEY=VALUE` adds an environment variable.
- `--allow-host host[:port]` adds an egress allowlist entry (repeatable).
- `--timeout SECONDS` sets the lifetime (0 = daemon default).
- `--socket` / `--token-file` override the daemon paths.

## Inspect and clean up

```shell
starforge sandbox exec <id> -- cat /workspace/result.txt
starforge sandbox cp <id> result.txt ./result.txt
starforge sandbox kill <id>
```

The sandbox workspace starts empty. The command must populate it, for
example with a clone through the egress proxy. The daemon tracks
sandboxes in memory; a daemon restart forgets the ids, so kill kept
sandboxes before restarting it.

## Egress

The sandbox has no network route except the egress proxy. A bare
`--allow-host host` entry permits ports 80 and 443. Use
`--allow-host host:port` for another port. The daemon's
`--egress-allow-cidr` admits special-use addresses (loopback, private)
only for the ranges the operator allows.

## Image requirements

The image must provide `/bin/sh`, `mkdir`, `chmod`, and `realpath -m`
(coreutils), a writable and executable `/workspace`, and a writable
`/run/starforge/egress` mount. See `packaging/sandbox/README.md`.
