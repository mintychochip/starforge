# Starforge M3c (SSH, SSH keys, deploy keys) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Git over SSH per spec §8.1:
- an embedded russh server on port 2222 by default;
- public-key authentication against user SSH keys and per-repository deploy keys (read-only or read-write);
- only `git-upload-pack`, `git-receive-pack`, and `git-upload-archive`;
- no shell, no port forwarding;
- per-connection idle and total timeouts, and per-user connection limits.

It also adds the §10.1 SSH-keys settings page and deploy-key management.

**Architecture:**
- **New crate `starforged-ssh`** (AGPL) holds the russh server. It authenticates through `Core`, authorizes through the same `Core` paths as smart HTTP, and spawns `git` with `Core::git_rpc_env` (M3b), so the hook enforces identical ref policy and protection.
- **`starforged-db`** gains `0024_ssh_keys.sql` (`ssh_keys`, `deploy_keys`).
- **`starforged-core`** gains `sshkeys.rs`: a hand-written OpenSSH public-key parser and fingerprinting (no new dependency in core); user key and deploy key management; and key lookup for authentication.
- **`starforged`** starts the SSH listener beside HTTP and stops it on shutdown.
- **`starforged-web`** gains `/settings/keys`, `/{owner}/{repo}/settings/keys`, and the SSH clone URL.

**Tech Stack:** as M3a, plus **russh 0.65.1** (new dependency, see D1) in `starforged-ssh` only. Tests use the system OpenSSH client (`ssh`, `ssh-keygen`) through `GIT_SSH_COMMAND`.

**Spec:** §8.1 (SSH transport), §6.1 (credentials: SSH keys per user; deploy keys per repo, read-only or read-write), §5.1 (`starforged-ssh` crate), §5.2 (one process), §12 (default SSH port 2222), §6.5 (audit credential changes), §10.1 (settings: SSH keys).

**Deferred (not built here):** SSH certificates; `sk-*` security-key types; host-key rotation tooling; SSH for the CLI's session upload.

## Global Constraints

- **New dependency (ruling D1):** only `starforged-ssh` depends on russh:
  ```toml
  russh = { version = "0.65.1", default-features = false, features = ["ring", "rsa", "flate2"] }
  ```
  Add it to `[workspace.dependencies]`. Use the `ring` backend, which is already in the tree and builds on musl; never `aws-lc-rs`. No other new crates. `starforge-*` crates never depend on it.
- **One authorization path:** `starforged-ssh` never decides permissions itself. It calls `Core` for key lookup, repository resolution (including rename redirects), the read/write tier decision, and the env snapshot.
- **The hook remains the ref-policy enforcer** for SSH pushes, exactly as for HTTP.
- **Migrations:** `0024_ssh_keys.sql` in both engines, forward-only.
- **Audit:** `ssh_key.add`, `ssh_key.remove`, `deploy_key.add`, and `deploy_key.remove` write exactly one audit row each (§6.5 credentials). Authentication success and failure are not audited per connection; they are logged at `debug` and `info` with the key fingerprint only, never key material.
- **Secrets:** the host private key file is created with mode 0600 under the data dir and is never logged.
- **Tests:** real `ssh` and `git` against an in-process server on `127.0.0.1:0`. Bounded waits only. `TMPDIR=/dev/shm`.
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. russh.** The spec names russh (D6, §4). Version 0.65.1, `ring` + `rsa` + `flate2` features, Apache-2.0 (AGPL-compatible). Ruling cost if wrong: one more large dependency tree in the server; isolated to one crate.
- **D2. Keys.**
  - **Parsing:** `core::sshkeys::parse_public_key(line) -> Result<PublicKey { algorithm, blob, comment, bits }>` parses the OpenSSH `authorized_keys` single-line format.
    - Accepted algorithms: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, and `ssh-rsa` with a modulus of at least 2048 bits.
    - The algorithm string inside the blob must match the prefix.
    - Options prefixes and multiple keys are refused.
  - **Fingerprint:** `SHA256:` + base64 (no padding) of SHA-256(blob), byte-identical to `ssh-keygen -lf`.
  - **Uniqueness:** a fingerprint is unique across ALL user keys and deploy keys (422 on a duplicate).
- **D3. Tables.**
  - `ssh_keys (id, user_id, title, algorithm, fingerprint UNIQUE, public_key, created_at, last_used_at)`.
  - `deploy_keys (id, repo_id, title, algorithm, fingerprint UNIQUE, public_key, read_write 0/1, created_by, created_at, last_used_at)`.
  - A shared `fingerprint` uniqueness check runs in `Core` (two tables).
  - `last_used_at` updates at most once per minute per key.
  - Caps: 100 keys per user, 50 deploy keys per repository.
- **D4. Management.**
  - **User keys:** the user only. Web `/settings/keys` (list with fingerprints, add title + key, delete; CSRF). API `GET|POST /api/v1/user/keys`, `DELETE /api/v1/user/keys/{id}` (scope as other account credential management).
  - **Deploy keys:** repository admins (the §6.1 capability row with collaborators). Web `/{owner}/{repo}/settings/keys`. API `GET|POST /api/v1/repos/{owner}/{repo}/keys` (with `read_write`), `DELETE …/keys/{id}`. Archived repositories refuse adds.
- **D5. Server behavior.**
  - **Config:**
    - `ssh.enabled` (default `true`);
    - `ssh.listen` (default `0.0.0.0:2222`);
    - `ssh.host_key_path` (default `<data_dir>/ssh_host_ed25519_key`, generated on first start or by `starforged init`);
    - `ssh.public_host` and `ssh.public_port` (for clone URLs; default from `server.base_url`'s host and 2222);
    - `ssh.idle_timeout_secs` (default 300);
    - `ssh.max_connection_secs` (default 3600);
    - `ssh.max_connections_per_user` (default 10).
    - All are overridable by `STARFORGE__SSH__*`.
  - **Authentication:**
    - the SSH user name must be `git`;
    - public-key only, with the key looked up by fingerprint;
    - user keys authenticate the user, who must be active (suspended users refused);
    - deploy keys authenticate a deploy identity bound to one repository;
    - password, keyboard-interactive, and `none` auth are refused.
  - **Channel requests:**
    - only `session` channels;
    - `exec` with exactly one of `git-upload-pack '<path>'`, `git-receive-pack '<path>'`, or `git-upload-archive '<path>'` (also `git upload-pack …` with a space);
    - `env` only for `GIT_PROTOCOL` (passed to git for protocol v2);
    - everything else refused: `shell`, `pty-req`, `subsystem`, `x11-req`, `auth-agent-req`, `tcpip-forward`, `direct-tcpip`, and other channel types.
    - A refused command prints a one-line `starforge: …` message on stderr and exits 1.
  - **Paths:** `[/]<owner>/<repo>[.git]`, resolved through the same lookup as HTTP, including rename redirects. Unknown or unreadable repositories answer "repository not found" (no existence leak).
  - **Authorization:**
    - upload-pack and upload-archive need read;
    - receive-pack follows HTTP's write tier or read tier (`refs/for` for readers);
    - archived repositories refuse receive-pack;
    - a deploy key works only for its repository: read-only keys may only fetch; read-write keys push as permission `write` with no user, so `refs/for` is refused because a change needs an author.
    - The post-receive scan records the pusher as `None` for deploy keys (webhook `sender: null`).
  - **Limits:**
    - the idle timeout closes connections with no channel traffic;
    - the total timeout closes any connection after `max_connection_secs`;
    - more than `max_connections_per_user` concurrent connections (per user; per key for deploy keys) are refused at authentication.
- **D6. Clone URLs.** When SSH is enabled, the repository page shows `ssh://git@<public_host>:<public_port>/<owner>/<repo>.git` beside the HTTP URL.

## File Structure

```
Cargo.toml                                        workspace dep russh (D1)
crates/starforged-ssh/{Cargo.toml,src/lib.rs,src/server.rs,src/command.rs}   new crate
crates/starforged-db/migrations/{sqlite,postgres}/0024_ssh_keys.sql
crates/starforged-db/src/sshkeys.rs               new
crates/starforged-core/src/sshkeys.rs             parser, fingerprints, management, auth lookup (new)
crates/starforged-api/src/sshkeys.rs              routes (new)
crates/starforged-web/src/pages/sshkeys.rs        user + deploy key pages (new), templates
crates/starforged/src/{config.rs,serve.rs,main.rs (init writes host key)}
crates/starforged/tests/{api_sshkeys.rs,web_sshkeys.rs,ssh_git.rs,ssh_security.rs}
README.md
```

---

### Task C1: SSH keys and deploy keys

**Files:**
- Create:
  - the 0024 migrations;
  - `crates/starforged-db/src/sshkeys.rs`;
  - `crates/starforged-core/src/sshkeys.rs`;
  - `crates/starforged-api/src/sshkeys.rs`;
  - `crates/starforged-web/src/pages/sshkeys.rs` and its templates;
  - tests `api_sshkeys.rs` and `web_sshkeys.rs`.
- Modify: the lib/route registration files and the settings navigation templates.

**Interfaces:**
```rust
pub struct PublicKey { pub algorithm: String, pub blob: Vec<u8>, pub comment: String, pub bits: u32 }
pub fn parse_public_key(line: &str) -> Result<PublicKey, CoreError>;
pub fn fingerprint(blob: &[u8]) -> String;   // "SHA256:…"
pub enum KeyIdentity { User(User), Deploy { key_id: i64, repo_id: i64, read_write: bool } }
impl Core {
    pub async fn add_ssh_key(&self, user: &User, title: &str, key: &str) -> CoreResult<SshKeyView>;
    pub async fn ssh_keys(&self, user: &User) -> CoreResult<Vec<SshKeyView>>;
    pub async fn remove_ssh_key(&self, user: &User, id: i64) -> CoreResult<()>;
    pub async fn add_deploy_key(&self, user: &User, owner: &str, repo: &str, title: &str, key: &str, read_write: bool) -> CoreResult<DeployKeyView>;
    pub async fn deploy_keys(&self, user: &User, owner: &str, repo: &str) -> CoreResult<Vec<DeployKeyView>>;
    pub async fn remove_deploy_key(&self, user: &User, owner: &str, repo: &str, id: i64) -> CoreResult<()>;
    /// Authentication lookup used by starforged-ssh; touches last_used_at (throttled).
    pub async fn identity_for_key(&self, fingerprint: &str) -> CoreResult<Option<KeyIdentity>>;
}
```

- [ ] **Step 1: Write the failing tests.**
  - **Parser:**
    - keys generated by `ssh-keygen` (ed25519, ecdsa-256, rsa-3072) parse;
    - the fingerprint equals `ssh-keygen -lf -E sha256` output;
    - rsa-1024 is refused;
    - a mismatched blob algorithm, options prefixes, and garbage are refused.
  - **User keys:** add, list, remove; a duplicate across users and deploy keys gives 422; the cap holds; audit rows.
  - **Deploy keys:**
    - admin-only: maintain gets 403, a non-reader gets 404;
    - read and read-write keys;
    - an archived repository refuses adds;
    - audit rows.
  - **Web:** both pages round-trip with CSRF; hostile titles render escaped; a forged token gives 403 and leaves state unchanged.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core sshkeys` and `cargo test -p starforged --test api_sshkeys --test web_sshkeys`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add SSH keys and deploy keys`.

---

### Task C2: The SSH server

**Files:**
- Create: the `starforged-ssh` crate and `crates/starforged/tests/ssh_git.rs`.
- Modify:
  - `Cargo.toml` (workspace member dependency russh);
  - `crates/starforged/src/{config.rs,serve.rs,main.rs}`;
  - `crates/starforged/tests/common/mod.rs` (`TestServer` with SSH on an ephemeral port, plus key helpers);
  - `crates/starforged-web/src/pages/` (repository page clone URL).

**Interfaces:**
- `starforged_ssh::serve(core: Core, cfg: SshConfig, shutdown) -> Result<SshHandle>`, returning the bound address.
- `starforged init` and first start write the host key when missing.
- Behavior per D5 and D6.

- [ ] **Step 1: Write the failing tests** (system `ssh` through `GIT_SSH_COMMAND` with `-i key -p port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityAgent=none`):
  - **User keys:**
    - clone, fetch, and push a branch;
    - a `refs/for` push creates a change;
    - protocol v2 is used (assert with `GIT_TRACE_PACKET` or a `git ls-remote` v2 capability line);
    - a renamed repository's old path works.
  - **Deploy keys:**
    - read-only clones but cannot push;
    - read-write pushes a branch with webhook `sender: null`, but cannot push `refs/for`;
    - a deploy key cannot reach another repository.
  - **Refusals:**
    - an unknown key;
    - a suspended user;
    - a user name other than `git`;
    - a private repository the user cannot read ("not found");
    - a write push by a read user;
    - push to an archived repository.
  - **Restrictions:**
    - `ssh … git@host` (shell) is refused;
    - `ssh … ls` is refused;
    - `ssh -N -L` port forwarding is refused (connection or channel failure);
    - an `env` request other than `GIT_PROTOCOL` is ignored or refused.
  - **Limits**, with a test config of idle 1 s, total 3 s, and per-user 1:
    - an idle connection closes;
    - a long connection closes;
    - a second concurrent connection is refused while the first is held.
  - **Repository page:** shows the SSH clone URL.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test ssh_git`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command 3 times, plus `--test smart_http --test protection` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Serve git over SSH`.

---

### Task C3: SSH sweep and docs

**Files:**
- Create: `crates/starforged/tests/ssh_security.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep.**
  - **SSH vs HTTP matrix:** roles (read, triage, write, maintain, admin, a team grant, an org base grant, a deploy key ro/rw) × visibility × operation (clone, branch push, `refs/for` push, tag push under tag protection, force push under branch protection). The SSH result must equal the HTTP result for every cell.
  - **Revocation:** removing a key, suspending a user, deleting a deploy key, and transferring a repository take effect on the next connection.
  - **Leaks:** no key material in logs at info level, checked through the test's captured tracing output if the harness supports it; otherwise assert on the audit rows only.
- [ ] **Step 2: Run the sweep** 3 times; all green. Fix defects found and report them.
- [ ] **Step 3: README:** a "Git over SSH" section (config, host key, clone URL, keys, deploy keys, limits, protocol v2, troubleshooting) and the SSH-keys and deploy-keys API routes.
- [ ] **Step 4: Commit** (PG gate first): `Add SSH sweep and docs`.
