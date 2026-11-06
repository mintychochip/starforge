# Starforge M4b (Git import and mirrors) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec §8.6 git-level import and mirroring:
- **One-time import** from any git URL: HTTPS with optional credentials, or SSH with a generated deploy key. It fetches only `refs/heads/*` and `refs/tags/*`.
- **Pull mirrors:** a scheduled `git fetch --prune` (default every hour) plus "sync now". Mirror repositories reject pushes and disable merging; Trails can still be opened for discussion.
- **Push mirrors:** after each push, debounced 30 s, push branches and tags with explicit refspecs. The last result and error show in repository settings.
- **Credentials:** encrypted at rest with XChaCha20-Poly1305 under a key derived from `secret_key`, never displayed after saving.

**Architecture:**
- **`starforged-git`** gains `remote.rs`: fetch and push with hermetic env, timeouts, credential injection through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` (never argv), a protocol allow-list, and pinned resolution.
- **`starforged-core`:**
  - `crypto.rs` gains a sealed-credentials box (XChaCha20-Poly1305 + HKDF-SHA256);
  - `remotes.rs` (new) holds URL policy, import, and mirrors;
  - `jobs.rs` gains the `ImportRepo`, `PullMirror` (recurring), and `PushMirror` (debounced) jobs.
- **`starforged-db`** gains `0026_mirrors.sql`: `repo_remotes` (import source, pull mirror, push mirrors), `repos.mirror` / `repos.import_state` columns.
- **The hook snapshot** (M3b `git_rpc_env`) carries a mirror flag: pull-mirror repositories refuse every receive-pack ref update except `refs/for` (discussion stays possible: "Trails can be opened"). `Core::merge_change` refuses on mirrors.
- **Web and API:**
  - an "Import" variant of the new-repository form;
  - repository settings → Mirrors (pull mirror config, sync now, push mirror list with last result);
  - matching API routes.

**Tech Stack:** as before, plus **chacha20poly1305 0.11.0** (new dependency, D1) in `starforged-core`. Tests use local `file://` remotes (§13) under a test-only URL policy flag, and a loopback HTTPS-less smart-HTTP remote served by a second `TestServer` for the credential paths.

**Spec:** §8.6 (import, pull mirrors, push mirrors, credential encryption), §11.4 (mirror credentials encrypted at rest), §12 (`secret_key` loss makes mirror credentials unreadable), §8.2 (post-receive enqueues push mirrors), §13 (mirror tests against `file://` remotes).

**Deferred (not built here):**
- GitHub metadata import (M4c);
- LFS (non-goal);
- mirroring `refs/trails/*` (custom refs are not mirrored, by design of the explicit refspecs);
- per-mirror ref filters.

## Global Constraints

- **New dependency (D1):** `chacha20poly1305 = { version = "0.11.0" }` (RustCrypto, pure Rust; its XChaCha20Poly1305 type) in `starforged-core` only. HKDF comes from `ring::hkdf` (already in the tree). No other new crates.
- **Outbound URL policy** (one fn, `Core::check_remote_url`), applied at save time AND before every fetch or push:
  - allowed schemes: `https`, `ssh` (`ssh://` and scp-like `user@host:path`), and `http` only when the resolved host is loopback and the test flag allows it;
  - refused: `file://`, local paths, `ext::`, `fd::`, and every other transport (`-c protocol.allow=never` plus explicit `protocol.<s>.allow=always` for the allowed ones), unless the test-only flag `remotes.allow_file_urls` is set (default false, documented as test-only);
  - hosts are resolved and refused by the existing webhook SSRF host rules (private, loopback, link-local, metadata, multicast) unless the test flag allows loopback;
  - the resolved address is pinned: HTTPS through `-c http.curloptResolve=<host>:<port>:<ip>`, SSH through `-o HostName=<ip>` with `HostKeyAlias=<host>`, so a DNS change between the check and git's own lookup cannot redirect the connection;
  - redirects are refused (`-c http.followRedirects=false`).
- **Credentials:**
  - stored only sealed. HTTPS uses a username and password/token; SSH uses a generated ed25519 private key, with the public key shown to the user to install upstream;
  - never displayed after saving; the API returns `has_credentials: bool` and, for SSH, the public key;
  - never placed in argv, URLs, logs, or error messages: git stderr is scrubbed of the URL's userinfo before it is stored or rendered;
  - SSH keys are written to a 0600 temp file for the duration of one git command and removed afterwards, including on failure.
- **Seal key:** derived as `HKDF-SHA256(ikm = secret_key bytes, salt = "starforge", info = "mirror-credentials-v1")`, separate from the webhook key.
- **Subprocess limits:** fetch and push use the hermetic env helper with timeouts (import 30 min, mirror operations 10 min), `GIT_TERMINAL_PROMPT=0`, and SSH `BatchMode=yes` with `StrictHostKeyChecking=accept-new` and a per-remote known-hosts file under the data dir.
- **Every new job** dedupes by kind and repository and uses the existing retry ladder. Failures are recorded on the remote row (`last_error`, scrubbed) and never block the repository.
- **Audit:** `repo.import`, `mirror.create`, `mirror.update`, `mirror.delete`, and `mirror.credentials_changed`, one row each (§6.5 lists mirrors via settings changes; credentials are audit-worthy).
- **Permissions:** mirrors need maintain+ (§6.1 capability table: "mirrors"). Import is part of repository creation (the creator's rights).
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. chacha20poly1305.** The spec names XChaCha20-Poly1305; ring lacks the 24-byte-nonce variant. Sealed format: `x1:` + base64(24-byte random nonce ‖ ciphertext). Cost if wrong: one small RustCrypto dependency.
- **D2. Tables.**
  - `repo_remotes (id, repo_id, role ∈ import|pull|push, url, auth ∈ none|https|ssh, username, sealed_secret, ssh_public_key, interval_secs, enabled 0/1, last_attempt_at, last_success_at, last_error, created_by, created_at, updated_at)`. Rules: at most one `import`, at most one `pull` per repository, and up to 10 `push`.
  - `repos.mirror` (0/1, true while a pull remote exists and is enabled) and `repos.import_state` (`none|pending|running|done|failed`).
- **D3. Import.**
  - `POST /api/v1/user/repos` and `POST /api/v1/orgs/{org}/repos` accept `"import": {"url", "auth": {...}}`, and the web new-repository form has an "Import from URL" section.
  - The repository is created empty with `import_state = pending`, and an `ImportRepo` job runs:
    `git fetch --prune <url> +refs/heads/*:refs/heads/* +refs/tags/*:refs/tags/*`
    then sets HEAD to the remote's default branch: `git ls-remote --symref <url> HEAD`, falling back to `main`.
  - While the state is `pending` or `running`, pushes are refused ("import in progress"). `failed` shows the scrubbed error with "retry" and "delete".
  - For SSH imports, the user first creates the repository with `auth: ssh`. The response and page show the generated public key; the user installs it upstream, then presses "start import". `pending` waits until then.
- **D4. Pull mirrors.**
  - Configured on an existing repository in settings or the API (`PUT /api/v1/repos/{owner}/{repo}/mirror/pull` with `{url, auth, interval_secs (≥ 300, default 3600)}`, plus `DELETE`, plus `POST …/mirror/pull/sync`).
  - Enabling it on a repository that has branch or tag protection rules is allowed; the rules simply never trigger, since pushes are refused.
  - `PullMirror` job: `git fetch --prune` with the D3 refspecs. Then, under the repository's ingest lock (M2f), every moved branch goes through the same branch-move ingest as post-receive (revisions for branch changes, mergeability), and `push` webhooks are dispatched with `sender: null`.
  - The job re-enqueues itself at `interval_secs` while enabled. "Sync now" enqueues immediately (deduped).
  - Mirror repositories:
    - refuse branch and tag pushes (hook snapshot) and merges (`Core::merge_change`), with a clear "this repository is a pull mirror" message;
    - accept `refs/for`, comments, and reviews.
  - Disabling the mirror turns the repository back into a normal one.
- **D5. Push mirrors.**
  - `POST /api/v1/repos/{owner}/{repo}/mirror/push` with `{url, auth}` (≤ 10), `DELETE …/mirror/push/{id}`, `POST …/mirror/push/{id}/sync`.
  - After every successful post-receive scan, a `PushMirror{remote_id}` job is enqueued at now + 30 s, deduped per remote, so pushes within 30 s coalesce.
  - The job runs `git push --prune <url> +refs/heads/*:refs/heads/* +refs/tags/*:refs/tags/*`: a true mirror of branches and tags. `refs/trails/*` and `refs/for/*` never go out.
  - Each run updates `last_attempt_at`, `last_success_at`, and `last_error`, which the settings page shows.

## File Structure

```
Cargo.toml                                               chacha20poly1305 workspace dep
crates/starforged-db/migrations/{sqlite,postgres}/0026_mirrors.sql
crates/starforged-db/src/remotes.rs                      new
crates/starforged-git/src/remote.rs                      fetch/push/ls-remote with injected config + pinning (new)
crates/starforged-core/src/{crypto.rs,remotes.rs (new),jobs.rs,repos.rs,merge.rs,changes.rs (scan → push-mirror enqueue)}
crates/starforged/src/config.rs                          remotes.allow_file_urls (test-only)
crates/starforged-api/src/{remotes.rs (new),repos.rs,orgs.rs,lib.rs}
crates/starforged-web/src/pages/{remotes.rs (new),repos.rs}, templates/mirrors.html, new_repo.html
crates/starforged/tests/{import.rs,pull_mirror.rs,push_mirror.rs,remotes_security.rs}
README.md
```

---

### Task I1: Sealed credentials, URL policy, and git remote operations

**Files:**
- Create:
  - `crates/starforged-git/src/remote.rs`;
  - the `crates/starforged-core/src/remotes.rs` policy part;
  - `crates/starforged/tests/remotes_policy.rs`.
- Modify:
  - `Cargo.toml`;
  - `crates/starforged-core/src/{crypto.rs,lib.rs}` and `Cargo.toml`;
  - `crates/starforged/src/config.rs`.

**Interfaces:**
- `crypto::CredentialBox::seal(&self, plain: &[u8]) -> String` and `open(&self, sealed: &str) -> Result<Vec<u8>>`, built from `secret_key`;
- `Core::check_remote_url(url) -> CoreResult<PinnedRemote>`;
- `remote::fetch(repo_dir, pinned, creds, refspecs, timeout) -> Result<FetchOutcome>`;
- `remote::push(…)`;
- `remote::ls_remote_head(…)`;
- `remote::scrub(stderr, url) -> String`.

- [ ] **Step 1: Write the failing tests.**
  - **Seal/open:** round-trip; tamper detection; a different `secret_key` cannot open.
  - **URL policy:**
    - `file://`, local paths, `ext::`, private IPs, loopback (flag off), and metadata IPs are refused;
    - `https` and `ssh` to public hosts are accepted (resolution is stubbed through an injectable resolver for unit tests);
    - pinning arguments are produced.
  - **Fetch:** from a `file://` remote with the test flag fetches only heads and tags; `refs/notes/*` and `refs/pull/*` are not fetched.
  - **HTTPS credentials:**
    - against a second `TestServer`, fetch works with a token;
    - the token never appears in argv (`/proc/<pid>/cmdline` is not checked; assert that the constructed argv lacks it) or in the scrubbed stderr of a failed attempt with a wrong token.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core crypto remotes` and `cargo test -p starforged-git remote` and `cargo test -p starforged --test remotes_policy`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add sealed remote credentials and the outbound git URL policy`.

---

### Task I2: One-time import

**Files:**
- Create:
  - the 0026 migrations;
  - `crates/starforged-db/src/remotes.rs`;
  - `crates/starforged/tests/import.rs`.
- Modify:
  - `crates/starforged-core/src/{remotes.rs,repos.rs,jobs.rs}`;
  - `crates/starforged-api/src/{repos.rs,orgs.rs}`;
  - `crates/starforged-web/src/pages/repos.rs` and `templates/new_repo.html`, plus a repository-page import banner;
  - the hook snapshot (`git_rpc_env`: import in progress means refuse).

**Interfaces:** D2 and D3. SSH key generation runs `ssh-keygen -t ed25519 -N '' -C starforge-import -f <tmp>` through a hermetic helper. OpenSSH is already a runtime dependency for SSH remotes; doctor (M5) checks for it.

- [ ] **Step 1: Write the failing tests.**
  - **Import from `file://`:** state goes pending → running → done; branches, tags, and the default branch match the source; Trails and sessions are empty.
  - **HTTPS with a token** from a second `TestServer`'s private repository.
  - **SSH flow:**
    - the public key is shown;
    - "start import" against a second `TestServer` with SSH enabled (M3c), with the key added as a deploy key upstream, fetches successfully.
  - **Refusals:**
    - a push during the import is refused;
    - a failed import shows the scrubbed error; retry works after fixing credentials;
    - an import URL refused by policy gives 422 at creation.
  - **Audit:** `repo.import`.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test import`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test api_repos --test smart_http` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Import repositories from git URLs`.

---

### Task I3: Pull mirrors

**Files:**
- Create: `crates/starforged/tests/pull_mirror.rs`.
- Modify:
  - `crates/starforged-core/src/{remotes.rs,jobs.rs,merge.rs,changes.rs}`;
  - `git_rpc_env`;
  - the API and web settings pages (`pages/remotes.rs`, `templates/mirrors.html`).

**Interfaces:** D4.

- [ ] **Step 1: Write the failing tests.**
  - **Configuration:** configure a pull mirror from a `file://` source; sync now; the refs match.
  - **Upstream changes:**
    - a new upstream commit on a branch that backs a branch change produces a revision and a `push` webhook with `sender: null`;
    - an upstream branch deletion is pruned.
  - **Refusals:**
    - a direct push is refused with the mirror message;
    - merging a Trail change is refused (409 or 422, consistent with archived);
    - `refs/for` works.
  - **Scheduling:** the interval re-enqueue happens (observed through the jobs table `run_at`).
  - **Disable:** disabling restores pushes.
  - **Access:** maintain+ only (403 for write, 404 for non-readers); audit rows; credentials never returned.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test pull_mirror`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test merge_changes --test protection` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add pull mirrors`.

---

### Task I4: Push mirrors

**Files:**
- Create: `crates/starforged/tests/push_mirror.rs`.
- Modify:
  - `crates/starforged-core/src/{remotes.rs,jobs.rs,changes.rs}` (enqueue after the scan);
  - the API and web settings pages.

**Interfaces:** D5.

- [ ] **Step 1: Write the failing tests.**
  - **Debounce:** add a push mirror to a `file://` bare target; push twice within the debounce window; exactly one push-mirror job runs (deduped); the target refs match after `run_due_jobs` with time advanced past 30 s (use the jobs test helper that makes jobs due).
  - **Mirroring:** branch deletion propagates (prune); tags propagate; `refs/trails/*` never appear in the target.
  - **Failure:** a failing target shows `last_error`, scrubbed.
  - **Access:** the cap of 10; maintain+; audit rows.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test push_mirror`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add push mirrors`.

---

### Task I5: Remotes sweep and docs

**Files:**
- Create: `crates/starforged/tests/remotes_security.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep.**
  - **URL policy** for every entry point (import, pull, push; API and web): disallowed schemes and hosts give 422.
  - **DNS rebinding:** an allowed resolution checked at save time cannot be changed into a private IP by the time git runs. Use the injectable resolver to return public at check time and private at run time; the run must fail closed.
  - **Credential non-disclosure:** no response, page, log line at info level, or stored `last_error` contains the secret.
  - **Matrix:** the 404/403 matrix for all mirror routes; CSRF on all forms.
  - **Secret-key change:** changing `secret_key` makes stored credentials unreadable, and jobs fail with a clear "credentials unreadable; re-enter them" error rather than a panic.
- [ ] **Step 2: Run the sweep** 3 times; all green. Fix defects found and report them.
- [ ] **Step 3: README:** an "Import and mirroring" section (import over HTTPS and SSH, pull mirrors, push mirrors, credential storage, URL policy, the `secret_key` warning, the API).
- [ ] **Step 4: Commit** (PG gate first): `Add remotes sweep and docs`.
