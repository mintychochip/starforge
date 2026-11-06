# Starforge M3b (Branch and tag protection) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The §8.2 ref policy in full.
- **Branch protection:** block direct pushes so changes must go through a Trail, block force pushes, block deletion, and let push allow-lists bypass the direct-push block.
- **Tag protection:** optional.
- **Ref namespaces:** pushes to any other namespace are refused unless a site admin allow-lists it.
- **Settings page:** the §10.1 repository settings page for branch and tag protection and gate rules, which until now existed only in the API.

**Architecture:** No new crates and no new third-party dependencies.
- **Branch protection extends the existing gate rules.** One rule per pattern carries both its merge gates and its push restrictions, which is how §6.2 attaches gate rules to a branch-protection pattern.
- **`starforged-db`** gains `0022_protection.sql`:
  - push-restriction columns on `gate_rules`;
  - the `gate_rule_push_allowlist` table (users or teams);
  - the `tag_protections` table.
- **`starforged-core`:**
  - gate-rule CRUD gains the push fields and the allow-list;
  - tag-protection CRUD is added;
  - one `Core` fn builds the whole git-RPC environment, including a protection snapshot for the pusher. HTTP uses it now and SSH (M3c) will reuse it.
- **The hook** (`crates/starforged/src/hook.rs` with `starforged-git/src/refpolicy.rs`) enforces the snapshot. It still never opens the database.
- **`starforged-web`** gains the "Branch protection" settings page.

**Tech Stack:** as M3a.

**Spec:** §8.2 (ref policy table: protection on `refs/heads/*`, optional tag protection, the site-admin namespace allow-list), §6.2 (gate rules attach to a branch-protection pattern), §6.1 (maintain manages protection rules), §6.5 (audit), §10.1 (settings: branch and tag protection, gate rules, merge methods).

**Deferred (not built here):** status-check bypass lists; protection on `refs/for` targets; signed-commit requirements; per-rule bypass for admins.

## Global Constraints

- **Toolchain, licenses, and migrations:** as M3a. Migration `0022_protection.sql` lands in both engine directories, forward-only. No new third-party dependencies.
- **No route bypasses `starforged-core`.**
- **The hook process never opens the database.** It enforces only the snapshot it receives through the environment. A snapshot that is missing, malformed, or unparseable fails closed: every branch and tag push is refused with a clear message, while `refs/for` keeps working.
- **Server-side operations bypass push rules:** merges (`git update-ref` in the server) and Trail ref writes. Only receive-pack pushes are subject to them.
- **Audit:** every protection change writes exactly one audit row: `gate_rule.created`, `gate_rule.updated`, and `gate_rule.deleted` (existing kinds; updates now include the push fields), plus `tag_protection.created` and `tag_protection.deleted`. No-ops write nothing.
- **Visibility:** management needs maintain+. Non-readers get 404; below-threshold users get 403; archived repositories refuse mutations.
- **Messages:** every refusal reaches the pusher as `remote: starforge: …`, naming the ref and the rule pattern that blocked it.
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. Rule model.**
  - `gate_rules` gains `block_direct_push`, `block_force_push`, and `block_deletion`, each `INTEGER NOT NULL DEFAULT 0`.
  - `gate_rule_push_allowlist (rule_id, user_id, team_id, created_at)` holds exactly one of `user_id`/`team_id`, unique per rule and target. Team entries are allowed only on org-owned repositories, for teams of that org.
  - The API path stays `/gate-rules`. The DTO gains the three flags and `push_allowlist: {"users": [handles], "teams": [slugs]}`. Allow-listed users must exist; listing a user without write access is allowed, but their pushes still need write.
  - `block_direct_push` means "require changes through a Trail".
- **D2. Matching.**
  - Every rule whose pattern matches the branch applies. A null pattern means all branches; patterns use the existing `gates::pattern_matches`.
  - A push is refused when ANY matching rule blocks it:
    - **deletion:** the new value is the zero oid and the rule has `block_deletion`;
    - **force push:** the old and new values are both non-zero, the old value is not an ancestor of the new one (checked in the hook with the quarantine-visible objects, using the existing ancestry helper), and the rule has `block_force_push`;
    - **direct push:** any create or update, and the rule has `block_direct_push`, unless the pusher is on THAT rule's allow-list (directly or through a team).
  - Deletion and force-push blocks have no bypass. A maintainer edits the rule to allow them.
- **D3. Tag protection.**
  - `tag_protections (id, repo_id, pattern NOT NULL, created_at, UNIQUE (repo_id, pattern))`, managed by maintain+.
  - Creating, moving, or deleting a tag that matches any pattern needs `maintain` or above. Non-matching tags need `write`, as today.
- **D4. Namespace allow-list.**
  - Config key `git.allowed_ref_namespaces = ["refs/notes/", …]`, overridable as `STARFORGE__GIT__ALLOWED_REF_NAMESPACES`.
  - Each entry must start with `refs/` and end with `/`, and must not be `refs/heads/`, `refs/tags/`, `refs/for/`, or `refs/trails/` or overlap them; startup fails on an invalid entry.
  - Pushes into an allow-listed namespace need `write` plus a write-scoped token, like branches. They are not subject to branch protection.
  - Site admins control the config file, which satisfies "a site admin allow-lists".
- **D5. Snapshot.**
  - `Core::git_rpc_env(access: &RepoAccess, user: Option<&User>, scope_write: bool, nonce: &str) -> Vec<(&'static str, String)>` replaces the env assembly in `githttp.rs`. It adds `STARFORGE_PROTECTION`, compact JSON:
    `{"v":1,"branches":[{"pattern":…,"direct":bool,"force":bool,"delete":bool,"exempt":bool}],"tags":[pattern…],"tag_ok":bool,"namespaces":[…]}`.
    - `exempt` is computed per pusher at spawn;
    - `tag_ok` is true when the pusher has maintain+.
  - `HookCtx` parses it; parse failure means fail closed (Global Constraints).
- **D6. Settings page.**
  - `/{owner}/{repo}/settings/protection` (maintain+) lists rules by pattern with their gates and push restrictions.
  - Create, edit, and delete forms cover every gate field (approvals, dismiss on push, block on request changes, required contexts, up to date, threads resolved, session evidence, allowed methods), every push field, and the allow-list (handles and team slugs).
  - A tag-protection list with add and remove forms.
  - All forms use CSRF and return 303 or a 422 re-render with errors.

## File Structure

```
crates/starforged-db/migrations/{sqlite,postgres}/0022_protection.sql
crates/starforged-db/src/checks.rs (gate rule rows) + src/protection.rs (allow-list, tag protections; new)
crates/starforged-core/src/{gate_rules.rs,protection.rs (new),repos.rs or git_env.rs (new)}
crates/starforged-git/src/refpolicy.rs          snapshot types, matching, namespace check (pure, unit-tested)
crates/starforged/src/{hook.rs,config.rs}       snapshot parse + enforcement; git.allowed_ref_namespaces
crates/starforged-web/src/{githttp.rs,pages/repo_settings.rs or pages/protection.rs}, templates/protection.html
crates/starforged/tests/{protection.rs (new),hook_cli.rs,api_gate_rules.rs,web_protection.rs (new)}
README.md
```

---

### Task B1: Branch protection and the shared push environment

**Files:**
- Create:
  - the 0022 migrations;
  - `crates/starforged-db/src/protection.rs`;
  - `crates/starforged-core/src/protection.rs`;
  - `crates/starforged/tests/protection.rs`.
- Modify:
  - `crates/starforged-db/src/checks.rs`;
  - `crates/starforged-core/src/{gate_rules.rs,lib.rs}`;
  - `crates/starforged-git/src/refpolicy.rs`;
  - `crates/starforged/src/hook.rs`;
  - `crates/starforged-web/src/githttp.rs`;
  - `crates/starforged-api/src/` gate-rule routes;
  - tests `api_gate_rules.rs` and `hook_cli.rs`.

**Interfaces:** D1, D2, and D5. `refpolicy` gains pure fns that tests drive directly:
- `parse_protection(&str) -> Result<Protection, String>`;
- `check_protected_update(&Protection, &RefUpdate, is_ancestor: impl Fn(&str, &str) -> bool) -> Result<(), String>`.

- [ ] **Step 1: Write the failing tests.**
  - **Pure refpolicy:**
    - each block kind;
    - all matching rules apply;
    - the allow-list exempts only the direct-push block;
    - a malformed snapshot fails closed.
  - **Real pushes** over HTTP, on a repository with rule `main`: direct + force + delete:
    - a write user's direct push is refused, with the pattern in the message;
    - an allow-listed write user's direct push succeeds;
    - a team allow-list works on an org repository;
    - force push and delete are refused for everyone, including admins;
    - other branches are unaffected;
    - a Trail merge into `main` still succeeds.
  - **API:**
    - the gate-rule DTO round-trips the new fields and the allow-list;
    - unknown handles or teams give 422;
    - team entries on a user-owned repository give 422;
    - exactly one audit row per change.
  - **Env:** `githttp` uses `Core::git_rpc_env` (no duplicate env assembly remains).
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-git refpolicy` and `cargo test -p starforged --test protection --test api_gate_rules --test hook_cli`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the Step 2 commands plus `--test smart_http --test merge_changes --test push_changes` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add branch protection to gate rules`.

---

### Task B2: Tag protection and the namespace allow-list

**Files:**
- Modify:
  - `crates/starforged-db/src/protection.rs`;
  - `crates/starforged-core/src/protection.rs`;
  - `crates/starforged-api/src/` (tag protection routes);
  - `crates/starforged-git/src/refpolicy.rs`;
  - `crates/starforged/src/{hook.rs,config.rs}`;
  - tests `protection.rs`, `hook_cli.rs`, and the config tests.

**Interfaces:**
- **API:**
  - `GET|POST /api/v1/repos/{owner}/{repo}/tag-protections` (body `{"pattern"}`);
  - `DELETE …/tag-protections/{id}`.
- **Read access:** maintain+ for reads too, matching gate rules.
- Behavior per D3 and D4.

- [ ] **Step 1: Write the failing tests.**
  - **Tag protection:** with `v*` protected:
    - a write user's `git push origin v1` is refused;
    - a maintainer's succeeds;
    - a write user's `release-1` tag succeeds;
    - deleting `v1` as a write user is refused.
  - **Namespaces:**
    - with `refs/notes/` allow-listed, a write user pushes notes and a read user is refused;
    - without the allow-list, the push is refused, as today;
    - an invalid config entry fails startup with a clear error.
  - **API:** tag protection CRUD, with audit rows and the 404/403 shape.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test protection --test hook_cli` and `cargo test -p starforged config`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus `cargo test -p starforged-git refpolicy` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add tag protection and the ref namespace allow-list`.

---

### Task B3: Branch protection settings page

**Files:**
- Create:
  - `crates/starforged-web/src/pages/protection.rs`;
  - `templates/protection.html`;
  - `crates/starforged/tests/web_protection.rs`.
- Modify:
  - `crates/starforged-web/src/lib.rs`;
  - the repository settings navigation template.

**Interfaces:** D6.

- [ ] **Step 1: Write the failing tests.**
  - **Round trip:**
    - create a rule with every field;
    - edit it;
    - add and remove an allow-listed user and team;
    - delete the rule;
    - add and remove a tag protection;
    - each step is reflected in the API GET.
  - **Validation:** an invalid pattern or an unknown handle re-renders with 422 and the error.
  - **Access:**
    - non-readers get 404;
    - write users get 403;
    - forged CSRF gives 403 and leaves state unchanged;
    - archived repositories refuse.
  - **XSS:** hostile patterns and context names render escaped.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test web_protection`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add the branch protection settings page`.

---

### Task B4: Protection sweep and docs

**Files:**
- Create: `crates/starforged/tests/protection_security.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep.**
  - **Matrix:**
    - operations: create, fast-forward, force, delete, tag create/move/delete, notes push;
    - roles: read, triage, write, maintain, admin, site admin, an allow-listed user, a team-allow-listed user;
    - rule combinations;
    - everything over real HTTP pushes, checking both the refusal message and the unchanged ref.
  - **Concurrency:** a rule change between two pushes takes effect on the second push.
  - **Server paths:** a server merge and Trail refs are unaffected.
  - **Access shape:** the gate-rule and tag-protection APIs follow the 404/403 matrix.
- [ ] **Step 2: Run the sweep** 3 times; all green. Fix defects found and report them.
- [ ] **Step 3: README:** a "Branch and tag protection" section (rules, matching, allow-lists, tags, namespaces config, the settings page, the API). Remove "gate-rule management screens" from the "Not yet" list.
- [ ] **Step 4: Commit** (PG gate first): `Add protection sweep and docs`.
