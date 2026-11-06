# Starforge M3a (Orgs, teams, base permissions, transfer) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Organizations that own repositories, teams that grant permission levels, org base permissions, and repository transfer between owners, per spec §6.1, with the org and team settings pages and the site-admin org list of §10.1.
- **Orgs** share the handle namespace with users and own repositories at `/<org>/<repo>`. An org has a display name, a description, owners, members, and a base permission (`none`, `read`, `write`) that every member gets on every org repo.
- **Teams** belong to an org. Each team grants one permission level on all org repositories, or on a selected set.
- **Effective permission** (§6.1) is the highest of: org ownership (admin), the org base permission, team grants, the collaborator grant, and implicit read (public repositories; internal ones for signed-in users). Site admins stay admins everywhere.
- **Repo member** (§6.1) is a user with an explicit grant: collaborator, team, org base permission (when not `none`), or org ownership. It feeds §6.4, `refs_for_access = members`, session upload rules, and the dashboard.
- **Transfer** (§8.5): moves a repository to another owner. Only database rows change; the old path keeps working through redirects.

**Architecture:** No new crates and no new third-party dependencies.
- **`starforged-db`** gains `0021_orgs_teams.sql`: the `orgs`, `org_members`, `teams`, `team_members`, and `team_repos` tables. Org owner rows use the existing `owners.kind = 'org'`.
- **`starforged-core`:**
  - a new `orgs.rs` holds org, membership, and team management;
  - `permission.rs` becomes a pure resolver over all grant sources, with proptests;
  - `repos.rs`: `permission_on`, `repos_of`, `dashboard_repos`, and creation learn about orgs, and transfer is added;
  - `read.rs`: `is_repo_member` uses the same grant sources.
- **`starforged-api`** gains `/orgs/…` routes and repository transfer.
- **`starforged-web`** gains:
  - org creation, the org profile, org settings (general, members, teams), and team pages;
  - a new-repository owner selector and the transfer form;
  - the site-admin org list.

**Tech Stack:** as M2f (Rust 1.99.1, axum 0.8, askama, sqlx `Any`, real `git` in tests), plus `proptest` (an existing workspace dev-dependency) in `starforged-core` tests.

**Spec:** §6.1 (owners, orgs, teams, levels, member, capability table), §6.4 (member semantics), §6.5 (audit of permission and membership changes), §8.5 (transfer), §10.1 (settings: org and team; site admin: orgs), §13 (property tests for permission resolution).

**Deferred (not built here):**
- org rename;
- org invitations by email (owners add existing users directly);
- outside-collaborator reports;
- per-org repository-creation policy (only owners create org repositories);
- team nesting.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned; edition 2024; `unsafe_code = "forbid"`; workspace lints.
- **Licenses:** server crates stay `AGPL-3.0-or-later`; `starforge-cli` never depends on `starforged-*`. No new third-party dependencies.
- **Migrations:** `0021_orgs_teams.sql` in BOTH engine directories, in lockstep and forward-only. Use only SQL valid on both engines: `$N` placeholders, `INTEGER`/`BIGINT` ids, `0`/`1` booleans, `now()` timestamps.
- **No route bypasses `starforged-core`.** Every permission decision goes through ONE resolver, the pure `permission::effective` fed by one `Core` grant-gathering fn. No call site computes permission or membership on its own.
- **Audit (§6.5):** every membership or permission change writes exactly one audit row, in the same `Core` method as its write. Kinds:
  - org: `org.create`, `org.update`, `org.delete`, `org.member_add`, `org.member_remove`, `org.member_role`;
  - team: `team.create`, `team.update`, `team.delete`, `team.member_add`, `team.member_remove`, `team.repo_add`, `team.repo_remove`;
  - repository: `repo.transfer`.
  No-ops write nothing.
- **Visibility:**
  - An org page is public (the handle namespace is public). The org's member list and team pages are visible only to org members and site admins; everyone else gets 404.
  - Repositories inside an org follow their own visibility.
  - Non-readers get 404, never 403, on every repository route.
- **Escaping:** org display names and descriptions, and team names and descriptions, render escaped.
- **Test tmpdirs:** `TMPDIR=/dev/shm`; one cargo build at a time.
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.
- **Out of scope:** the deferred list; SSH; protection rules; OIDC.

## Decisions this plan makes where the spec is silent

- **D1. Org identity.**
  - An org is an `owners` row with `kind = 'org'` plus an `orgs` row (`id` = owner id, `display_name`, `description`, `base_permission` ∈ `none|read|write`, default `none`, `created_at`, `updated_at`).
  - Handles follow the user handle rules and reserved names, unique across users and orgs.
  - Any active signed-in user may create an org and becomes its first owner.
  - Orgs cannot sign in, hold tokens, or be collaborators. Every user-only path must refuse an org owner row:
    - collaborator add;
    - assignee, review request, and mentions;
    - token creation;
    - login.
- **D2. Org membership.**
  - `org_members (org_id, user_id, role ∈ owner|member, created_at, UNIQUE (org_id, user_id))`.
  - Owners add existing active users directly as `member` or `owner`, change roles, and remove members. A member may leave.
  - The last owner cannot be removed, demoted, or leave (422).
  - Removing a member also removes them from every team of that org, in the same `Core` method; one audit row for the removal.
- **D3. Teams.**
  - Tables:
    - `teams (id, org_id, name, lower_name, description, permission ∈ read|triage|write|maintain|admin, all_repos 0/1, created_at, updated_at, UNIQUE (org_id, lower_name))`;
    - `team_members (team_id, user_id, UNIQUE)`, where the user must be an org member;
    - `team_repos (team_id, repo_id, UNIQUE)`, where the repository must be owned by the team's org.
  - Team names: 1–64 characters of `[A-Za-z0-9 _.-]`, unique per org, case-insensitive.
  - Org owners manage teams. Org members can list teams and team members.
  - Team URLs use the lower name, with spaces as `-`. Implement a single `team_slug` fn and use it everywhere.
- **D4. Resolution (one place).**
  - `permission::effective(Grants { site_admin, user_owner, org_owner, org_base, teams: &[Permission], collaborator, visibility, signed_in }) -> Option<Permission>` returns the max of:
    - Admin, when `site_admin`, `user_owner`, or `org_owner`;
    - the org base permission (`none` contributes nothing; `read`/`write` map to the levels);
    - every team grant that covers the repository (`all_repos` or a `team_repos` row);
    - the collaborator grant;
    - implicit `Read`, for public repositories, and for internal repositories when signed in.
  - `Core::grants_for(repo, user)` gathers the facts in at most three queries.
  - `is_repo_member` is true when any explicit grant exists: user owner, org owner, an org member with base ≠ `none`, a covering team, or a collaborator. Site admins are not members by that fact alone. Implicit read never makes a member.
  - Proptests:
    - the result is the max of the grant sources;
    - removing a grant never raises the level;
    - anonymous viewers get at most `Read`, and only on public repositories;
    - membership is equivalent to "at least one explicit grant".
- **D5. Org repositories.**
  - Org owners create repositories in the org: the new-repository form and `POST /api/v1/orgs/{org}/repos` (the same body as user repo creation).
  - `/{org}` lists the org's repositories that the viewer can read, the display name, and the description. Org members also see member and team counts and links.
- **D6. Transfer.**
  - `POST /api/v1/repos/{owner}/{repo}/transfer` with `{"new_owner": "<handle>"}`, plus a form in repository settings (admin, CSRF).
  - Allowed when the actor is a repo admin AND may create repositories under the new owner: the new owner is the actor, or an org the actor owns.
  - The new owner must not already have a repository with that name (422). Archived repositories may be transferred.
  - Effects:
    - the repository's `owner_id` changes;
    - the old `<owner>/<repo>` path is recorded in `repo_redirects`, reusing the rename redirect, so web, API, and git paths answer like a rename;
    - leaving an org drops that org's `team_repos` rows;
    - collaborators are kept;
    - one `repo.transfer` audit row (from and to).
  - Sessions, Trails, and hooks are unaffected (ids are stable).
- **D7. Org deletion.**
  - `DELETE /api/v1/orgs/{org}` and a settings form (owners, CSRF).
  - Allowed only when the org owns no repositories, including soft-deleted ones inside the grace period (422 otherwise, naming the count).
  - Deletes the org's teams and memberships, and frees the handle. One `org.delete` audit row.
- **D8. API shape** (mirrors existing JSON conventions and error envelope):
  - **Orgs:**
    - `POST /orgs {handle, display_name?, description?}`;
    - `GET|PATCH|DELETE /orgs/{org}`;
    - `GET /orgs/{org}/repos` (readable ones only).
  - **Org members:**
    - `GET /orgs/{org}/members`;
    - `PUT /orgs/{org}/members/{handle} {role}`;
    - `DELETE /orgs/{org}/members/{handle}`.
  - **Teams:**
    - `GET|POST /orgs/{org}/teams`;
    - `GET|PATCH|DELETE /orgs/{org}/teams/{team}`;
    - `GET /orgs/{org}/teams/{team}/members`;
    - `PUT|DELETE /orgs/{org}/teams/{team}/members/{handle}`;
    - `GET /orgs/{org}/teams/{team}/repos`;
    - `PUT|DELETE /orgs/{org}/teams/{team}/repos/{repo}`.
  - **Token scopes:** reads need `repo:read`; mutations need the same scope as repository collaborator management today.
  - **Error shape:** non-members asking for member-only org data get 404.
- **D9. Site admin.** `/admin/orgs` lists orgs (handle, display name, member count, repository count) with links. Site admins can view any org's members and teams; no extra admin mutations.

## File Structure

```
crates/starforged-db/migrations/{sqlite,postgres}/0021_orgs_teams.sql
crates/starforged-db/src/orgs.rs                 org, member, team, team member, team repo queries (new)
crates/starforged-core/src/permission.rs         Grants + effective + proptests
crates/starforged-core/src/orgs.rs               D1-D3, D7 (new)
crates/starforged-core/src/repos.rs              grants_for, permission_on, repos_of, dashboard_repos, create in org, transfer
crates/starforged-core/src/read.rs               is_repo_member
crates/starforged-api/src/orgs.rs                D8 (new), repos.rs transfer
crates/starforged-web/src/pages/orgs.rs          org/team pages (new), templates/org*.html, team*.html
crates/starforged-web/src/pages/{repo_settings.rs,repos.rs,admin.rs}
crates/starforged/tests/{api_orgs.rs,web_orgs.rs,org_permissions.rs}
README.md
```

---

### Task A1: Org schema, membership, and one permission resolver

**Files:**
- Create:
  - the 0021 migrations;
  - `crates/starforged-db/src/orgs.rs`;
  - `crates/starforged-core/src/orgs.rs`;
  - `crates/starforged-api/src/orgs.rs`;
  - `crates/starforged/tests/api_orgs.rs` and `org_permissions.rs`.
- Modify:
  - `crates/starforged-core/src/{permission.rs,repos.rs,read.rs,lib.rs}` (plus `Cargo.toml` dev-dependency `proptest.workspace = true`);
  - `crates/starforged-db/src/{lib.rs,users.rs}`;
  - `crates/starforged-api/src/lib.rs`;
  - every user-only path named in D1, so it refuses org rows.

**Interfaces:**
- Produces:
  ```rust
  pub struct Grants<'a> { pub site_admin: bool, pub user_owner: bool, pub org_owner: bool, pub org_base: Option<Permission>,
                          pub teams: &'a [Permission], pub collaborator: Option<Permission>, pub visibility: Visibility, pub signed_in: bool }
  pub fn effective(g: &Grants) -> Option<Permission>;
  pub fn is_member(g: &Grants) -> bool;   // explicit grant exists (D4)
  impl Core {
      pub async fn create_org(&self, user: &User, input: NewOrgInput) -> CoreResult<OrgView>;
      pub async fn org(&self, viewer: Option<&User>, handle: &str) -> CoreResult<OrgView>;            // public fields; member-only fields when member/site admin
      pub async fn update_org(&self, user: &User, handle: &str, input: OrgPatch) -> CoreResult<OrgView>; // owners; base_permission audit
      pub async fn delete_org(&self, user: &User, handle: &str) -> CoreResult<()>;                      // D7
      pub async fn org_members(&self, viewer: &User, handle: &str) -> CoreResult<Vec<OrgMemberView>>;
      pub async fn set_org_member(&self, user: &User, handle: &str, member: &str, role: OrgRole) -> CoreResult<OrgMemberView>;
      pub async fn remove_org_member(&self, user: &User, handle: &str, member: &str) -> CoreResult<()>;
  }
  ```
  The team input to `Grants` is wired to an empty slice in A1; A2 fills it.

- [ ] **Step 1: Write the failing tests.**
  - **Proptests** (D4) in `permission.rs`.
  - **API org lifecycle:**
    - create an org: the creator is an owner and `/orgs/{org}` returns it;
    - a handle clash with a user or org, or a reserved handle, gives 422;
    - add a member, then promote them;
    - the last owner cannot leave or be demoted (422);
    - removing a member works;
    - a non-member gets 404 on the member list; a member reads it;
    - audit rows, exactly one per change.
  - **Org rows on user-only paths:** adding an org as a collaborator, assignee, or review request gives 422 (or the path's existing "not a user" error).
  - **Base permission** on a repository moved into the org: create the repo under the user, then set `owner_id` through a db test helper, because org repository creation is A3.
    - `base=read` gives org members `Read` and makes them repo members (they see unpublished sessions on a public repo);
    - `base=none` gives them nothing beyond public read;
    - org owners get `Admin`.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core permission` and `cargo test -p starforged --test api_orgs --test org_permissions`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the Step 2 commands, then `cargo test -p starforged --test api_repos --test web_session_security --test api_sessions` (permission regressions), then clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add orgs with owners, members, and base permissions`.

---

### Task A2: Teams

**Files:**
- Modify:
  - `crates/starforged-db/src/orgs.rs`;
  - `crates/starforged-core/src/{orgs.rs,repos.rs}`;
  - `crates/starforged-api/src/{orgs.rs,lib.rs}`;
  - tests `api_orgs.rs` and `org_permissions.rs`.

**Interfaces:**
- Produces the `Core` team fns:
  - `create_team`, `team`, `teams`, `update_team`, `delete_team`;
  - `set_team_member`, `remove_team_member`;
  - `add_team_repo`, `remove_team_repo`;
  - `team_slug`.
- `grants_for` fills `teams` (D3, D4).

- [ ] **Step 1: Write the failing tests.**
  - **Team CRUD:**
    - an owner creates a team; a member cannot (403);
    - a duplicate name, case-insensitive, gives 422;
    - adding a non-org-member to a team gives 422;
    - adding a repository from another owner gives 422.
  - **Grants:**
    - a `write` team with `all_repos` gives `Write` on every org repository;
    - a `triage` team with a selected set covers only that set;
    - the highest of base, team, and collaborator wins;
    - deleting the team, removing the member, or removing the repository drops the grant immediately.
  - **Org member removal** also removes the user from that org's teams.
  - **Audit:** exactly one row per change; none for no-ops.
  - **Membership:** a team grant makes a repo member, so `refs_for_access = members` admits that user's `refs/for` push.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test api_orgs --test org_permissions`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus `--test smart_http` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add teams that grant permission on org repositories`.

---

### Task A3: Org repositories, transfer, and org deletion

**Files:**
- Modify:
  - `crates/starforged-core/src/{repos.rs,orgs.rs}`;
  - `crates/starforged-db/src/{repos.rs,redirects.rs,orgs.rs}`;
  - `crates/starforged-api/src/{orgs.rs,repos.rs,lib.rs}`;
  - tests `api_orgs.rs`, `api_repos.rs`, and the redirect tests.

**Interfaces:**
- Produces:
  - `Core::create_repo` accepting an owner handle (the actor, or an org the actor owns);
  - `Core::transfer_repo(user, owner, repo, new_owner) -> CoreResult<Repo>`;
  - `Core::delete_org` enforcing D7;
  - `repos_of` resolving org owners;
  - `dashboard_repos` covering every repository where the user is a member (D4), not only owned and collaborator repositories.

- [ ] **Step 1: Write the failing tests.**
  - **Org repository creation:**
    - an org owner creates `/{org}/{repo}` through the API;
    - a plain member gets 403;
    - the repository is cloneable over HTTP by a team member with `read`.
  - **Transfer:**
    - user → org (the actor owns the org), then org → user;
    - the old path redirects for web (301), API (301), and `git clone`;
    - a name clash gives 422;
    - a non-admin gets 403;
    - a target org the actor does not own gives 403;
    - team grants from the old org disappear;
    - collaborators are kept;
    - one `repo.transfer` audit row.
  - **Org deletion:** 422 while the org owns a repository, including a soft-deleted one inside the grace period; succeeds once none remain and frees the handle.
  - **Dashboard:** lists an org repository where the user is a member through base permission or a team.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test api_orgs --test api_repos`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus `--test web_repo_rename --test smart_http` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Let orgs own repositories and transfer repositories between owners`.

---

### Task A4: Org and team web pages, owner selector, transfer form, admin org list

**Files:**
- Create:
  - `crates/starforged-web/src/pages/orgs.rs`;
  - templates `org.html`, `org_settings.html`, `org_members.html`, `org_teams.html`, `team.html`, `org_new.html`, and `admin_orgs.html`;
  - `crates/starforged/tests/web_orgs.rs`.
- Modify:
  - `crates/starforged-web/src/{lib.rs,pages/repos.rs,pages/repo_settings.rs,pages/admin.rs}` and the owner-page handler `/{owner}`;
  - templates `new_repo.html`, `repo_settings.html`, the base layout navigation, and `admin*.html`.

**Interfaces:**
- **Routes**, mirroring the settings-page CSRF pattern (`XPage { nav_user, csrf, … }`, `Form { csrf }`, `verify_csrf`, 303):
  - `/orgs/new` (GET, POST);
  - `/{org}`: org profile when the handle is an org; the user profile otherwise;
  - `/{org}/settings`: general, base permission, delete;
  - `/{org}/settings/members` (owners) and `/{org}/members` (members);
  - `/{org}/teams` and `/{org}/teams/new`;
  - `/{org}/teams/{team}`: members, repositories, settings;
  - the new-repository owner select;
  - `/{owner}/{repo}/settings/transfer`;
  - `/admin/orgs`.

- [ ] **Step 1: Write the failing tests.**
  - **Org lifecycle in the web:**
    - create an org;
    - set the display name and base permission;
    - add a member and promote them;
    - create a team, add a member and a repository;
    - create an org repository from the owner select;
    - transfer a repository from settings.
  - **Page access:**
    - the org page is public, and lists only repositories the viewer can read;
    - member and team pages give 404 to non-members and anonymous viewers;
    - management forms give 403 to plain members.
  - **CSRF** on every new form: a forged token gives 403 and leaves state unchanged.
  - **XSS:** a hostile display name, description, and team name render escaped.
  - **Admin:** `/admin/orgs` lists orgs for site admins and gives 404 to others, matching existing admin pages.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test web_orgs`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test web_repo_settings --test web_admin` (or the existing equivalents) and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add org, team, and transfer pages`.

---

### Task A5: Permission sweep and docs

**Files:**
- Create: `crates/starforged/tests/org_security.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep.**
  - **Matrix:** grant source (org owner, base read, base write, team read/triage/write/maintain/admin with all-repos or a selected set, collaborator, none) × visibility (public, internal, private) × surface:
    - web repository page;
    - API repository read;
    - `git clone`;
    - `git push` to a branch;
    - `refs/for` push with `refs_for_access = members`;
    - gate approval counting;
    - §6.4: an unpublished session on a public repository, read through every M2f session surface: the session page, the Trail Sessions tab, `has_sessions` (its SQL binds the viewer's member and admin facts, which must come from the new resolver), timeline rows, and the commit panel.
  - **Expected:** the effective level and member status match D4. Non-readers get 404; below-threshold users get 403.
  - **Revocation is immediate on every surface:** remove the member, delete the team, transfer the repository away, or lower the base permission.
  - **Org-only paths:** every user-only path (D1) refuses an org.
- [ ] **Step 2: Run the sweep** 3 times; all green. Fix production defects found, in their owning modules, and report them.
- [ ] **Step 3: README:** an "Organizations and teams" section covering orgs, members, base permissions, teams, effective permission, members, transfer, the API routes, and the admin list. Check every example against the code.
- [ ] **Step 4: Commit** (PG gate first): `Add org permission sweep and docs`.
