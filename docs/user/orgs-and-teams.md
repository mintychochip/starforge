# Orgs and teams

Organizations share the handle namespace with users and own repositories at `/{org}/{repo}`. Any active
signed-in user can create one from **New organization** (`/orgs/new`); the creator becomes its first owner.
An org has a display name, a description, owners, members, and a **base permission** (`none`, `read`, or
`write`, default `none`) that every member holds on every org repository. The org profile (`/{org}`) is
public and lists the display name, the description, and the repositories the viewer can read; org members
also see member and team links with the member count, plus the base permission.

Owners manage membership in **Members** (`/orgs/{org}/members`): they add existing users directly as
`member` or `owner`, change roles, and remove members. The last owner cannot be removed, demoted, or leave
(the API answers 422). Removing a member also removes them from every team of the org. The member list and
every team page answer 404 to anyone who is not an org member or a site admin, so membership stays private.

**Teams** (`/orgs/{org}/teams`) belong to an org and grant one permission level (`read`, `triage`, `write`,
`maintain`, `admin`) on all of the org's repositories or on a selected set. Team names are 1–64 characters
of letters, digits, spaces, `_`, `.`, and `-`, unique per org ignoring case; team pages live at
`/orgs/{org}/teams/{team}` under the lowercased name with spaces as `-`. Team members must be org members,
and team repositories must be owned by the team's org. Org members can list teams and their members; only
owners change them, from `/orgs/{org}/teams/new` and the team page.

The **effective permission** on a repository is the highest of: site admin, the owner's own repositories,
and org ownership (all `admin`); the org base permission; every team grant covering the repository; the
collaborator grant; and implicit `read` (public repositories, and internal ones for signed-in users). A
repository **member** is a user with an explicit grant — collaborator, covering team, non-`none` base
permission, or ownership. Site admins are not members by that fact alone, and implicit read never counts.
Membership feeds `refs/for` pushes when `refs_for_access` is `members`, unpublished-session visibility, and
the dashboard. Losing a grant — member removal, team deletion, base lowering, transfer away — takes effect
immediately on every surface.

**Transfer** moves a repository to another owner from **Settings → Transfer**
(`/{owner}/{repo}/settings/transfer`). The actor must be a repository admin, and the new owner must be the
actor or an org the actor owns — site admins have no bypass. The old path redirects to the new one for
pages, API reads, and git; team links from the old org drop while collaborators stay.

The API mirrors this at `/api/v1`: `POST /orgs`; `GET`/`PATCH`/`DELETE /orgs/{org}` (deleting needs an
empty org, including soft-deleted repositories inside the grace period, else 422); `GET /orgs/{org}/repos`
and `POST` it to create (owners only; plain members get 403); `GET /orgs/{org}/members` and
`PUT`/`DELETE /orgs/{org}/members/{handle}`; `GET`/`POST /orgs/{org}/teams`;
`GET`/`PATCH`/`DELETE /orgs/{org}/teams/{team}`; `GET /orgs/{org}/teams/{team}/members` with
`PUT`/`DELETE …/{handle}`; `GET /orgs/{org}/teams/{team}/repos` with `PUT`/`DELETE …/{repo}`; and
`POST /repos/{owner}/{repo}/transfer` (`{"new_owner": "<handle>"}`). Reads need the `repo:read` token
scope and mutations need `repo:write`; member-only data answers 404 to outsiders while below-threshold
actors get 403. Every membership or permission change writes exactly one audit row.

Site admins see every org under **Admin → Orgs** (`/admin/orgs`: handle, display name, member and
repository counts, with links) and can view any org's members and teams, but have no extra org-management
powers.
