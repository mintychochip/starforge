# Trails

Trails are per-repo numbered issues: `/{owner}/{repo}/trails` lists them (`?page=N`, 30 per page,
`?state=open|closed`, `?label=`, `?assignee=`), `.../trails/new` opens one, and
`.../trails/{number}` shows the detail — description, comments, labels, assignees, and the
timeline — with triage-gated close/reopen, label, assignee, and ready controls. Titles and
descriptions render as sanitized Markdown (labels are `[a-z0-9-_.]`, lowercase, max 50 chars);
creating and commenting need read access, everything curatorial needs triage, comment edits
belong to the author or an admin, and strangers get `404` so trail numbers stay undiscoverable.
Every web form carries a `_csrf` token.

The JSON API mirrors the pages: `GET`/`POST /api/v1/repos/{owner}/{repo}/trails` (keyset
`?after=&limit=`, `next_after` cursor), `GET`/`PATCH .../trails/{n}` (title, intent, ready,
state; `merged` is refused — only the merge path may set it), `GET`/`POST
.../trails/{n}/comments` plus `PATCH .../comments/{id}`, and `POST`/`DELETE .../labels` and
`.../assignees` (assignees must already be repo members). Reads need `repo:read`; every
mutation needs `trail:write` on top, so a curator token carries `"repo:read trail:write"`.
Errors use the shared `{"error": {"code", "message"}}` envelope.

### Trail page

Every Trail page shares three tabs — Conversation (`.../trails/{n}`),
Changes (`.../trails/{n}/changes`, one row per change with its state and a
gate summary), and Sessions (`.../trails/{n}/sessions`, with the count of
sessions the viewer may read) — plus a header with the intent, labels,
assignees, reviewers, and a gate panel per open change. The panel shows
approvals (have/need), the required checks with their states, conflicts
(mergeability and conflicting paths), and session evidence; viewers with
merge permission also get the merge button with a method selector limited
to the allowed methods, posting to the existing change merge route. The
panel reuses the gate evaluation — there is no separate gate logic — and
the merge re-checks everything server-side, so a stale page authorizes
nothing.

The Conversation timeline merges stored events with derived rows in time
order: linked sessions (one row per readable session linked through a
commit, timed at the later of the upload and the first revision containing
its commit), checks (the latest row per (context, head SHA), because the
checks table upserts, with context, state, description, and an `http(s)` target link), and readable
sentences for every stored `change.*`, `review.*`, and
`trail.session_linked/unlinked` kind. Derived rows are computed per request
and filtered for the viewer.

The Sessions tab groups one section per Trail commit that has a readable
session (newest first), then a "Linked by hand" group, each row showing the
agent name and version, models, title as prompt preview (escaped, 120
characters), token totals, link confidence (`exact`/`heuristic`/`explicit`),
uploader, start time, and a `#turn-<seq_start>` deep link when the commit
link carries a start sequence, with per-group and Trail-wide totals. The
JSON API mirrors it at `GET
/api/v1/repos/{owner}/{repo}/trails/{n}/sessions`. Sessions link two ways:
through commits (a `Starforge-Session: <ULID>` trailer or a CLI commit
claim joins an uploaded session to a commit in the Trail's changes,
whichever side arrives first) or by hand — triage and up may link any
readable same-repo session, and the Trail author may link sessions they
uploaded themselves (at most 50 explicit links per Trail; linking is
idempotent). The API is `POST .../trails/{n}/sessions` with `{"session":
"<ulid>"}` and `DELETE .../trails/{n}/sessions/{ulid}` (both answer the
Sessions JSON); the tab carries link/unlink forms. Every link and unlink
writes a `trail.session_linked`/`trail.session_unlinked` timeline row and
a matching webhook. Every session surface — the tab, the API,
`has_sessions`, the timeline, and the commit Sessions panel — applies the
session read rules for the current viewer, so no title, ULID, or total of
an unreadable session ever reaches them.

Not yet: trail deletion (close covers M2a).

### Trails from the command line (M2d)

`starforge trail` drives a trail end to end from the terminal. Every command
takes `--format text|json` (default `text`); `show` also accepts `agent`, and
`json` prints the pretty-printed response the command acted on:

```bash
starforge trail list --state open
starforge trail show 12
starforge trail show 12 --format agent
starforge trail create --title "Faster sync" --body "Why this exists"
starforge trail comment 12 --body "Needs a test"
starforge trail push --trail 12
starforge trail checkout 12
starforge trail review 12 --approve
starforge trail review 12 --request-changes --comments '[{"path":"a.txt","side":"head","start_line":1,"end_line":2,"body":"nit"}]'
starforge trail merge 12
```

Without `--body`/`--body-file`, `trail review` posts a one-line body restating the verdict ("Approved.", "Changes requested.", or "Commented."), because the server rejects empty review bodies.

`show` prints the header, the intent, one line per change, then — under each
change with any — its reviews (`#id verdict by author on revision R`, with
`(dismissed)` when dismissed, plus the body) and its inline threads
(`#id path:start-end (side, revision R)`, with `resolved`/`outdated` flags,
plus each comment as `author: body`), then the trail comments.
`show --format json` returns `{trail, changes: [{change, status}]}`, where
`change.gates` is the gate report (`passed` plus per-rule results),
`status` the combined commit status, and the change detail keeps its
`reviews` and `threads` (only `files` and `truncated` are stripped).
`--format agent` keeps the same structure and frames every review body
(source `trail #N change K review <id>`) and every thread-comment body
(source `trail #N change K thread <tid> comment <cid>`), each with its
author, in nonce-tagged `<untrusted-data>` blocks. Frame delimiters are
escaped, so a hostile body can neither close nor open a frame, and an agent
reading the trail cannot be steered by attacker-written text it is then
asked to act on (for example by running `trail merge`).

`push` defaults the base to the remote's HEAD branch and the topic to a slug
of the current branch (`--base`/`--topic` override; `--trail N` files the
revision under that trail and `--title` names a new one). After a successful
push it prints `trail #N change K revision R: <url>`; if the server has not
recorded the change within 10 s it prints `pushed <sha>; ...` instead and
still exits `0`. `checkout` creates the branch `trail/<n>/<k>` at the head
(fast-forwarding an ancestor, refusing on divergence and touching nothing),
or detaches at `--rev R` for an immutable revision. Without `--change` the
single open change wins, erroring when there are zero or several — except
`checkout`, which also accepts the only change when none is open, since
inspecting a merged change is legitimate. Without `--method`, `merge` uses
`merge` when allowed, else the single allowed
method. Git authenticates with your own remote configuration — the CLI never
hands its API token to git — so push and fetch use your usual credentials
and prompts. Exits are `0` on success, `1` on any failure; usage errors keep
clap's `2`.

Review requests mark the Trails that need eyes. They are per Trail: triage
and up may request any repository member except the Trail's author (at most
10 per Trail; adding twice is a no-op), and the request clears itself when
that user submits any review on any change of the Trail — `review.submitted`
records the clearing, so no extra timeline row appears. The API is
`POST`/`DELETE /api/v1/repos/{owner}/{repo}/trails/{n}/review-requests` with
`{"user": "<handle>"}` (`200` with the updated Trail; unknown, non-member,
and author targets are `422`, non-reader callers `404`, below-triage readers
`403`); the Trail page carries a Reviewers section with add/remove forms.
Every add and remove writes exactly one `trail.review_requested` /
`trail.review_request_removed` timeline row and fans out a `trail`
`updated` webhook with the matching `cause`.

The Trail list filters compose: `?state=open|closed|merged`, `?label=`,
`?assignee=`, `?author=`, `?has_changes=true|false`,
`?has_sessions=true|false`, and `?review_requested=<handle>` (an unknown
handle lists nothing, never `404`), 30 per page with pager links that keep
the filters. `has_sessions=true` keeps Trails with at least one linked
session the viewer may read (through commits or by hand); `false` keeps
the rest. The API and CLI reject any other `has_sessions` value with `422`;
the web list treats other values as no filter.
The API mirrors these as
keyset filters — `GET .../trails?state=&label=&assignee=&author=&has_changes=&has_sessions=&review_requested=&after=&limit=` with a `next_after` cursor
(`has_changes=maybe` and `has_sessions=maybe` are `422`) — and the CLI as
`starforge trail list [--state open|closed|merged|all] [--label=…]
[--assignee=…] [--author=…] [--has-changes true|false]
[--has-sessions true|false] [--review-requested <handle>]`.

The dashboard (`/`, signed in) adds three sections above the repository
list — "Assigned to you" and "Awaiting your review" (open Trails, newest
updated first, at most 20 each) and "Your recent sessions" (your uploads you
may still read, newest first, at most 10). Every row is re-checked against
your current permission, so losing access hides it immediately; anonymous
visitors see the marketing page with no sections.

Push to `refs/for/<branch>` to propose work without moving the branch — the `refs/for`
ref itself is never stored. `refs/for/<branch>/<topic>` names the thread; without a topic
the pusher's handle is used, so re-pushing the same `<branch>/<topic>` appends a revision
to your open change (re-pushing the same SHA is a no-op), while another user or topic
starts a fresh change:

```bash
git push origin HEAD:refs/for/main/feature-x
git push -o trail=3 -o title="Faster sync" origin HEAD:refs/for/main
```

`-o trail=<n>` files the change under that trail (default: a new trail titled from the
tip subject). Duplicate, unknown, or malformed options reject the whole push, and
anonymous pushes are rejected everywhere. Triage can also track an existing branch as a
change from the trail page.

Every change keeps its revisions with diffs (same line- and byte-caps as the compare
page) and a mergeability verdict — `clean`, or `conflict` with the conflicting paths —
recomputed on each revision and each base-branch move. Any reader may review (approve,
request changes, comment) and open file/line threads, but only reviews from writers and
above count toward merge; triage dismisses reviews, the thread author or triage resolves
them, and the creator or triage closes and reopens. Threads anchored at older revisions
are marked outdated. The change page (`/{owner}/{repo}/trails/{n}/changes/{k}`, `?rev=`
selects the revision) shows all of this with role-gated controls. The merge form
offers the methods the matching gate rules allow and stays disabled until every gate
passes; the server re-checks gates, permission, and method at merge time, so a stale
page authorizes nothing. Gate and conflict failures re-render the change page with `422`.
The page's compare picker (or `?from=<r1>&to=<r2>`, two distinct revisions of the
change) shows the tree diff between those revisions' heads, labeled as such with a
note that it includes base changes when the change was rebased; an unknown revision
is `404`, `from == to` is `422`. In the default revision view, threads anchored on
that revision render inline under their `(path, side, end_line)` diff line; threads
anchored elsewhere — or whose line is absent from the displayed hunks — list below,
marked outdated where they are. Signed-in readers may mark files viewed
(`viewed=1|0`); the mark stores the file's blob at the displayed head, so a later
revision that changes the file resets it while one that leaves it alone keeps it
viewed, and viewed files render collapsed. The viewed toggle, like every other
change form, carries a `_csrf` token; anonymous viewers see no toggles, and archived
repos refuse with `422`.

The JSON API mirrors the page: `GET`/`POST .../trails/{n}/changes` (triage to track a
branch), `GET`/`PATCH .../changes/{k}` (close/reopen; `merged` is refused), `.../state`,
`.../diff[?from=&to=]`, `.../revisions[/{r}]`, `.../reviews` (`POST .../{id}/dismiss` for triage),
and `.../threads` (`POST .../{t}/resolve`, `.../{t}/comments`). Reads need `repo:read`,
mutations need `trail:write`; strangers get `404` so change numbers stay undiscoverable.

### Pending reviews

A signed-in reader holds at most one pending (draft) review per change. Posting a
thread or a thread comment with `"pending": true` attaches the comment to the
actor's draft — created on demand on the change's current revision — instead of
opening a public thread; pending comments, and threads whose only comments are
pending, are visible only to their author (web, API, and therefore CLI). Pending
reviews never count toward gates, never appear in the timeline, and dispatch
nothing. Posting a review converts the actor's draft: the review takes the given
verdict and body at the change's current revision with the draft's comments
attached, writing exactly one `review.submitted` timeline row and one
`review`/`submitted` webhook, clearing the review request and counting toward
gates; without a draft the submit behaves as before. `GET
.../changes/{k}/reviews/pending` returns the actor's draft or `404`;
`DELETE .../changes/{k}/reviews/pending` discards the draft's comments plus the
threads left empty, with no timeline row. Dismissing a pending review is `422`.
On the web the inline comment form offers "Comment" and "Add to review", and a
"Finish your review" panel shows the draft comment count with verdict, body,
Submit, and Discard.

CI pushes per-commit statuses: `POST /api/v1/repos/{owner}/{repo}/statuses/{sha}` with
`{"state": "pending|success|failure|error", "context": "ci/unit"}` (context names are
1-255 characters without control characters; plus an optional `description` of at most 1024 chars and an `http(s)` `target_url` of at most 2048 chars).
Posting needs write access (`repo:write` on top of read) and answers `201`, like GitHub's;
reads need `repo:read`. `GET .../commits/{ref}/status` folds every latest-per-context row
into one state (`error` beats `failure` beats `pending` beats `success`; an unknown SHA is
`pending` with nothing behind it). `{ref}` is a SHA, a branch, or an annotated tag (a
branch shadows a same-named tag; anything else is `404`); slashes arrive percent-encoded.
A bad SHA, state, or context answers `422`. Every API error body is
`{"error": {"code", "message", "details": null}}`.

Gate rules make merging fail closed. Each rule is stored on the repository with a
branch glob (empty matches every branch); every rule matching the change's base must
pass, and zero matching rules means only clean mergeability is required. A rule can
demand N writer approvals (only write+ reviews count; each reviewer counts
once, by their latest approve or request-changes verdict, so a later approval
clears that reviewer's own request for changes; dismiss-on-push drops
older-revision votes, while request-changes blocks on rules that ask it to), green
required contexts, an up-to-date head, resolved threads, and session evidence linking
the commits to uploaded agent sessions. The change page's Gates panel — and
`GET .../trails/{n}/changes/{k}/gates` — shows which rules match and why; evaluation
writes nothing, and merging re-evaluates everything server-side, so a stale client
report can never authorize a merge. Admins manage rules from the repository
settings "Merge gates" section or via `GET`/`POST .../repos/{owner}/{repo}/gate-rules`
and `PATCH`/`DELETE .../gate-rules/{id}` (reads need `repo:read`, mutations
`repo:write` on top of maintain): each rule pairs one branch pattern (empty or
null means all branches, at most one rule per pattern) with approval, context, and
method requirements, and every change lands exactly one `gate_rule.*` timeline row.

Merging needs write access on a non-archived repo: `POST .../changes/{k}/merge` with
`{"method": "merge|squash|fast_forward"}`. `merge` writes a two-parent merge commit,
`squash` condenses the head into one commit (subject lines first, then one
`Starforge-Session:` trailer per session in order of appearance), and `fast_forward`
moves the ref only when the head already contains the base; every commit carries a
`Starforge-Trail: <owner>/<repo>#<n>` trailer. The change flips to `merged`, and its
trail closes once no open change remains. Conflicts and CAS races answer `409` with the
fresh SHAs; failing gates answer `422` with the reasons.

Gate rules double as branch protection. Each rule carries three push
restrictions alongside its merge gates: `block_direct_push` (changes must go
through a Trail), `block_force_push`, and `block_deletion`. Patterns are
globs (`*` matches any run, `?` one character; empty or null means all
branches, at most one rule per pattern); every rule matching the branch
applies, and a push is refused when ANY matching rule blocks it. Only the
direct-push block can be bypassed, through the rule's allow-list; force-push
and deletion blocks stop everyone, including admins and site admins. Protection
refusals reach the pusher as `remote: starforge: …`, naming the ref and the
rule pattern, and the server-side ref is left untouched; write-tier,
namespace, and snapshot failures name only the ref.

Each rule may exempt individual users (by handle) and, on org-owned
repositories only, whole teams (by slug) from the direct-push block via
`push_allowlist: {"users": [...], "teams": [...]}`. The exemption covers
only direct pushes on that rule: an allow-listed writer still cannot force
push or delete, and allow-listed users still need write access to push at
all. Unknown handles, unknown teams, and team entries on a user-owned
repository answer `422`.

Tag protection is a separate per-repository pattern list: creating, moving,
or deleting a tag that matches any pattern needs maintain or above, while
non-matching tags need only write, as before. The API is
`GET`/`POST .../repos/{owner}/{repo}/tag-protections` (body `{"pattern"}`)
and `DELETE .../tag-protections/{id}`; like the gate-rule list, tag-protection
reads are open to any repository reader (non-readers `404`) and mutations
need maintain, plus the `repo:write` token scope. Both lists answer `404`
for unknown ids.

Pushes to any other namespace are refused unless a site admin allow-lists
it in `git.allowed_ref_namespaces` (e.g. `allowed_ref_namespaces =
["refs/notes/"]`, overridable as
`STARFORGE__GIT__ALLOWED_REF_NAMESPACES`). Each entry must start with
`refs/` and end with `/`, and must neither equal nor overlap `refs/heads/`,
`refs/tags/`, `refs/for/`, or `refs/trails/` — a bad entry fails startup
naming the entry. Allow-listed namespaces need write access plus a
write-scoped token and are never subject to branch protection. Server-side
writes bypass all of this: Trail merges move protected branches, and
`refs/trails/*` stays server-only (clients cannot push it, and fetches hide
it).

The repository settings **Branch protection** page
(`/{owner}/{repo}/settings/protection`, maintain and up) lists the rules by
pattern with their gates and push restrictions, with create, edit, and
delete forms covering every gate field, every push field, and the
allow-list, plus the tag-protection list with add and remove forms. All
forms carry CSRF and answer `303` or a `422` re-render.

Every protection change writes exactly one audit row —
`gate_rule.created`/`gate_rule.updated`/`gate_rule.deleted` and
`tag_protection.created`/`tag_protection.deleted` — while no-op updates
write nothing. Branch protection lives in migration `0022`, tag protection
in `0023`.
