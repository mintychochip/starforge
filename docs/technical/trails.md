# Trails

## Purpose

This page explains the Trail collaboration model.
It covers Trails, changes, revisions, reviews, threads, checks, and gate rules.

Read this page with [git-hosting.md](git-hosting.md).
That page covers git mechanics.
This page covers collaboration state.

## Scope

The code in `starforged-core/src/trails.rs` owns Trails. The code in `starforged-core/src/changes.rs` owns changes, revisions, reviews, and threads. The code in `checks.rs` owns commit checks. The code in `gates.rs` and `gate_rules.rs` owns gates.

Storage lives in `starforged-db::trails` and `starforged-db::checks`. Routes delegate to core functions.

## How it works

### Trails

`TrailView` describes one Trail. The fields include number, title, intent, state, ready flag, author, labels, assignees, and timestamps. `create_trail` opens a Trail. `trail_by_number` reads one Trail. `list_trails` lists Trails with filters. `dashboard_trails` lists the viewer's dashboard Trails.

A Trail state takes one of three values. The values are `open`, `closed`, and `merged`. New Trails open in state `open`. New Trails start with `ready` set to false.

`set_trail_state` moves a Trail between `open` and `closed`. `update_trail` applies field changes. State `merged` belongs to the merge path only. Calls that set `merged` fail with `Invalid`.

Trail numbers come from a counter in the insert transaction. The counter lives in `trail_sequences`. A unique constraint covers the number column as a fallback.

A title holds at most 200 characters. An intent or comment holds at most 64 KiB. A label holds at most 50 bytes. Labels use lowercase letters, digits, hyphens, underscores, and dots. One Trail holds at most 10 labels, 10 assignees, 10 review requests, and 50 session links.

`add_label` and `remove_label` manage labels. `add_assignee` and `remove_assignee` manage assignees. `request_review` and `remove_review_request` manage review requests. `link_trail_session` and `unlink_trail_session` manage session links.

### Permissions

Reads below effective `Read` permission return `NotFound`. The response masks existence. Mutations below the action threshold return `Forbidden`. `Write` alone grants no Trail powers. Assignees join through the `is_repo_member` grant.

Archived repositories refuse writes. The `ready` toggle stays triage only.

### Timeline and audit

`trail_timeline` returns timeline entries. Entry kinds include stored entries, session entries, and check entries. Trail open, close, and reopen record `trail.open`, `trail.close`, and `trail.reopen` audit rows. Merges also record `change.merge` and `trail.merged`. Gate rule changes record `gate_rule.created`, `gate_rule.updated`, and `gate_rule.deleted`. Reviews, threads, comments, and checks write timeline rows only.

### Changes and revisions

A change is a proposed head ref into a base branch. A revision is an immutable snapshot of a change. Git pushes to `refs/for` create changes. Rejected `refs/for` pushes create no change.

`record_agit_push` ingests one `refs/for` push. `list_changes` lists changes on a Trail. `get_change` reads one change. `record_branch_move` records branch head movement.

Server refs record each change. The refs look like `refs/trails/<n>/changes/<k>/head` and `refs/trails/<n>/changes/<k>/rev/<r>`. Change numbers start at `k=1`. Revision numbers start at `r=1`.

A re-push of the same head commit writes nothing. `append_revision` records dismissal in the same step. Trail refs replay through the mergeability job.

Change states are `open`, `closed`, and `merged`. `set_change_state` moves a change between `open` and `closed` only. The change creator can call it at `Read` or above. A triage user can call it at triage or above. Setting `merged` fails with `Invalid`. The merge path sets `merged`.

### Reviews and threads

`ReviewView` describes one review. The fields include revision, verdict, body, session ULID, state, and author. Verdict values are `approve`, `request_changes`, and `comment`. Review states are `pending`, `submitted`, and `dismissed`. Pending reviews are drafts. Lists hide them.

A user can only submit or discard a pending review.

`submit_review` accepts a review on a revision. Any caller with read permission can submit. Pending reviews convert in place. One `review.submitted` event fires per submit. A webhook reports the submit.

`dismiss_review` marks one review dismissed. Dismissal records a `review.dismissed` timeline row and dispatches a review event. It writes no audit row. Dismissal on push supersedes submitted `approve` verdicts on older revisions. It never dismisses `request_changes` or `comment` verdicts. The dismissal applies only when at least one gate rule matches the base branch and every matching rule sets `dismiss_on_push`.

`create_thread` opens one thread. `list_threads` lists threads. `resolve_thread` marks one thread resolved. `add_thread_comment` appends one reply. Draft threads stay out of gate counts.

### Checks

`StatusDto` describes one check. The fields include SHA, context, state, target URL, description, creator, and timestamps. `CombinedDto` describes the combined state for one SHA.

`submit_status` upserts one check by SHA and context. Callers need write permission. Archived repositories refuse submits. `list_statuses` lists checks for one SHA. `combined_status` folds one SHA set into one state. `combined_status_for_ref` resolves a branch or tag first.

Status states are `pending`, `success`, `failure`, and `error`. A context holds 1 to 255 characters. A context holds no control characters. A target URL stays empty or starts with `http://` or `https://`. A target URL holds at most 2048 characters. A description holds at most 1024 characters.

Combined precedence ranks `error` above `failure` above `pending` above `success`. An unknown SHA returns `pending` with an empty list. Writes record no timeline or audit rows. Writes fire the `check` webhook event. Reads below read permission return `NotFound`.

CI writes checks with two context forms. A job result uses context `ci/<job>`. `finish_ci_job` writes the terminal check through `submit_ci_status`. The sweep, cancel, and quota refusal also write terminal `ci/<job>` checks.

A spec failure uses context `ci/spec`. The server writes an `error` check when a commit spec fails to parse or validate. It writes the check only when the queue call names a creator. A system trigger with no creator writes no check.

`evaluate_gates` reads checks from the checks table. A required context passes only with `success` on the current head. A gate can require `ci/<job>` or `ci/spec` by name.

Read the [CI and sandboxes page](ci-and-sandboxes.md) for CI runs and quotas.

### Gates

`GateRuleDto` describes one gate rule. The fields include pattern, required approvals, dismiss flag, request-changes block, required contexts, up-to-date flag, threads flag, session evidence flag, allowed methods, and push rules. `GateRuleInput` uses absent versus null semantics for updates.

`list_gate_rules` accepts any reader. Mutations need maintain permission. Archived repositories refuse mutations. Patterns normalize to null for match-all. Non-null patterns hold 1 to 100 characters. Patterns allow letters, digits, dot, underscore, hyphen, slash, star, and question mark.

Approvals hold 0 to 20. Contexts hold at most 50 entries. Methods stay inside the set of `merge`, `squash`, `fast_forward`, and `rebase`. Empty methods mean all methods.

Intersections across matching rules narrow the allowed set. One normalized pattern exists per repository. Duplicates return `Conflict`.

`evaluate_gates` evaluates all matching rules. `evaluate_rule` evaluates one rule. Zero matching rules pass. No current revision fails. Rules combine with AND logic.

Approval counting takes the latest decisive verdict per author. Authors need write permission. `block_on_request_changes` fails the rule on any request-changes verdict. Dismissal on push limits counts to current revision approvals.

Rules match the base branch by glob. `pattern_matches` treats star and question mark as wildcards. Required contexts must show `success` on the current head. `require_up_to_date` checks that the merge base equals the base tip. `require_threads_resolved` counts public comments only. `require_session_evidence` walks at most 1024 commits and 64 trailers per commit.

Session evidence fails closed. Each `Starforge-Session` trailer must name an existing session ULID. Each named session stays out of quarantine. Read [sessions.md](sessions.md) for session capture.

### Merge from the Trail side

`merge_change` merges one change into its base branch. The caller needs write permission. The function holds the shared repository lock. The function re-evaluates gates at merge time. The function checks allowed methods.

`rebase` uses `starforged_git::merge::rebase_onto`. The function reads `merge-base..head` oldest first. For each commit it runs `git merge-tree --write-tree --merge-base=<original-parent>` against the new parent. It writes the result with `commit_tree_as`, which keeps the original author and sets the server as committer.

The function refuses a merge commit, a conflict, or more than 1024 commits. The base ref moves with the same CAS as the other methods.

A cross-repository change has a `change_sources` row. The row stores the source repository and branch. `create_cross_repo_change` fetches the source branch with `write::fetch_branch` into a temporary import ref, verifies the object, records the change and revision, then deletes the temporary ref. The trail head ref keeps the objects reachable.

`refresh_cross_repo_change` repeats the fetch and appends a revision when the head moved. The leak rule allows a public source, a same-owner source, or a source admin. `merge_change` also requires read access on the source.

Gate-rule push rules act in branch protection at push time. The fields are `block_direct_push`, `block_force_push`, and `block_deletion`. `merge_change` does not re-check them.

An empty intersection of allowed methods stops the merge. `finish_merge` moves the Trail to `merged` when no open change remains. `finish_merge` records `change.merge` in timeline and audit.

Read [git-hosting.md](git-hosting.md) for branch CAS updates and conflict retries. Read [http-api.md](http-api.md) for REST endpoints.

## Interfaces

`create_trail`, `update_trail`, and `set_trail_state` manage Trails. `add_comment` and `edit_comment` manage Trail comments. `trail_by_number`, `list_trails`, and `trail_timeline` read state.

`record_agit_push`, `list_changes`, and `get_change` manage changes. `create_cross_repo_change` and `refresh_cross_repo_change` manage cross-repository changes. `change_source` reads the source row. `submit_review`, `list_reviews`, and `dismiss_review` manage reviews. `create_thread`, `resolve_thread`, and `add_thread_comment` manage threads.

`submit_status`, `list_statuses`, and `combined_status` manage checks. `evaluate_gates` reports gate state. `create_gate_rule`, `update_gate_rule`, and `delete_gate_rule` manage gate rules.

## Failure behavior

Only the merge path sets `merged`. Direct calls that set `merged` fail with `Invalid`. A merged Trail can still move back to `open` or `closed` through `set_trail_state`. A merged Trail still accepts title, intent, and ready edits through `update_trail`. Invalid states return `Invalid`. Unknown Trails return `NotFound`.

Unknown SHAs return `pending` with an empty list. Unresolvable refs return `NotFound`. Unverifiable session evidence fails the gate. Gate failure stops the merge.

Duplicate head commits write nothing. Re-pushes stay idempotent. Unique violations return `Conflict` without an internal retry. The caller can retry. The merge path separately retries its base-branch compare and swap once.

## Verification

Integration tests cover Trail state machine and number preservation. Integration tests cover timeline and audit counts. Integration tests cover review verdicts and thread resolution.

Integration tests cover gate evaluation and combined check precedence. Integration tests cover session evidence and quarantine behavior.

## Related

Read [git-hosting.md](git-hosting.md) for push and merge mechanics. Read [http-api.md](http-api.md) for REST endpoints. Read [sessions.md](sessions.md) for session evidence.

<!-- ste-sources
crates/starforged-core/src/trails.rs
crates/starforged-core/src/changes.rs
crates/starforged-core/src/checks.rs
crates/starforged-core/src/gates.rs
crates/starforged-core/src/gate_rules.rs
crates/starforged-core/src/merge.rs
crates/starforged-core/src/ci.rs
crates/starforged-db/src
-->
